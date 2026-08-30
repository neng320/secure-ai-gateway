package audit

import (
	"errors"
	"strings"
	"testing"
	"time"

	"ai-gateway/internal/database"
	"ai-gateway/internal/models"

	"gorm.io/gorm"
)

func newP108BS1DB(t *testing.T) (*gorm.DB, string) {
	t.Helper()
	path := t.TempDir() + "/audit.db"
	db, err := database.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := MigrateIntegrity(db); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if sqlDB, err := db.DB(); err == nil {
			_ = sqlDB.Close()
		}
	})
	return db, path
}

func testAuditEvent(targetID string) models.AuditEvent {
	return models.AuditEvent{
		Action:    ActionClientCreated,
		ActorType: "admin",
		ActorID:   "s1-test-admin",
		TargetID:  targetID,
		Reason:    "slice one test",
	}
}

func TestP108B_S1_RecordTxRequiresTransaction(t *testing.T) {
	db, _ := newP108BS1DB(t)
	svc := NewService(db)

	if err := svc.RecordTx(db, testAuditEvent("non-transaction")); !errors.Is(err, ErrAuditTransactionRequired) {
		t.Fatalf("RecordTx on a non-transaction DB should return ErrAuditTransactionRequired, got %v", err)
	}

	var eventCount int64
	if err := db.Model(&models.AuditEvent{}).Count(&eventCount).Error; err != nil {
		t.Fatal(err)
	}
	if eventCount != 0 {
		t.Fatalf("rejected non-transaction RecordTx inserted %d event(s)", eventCount)
	}
	var state models.AuditChainState
	if err := db.First(&state, 1).Error; err != nil {
		t.Fatal(err)
	}
	if state.HeadHash != "" {
		t.Fatalf("rejected non-transaction RecordTx changed chain head to %q", state.HeadHash)
	}
}

func TestP108B_S1_FreshInstallMigration(t *testing.T) {
	db, _ := newP108BS1DB(t)
	var states []models.AuditChainState
	if err := db.Order("id ASC").Find(&states).Error; err != nil {
		t.Fatal(err)
	}
	if len(states) != 1 || states[0].ID != 1 || states[0].ChainVersion != chainVersionV1 || states[0].HeadHash != "" {
		t.Fatalf("fresh migration must create exactly one empty v1 state: %+v", states)
	}
	if err := NewService(db).VerifyAuditChain(); err != nil {
		t.Fatalf("fresh empty audit chain should verify: %v", err)
	}
}

func TestP108B_S1_StandaloneRecordCreatesChain(t *testing.T) {
	db, _ := newP108BS1DB(t)
	svc := NewService(db)

	if err := svc.Record(testAuditEvent("standalone")); err != nil {
		t.Fatal(err)
	}
	if err := svc.VerifyAuditChain(); err != nil {
		t.Fatalf("standalone Record should produce a valid chain: %v", err)
	}

	var event models.AuditEvent
	if err := db.First(&event).Error; err != nil {
		t.Fatal(err)
	}
	if event.ChainVersion != chainVersionV1 || event.EventHash == "" || event.PrevHash != "" {
		t.Fatalf("unexpected first chained event: %+v", event)
	}
	var state models.AuditChainState
	if err := db.First(&state, 1).Error; err != nil {
		t.Fatal(err)
	}
	if state.HeadHash != event.EventHash {
		t.Fatalf("chain head %q does not match event hash %q", state.HeadHash, event.EventHash)
	}
}

func TestP108B_S1_RecordOwnsChainMaterial(t *testing.T) {
	db, _ := newP108BS1DB(t)
	svc := NewService(db)
	callerTime := time.Unix(1, 2).UTC()
	if err := svc.Record(models.AuditEvent{
		EventID:      "caller-event-id",
		ChainVersion: "v9",
		PrevHash:     strings.Repeat("a", 64),
		EventHash:    strings.Repeat("b", 64),
		Action:       ActionClientCreated,
		ActorType:    "admin",
		ActorID:      "s1-test-admin",
		TargetID:     "owned-material",
		CreatedAt:    callerTime,
	}); err != nil {
		t.Fatal(err)
	}
	var event models.AuditEvent
	if err := db.First(&event).Error; err != nil {
		t.Fatal(err)
	}
	if event.EventID == "caller-event-id" || event.ChainVersion != chainVersionV1 || event.PrevHash != "" || event.EventHash == strings.Repeat("b", 64) || event.CreatedAt.Equal(callerTime) {
		t.Fatalf("Record must own event ID/time/chain fields: %+v", event)
	}
}

func TestP108B_S1_RecordTxRollbackKeepsEventAndState(t *testing.T) {
	db, _ := newP108BS1DB(t)
	svc := NewService(db)
	rollback := errors.New("forced slice one rollback")

	if err := db.Transaction(func(tx *gorm.DB) error {
		if err := svc.RecordTx(tx, testAuditEvent("rollback")); err != nil {
			return err
		}
		return rollback
	}); !errors.Is(err, rollback) {
		t.Fatalf("expected caller transaction rollback, got %v", err)
	}

	var eventCount int64
	if err := db.Model(&models.AuditEvent{}).Count(&eventCount).Error; err != nil {
		t.Fatal(err)
	}
	if eventCount != 0 {
		t.Fatalf("rolled-back RecordTx left %d event(s)", eventCount)
	}
	var state models.AuditChainState
	if err := db.First(&state, 1).Error; err != nil {
		t.Fatal(err)
	}
	if state.HeadHash != "" {
		t.Fatalf("rolled-back RecordTx left head hash %q", state.HeadHash)
	}
	if err := svc.VerifyAuditChain(); err != nil {
		t.Fatalf("empty rolled-back chain should verify: %v", err)
	}
}

func TestP108B_S1_TimestampRoundTripPreservesHash(t *testing.T) {
	db, path := newP108BS1DB(t)
	svc := NewService(db)
	if err := svc.Record(testAuditEvent("timestamp-round-trip")); err != nil {
		t.Fatal(err)
	}

	var before models.AuditEvent
	if err := db.First(&before).Error; err != nil {
		t.Fatal(err)
	}
	beforeUnixNano := before.CreatedAt.UTC().UnixNano()
	beforeHash := before.EventHash
	if err := svc.VerifyAuditChain(); err != nil {
		t.Fatal(err)
	}
	if sqlDB, err := db.DB(); err == nil {
		if err := sqlDB.Close(); err != nil {
			t.Fatal(err)
		}
	}

	reopened, err := database.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if sqlDB, err := reopened.DB(); err == nil {
			_ = sqlDB.Close()
		}
	}()
	if err := MigrateIntegrity(reopened); err != nil {
		t.Fatal(err)
	}
	var after models.AuditEvent
	if err := reopened.First(&after).Error; err != nil {
		t.Fatal(err)
	}
	if got := after.CreatedAt.UTC().UnixNano(); got != beforeUnixNano {
		t.Fatalf("CreatedAt UnixNano changed across SQLite round-trip: before=%d after=%d", beforeUnixNano, got)
	}
	if after.EventHash != beforeHash || eventHash(after) != beforeHash {
		t.Fatalf("EventHash changed across SQLite round-trip: before=%s after=%s recomputed=%s", beforeHash, after.EventHash, eventHash(after))
	}
	if err := NewService(reopened).VerifyAuditChain(); err != nil {
		t.Fatalf("reopened chain should verify: %v", err)
	}
	if time.Since(after.CreatedAt) < 0 {
		t.Fatalf("round-tripped timestamp is unexpectedly in the future: %v", after.CreatedAt)
	}
}

func TestP108B_S1_DatabaseMutationGuards(t *testing.T) {
	db, _ := newP108BS1DB(t)
	svc := NewService(db)
	if err := svc.Record(testAuditEvent("immutable")); err != nil {
		t.Fatal(err)
	}

	if err := db.Exec("UPDATE audit_events SET reason = ? WHERE id = 1", "tampered").Error; err == nil || !strings.Contains(err.Error(), "AUDIT_EVENT_IMMUTABLE") {
		t.Fatalf("raw UPDATE should be rejected with AUDIT_EVENT_IMMUTABLE, got %v", err)
	}
	if err := db.Exec("DELETE FROM audit_events WHERE id = 1").Error; err == nil || !strings.Contains(err.Error(), "AUDIT_EVENT_IMMUTABLE") {
		t.Fatalf("raw DELETE should be rejected with AUDIT_EVENT_IMMUTABLE, got %v", err)
	}
	if err := svc.Record(testAuditEvent("insert-after-guard")); err != nil {
		t.Fatalf("normal INSERT should remain allowed after guards: %v", err)
	}
	if err := svc.VerifyAuditChain(); err != nil {
		t.Fatalf("guarded chain should verify: %v", err)
	}
}

func TestP108B_S1_MutationGuardsSurviveReopen(t *testing.T) {
	db, path := newP108BS1DB(t)
	svc := NewService(db)
	if err := svc.Record(testAuditEvent("reopen-guards")); err != nil {
		t.Fatal(err)
	}
	if sqlDB, err := db.DB(); err == nil {
		if err := sqlDB.Close(); err != nil {
			t.Fatal(err)
		}
	}

	reopened, err := database.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if sqlDB, err := reopened.DB(); err == nil {
			_ = sqlDB.Close()
		}
	}()
	if err := MigrateIntegrity(reopened); err != nil {
		t.Fatal(err)
	}
	if err := reopened.Exec("UPDATE audit_events SET reason = ? WHERE id = 1", "tampered").Error; err == nil || !strings.Contains(err.Error(), "AUDIT_EVENT_IMMUTABLE") {
		t.Fatalf("reopened database must reject UPDATE, got %v", err)
	}
	if err := reopened.Exec("DELETE FROM audit_events WHERE id = 1").Error; err == nil || !strings.Contains(err.Error(), "AUDIT_EVENT_IMMUTABLE") {
		t.Fatalf("reopened database must reject DELETE, got %v", err)
	}
}

func TestP108B_S1_TriggerDefinitionsAreExact(t *testing.T) {
	db, _ := newP108BS1DB(t)
	var rows []auditTriggerDefinition
	if err := db.Raw("SELECT name, sql FROM sqlite_master WHERE type = 'trigger' AND tbl_name = 'audit_events'").Scan(&rows).Error; err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 {
		t.Fatalf("expected exactly two audit mutation guards, got %d", len(rows))
	}
	got := make(map[string]string, len(rows))
	for _, row := range rows {
		got[row.Name] = normalizeTriggerSQL(row.SQL)
	}
	for name, want := range map[string]string{
		auditUpdateTriggerName: normalizeTriggerSQL(auditUpdateTriggerSQL),
		auditDeleteTriggerName: normalizeTriggerSQL(auditDeleteTriggerSQL),
	} {
		if got[name] != want {
			t.Fatalf("trigger %q definition mismatch: got=%q want=%q", name, got[name], want)
		}
	}
}

func TestP108B_S1_AppendRejectsStateTailMismatch(t *testing.T) {
	db, _ := newP108BS1DB(t)
	svc := NewService(db)
	if err := svc.Record(testAuditEvent("state-tail")); err != nil {
		t.Fatal(err)
	}
	if err := db.Model(&models.AuditChainState{}).Where("id = 1").Update("head_hash", strings.Repeat("0", 64)).Error; err != nil {
		t.Fatal(err)
	}

	err := svc.Record(testAuditEvent("must-reject"))
	if !errors.Is(err, ErrAuditIntegrity) {
		t.Fatalf("state/tail mismatch should return ErrAuditIntegrity, got %v", err)
	}
	var eventCount int64
	if err := db.Model(&models.AuditEvent{}).Count(&eventCount).Error; err != nil {
		t.Fatal(err)
	}
	if eventCount != 1 {
		t.Fatalf("mismatched append should not insert an event, got %d", eventCount)
	}
}
