package audit

import (
	"errors"
	"strings"
	"testing"

	"ai-gateway/internal/models"

	"gorm.io/gorm"
)

func TestP108A_AuditEventSchemaIsMinimalAndUnlinked(t *testing.T) {
	db := newAuditTestDB(t)

	rows, err := db.Raw("PRAGMA table_info(audit_events)").Rows()
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()

	columns := make(map[string]bool)
	for rows.Next() {
		var cid, notNull, primaryKey int
		var name, columnType string
		var defaultValue any
		if err := rows.Scan(&cid, &name, &columnType, &notNull, &defaultValue, &primaryKey); err != nil {
			t.Fatal(err)
		}
		columns[name] = true
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}

	want := []string{"id", "event_id", "action", "actor_type", "actor_id", "target_type", "target_id", "reason", "created_at"}
	want = append(want, "chain_version", "prev_hash", "event_hash")
	if len(columns) != len(want) {
		t.Fatalf("audit_events schema does not match the P1-08B chained shape: got %v", columns)
	}
	for _, name := range want {
		if !columns[name] {
			t.Fatalf("audit_events is missing expected column %q: %v", name, columns)
		}
	}
	for _, forbidden := range []string{"api_key", "api_key_hash", "provider_key", "authorization", "request_body", "payload", "metadata"} {
		if columns[forbidden] {
			t.Fatalf("audit_events must not persist secret/body/payload column %q", forbidden)
		}
	}

	var foreignKeys int64
	if err := db.Raw("SELECT count(*) FROM pragma_foreign_key_list('audit_events')").Scan(&foreignKeys).Error; err != nil {
		t.Fatal(err)
	}
	if foreignKeys != 0 {
		t.Fatalf("audit_events must not have foreign keys, got %d", foreignKeys)
	}

	var triggers int64
	if err := db.Raw("SELECT count(*) FROM sqlite_master WHERE type = 'trigger' AND tbl_name = 'audit_events'").Scan(&triggers).Error; err != nil {
		t.Fatal(err)
	}
	if triggers != 2 {
		t.Fatalf("P1-08B baseline must have two audit_events integrity triggers, got %d", triggers)
	}
}

func TestP108A_ApplicationAppendOnlyDoesNotImplyDatabaseImmutability(t *testing.T) {
	db := newAuditTestDB(t)
	svc := NewService(db)
	if err := svc.Record(models.AuditEvent{
		Action:    ActionClientCreated,
		ActorType: "admin",
		ActorID:   "p108a-test-admin",
		TargetID:  "client-1",
		Reason:    "original",
	}); err != nil {
		t.Fatal(err)
	}

	var event models.AuditEvent
	if err := db.First(&event).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Model(&event).Update("reason", "direct database mutation").Error; err == nil || !strings.Contains(err.Error(), "AUDIT_EVENT_IMMUTABLE") {
		t.Fatalf("direct update should be blocked by the P1-08B guard, got %v", err)
	}
	if err := db.Delete(&event).Error; err == nil || !strings.Contains(err.Error(), "AUDIT_EVENT_IMMUTABLE") {
		t.Fatalf("direct delete should be blocked by the P1-08B guard, got %v", err)
	}

	var count int64
	if err := db.Model(&models.AuditEvent{}).Count(&count).Error; err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("database mutation guard should retain the audit event, got %d rows", count)
	}
}

func TestP108A_RecordTxParticipatesInCallerTransaction(t *testing.T) {
	db := newAuditTestDB(t)
	svc := NewService(db)
	event := models.AuditEvent{
		Action:    ActionClientCreated,
		ActorType: "admin",
		ActorID:   "p108a-test-admin",
		TargetID:  "client-rollback",
	}

	rollbackErr := errors.New("force rollback")
	if err := db.Transaction(func(tx *gorm.DB) error {
		if err := svc.RecordTx(tx, event); err != nil {
			return err
		}
		return rollbackErr
	}); !errors.Is(err, rollbackErr) {
		t.Fatalf("expected caller transaction rollback, got %v", err)
	}

	var count int64
	if err := db.Model(&models.AuditEvent{}).Where("target_id = ?", event.TargetID).Count(&count).Error; err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("rolled-back RecordTx leaked %d event(s)", count)
	}

	if err := db.Transaction(func(tx *gorm.DB) error {
		return svc.RecordTx(tx, models.AuditEvent{
			Action:    ActionClientCreated,
			ActorType: "admin",
			ActorID:   "p108a-test-admin",
			TargetID:  "client-committed",
		})
	}); err != nil {
		t.Fatal(err)
	}
	if err := db.Model(&models.AuditEvent{}).Count(&count).Error; err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("committed RecordTx should persist exactly one event, got %d", count)
	}
}

func TestP108B_ActionWhitelistIncludesApprovedManagementActions(t *testing.T) {
	expected := map[string]bool{
		"CLIENT_CREATED":                    true,
		"CLIENT_KEY_ROTATED":                true,
		"CLIENT_SUSPENDED":                  true,
		"CLIENT_RESUMED":                    true,
		"CLIENT_REVOKED":                    true,
		"CLIENT_DELETED":                    true,
		"CLIENT_SETTINGS_UPDATED":           true,
		"CLIENT_PROVIDER_SECRET_CHANGED":    true,
		"CLIENT_MODELS_UPDATED":             true,
		"SERVER_TOOLS_UPDATED":              true,
		"GLOBAL_PROVIDER_SECRET_CHANGED":    true,
		"ADMIN_LOGIN_SUCCEEDED":             true,
		"ADMIN_LOGOUT":                      true,
		"SETUP_COMPLETED":                   true,
		"REQUEST_BODY_CAPTURE_READ":         true,
		"ADMIN_PASSWORD_RESET":              true,
		"PROVIDER_SECRET_MIGRATION_STARTED": true,
		"PROVIDER_SECRET_MIGRATION":         true,
		"REQUEST_LOG_SCRUB_STARTED":         true,
		"REQUEST_LOG_SCRUB":                 true,
	}
	if len(allowedActions) != len(expected) {
		t.Fatalf("audit action whitelist must contain exactly the approved lifecycle/management actions, got %d", len(allowedActions))
	}
	for action := range expected {
		if !IsKnownAction(action) || !allowedActions[action] {
			t.Fatalf("expected P1-05C lifecycle action %q to remain accepted", action)
		}
	}
	for action := range allowedActions {
		if !expected[action] {
			t.Fatalf("unexpected action in P1-08A baseline whitelist: %q", action)
		}
	}
}
