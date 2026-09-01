package audit

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"

	"ai-gateway/internal/database"
	"ai-gateway/internal/models"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

func beginMaintenanceForTest(t *testing.T, db *gorm.DB, kind MaintenanceKind) (MaintenanceOperation, error) {
	t.Helper()
	var operation MaintenanceOperation
	err := db.Transaction(func(tx *gorm.DB) error {
		var err error
		operation, err = NewService(db).BeginMaintenanceTx(tx, kind)
		return err
	})
	return operation, err
}

func completeMaintenanceForTest(t *testing.T, db *gorm.DB, operation MaintenanceOperation) error {
	t.Helper()
	return db.Transaction(func(tx *gorm.DB) error {
		return NewService(db).CompleteMaintenanceTx(tx, operation)
	})
}

func maintenanceEventsForTest(t *testing.T, db *gorm.DB) []models.AuditEvent {
	t.Helper()
	var events []models.AuditEvent
	actions := []string{
		ActionProviderSecretMigrationStarted,
		ActionProviderSecretMigration,
		ActionRequestLogScrubStarted,
		ActionRequestLogScrub,
	}
	if err := db.Where("action IN ?", actions).Order("id ASC").Find(&events).Error; err != nil {
		t.Fatal(err)
	}
	return events
}

func maintenanceEventsForKindForTest(t *testing.T, db *gorm.DB, kind MaintenanceKind) []models.AuditEvent {
	t.Helper()
	var actions []string
	switch kind {
	case MaintenanceKindProviderSecretMigration:
		actions = []string{ActionProviderSecretMigrationStarted, ActionProviderSecretMigration}
	case MaintenanceKindRequestLogScrub:
		actions = []string{ActionRequestLogScrubStarted, ActionRequestLogScrub}
	default:
		t.Fatalf("unknown maintenance kind: %q", kind)
	}
	var events []models.AuditEvent
	if err := db.Where("action IN ?", actions).Order("id ASC").Find(&events).Error; err != nil {
		t.Fatal(err)
	}
	return events
}

func appendMaintenanceEventForTest(t *testing.T, db *gorm.DB, event models.AuditEvent) {
	t.Helper()
	if err := NewService(db).Record(event); err != nil {
		t.Fatal(err)
	}
}

func TestP108B_S7_MaintenanceActionsAndKinds(t *testing.T) {
	for _, action := range []string{
		ActionProviderSecretMigrationStarted,
		ActionProviderSecretMigration,
		ActionRequestLogScrubStarted,
		ActionRequestLogScrub,
	} {
		if !IsKnownAction(action) {
			t.Fatalf("maintenance action must be allowlisted: %q", action)
		}
	}
	if IsKnownAction("MAINTENANCE_UNKNOWN") {
		t.Fatal("unexpected maintenance action accepted")
	}
	if MaintenanceKindProviderSecretMigration == MaintenanceKindRequestLogScrub {
		t.Fatal("maintenance kinds must remain distinct")
	}
}

func TestP108B_S7_MaintenanceBeginNewAndServerUUID(t *testing.T) {
	db := newAuditTestDB(t)
	operation, err := beginMaintenanceForTest(t, db, MaintenanceKindProviderSecretMigration)
	if err != nil {
		t.Fatal(err)
	}
	if operation.Kind != MaintenanceKindProviderSecretMigration ||
		operation.ActorType != "cli" ||
		operation.ActorID != "migrate-provider-secrets" ||
		operation.TargetType != "maintenance-operation" ||
		operation.StartedAction != ActionProviderSecretMigrationStarted ||
		operation.SuccessAction != ActionProviderSecretMigration {
		t.Fatalf("unexpected provider operation identity: %+v", operation)
	}
	if _, err := uuid.Parse(operation.TargetID); err != nil {
		t.Fatalf("target ID must be a server UUID: %q (%v)", operation.TargetID, err)
	}
	events := maintenanceEventsForTest(t, db)
	if len(events) != 1 || events[0].TargetID != operation.TargetID || events[0].Action != ActionProviderSecretMigrationStarted {
		t.Fatalf("expected one provider STARTED event, got %+v", events)
	}

	scrub, err := beginMaintenanceForTest(t, db, MaintenanceKindRequestLogScrub)
	if err != nil {
		t.Fatal(err)
	}
	if scrub.ActorID != "scrub-request-log-content" || scrub.StartedAction != ActionRequestLogScrubStarted || scrub.SuccessAction != ActionRequestLogScrub {
		t.Fatalf("unexpected scrub operation identity: %+v", scrub)
	}
	if _, err := uuid.Parse(scrub.TargetID); err != nil {
		t.Fatalf("scrub target ID must be a server UUID: %q (%v)", scrub.TargetID, err)
	}
}

func TestP108B_S7_MaintenanceBeginResumesWithoutSecondStarted(t *testing.T) {
	db := newAuditTestDB(t)
	first, err := beginMaintenanceForTest(t, db, MaintenanceKindRequestLogScrub)
	if err != nil {
		t.Fatal(err)
	}
	second, err := beginMaintenanceForTest(t, db, MaintenanceKindRequestLogScrub)
	if err != nil {
		t.Fatal(err)
	}
	if second != first {
		t.Fatalf("resume must return the same operation identity: first=%+v second=%+v", first, second)
	}
	events := maintenanceEventsForTest(t, db)
	if len(events) != 1 || events[0].Action != ActionRequestLogScrubStarted {
		t.Fatalf("resume must not append another STARTED event: %+v", events)
	}
}

func TestP108B_S7_MaintenanceCompletionUsesSameCorrelation(t *testing.T) {
	db := newAuditTestDB(t)
	for _, kind := range []MaintenanceKind{MaintenanceKindProviderSecretMigration, MaintenanceKindRequestLogScrub} {
		operation, err := beginMaintenanceForTest(t, db, kind)
		if err != nil {
			t.Fatal(err)
		}
		if err := completeMaintenanceForTest(t, db, operation); err != nil {
			t.Fatal(err)
		}
		events := maintenanceEventsForKindForTest(t, db, kind)
		if len(events) != 2 || events[0].TargetID != events[1].TargetID || events[1].Action != operation.SuccessAction {
			t.Fatalf("expected correlated STARTED/SUCCESS for %s, got %+v", kind, events)
		}
	}
}

func TestP108B_S7_MaintenanceDuplicateAndOrphanCompletionFailClosed(t *testing.T) {
	db := newAuditTestDB(t)
	operation, err := beginMaintenanceForTest(t, db, MaintenanceKindProviderSecretMigration)
	if err != nil {
		t.Fatal(err)
	}
	if err := completeMaintenanceForTest(t, db, operation); err != nil {
		t.Fatal(err)
	}
	if err := completeMaintenanceForTest(t, db, operation); !errors.Is(err, ErrAuditIntegrity) {
		t.Fatalf("duplicate completion must fail closed, got %v", err)
	}

	db = newAuditTestDB(t)
	orphan := MaintenanceOperation{
		Kind:          MaintenanceKindRequestLogScrub,
		ActorType:     "cli",
		ActorID:       "scrub-request-log-content",
		TargetType:    "maintenance-operation",
		TargetID:      uuid.NewString(),
		StartedAction: ActionRequestLogScrubStarted,
		SuccessAction: ActionRequestLogScrub,
	}
	if err := completeMaintenanceForTest(t, db, orphan); !errors.Is(err, ErrAuditIntegrity) {
		t.Fatalf("orphan completion must fail closed, got %v", err)
	}
}

func TestP108B_S7_MaintenanceCompletionRejectsForgedCorrelation(t *testing.T) {
	db := newAuditTestDB(t)
	operation, err := beginMaintenanceForTest(t, db, MaintenanceKindProviderSecretMigration)
	if err != nil {
		t.Fatal(err)
	}

	for _, forged := range []MaintenanceOperation{
		func() MaintenanceOperation {
			copy := operation
			copy.TargetID = uuid.NewString()
			return copy
		}(),
		func() MaintenanceOperation {
			copy := operation
			copy.SuccessAction = ActionRequestLogScrub
			return copy
		}(),
	} {
		if err := completeMaintenanceForTest(t, db, forged); !errors.Is(err, ErrAuditIntegrity) {
			t.Fatalf("forged completion correlation must fail closed: %+v got %v", forged, err)
		}
	}
	if events := maintenanceEventsForKindForTest(t, db, MaintenanceKindProviderSecretMigration); len(events) != 1 || events[0].Action != ActionProviderSecretMigrationStarted {
		t.Fatalf("forged completion must not append SUCCESS: %+v", events)
	}
}

func TestP108B_S7_MaintenancePendingCardinalityAndCorrelationFailClosed(t *testing.T) {
	cases := []struct {
		name  string
		event models.AuditEvent
	}{
		{
			name: "multiple pending",
			event: models.AuditEvent{
				Action:     ActionProviderSecretMigrationStarted,
				ActorType:  "cli",
				ActorID:    "migrate-provider-secrets",
				TargetType: "maintenance-operation",
				TargetID:   uuid.NewString(),
			},
		},
		{
			name: "malformed UUID",
			event: models.AuditEvent{
				Action:     ActionRequestLogScrubStarted,
				ActorType:  "cli",
				ActorID:    "scrub-request-log-content",
				TargetType: "maintenance-operation",
				TargetID:   "not-a-uuid",
			},
		},
		{
			name: "actor mismatch",
			event: models.AuditEvent{
				Action:     ActionProviderSecretMigrationStarted,
				ActorType:  "cli",
				ActorID:    "untrusted-actor",
				TargetType: "maintenance-operation",
				TargetID:   uuid.NewString(),
			},
		},
		{
			name: "target type mismatch",
			event: models.AuditEvent{
				Action:     ActionRequestLogScrubStarted,
				ActorType:  "cli",
				ActorID:    "scrub-request-log-content",
				TargetType: "client",
				TargetID:   uuid.NewString(),
			},
		},
		{
			name: "success action without STARTED",
			event: models.AuditEvent{
				Action:     ActionProviderSecretMigration,
				ActorType:  "cli",
				ActorID:    "migrate-provider-secrets",
				TargetType: "maintenance-operation",
				TargetID:   uuid.NewString(),
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			db := newAuditTestDB(t)
			appendMaintenanceEventForTest(t, db, tc.event)
			if tc.name == "multiple pending" {
				appendMaintenanceEventForTest(t, db, models.AuditEvent{
					Action:     ActionProviderSecretMigrationStarted,
					ActorType:  "cli",
					ActorID:    "migrate-provider-secrets",
					TargetType: "maintenance-operation",
					TargetID:   uuid.NewString(),
				})
			}
			if _, err := beginMaintenanceForTest(t, db, MaintenanceKindProviderSecretMigration); !errors.Is(err, ErrAuditIntegrity) {
				t.Fatalf("expected integrity failure, got %v", err)
			}
		})
	}
}

func TestP108B_S7_MaintenanceRejectsNonTransactions(t *testing.T) {
	db := newAuditTestDB(t)
	svc := NewService(db)
	if _, err := svc.BeginMaintenanceTx(db, MaintenanceKindProviderSecretMigration); !errors.Is(err, ErrAuditTransactionRequired) {
		t.Fatalf("plain DB begin must be rejected, got %v", err)
	}
	if err := svc.CompleteMaintenanceTx(db, MaintenanceOperation{Kind: MaintenanceKindProviderSecretMigration}); !errors.Is(err, ErrAuditTransactionRequired) {
		t.Fatalf("plain DB completion must be rejected, got %v", err)
	}

	var committed, rolledBack *gorm.DB
	if err := db.Transaction(func(tx *gorm.DB) error { committed = tx; return nil }); err != nil {
		t.Fatal(err)
	}
	if err := db.Transaction(func(tx *gorm.DB) error { rolledBack = tx; return errors.New("rollback") }); err == nil {
		t.Fatal("expected rollback sentinel")
	}
	if _, err := svc.BeginMaintenanceTx(committed, MaintenanceKindProviderSecretMigration); !errors.Is(err, ErrAuditTransactionRequired) {
		t.Fatalf("committed transaction must be rejected, got %v", err)
	}
	if _, err := svc.BeginMaintenanceTx(rolledBack, MaintenanceKindProviderSecretMigration); !errors.Is(err, ErrAuditTransactionRequired) {
		t.Fatalf("rolled-back transaction must be rejected, got %v", err)
	}
	if _, err := svc.BeginMaintenanceTx(nil, MaintenanceKindProviderSecretMigration); !errors.Is(err, ErrAuditTransactionRequired) {
		t.Fatalf("nil transaction must be rejected, got %v", err)
	}
}

func TestP108B_S7_MaintenanceConcurrentBeginNoFork(t *testing.T) {
	path := t.TempDir() + "/shared-maintenance.db"
	seed := newMaintenanceHandle(t, path)
	if err := MigrateIntegrity(seed); err != nil {
		t.Fatal(err)
	}

	const handles = 4
	dbs := make([]*gorm.DB, 0, handles)
	for i := 0; i < handles; i++ {
		dbs = append(dbs, newMaintenanceHandle(t, path))
	}
	start := make(chan struct{})
	results := make(chan struct {
		operation MaintenanceOperation
		err       error
	}, handles)
	var wg sync.WaitGroup
	wg.Add(handles)
	for _, db := range dbs {
		go func(db *gorm.DB) {
			defer wg.Done()
			<-start
			operation, err := beginMaintenanceForTest(t, db, MaintenanceKindProviderSecretMigration)
			results <- struct {
				operation MaintenanceOperation
				err       error
			}{operation: operation, err: err}
		}(db)
	}
	close(start)
	wg.Wait()
	close(results)

	var expected MaintenanceOperation
	for result := range results {
		if result.err != nil {
			t.Fatalf("concurrent begin failed: %v", result.err)
		}
		if expected.TargetID == "" {
			expected = result.operation
		} else if result.operation != expected {
			t.Fatalf("concurrent begin forked operation: expected=%+v got=%+v", expected, result.operation)
		}
	}
	events := maintenanceEventsForTest(t, seed)
	if len(events) != 1 || events[0].Action != ActionProviderSecretMigrationStarted {
		t.Fatalf("concurrent begin must create exactly one pending STARTED: %+v", events)
	}
}

func TestP108B_S7_MaintenancePrivacyCanaryAbsentFromEventAndRawDB(t *testing.T) {
	db := newAuditTestDB(t)
	canary := "P108B_MAINTENANCE_PRIVACY_CANARY"
	operation, err := beginMaintenanceForTest(t, db, MaintenanceKindProviderSecretMigration)
	if err != nil {
		t.Fatal(err)
	}
	if err := completeMaintenanceForTest(t, db, operation); err != nil {
		t.Fatal(err)
	}
	for _, event := range maintenanceEventsForTest(t, db) {
		if strings.Contains(fmt.Sprintf("%+v", event), canary) {
			t.Fatalf("privacy canary leaked into event fields: %+v", event)
		}
	}
	rows, err := db.Raw("SELECT action || '|' || actor_type || '|' || actor_id || '|' || target_type || '|' || target_id || '|' || reason FROM audit_events").Rows()
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var raw string
		if err := rows.Scan(&raw); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(raw, canary) {
			t.Fatalf("privacy canary leaked into raw audit DB: %q", raw)
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
}

func TestP108B_S7_MaintenanceChainRemainsValid(t *testing.T) {
	db := newAuditTestDB(t)
	operation, err := beginMaintenanceForTest(t, db, MaintenanceKindRequestLogScrub)
	if err != nil {
		t.Fatal(err)
	}
	if err := completeMaintenanceForTest(t, db, operation); err != nil {
		t.Fatal(err)
	}
	if err := NewService(db).VerifyAuditChain(); err != nil {
		t.Fatal(err)
	}
}

func newMaintenanceHandle(t *testing.T, path string) *gorm.DB {
	t.Helper()
	db, err := database.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatal(err)
	}
	sqlDB.SetMaxOpenConns(1)
	sqlDB.SetMaxIdleConns(1)
	t.Cleanup(func() { _ = sqlDB.Close() })
	return db
}
