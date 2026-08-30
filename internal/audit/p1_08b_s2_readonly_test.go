package audit

import (
	"bytes"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"ai-gateway/internal/database"
	"ai-gateway/internal/models"
)

func TestP108B_S2_ValidOfflineVerify(t *testing.T) {
	db, _ := newP108BS1DB(t)
	svc := NewService(db)
	if err := svc.Record(testAuditEvent("offline-valid-1")); err != nil {
		t.Fatal(err)
	}
	if err := svc.Record(testAuditEvent("offline-valid-2")); err != nil {
		t.Fatal(err)
	}
	var expected models.AuditEvent
	if err := db.Order("id DESC").First(&expected).Error; err != nil {
		t.Fatal(err)
	}
	summary, err := VerifyIntegrityReadOnly(db)
	if err != nil {
		t.Fatal(err)
	}
	if summary.EventCount != 2 || summary.HeadHash != expected.EventHash {
		t.Fatalf("unexpected read-only summary: %+v", summary)
	}
}

func TestP108B_S2_LegacyOfflineRequiresMigration(t *testing.T) {
	path := t.TempDir() + "/legacy-offline.db"
	db, err := database.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	createLegacyP105CSchema(t, db)
	insertLegacyAuditEvent(t, db, models.AuditEvent{ID: 1, EventID: "legacy-offline", Action: ActionClientCreated, ActorType: "admin", ActorID: "admin", TargetType: "client", TargetID: "client", CreatedAt: time.Unix(1788064496, 3).UTC()})
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if sqlDB, err := db.DB(); err == nil {
		_ = sqlDB.Close()
	}
	readonly, err := database.OpenReadOnly(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if sqlDB, err := readonly.DB(); err == nil {
			_ = sqlDB.Close()
		}
	}()
	if _, err := VerifyIntegrityReadOnly(readonly); !errors.Is(err, ErrAuditMigrationRequired) {
		t.Fatalf("legacy offline verification must require migration, got %v", err)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("legacy offline verification changed database bytes")
	}
	var chainColumns int64
	if err := readonly.Raw("SELECT count(*) FROM pragma_table_info('audit_events') WHERE name IN ('chain_version', 'prev_hash', 'event_hash')").Scan(&chainColumns).Error; err != nil {
		t.Fatal(err)
	}
	if chainColumns != 0 {
		t.Fatalf("legacy offline verification added chain columns: %d", chainColumns)
	}
}

func TestP108B_S2_FreshOfflineRequiresMigration(t *testing.T) {
	path := t.TempDir() + "/fresh-offline.db"
	db, err := database.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if sqlDB, err := db.DB(); err == nil {
		_ = sqlDB.Close()
	}
	readonly, err := database.OpenReadOnly(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if sqlDB, err := readonly.DB(); err == nil {
			_ = sqlDB.Close()
		}
	}()
	if _, err := VerifyIntegrityReadOnly(readonly); !errors.Is(err, ErrAuditMigrationRequired) {
		t.Fatalf("fresh offline verification must require migration, got %v", err)
	}
}

func TestP108B_S2_CorruptOfflineFailsClosed(t *testing.T) {
	db, path := newP108BS1DB(t)
	seedTwoAuditEvents(t, db)
	dropAuditMutationTriggers(t, db)
	if err := db.Exec("UPDATE audit_events SET reason = ? WHERE id = 1", "tampered-offline").Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Exec(auditUpdateTriggerSQL).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Exec(auditDeleteTriggerSQL).Error; err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	readonly, err := database.OpenReadOnly(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if sqlDB, err := readonly.DB(); err == nil {
			_ = sqlDB.Close()
		}
	}()
	if _, err := VerifyIntegrityReadOnly(readonly); !errors.Is(err, ErrAuditIntegrity) {
		t.Fatalf("corrupt offline chain must fail closed, got %v", err)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("corrupt offline verification changed database bytes")
	}
}

func TestP108B_S2_MissingTriggerFailsClosed(t *testing.T) {
	db, _ := newP108BS1DB(t)
	dropAuditMutationTriggers(t, db)
	if _, err := VerifyIntegrityReadOnly(db); !errors.Is(err, ErrAuditIntegrity) {
		t.Fatalf("missing trigger must fail closed, got %v", err)
	}
}

func TestP108B_S2_WrongTriggerFailsClosed(t *testing.T) {
	db, _ := newP108BS1DB(t)
	dropAuditMutationTriggers(t, db)
	if err := db.Exec("CREATE TRIGGER audit_events_no_update BEFORE UPDATE ON audit_events BEGIN SELECT 1; END").Error; err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyIntegrityReadOnly(db); !errors.Is(err, ErrAuditIntegrity) {
		t.Fatalf("wrong trigger must fail closed, got %v", err)
	}
}

func TestP108B_S2_MissingIndexFailsClosed(t *testing.T) {
	db, _ := newP108BS1DB(t)
	if err := db.Exec("DROP INDEX idx_audit_events_action").Error; err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyIntegrityReadOnly(db); !errors.Is(err, ErrAuditIntegrity) {
		t.Fatalf("missing index must fail closed, got %v", err)
	}
}

func TestP108B_S2_WrongIndexFailsClosed(t *testing.T) {
	db, _ := newP108BS1DB(t)
	if err := db.Exec("DROP INDEX idx_audit_events_action").Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Exec("CREATE UNIQUE INDEX idx_audit_events_action ON audit_events(actor_id)").Error; err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyIntegrityReadOnly(db); !errors.Is(err, ErrAuditIntegrity) {
		t.Fatalf("wrong index definition must fail closed, got %v", err)
	}
}

func TestP108B_S2_ExtraColumnFailsClosed(t *testing.T) {
	db, _ := newP108BS1DB(t)
	if err := db.Exec("ALTER TABLE audit_events ADD COLUMN payload text").Error; err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyIntegrityReadOnly(db); !errors.Is(err, ErrAuditIntegrity) {
		t.Fatalf("extra audit column must fail closed, got %v", err)
	}
}

func TestP108B_S2_PartialSchemaFailsClosed(t *testing.T) {
	db, _ := newP108BS1DB(t)
	seedTwoAuditEvents(t, db)
	if err := db.Exec("DROP TABLE audit_chain_states").Error; err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyIntegrityReadOnly(db); !errors.Is(err, ErrAuditIntegrity) {
		t.Fatalf("partial audit schema must fail closed, got %v", err)
	}
}

func TestP108B_S2_ReadOnlyVerifierDoesNotCallMigration(t *testing.T) {
	db, _ := newP108BS1DB(t)
	if _, err := VerifyIntegrityReadOnly(db); err != nil {
		t.Fatal(err)
	}
	if err := db.Exec("UPDATE audit_events SET reason = ? WHERE 0", strings.Repeat("x", 8)).Error; err != nil {
		t.Fatal(err)
	}
}
