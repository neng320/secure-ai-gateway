package audit

import (
	"errors"
	"fmt"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"ai-gateway/internal/database"
	"ai-gateway/internal/models"

	"gorm.io/gorm"
)

func dropAuditMutationTriggers(t *testing.T, db *gorm.DB) {
	t.Helper()
	for _, name := range []string{auditUpdateTriggerName, auditDeleteTriggerName} {
		if err := db.Exec("DROP TRIGGER IF EXISTS " + name).Error; err != nil {
			t.Fatal(err)
		}
	}
}

func seedTwoAuditEvents(t *testing.T, db *gorm.DB) {
	t.Helper()
	svc := NewService(db)
	if err := svc.Record(testAuditEvent("first")); err != nil {
		t.Fatal(err)
	}
	if err := svc.Record(testAuditEvent("second")); err != nil {
		t.Fatal(err)
	}
}

const legacyP105CAuditSchemaSQL = `CREATE TABLE audit_events (
	id integer PRIMARY KEY AUTOINCREMENT,
	event_id varchar(64),
	action varchar(64),
	actor_type varchar(32),
	actor_id varchar(255),
	target_type varchar(32),
	target_id varchar(36),
	reason varchar(256),
	created_at datetime
)`

func createLegacyP105CSchema(t *testing.T, db *gorm.DB) {
	t.Helper()
	if err := db.Exec(legacyP105CAuditSchemaSQL).Error; err != nil {
		t.Fatal(err)
	}
	for _, statement := range auditEventIndexSQL[:6] {
		if err := db.Exec(statement).Error; err != nil {
			t.Fatal(err)
		}
	}
}

func insertLegacyAuditEvent(t *testing.T, db *gorm.DB, event models.AuditEvent) {
	t.Helper()
	if err := db.Exec(`INSERT INTO audit_events
		(id, event_id, action, actor_type, actor_id, target_type, target_id, reason, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		event.ID, event.EventID, event.Action, event.ActorType, event.ActorID,
		event.TargetType, event.TargetID, event.Reason, event.CreatedAt).Error; err != nil {
		t.Fatal(err)
	}
}

func auditSchemaFingerprint(t *testing.T, db *gorm.DB) string {
	t.Helper()
	var objects []struct {
		Type  string `gorm:"column:type"`
		Name  string `gorm:"column:name"`
		Table string `gorm:"column:tbl_name"`
		SQL   string `gorm:"column:sql"`
	}
	if err := db.Raw("SELECT type, name, tbl_name, sql FROM sqlite_master WHERE type IN ('table', 'index', 'trigger') ORDER BY type, name").Scan(&objects).Error; err != nil {
		t.Fatal(err)
	}
	var eventColumns []sqliteTableColumn
	if err := db.Raw("PRAGMA table_info(audit_events)").Scan(&eventColumns).Error; err != nil {
		t.Fatal(err)
	}
	var stateColumns []sqliteTableColumn
	if err := db.Raw("PRAGMA table_info(audit_chain_states)").Scan(&stateColumns).Error; err != nil {
		t.Fatal(err)
	}
	return fmt.Sprintf("objects=%v event_columns=%v state_columns=%v", objects, eventColumns, stateColumns)
}

func assertAuditVerificationFails(t *testing.T, db *gorm.DB) {
	t.Helper()
	if err := NewService(db).VerifyAuditChain(); !errors.Is(err, ErrAuditIntegrity) {
		t.Fatalf("expected ErrAuditIntegrity, got %v", err)
	}
}

func TestP108B_S1_VerifierCorruptionMatrix(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*testing.T, *gorm.DB)
	}{
		{name: "event hash", mutate: func(t *testing.T, db *gorm.DB) {
			if err := db.Exec("UPDATE audit_events SET event_hash = ? WHERE id = 1", "0"+strings.Repeat("0", 63)).Error; err != nil {
				t.Fatal(err)
			}
		}},
		{name: "previous hash", mutate: func(t *testing.T, db *gorm.DB) {
			if err := db.Exec("UPDATE audit_events SET prev_hash = ? WHERE id = 2", strings.Repeat("1", 64)).Error; err != nil {
				t.Fatal(err)
			}
		}},
		{name: "action", mutate: func(t *testing.T, db *gorm.DB) {
			if err := db.Exec("UPDATE audit_events SET action = ? WHERE id = 1", ActionClientDeleted).Error; err != nil {
				t.Fatal(err)
			}
		}},
		{name: "reason", mutate: func(t *testing.T, db *gorm.DB) {
			if err := db.Exec("UPDATE audit_events SET reason = ? WHERE id = 1", "tampered").Error; err != nil {
				t.Fatal(err)
			}
		}},
		{name: "created at", mutate: func(t *testing.T, db *gorm.DB) {
			if err := db.Model(&models.AuditEvent{}).Where("id = 1").Update("created_at", time.Unix(1, 0).UTC()).Error; err != nil {
				t.Fatal(err)
			}
		}},
		{name: "event id", mutate: func(t *testing.T, db *gorm.DB) {
			if err := db.Exec("UPDATE audit_events SET event_id = ? WHERE id = 1", "evt-tampered").Error; err != nil {
				t.Fatal(err)
			}
		}},
		{name: "genesis", mutate: func(t *testing.T, db *gorm.DB) {
			if err := db.Exec("UPDATE audit_events SET prev_hash = ? WHERE id = 1", strings.Repeat("1", 64)).Error; err != nil {
				t.Fatal(err)
			}
		}},
		{name: "middle delete", mutate: func(t *testing.T, db *gorm.DB) {
			if err := db.Exec("DELETE FROM audit_events WHERE id = 1").Error; err != nil {
				t.Fatal(err)
			}
		}},
		{name: "tail delete", mutate: func(t *testing.T, db *gorm.DB) {
			if err := db.Exec("DELETE FROM audit_events WHERE id = 2").Error; err != nil {
				t.Fatal(err)
			}
		}},
		{name: "event reorder", mutate: func(t *testing.T, db *gorm.DB) {
			for _, statement := range []string{
				"UPDATE audit_events SET id = 99 WHERE id = 1",
				"UPDATE audit_events SET id = 1 WHERE id = 2",
				"UPDATE audit_events SET id = 2 WHERE id = 99",
			} {
				if err := db.Exec(statement).Error; err != nil {
					t.Fatal(err)
				}
			}
		}},
		{name: "state head", mutate: func(t *testing.T, db *gorm.DB) {
			if err := db.Exec("UPDATE audit_chain_states SET head_hash = ? WHERE id = 1", strings.Repeat("0", 64)).Error; err != nil {
				t.Fatal(err)
			}
		}},
		{name: "state version", mutate: func(t *testing.T, db *gorm.DB) {
			if err := db.Exec("UPDATE audit_chain_states SET chain_version = ? WHERE id = 1", "v2").Error; err != nil {
				t.Fatal(err)
			}
		}},
		{name: "event version", mutate: func(t *testing.T, db *gorm.DB) {
			if err := db.Exec("UPDATE audit_events SET chain_version = ? WHERE id = 1", "v2").Error; err != nil {
				t.Fatal(err)
			}
		}},
		{name: "extra state row", mutate: func(t *testing.T, db *gorm.DB) {
			if err := db.Exec("INSERT INTO audit_chain_states (id, chain_version, head_hash, updated_at) SELECT 2, chain_version, head_hash, updated_at FROM audit_chain_states WHERE id = 1").Error; err != nil {
				t.Fatal(err)
			}
		}},
		{name: "state tail mismatch", mutate: func(t *testing.T, db *gorm.DB) {
			if err := db.Exec("UPDATE audit_chain_states SET head_hash = ? WHERE id = 1", strings.Repeat("f", 64)).Error; err != nil {
				t.Fatal(err)
			}
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			db, _ := newP108BS1DB(t)
			seedTwoAuditEvents(t, db)
			dropAuditMutationTriggers(t, db)
			tc.mutate(t, db)
			assertAuditVerificationFails(t, db)
		})
	}
}

func TestP108B_S11_RealLegacySchemaUpgrade(t *testing.T) {
	path := t.TempDir() + "/legacy.db"
	db, err := database.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if sqlDB, err := db.DB(); err == nil {
			_ = sqlDB.Close()
		}
	})
	createLegacyP105CSchema(t, db)
	created := time.Unix(1788064496, 123456789).UTC()
	legacy := []models.AuditEvent{
		{ID: 20, EventID: "legacy-high", Action: ActionClientDeleted, ActorType: "admin", ActorID: "legacy-admin", TargetType: "client", TargetID: "client-1", Reason: "second", CreatedAt: created},
		{ID: 10, EventID: "legacy-low", Action: ActionClientCreated, ActorType: "admin", ActorID: "legacy-admin", TargetType: "client", TargetID: "client-1", Reason: "  preserve spaces  ", CreatedAt: created},
	}
	for _, event := range legacy {
		insertLegacyAuditEvent(t, db, event)
	}
	beforeSchema := auditSchemaFingerprint(t, db)
	if strings.Contains(beforeSchema, "chain_version") || strings.Contains(beforeSchema, "prev_hash") || strings.Contains(beforeSchema, "event_hash") || strings.Contains(beforeSchema, "audit_chain_states") {
		t.Fatalf("real legacy fixture unexpectedly contains chain schema: %s", beforeSchema)
	}
	if err := MigrateIntegrity(db); err != nil {
		t.Fatal(err)
	}
	var after []models.AuditEvent
	if err := db.Order("id ASC").Find(&after).Error; err != nil {
		t.Fatal(err)
	}
	if len(after) != 2 || after[0].ID != 10 || after[1].ID != 20 || after[0].PrevHash != "" || after[1].PrevHash != after[0].EventHash {
		t.Fatalf("legacy rows must be chained by immutable ID ASC: %+v", after)
	}
	if after[0].EventID != "legacy-low" || after[1].EventID != "legacy-high" || after[0].Reason != "  preserve spaces  " || after[1].Reason != "second" {
		t.Fatalf("legacy semantic fields or ID order changed: %+v", after)
	}
	for _, event := range after {
		if !event.CreatedAt.Equal(created) {
			t.Fatalf("legacy timestamp changed for %s: %v", event.EventID, event.CreatedAt)
		}
	}
	var states []models.AuditChainState
	if err := db.Order("id ASC").Find(&states).Error; err != nil {
		t.Fatal(err)
	}
	if len(states) != 1 || states[0].ID != 1 || states[0].HeadHash != after[1].EventHash {
		t.Fatalf("legacy migration must create state at the final ID-ordered event: %+v", states)
	}
	if err := NewService(db).VerifyAuditChain(); err != nil {
		t.Fatal(err)
	}
}

func TestP108B_S1_MigrationIdempotent(t *testing.T) {
	db, _ := newP108BS1DB(t)
	seedTwoAuditEvents(t, db)
	var beforeEvents []models.AuditEvent
	if err := db.Order("id ASC").Find(&beforeEvents).Error; err != nil {
		t.Fatal(err)
	}
	var beforeState models.AuditChainState
	if err := db.First(&beforeState, 1).Error; err != nil {
		t.Fatal(err)
	}
	if err := MigrateIntegrity(db); err != nil {
		t.Fatal(err)
	}
	var afterEvents []models.AuditEvent
	if err := db.Order("id ASC").Find(&afterEvents).Error; err != nil {
		t.Fatal(err)
	}
	var afterState models.AuditChainState
	if err := db.First(&afterState, 1).Error; err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(beforeEvents, afterEvents) || !reflect.DeepEqual(beforeState, afterState) {
		t.Fatalf("second migration changed chained history/state: before=%+v/%+v after=%+v/%+v", beforeEvents, beforeState, afterEvents, afterState)
	}
}

func TestP108B_S1_MixedAndPartialChainFailClosed(t *testing.T) {
	t.Run("mixed events", func(t *testing.T) {
		db, _ := newP108BS1DB(t)
		dropAuditMutationTriggers(t, db)
		if err := db.Create(&models.AuditEvent{EventID: "legacy", Action: ActionClientCreated, ActorType: "admin", ActorID: "admin", TargetType: "client", TargetID: "client", CreatedAt: time.Now().UTC(), EventHash: "partial"}).Error; err != nil {
			t.Fatal(err)
		}
		if err := db.Create(&models.AuditEvent{EventID: "legacy-2", Action: ActionClientDeleted, ActorType: "admin", ActorID: "admin", TargetType: "client", TargetID: "client", CreatedAt: time.Now().UTC()}).Error; err != nil {
			t.Fatal(err)
		}
		if err := MigrateIntegrity(db); !errors.Is(err, ErrAuditIntegrity) {
			t.Fatalf("mixed chain must fail closed, got %v", err)
		}
	})

	t.Run("chained events without state", func(t *testing.T) {
		db, _ := newP108BS1DB(t)
		seedTwoAuditEvents(t, db)
		if err := db.Exec("DROP TABLE audit_chain_states").Error; err != nil {
			t.Fatal(err)
		}
		if err := MigrateIntegrity(db); !errors.Is(err, ErrAuditIntegrity) {
			t.Fatalf("chained events with missing state must fail closed, got %v", err)
		}
	})
}

func TestP108B_S11_PartialSchemaMatrixFailsBeforeMutation(t *testing.T) {
	cases := []struct {
		name  string
		setup func(*testing.T, *gorm.DB)
	}{
		{name: "legacy plus chain_version", setup: func(t *testing.T, db *gorm.DB) {
			createLegacyP105CSchema(t, db)
			if err := db.Exec("ALTER TABLE audit_events ADD COLUMN chain_version varchar(16)").Error; err != nil {
				t.Fatal(err)
			}
		}},
		{name: "legacy plus two chain columns", setup: func(t *testing.T, db *gorm.DB) {
			createLegacyP105CSchema(t, db)
			for _, statement := range []string{
				"ALTER TABLE audit_events ADD COLUMN chain_version varchar(16)",
				"ALTER TABLE audit_events ADD COLUMN prev_hash varchar(64)",
			} {
				if err := db.Exec(statement).Error; err != nil {
					t.Fatal(err)
				}
			}
		}},
		{name: "chained columns without state", setup: func(t *testing.T, db *gorm.DB) {
			createLegacyP105CSchema(t, db)
			for _, statement := range []string{
				"ALTER TABLE audit_events ADD COLUMN chain_version varchar(16)",
				"ALTER TABLE audit_events ADD COLUMN prev_hash varchar(64)",
				"ALTER TABLE audit_events ADD COLUMN event_hash varchar(64)",
			} {
				if err := db.Exec(statement).Error; err != nil {
					t.Fatal(err)
				}
			}
			insertLegacyAuditEvent(t, db, models.AuditEvent{ID: 1, EventID: "partial-no-state", Action: ActionClientCreated, ActorType: "admin", ActorID: "admin", TargetType: "client", TargetID: "client", CreatedAt: time.Unix(1788064496, 1).UTC()})
			if err := db.Exec("UPDATE audit_events SET chain_version = ?, event_hash = ? WHERE id = 1", chainVersionV1, strings.Repeat("a", 64)).Error; err != nil {
				t.Fatal(err)
			}
		}},
		{name: "legacy event plus state", setup: func(t *testing.T, db *gorm.DB) {
			createLegacyP105CSchema(t, db)
			if err := db.Exec(createChainStateTableSQL).Error; err != nil {
				t.Fatal(err)
			}
		}},
		{name: "chained schema missing prev_hash", setup: func(t *testing.T, db *gorm.DB) {
			// This case is built independently so its connection remains the
			// subject of the pre-state snapshot and migration attempt.
			if err := db.Exec(createAuditEventsTableSQL).Error; err != nil {
				t.Fatal(err)
			}
			for _, statement := range auditEventIndexSQL {
				if err := db.Exec(statement).Error; err != nil {
					t.Fatal(err)
				}
			}
			if err := db.Exec(createChainStateTableSQL).Error; err != nil {
				t.Fatal(err)
			}
			if err := db.Exec("INSERT INTO audit_chain_states (id, chain_version, head_hash, updated_at) VALUES (1, ?, ?, ?)", chainVersionV1, "", time.Now().UTC()).Error; err != nil {
				t.Fatal(err)
			}
			if err := db.Exec("DROP INDEX idx_audit_events_prev_hash").Error; err != nil {
				t.Fatal(err)
			}
			if err := db.Exec("ALTER TABLE audit_events DROP COLUMN prev_hash").Error; err != nil {
				t.Skipf("SQLite build does not support DROP COLUMN: %v", err)
			}
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := t.TempDir() + "/partial.db"
			db, err := database.Open(path)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if sqlDB, err := db.DB(); err == nil {
					_ = sqlDB.Close()
				}
			})
			tc.setup(t, db)
			before := auditSchemaFingerprint(t, db)
			if err := MigrateIntegrity(db); !errors.Is(err, ErrAuditIntegrity) {
				t.Fatalf("partial schema must fail closed, got %v", err)
			}
			after := auditSchemaFingerprint(t, db)
			if after != before {
				t.Fatalf("partial schema changed before rejection: before=%s after=%s", before, after)
			}
		})
	}
}

func createCurrentAuditEventsWithoutState(t *testing.T, db *gorm.DB) {
	t.Helper()
	if err := db.Exec(createAuditEventsTableSQL).Error; err != nil {
		t.Fatal(err)
	}
	for _, statement := range auditEventIndexSQL {
		if err := db.Exec(statement).Error; err != nil {
			t.Fatal(err)
		}
	}
}

func TestP108B_S12_CurrentColumnsNoStateEmptyFailsClosed(t *testing.T) {
	db, err := database.Open(t.TempDir() + "/empty-current.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if sqlDB, err := db.DB(); err == nil {
			_ = sqlDB.Close()
		}
	})
	createCurrentAuditEventsWithoutState(t, db)
	before := auditSchemaFingerprint(t, db)
	if err := MigrateIntegrity(db); !errors.Is(err, ErrAuditIntegrity) {
		t.Fatalf("current columns without state must fail closed, got %v", err)
	}
	if after := auditSchemaFingerprint(t, db); after != before {
		t.Fatalf("empty current partial schema changed: before=%s after=%s", before, after)
	}
}

func TestP108B_S12_CurrentColumnsNoStateUnchainedRowsFailsClosed(t *testing.T) {
	db, err := database.Open(t.TempDir() + "/unchained-current.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if sqlDB, err := db.DB(); err == nil {
			_ = sqlDB.Close()
		}
	})
	createCurrentAuditEventsWithoutState(t, db)
	insertLegacyAuditEvent(t, db, models.AuditEvent{ID: 1, EventID: "unchained-current", Action: ActionClientCreated, ActorType: "admin", ActorID: "admin", TargetType: "client", TargetID: "client", CreatedAt: time.Unix(1788064496, 2).UTC()})
	before := auditSchemaFingerprint(t, db)
	if err := MigrateIntegrity(db); !errors.Is(err, ErrAuditIntegrity) {
		t.Fatalf("current columns without state and unchained rows must fail closed, got %v", err)
	}
	if after := auditSchemaFingerprint(t, db); after != before {
		t.Fatalf("unchained current partial schema changed: before=%s after=%s", before, after)
	}
}

func TestP108B_S12_LegacyExtraColumnFailsClosed(t *testing.T) {
	db, err := database.Open(t.TempDir() + "/legacy-extra.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if sqlDB, err := db.DB(); err == nil {
			_ = sqlDB.Close()
		}
	})
	createLegacyP105CSchema(t, db)
	if err := db.Exec("ALTER TABLE audit_events ADD COLUMN payload text").Error; err != nil {
		t.Fatal(err)
	}
	before := auditSchemaFingerprint(t, db)
	if err := MigrateIntegrity(db); !errors.Is(err, ErrAuditIntegrity) {
		t.Fatalf("legacy extra column must fail closed, got %v", err)
	}
	if after := auditSchemaFingerprint(t, db); after != before {
		t.Fatalf("legacy extra-column schema changed: before=%s after=%s", before, after)
	}
}

func TestP108B_S12_CurrentExtraColumnFailsClosed(t *testing.T) {
	db, _ := newP108BS1DB(t)
	if err := db.Exec("ALTER TABLE audit_events ADD COLUMN raw_body text").Error; err != nil {
		t.Fatal(err)
	}
	before := auditSchemaFingerprint(t, db)
	if err := MigrateIntegrity(db); !errors.Is(err, ErrAuditIntegrity) {
		t.Fatalf("current extra column must fail closed, got %v", err)
	}
	if after := auditSchemaFingerprint(t, db); after != before {
		t.Fatalf("current extra-column schema changed: before=%s after=%s", before, after)
	}
}

func TestP108B_S12_StateExtraColumnFailsClosed(t *testing.T) {
	db, _ := newP108BS1DB(t)
	if err := db.Exec("ALTER TABLE audit_chain_states ADD COLUMN secret text").Error; err != nil {
		t.Fatal(err)
	}
	before := auditSchemaFingerprint(t, db)
	if err := MigrateIntegrity(db); !errors.Is(err, ErrAuditIntegrity) {
		t.Fatalf("chain state extra column must fail closed, got %v", err)
	}
	if after := auditSchemaFingerprint(t, db); after != before {
		t.Fatalf("chain state extra-column schema changed: before=%s after=%s", before, after)
	}
}

func TestP108B_S12_FreshIndexNameCollisionRollsBack(t *testing.T) {
	db, err := database.Open(t.TempDir() + "/index-collision.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if sqlDB, err := db.DB(); err == nil {
			_ = sqlDB.Close()
		}
	})
	if err := db.Exec("CREATE TABLE dummy (id integer)").Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Exec("CREATE INDEX idx_audit_events_event_id ON dummy(id)").Error; err != nil {
		t.Fatal(err)
	}
	before := auditSchemaFingerprint(t, db)
	if err := MigrateIntegrity(db); !errors.Is(err, ErrAuditIntegrity) {
		t.Fatalf("fresh index-name collision must fail closed, got %v", err)
	}
	if after := auditSchemaFingerprint(t, db); after != before {
		t.Fatalf("fresh index collision changed schema: before=%s after=%s", before, after)
	}
	var count int64
	if err := db.Raw("SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name IN ('audit_events', 'audit_chain_states')").Scan(&count).Error; err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("fresh index collision must not create audit tables, got %d", count)
	}
}

func TestP108B_S12_PostMigrationIndexesExact(t *testing.T) {
	db, _ := newP108BS1DB(t)
	if err := verifyExpectedAuditIndexes(db, auditIndexSpecs); err != nil {
		t.Fatalf("post-migration audit indexes are not exact: %v", err)
	}
}

func TestP108B_S12_EventIDUniqueConstraint(t *testing.T) {
	db, _ := newP108BS1DB(t)
	svc := NewService(db)
	if err := svc.Record(testAuditEvent("unique-event-id")); err != nil {
		t.Fatal(err)
	}
	var event models.AuditEvent
	if err := db.First(&event).Error; err != nil {
		t.Fatal(err)
	}
	duplicate := event
	duplicate.ID = 0
	duplicate.TargetID = "duplicate-target"
	if err := db.Create(&duplicate).Error; err == nil {
		t.Fatal("duplicate event_id insert must fail at the database constraint")
	}
}

func TestP108B_S1_TriggerDefinitionMismatchFailsClosed(t *testing.T) {
	db, _ := newP108BS1DB(t)
	dropAuditMutationTriggers(t, db)
	if err := db.Exec("CREATE TRIGGER audit_events_no_update BEFORE UPDATE ON audit_events BEGIN SELECT 1; END").Error; err != nil {
		t.Fatal(err)
	}
	if err := MigrateIntegrity(db); !errors.Is(err, ErrAuditIntegrity) {
		t.Fatalf("mismatched trigger definition must fail closed, got %v", err)
	}
}

func TestP108B_S1_MigrationFailureRollsBack(t *testing.T) {
	path := t.TempDir() + "/rollback.db"
	db, err := database.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if sqlDB, err := db.DB(); err == nil {
			_ = sqlDB.Close()
		}
	})
	createLegacyP105CSchema(t, db)
	legacy := models.AuditEvent{ID: 1, EventID: "legacy-rollback", Action: ActionClientCreated, ActorType: "admin", ActorID: "admin", TargetType: "client", TargetID: "client", Reason: "legacy", CreatedAt: time.Unix(1788064496, 987654321).UTC()}
	insertLegacyAuditEvent(t, db, legacy)
	if err := db.Exec("CREATE TABLE trigger_name_blocker (id INTEGER)").Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Exec("CREATE TRIGGER audit_events_no_update BEFORE UPDATE ON trigger_name_blocker BEGIN SELECT 1; END").Error; err != nil {
		t.Fatal(err)
	}

	if err := MigrateIntegrity(db); !errors.Is(err, ErrAuditIntegrity) {
		t.Fatalf("trigger-name collision should fail migration, got %v", err)
	}
	var after struct {
		ID         int64
		EventID    string
		Action     string
		ActorType  string
		ActorID    string
		TargetType string
		TargetID   string
		Reason     string
		CreatedAt  time.Time
	}
	if err := db.Raw("SELECT id, event_id, action, actor_type, actor_id, target_type, target_id, reason, created_at FROM audit_events WHERE event_id = ?", legacy.EventID).Scan(&after).Error; err != nil {
		t.Fatal(err)
	}
	if after.ID != legacy.ID || after.EventID != legacy.EventID || after.Action != legacy.Action || after.ActorType != legacy.ActorType || after.ActorID != legacy.ActorID || after.TargetType != legacy.TargetType || after.TargetID != legacy.TargetID || after.Reason != legacy.Reason || !after.CreatedAt.Equal(legacy.CreatedAt) {
		t.Fatalf("failed migration changed legacy row, got %+v", after)
	}
	var columnRows []sqliteTableColumn
	if err := db.Raw("PRAGMA table_info(audit_events)").Scan(&columnRows).Error; err != nil {
		t.Fatal(err)
	}
	columns := make(map[string]sqliteTableColumn, len(columnRows))
	for _, column := range columnRows {
		columns[column.Name] = column
	}
	for _, name := range []string{"chain_version", "prev_hash", "event_hash"} {
		if _, ok := columns[name]; ok {
			t.Fatalf("failed migration must roll back legacy column %q", name)
		}
	}
	var stateTables int64
	if err := db.Raw("SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name = 'audit_chain_states'").Scan(&stateTables).Error; err != nil {
		t.Fatal(err)
	}
	if stateTables != 0 {
		t.Fatalf("failed migration must roll back chain-state table creation, got %d", stateTables)
	}
	var auditTriggers int64
	if err := db.Raw("SELECT count(*) FROM sqlite_master WHERE type = 'trigger' AND tbl_name = 'audit_events'").Scan(&auditTriggers).Error; err != nil {
		t.Fatal(err)
	}
	if auditTriggers != 0 {
		t.Fatalf("failed migration must not leave audit triggers, got %d", auditTriggers)
	}
}

func TestP108B_S1_SQLiteBusyTimeoutConfigured(t *testing.T) {
	db, err := database.Open(t.TempDir() + "/busy.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if sqlDB, err := db.DB(); err == nil {
			_ = sqlDB.Close()
		}
	})
	var timeout int
	if err := db.Raw("PRAGMA busy_timeout").Scan(&timeout).Error; err != nil {
		t.Fatal(err)
	}
	if timeout != 5000 {
		t.Fatalf("SQLite busy_timeout must be 5000ms, got %d", timeout)
	}
}

func TestP108B_S1_ConcurrentAppendNoFork(t *testing.T) {
	// Keep the 32 goroutines and four independent SQLite handles genuinely
	// concurrent while avoiding host-level package-runner oversubscription that
	// can starve a writer past the fixed 5s SQLite busy timeout.
	previousProcs := runtime.GOMAXPROCS(1)
	t.Cleanup(func() { runtime.GOMAXPROCS(previousProcs) })

	path := t.TempDir() + "/concurrent.db"
	bootstrap, err := database.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := MigrateIntegrity(bootstrap); err != nil {
		t.Fatal(err)
	}
	if sqlDB, err := bootstrap.DB(); err == nil {
		_ = sqlDB.Close()
	}

	const handles = 4
	const workers = 32
	const appendsPerWorker = 25
	dbs := make([]*gorm.DB, handles)
	services := make([]*Service, handles)
	for i := 0; i < handles; i++ {
		dbs[i], err = database.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		if sqlDB, err := dbs[i].DB(); err == nil {
			sqlDB.SetMaxOpenConns(1)
			sqlDB.SetMaxIdleConns(1)
		}
		services[i] = NewService(dbs[i])
		dbForCleanup := dbs[i]
		t.Cleanup(func() {
			if sqlDB, err := dbForCleanup.DB(); err == nil {
				_ = sqlDB.Close()
			}
		})
	}

	var wg sync.WaitGroup
	errorsCh := make(chan error, workers*appendsPerWorker)
	for worker := 0; worker < workers; worker++ {
		worker := worker
		wg.Add(1)
		go func() {
			defer wg.Done()
			for appendIndex := 0; appendIndex < appendsPerWorker; appendIndex++ {
				targetID := "concurrent-" + strconv.Itoa(worker) + "-" + strconv.Itoa(appendIndex)
				if err := services[worker%handles].Record(testAuditEvent(targetID)); err != nil {
					errorsCh <- fmt.Errorf("worker %d append %d: %w", worker, appendIndex, err)
				}
			}
		}()
	}
	wg.Wait()
	close(errorsCh)
	for err := range errorsCh {
		t.Fatalf("concurrent append failed: %v", err)
	}

	verifyDB, err := database.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if sqlDB, err := verifyDB.DB(); err == nil {
			_ = sqlDB.Close()
		}
	}()
	var count int64
	if err := verifyDB.Model(&models.AuditEvent{}).Count(&count).Error; err != nil {
		t.Fatal(err)
	}
	if count != workers*appendsPerWorker {
		t.Fatalf("expected %d concurrent events, got %d", workers*appendsPerWorker, count)
	}
	if err := NewService(verifyDB).VerifyAuditChain(); err != nil {
		t.Fatalf("concurrent chain verification failed: %v", err)
	}
}
