package audit

import (
	"errors"
	"fmt"
	"reflect"
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

func TestP108B_S1_LegacyBackfillByIDAndFieldsPreserved(t *testing.T) {
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
	if err := db.AutoMigrate(&models.AuditEvent{}); err != nil {
		t.Fatal(err)
	}
	created := time.Unix(1788064496, 123456789).UTC()
	legacy := []models.AuditEvent{
		{EventID: "legacy-1", Action: ActionClientCreated, ActorType: "admin", ActorID: "legacy-admin", TargetType: "client", TargetID: "client-1", Reason: "  preserve spaces  ", CreatedAt: created},
		{EventID: "legacy-2", Action: ActionClientDeleted, ActorType: "admin", ActorID: "legacy-admin", TargetType: "client", TargetID: "client-1", Reason: "second", CreatedAt: created},
	}
	for i := range legacy {
		if err := db.Create(&legacy[i]).Error; err != nil {
			t.Fatal(err)
		}
	}
	var before []models.AuditEvent
	if err := db.Order("id ASC").Find(&before).Error; err != nil {
		t.Fatal(err)
	}
	if err := MigrateIntegrity(db); err != nil {
		t.Fatal(err)
	}
	var after []models.AuditEvent
	if err := db.Order("id ASC").Find(&after).Error; err != nil {
		t.Fatal(err)
	}
	if len(after) != 2 || after[0].PrevHash != "" || after[1].PrevHash != after[0].EventHash {
		t.Fatalf("legacy rows must be chained by immutable ID ASC: %+v", after)
	}
	for i := range before {
		before[i].ChainVersion, before[i].PrevHash, before[i].EventHash = "", "", ""
		if before[i].EventID != after[i].EventID || before[i].Action != after[i].Action || before[i].ActorType != after[i].ActorType || before[i].ActorID != after[i].ActorID || before[i].TargetType != after[i].TargetType || before[i].TargetID != after[i].TargetID || before[i].Reason != after[i].Reason || !before[i].CreatedAt.Equal(after[i].CreatedAt) {
			t.Fatalf("legacy semantic fields changed at index %d: before=%+v after=%+v", i, before[i], after[i])
		}
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
		path := t.TempDir() + "/mixed.db"
		db, err := database.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if sqlDB, err := db.DB(); err == nil {
				_ = sqlDB.Close()
			}
		})
		if err := db.AutoMigrate(&models.AuditEvent{}); err != nil {
			t.Fatal(err)
		}
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
	if err := db.AutoMigrate(&models.AuditEvent{}); err != nil {
		t.Fatal(err)
	}
	legacy := models.AuditEvent{EventID: "legacy-rollback", Action: ActionClientCreated, ActorType: "admin", ActorID: "admin", TargetType: "client", TargetID: "client", Reason: "legacy", CreatedAt: time.Now().UTC()}
	if err := db.Create(&legacy).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Exec("CREATE TABLE trigger_name_blocker (id INTEGER)").Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Exec("CREATE TRIGGER audit_events_no_update BEFORE UPDATE ON trigger_name_blocker BEGIN SELECT 1; END").Error; err != nil {
		t.Fatal(err)
	}

	if err := MigrateIntegrity(db); !errors.Is(err, ErrAuditIntegrity) {
		t.Fatalf("trigger-name collision should fail migration, got %v", err)
	}
	var after models.AuditEvent
	if err := db.First(&after, "event_id = ?", legacy.EventID).Error; err != nil {
		t.Fatal(err)
	}
	if after.ChainVersion != "" || after.PrevHash != "" || after.EventHash != "" {
		t.Fatalf("failed migration must roll back legacy backfill, got %+v", after)
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
