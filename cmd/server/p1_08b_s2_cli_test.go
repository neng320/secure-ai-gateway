package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"ai-gateway/internal/audit"
	"ai-gateway/internal/database"
	"ai-gateway/internal/models"

	"gorm.io/gorm"
)

func writeS2Config(t *testing.T, dir, dbPath, extra string) string {
	t.Helper()
	path := filepath.Join(dir, "config.yaml")
	contents := "database:\n  path: \"" + filepath.ToSlash(dbPath) + "\"\n" + extra
	if err := os.WriteFile(path, []byte(contents), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func newS2MigratedDB(t *testing.T) (*gorm.DB, string, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "gateway.db")
	db, err := database.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := audit.MigrateIntegrity(db); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if sqlDB, err := db.DB(); err == nil {
			_ = sqlDB.Close()
		}
	})
	return db, path, filepath.Dir(path)
}

const s2LegacyAuditSchemaSQL = `CREATE TABLE audit_events (
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

func newS2LegacyDB(t *testing.T) (*gorm.DB, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "legacy.db")
	db, err := database.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Exec(s2LegacyAuditSchemaSQL).Error; err != nil {
		t.Fatal(err)
	}
	for _, statement := range []string{
		"CREATE UNIQUE INDEX idx_audit_events_event_id ON audit_events(event_id)",
		"CREATE INDEX idx_audit_events_action ON audit_events(action)",
		"CREATE INDEX idx_audit_events_actor_id ON audit_events(actor_id)",
		"CREATE INDEX idx_audit_events_target_type ON audit_events(target_type)",
		"CREATE INDEX idx_audit_events_target_id ON audit_events(target_id)",
		"CREATE INDEX idx_audit_events_created_at ON audit_events(created_at)",
	} {
		if err := db.Exec(statement).Error; err != nil {
			t.Fatal(err)
		}
	}
	if err := db.Exec(`INSERT INTO audit_events
		(id, event_id, action, actor_type, actor_id, target_type, target_id, reason, created_at)
		VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?)`,
		"legacy-s2", audit.ActionClientCreated, "admin", "admin", "client", "client-1", "legacy", time.Unix(1788064496, 4).UTC()).Error; err != nil {
		t.Fatal(err)
	}
	return db, path
}

func closeS2DB(t *testing.T, db *gorm.DB) {
	t.Helper()
	if sqlDB, err := db.DB(); err == nil {
		if err := sqlDB.Close(); err != nil {
			t.Fatal(err)
		}
	}
}

func s2AuditEvent(targetID string) models.AuditEvent {
	return models.AuditEvent{Action: audit.ActionClientCreated, ActorType: "admin", ActorID: "s2-admin", TargetID: targetID}
}

func TestP108B_S2_ValidOfflineVerifyCLI(t *testing.T) {
	db, dbPath, dir := newS2MigratedDB(t)
	svc := audit.NewService(db)
	if err := svc.Record(models.AuditEvent{Action: audit.ActionClientCreated, ActorType: "admin", ActorID: "offline-admin", TargetID: "offline-client"}); err != nil {
		t.Fatal(err)
	}
	var event models.AuditEvent
	if err := db.First(&event).Error; err != nil {
		t.Fatal(err)
	}
	closeS2DB(t, db)
	configPath := writeS2Config(t, dir, dbPath, "")
	configBefore, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	dbBefore, err := os.ReadFile(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if code := runVerifyAuditLog(configPath, &stdout, &stderr); code != 0 {
		t.Fatalf("valid offline verification exit=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	want := "AUDIT_VERIFY_OK\nevents=1\nhead_sha256=" + event.EventHash + "\n"
	if stdout.String() != want || stderr.Len() != 0 {
		t.Fatalf("unexpected valid offline output: stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
	if got, _ := os.ReadFile(configPath); !bytes.Equal(got, configBefore) {
		t.Fatal("offline verification changed config bytes")
	}
	if got, _ := os.ReadFile(dbPath); !bytes.Equal(got, dbBefore) {
		t.Fatal("offline verification changed database bytes")
	}
	for _, forbidden := range []string{event.EventID, event.Action, event.ActorID, event.TargetID, event.Reason} {
		if forbidden == "" {
			continue
		}
		if strings.Contains(stdout.String()+stderr.String(), forbidden) {
			t.Fatalf("offline output leaked event field %q", forbidden)
		}
	}
}

func TestP108B_S2_LegacyOfflineRequiresMigration(t *testing.T) {
	db, dbPath := newS2LegacyDB(t)
	closeS2DB(t, db)
	configPath := writeS2Config(t, filepath.Dir(dbPath), dbPath, "")
	before, err := os.ReadFile(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if code := runVerifyAuditLog(configPath, &stdout, &stderr); code != 2 {
		t.Fatalf("legacy offline verification exit=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	if stdout.Len() != 0 || stderr.String() != "AUDIT_SCHEMA_MIGRATION_REQUIRED\n" {
		t.Fatalf("unexpected legacy offline output: stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
	if got, _ := os.ReadFile(dbPath); !bytes.Equal(got, before) {
		t.Fatal("legacy offline verification changed database bytes")
	}
}

func TestP108B_S2_FreshOfflineRequiresMigration(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "fresh.db")
	db, err := database.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	closeS2DB(t, db)
	configPath := writeS2Config(t, filepath.Dir(dbPath), dbPath, "")
	var stdout, stderr bytes.Buffer
	if code := runVerifyAuditLog(configPath, &stdout, &stderr); code != 2 {
		t.Fatalf("fresh offline verification exit=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	if stdout.Len() != 0 || stderr.String() != "AUDIT_SCHEMA_MIGRATION_REQUIRED\n" {
		t.Fatalf("unexpected fresh offline output: stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
}

func TestP108B_S2_OfflineNoMasterKeyDependency(t *testing.T) {
	db, dbPath, dir := newS2MigratedDB(t)
	if err := audit.NewService(db).Record(s2AuditEvent("offline-no-master-key")); err != nil {
		t.Fatal(err)
	}
	closeS2DB(t, db)
	configPath := writeS2Config(t, dir, dbPath, "providers:\n  openai:\n    api_key: master-key-canary\n    base_url: authorization-canary\n  gemini:\n    api_key: prompt-canary\n")
	var stdout, stderr bytes.Buffer
	if code := runVerifyAuditLog(configPath, &stdout, &stderr); code != 0 {
		t.Fatalf("offline verification must not need master key: exit=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	for _, canary := range []string{"master-key-canary", "authorization-canary", "prompt-canary", "provider-secret-canary"} {
		if strings.Contains(stdout.String()+stderr.String(), canary) {
			t.Fatalf("offline output leaked canary %q", canary)
		}
	}
}

func TestP108B_S2_OfflineNoFilesystemSideEffects(t *testing.T) {
	db, dbPath, dir := newS2MigratedDB(t)
	closeS2DB(t, db)
	configPath := writeS2Config(t, dir, dbPath, "")
	var stdout, stderr bytes.Buffer
	if code := runVerifyAuditLog(configPath, &stdout, &stderr); code != 0 {
		t.Fatalf("offline verification failed: %d %q", code, stderr.String())
	}
	for _, name := range []string{"data", "logs"} {
		if _, err := os.Stat(filepath.Join(dir, name)); !os.IsNotExist(err) {
			t.Fatalf("offline verification created %s: %v", name, err)
		}
	}
}

func TestP108B_S2_CorruptStartupBlocksServing(t *testing.T) {
	db, dbPath, _ := newS2MigratedDB(t)
	if err := audit.NewService(db).Record(s2AuditEvent("startup-corrupt")); err != nil {
		t.Fatal(err)
	}
	if err := db.Exec("DROP TRIGGER audit_events_no_update").Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Exec("UPDATE audit_events SET reason = ? WHERE id = 1", "startup-tamper").Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Exec("CREATE TRIGGER audit_events_no_update BEFORE UPDATE ON audit_events BEGIN SELECT RAISE(ABORT, 'AUDIT_EVENT_IMMUTABLE'); END").Error; err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	started := false
	err = runAuditPreflightThen(db, func() error {
		started = true
		return nil
	})
	if err == nil || !strings.Contains(err.Error(), "AUDIT_INTEGRITY_CHECK_FAILED") || started {
		t.Fatalf("corrupt startup must block serving: err=%v started=%v", err, started)
	}
	after, err := os.ReadFile(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("corrupt startup preflight repaired or changed the database")
	}
	closeS2DB(t, db)
}

func TestP108B_S2_FreshStartupPasses(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fresh.db")
	db, err := database.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer closeS2DB(t, db)
	if err := runAuditStartupPreflight(db); err != nil {
		t.Fatal(err)
	}
	if err := audit.NewService(db).VerifyAuditChain(); err != nil {
		t.Fatalf("fresh startup preflight must leave a valid chain: %v", err)
	}
}

func TestP108B_S2_LegacyStartupMigrates(t *testing.T) {
	db, _ := newS2LegacyDB(t)
	defer closeS2DB(t, db)
	if err := runAuditStartupPreflight(db); err != nil {
		t.Fatal(err)
	}
	var count int64
	if err := db.Raw("SELECT count(*) FROM audit_chain_states").Scan(&count).Error; err != nil {
		t.Fatal(err)
	}
	if count != 1 || audit.NewService(db).VerifyAuditChain() != nil {
		t.Fatalf("legacy startup migration did not produce a valid chained database")
	}
}

func TestP108B_S2_CurrentStartupIdempotent(t *testing.T) {
	db, dbPath, _ := newS2MigratedDB(t)
	defer closeS2DB(t, db)
	if err := audit.NewService(db).Record(s2AuditEvent("current-idempotent")); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := runAuditStartupPreflight(db); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("current startup preflight rewrote a valid audit database")
	}
}

func TestP108B_S2_StartupOrderStaticGate(t *testing.T) {
	source, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	text := string(source)
	positions := []string{"flag.Parse()", "if *verifyAuditLog", "printBanner()", "logger.Init", "os.MkdirAll(\"./data\"", "autoMigrate(db)", "runAuditPreflightThen(db", "newGatewayDeps(", "startListeners("}
	last := -1
	for _, marker := range positions {
		position := strings.Index(text, marker)
		if position <= last {
			t.Fatalf("startup order marker %q is not after previous marker: %d <= %d", marker, position, last)
		}
		last = position
	}
	if !strings.Contains(text, "func runAuditStartupPreflight") || !strings.Contains(text, "audit.MigrateIntegrity(db)") {
		t.Fatal("startup must centralize audit integrity migration in runAuditStartupPreflight")
	}
}

func assertS21CurrentTriggerStartupFails(t *testing.T, triggerNames ...string) {
	t.Helper()
	db, dbPath, _ := newS2MigratedDB(t)
	defer closeS2DB(t, db)
	for _, name := range triggerNames {
		if err := db.Exec("DROP TRIGGER " + name).Error; err != nil {
			t.Fatal(err)
		}
	}
	before, err := os.ReadFile(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	started := false
	preflightErr := runAuditPreflightThen(db, func() error {
		started = true
		return nil
	})
	if preflightErr == nil || !strings.Contains(preflightErr.Error(), "AUDIT_INTEGRITY_CHECK_FAILED") || started {
		t.Fatalf("current missing trigger must block startup: err=%v started=%v", preflightErr, started)
	}
	after, err := os.ReadFile(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("startup preflight repaired a missing current trigger")
	}
	for _, name := range triggerNames {
		var count int64
		if err := db.Raw("SELECT count(*) FROM sqlite_master WHERE type = 'trigger' AND name = ?", name).Scan(&count).Error; err != nil {
			t.Fatal(err)
		}
		if count != 0 {
			t.Fatalf("startup preflight recreated missing trigger %q", name)
		}
	}
}

func TestP108B_S21_CurrentMissingUpdateTriggerStartupFailsClosed(t *testing.T) {
	assertS21CurrentTriggerStartupFails(t, "audit_events_no_update")
}

func TestP108B_S21_CurrentMissingDeleteTriggerStartupFailsClosed(t *testing.T) {
	assertS21CurrentTriggerStartupFails(t, "audit_events_no_delete")
}

func TestP108B_S21_CurrentBothTriggersMissingStartupFailsClosed(t *testing.T) {
	assertS21CurrentTriggerStartupFails(t, "audit_events_no_update", "audit_events_no_delete")
}

func TestP108B_S21_CurrentWrongTriggerStartupFailsClosed(t *testing.T) {
	db, dbPath, _ := newS2MigratedDB(t)
	defer closeS2DB(t, db)
	if err := db.Exec("DROP TRIGGER audit_events_no_update").Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Exec("CREATE TRIGGER audit_events_no_update BEFORE UPDATE ON audit_events BEGIN SELECT 1; END").Error; err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	started := false
	preflightErr := runAuditPreflightThen(db, func() error {
		started = true
		return nil
	})
	if preflightErr == nil || !strings.Contains(preflightErr.Error(), "AUDIT_INTEGRITY_CHECK_FAILED") || started {
		t.Fatalf("wrong current trigger must block startup: err=%v started=%v", preflightErr, started)
	}
	after, err := os.ReadFile(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("startup preflight repaired a wrong current trigger")
	}
}

func TestP108B_S21_CurrentExtraTriggerStartupFailsClosed(t *testing.T) {
	db, dbPath, _ := newS2MigratedDB(t)
	defer closeS2DB(t, db)
	if err := db.Exec("CREATE TRIGGER audit_events_extra_guard BEFORE INSERT ON audit_events BEGIN SELECT 1; END").Error; err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	started := false
	preflightErr := runAuditPreflightThen(db, func() error {
		started = true
		return nil
	})
	if preflightErr == nil || !strings.Contains(preflightErr.Error(), "AUDIT_INTEGRITY_CHECK_FAILED") || started {
		t.Fatalf("extra current trigger must block startup: err=%v started=%v", preflightErr, started)
	}
	after, err := os.ReadFile(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("startup preflight deleted an extra current trigger")
	}
}
