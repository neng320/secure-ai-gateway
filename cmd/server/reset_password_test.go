package main

import (
	"bytes"
	"context"
	"errors"
	"log"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"ai-gateway/internal/audit"
	"ai-gateway/internal/auth"
	"ai-gateway/internal/config"
	"ai-gateway/internal/database"
	"ai-gateway/internal/models"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

const s5ResetPasswordCanary = "P108B-S5-PASSWORD-CANARY"

func resetAssertNoCanaryInSQLiteFiles(t *testing.T, dbPath string, canaries ...string) {
	t.Helper()
	for _, suffix := range []string{"", "-wal", "-shm", "-journal"} {
		path := dbPath + suffix
		data, err := os.ReadFile(path)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		for _, canary := range canaries {
			if bytes.Contains(data, []byte(canary)) {
				t.Fatalf("canary %q reached SQLite file %s", canary, filepath.Base(path))
			}
		}
	}
}

func resetSeedSession(t *testing.T, configPath string) (*gorm.DB, *auth.SQLiteStore, string) {
	t.Helper()
	cfg, err := config.LoadExistingForMigration(configPath)
	if err != nil {
		t.Fatal(err)
	}
	db, err := database.Open(cfg.Database.Path)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.AutoMigrate(&models.AdminSession{}); err != nil {
		t.Fatal(err)
	}
	store := auth.NewSQLiteStore(db)
	token, err := store.Create(context.Background(), "admin", time.Now().UTC().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if sqlDB, err := db.DB(); err == nil {
			_ = sqlDB.Close()
		}
	})
	return db, store, token
}

func TestP108B_S5_ResetPasswordRevokesSessions(t *testing.T) {
	path := writeProvConfig(t, "    type: openai\n")
	var logOutput bytes.Buffer
	previousLogWriter := log.Writer()
	log.SetOutput(&logOutput)
	t.Cleanup(func() { log.SetOutput(previousLogWriter) })
	db, _, token := resetSeedSession(t, path)
	if sqlDB, err := db.DB(); err == nil {
		_ = sqlDB.Close()
	}
	reader := newAdminPasswordReader(strings.NewReader("  "+s5ResetPasswordCanary+"  \n"), true)
	var out bytes.Buffer
	if err := runResetAdminPassword(path, reader, &out); err != nil {
		t.Fatalf("reset password failed: %v", err)
	}
	if strings.Contains(out.String(), s5ResetPasswordCanary) {
		t.Fatal("reset password leaked password to stdout")
	}
	cfg, err := config.LoadExistingForMigration(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := bcrypt.CompareHashAndPassword([]byte(cfg.Admin.PasswordHash), []byte("  "+s5ResetPasswordCanary+"  ")); err != nil {
		t.Fatalf("stdin password was not preserved exactly: %v", err)
	}
	db, err = database.Open(cfg.Database.Path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if sqlDB, err := db.DB(); err == nil {
			_ = sqlDB.Close()
		}
	}()
	if _, err := auth.NewSQLiteStore(db).Validate(context.Background(), token); !errors.Is(err, auth.ErrSessionRevoked) {
		t.Fatalf("reset did not revoke active session: %v", err)
	}
	var events []models.AuditEvent
	if err := db.Order("id ASC").Find(&events).Error; err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || events[0].Action != audit.ActionAdminPasswordReset || events[0].ActorType != "cli" || events[0].ActorID != "reset-password" || events[0].TargetType != "admin" || events[0].TargetID != "admin" || events[0].Reason != "" {
		t.Fatalf("reset audit event mismatch: %+v", events)
	}
	if strings.Contains(events[0].Action+events[0].ActorType+events[0].ActorID+events[0].TargetType+events[0].TargetID+events[0].Reason, s5ResetPasswordCanary) {
		t.Fatal("reset password canary reached audit metadata")
	}
	if raw, err := os.ReadFile(path); err != nil {
		t.Fatal(err)
	} else if bytes.Contains(raw, []byte(s5ResetPasswordCanary)) {
		t.Fatal("reset password canary reached config storage")
	}
	if sqlDB, err := db.DB(); err == nil {
		_ = sqlDB.Close()
	}
	resetAssertNoCanaryInSQLiteFiles(t, cfg.Database.Path, s5ResetPasswordCanary)
	if strings.Contains(logOutput.String(), s5ResetPasswordCanary) {
		t.Fatal("reset password canary reached runtime logs")
	}
}

func TestP108B_S5_ResetPasswordStdin(t *testing.T) {
	reader := newAdminPasswordReader(strings.NewReader(" password with spaces\n"), true)
	got, err := reader()
	if err != nil || string(got) != " password with spaces" {
		t.Fatalf("stdin reader changed intentional password characters: %q err=%v", string(got), err)
	}
	if _, err := newAdminPasswordReader(strings.NewReader("anything"), false)(); err == nil || !strings.Contains(err.Error(), "-reset-password-stdin") {
		t.Fatalf("non-TTY reader should fail closed: %v", err)
	}
	for _, input := range []string{"\n", "first\nsecond\n"} {
		if _, err := newAdminPasswordReader(strings.NewReader(input), true)(); err == nil {
			t.Fatalf("invalid stdin password input should fail: %q", input)
		}
	}
}

func TestP108B_S5_ResetPasswordNoArgvSecret(t *testing.T) {
	source, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	text := string(source)
	if !strings.Contains(text, `flag.Bool("reset-password"`) || strings.Contains(text, `flag.String("reset-password"`) {
		t.Fatal("reset-password must not accept a password value from argv")
	}
}

func TestP108B_S5_ResetPasswordMissingDBFailsClosed(t *testing.T) {
	path, dbPath := writeProvConfigWithMissingDB(t, "    type: openai\n")
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	reader := newAdminPasswordReader(strings.NewReader(s5ResetPasswordCanary+"\n"), true)
	if err := runResetAdminPassword(path, reader, &out); err == nil {
		t.Fatal("missing audit DB must reject password reset")
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(after, before) {
		t.Fatal("missing DB reset changed config")
	}
	if _, err := os.Stat(dbPath); !os.IsNotExist(err) {
		t.Fatalf("missing DB reset bootstrapped database: %v", err)
	}
	if out.Len() != 0 {
		t.Fatalf("failed reset wrote output: %q", out.String())
	}
}

func TestP108B_S5_ResetPasswordMissingSessionSchemaFailsClosed(t *testing.T) {
	path := writeProvConfig(t, "    type: openai\n")
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	reader := newAdminPasswordReader(strings.NewReader(s5ResetPasswordCanary+"\n"), true)
	if err := runResetAdminPassword(path, reader, &out); err == nil {
		t.Fatal("missing admin session schema must reject password reset")
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(after, before) {
		t.Fatal("missing session schema reset changed config")
	}
}

func TestP108B_S5_ResetPasswordAuditFailureRollsBack(t *testing.T) {
	path := writeProvConfig(t, "    type: openai\n")
	db, _, token := resetSeedSession(t, path)
	if sqlDB, err := db.DB(); err == nil {
		_ = sqlDB.Close()
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	countBefore, headBefore := provisionAuditState(t, path)
	openAuditDB := func(dbPath string) (*gorm.DB, error) {
		db, err := openExistingResetAuditDB(dbPath)
		if err != nil {
			return nil, err
		}
		if err := db.Exec("CREATE TRIGGER s5_reject_reset BEFORE INSERT ON audit_events WHEN NEW.action = 'ADMIN_PASSWORD_RESET' BEGIN SELECT RAISE(ABORT, 'TEST_RESET_AUDIT_FAILED'); END").Error; err != nil {
			if sqlDB, dbErr := db.DB(); dbErr == nil {
				_ = sqlDB.Close()
			}
			return nil, err
		}
		return db, nil
	}
	reader := newAdminPasswordReader(strings.NewReader(s5ResetPasswordCanary+"\n"), true)
	var out bytes.Buffer
	if err := runResetAdminPasswordWithAuditDBOpener(path, reader, openAuditDB, &out); err == nil {
		t.Fatal("reset audit failure must reject mutation")
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(after, before) {
		t.Fatal("reset audit failure did not restore exact config")
	}
	cfg, err := config.LoadExistingForMigration(path)
	if err != nil {
		t.Fatal(err)
	}
	db, err = database.Open(cfg.Database.Path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if sqlDB, err := db.DB(); err == nil {
			_ = sqlDB.Close()
		}
	}()
	if _, err := auth.NewSQLiteStore(db).Validate(context.Background(), token); err != nil {
		t.Fatalf("reset audit failure revoked existing session: %v", err)
	}
	var count int64
	if err := db.Model(&models.AuditEvent{}).Count(&count).Error; err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("reset audit failure left %d events", count)
	}
	countAfter, headAfter := provisionAuditState(t, path)
	if countAfter != countBefore || headAfter != headBefore {
		t.Fatalf("reset audit failure changed audit chain state")
	}
	if strings.Contains(out.String(), s5ResetPasswordCanary) {
		t.Fatal("reset audit failure leaked password")
	}
	if sqlDB, err := db.DB(); err == nil {
		_ = sqlDB.Close()
	}
	resetAssertNoCanaryInSQLiteFiles(t, cfg.Database.Path, s5ResetPasswordCanary)
	if leftovers, err := filepath.Glob(filepath.Join(filepath.Dir(path), ".config.yaml.tmp-*")); err != nil || len(leftovers) != 0 {
		t.Fatalf("reset left temporary files: %v err=%v", leftovers, err)
	}
}

type resetAuditSnapshot struct {
	Events []models.AuditEvent
	Head   string
}

func newS7CorruptResetFixture(t *testing.T, corruption string) (configPath, dbPath, token, passwordHash string, beforeDB []byte, beforeAudit resetAuditSnapshot) {
	t.Helper()
	dir := t.TempDir()
	dbPath = filepath.Join(dir, "gateway.db")
	db, err := database.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := audit.MigrateIntegrity(db); err != nil {
		t.Fatal(err)
	}
	if err := db.AutoMigrate(&models.AdminSession{}); err != nil {
		t.Fatal(err)
	}
	if err := audit.NewService(db).Record(models.AuditEvent{
		Action:     audit.ActionClientCreated,
		ActorType:  "test",
		ActorID:    "s7-reset",
		TargetType: "client",
		TargetID:   "s7-reset-client",
	}); err != nil {
		t.Fatal(err)
	}
	store := auth.NewSQLiteStore(db)
	token, err = store.Create(context.Background(), "admin", time.Now().UTC().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if sqlDB, err := db.DB(); err == nil {
		_ = sqlDB.Close()
	}

	configPath = writeS2Config(t, dir, dbPath, "")
	cfg, err := config.LoadExistingForMigration(configPath)
	if err != nil {
		t.Fatal(err)
	}
	passwordHash = cfg.Admin.PasswordHash

	db, err = database.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	switch corruption {
	case "event":
		if err := db.Exec("DROP TRIGGER audit_events_no_update").Error; err != nil {
			t.Fatal(err)
		}
		if err := db.Exec("UPDATE audit_events SET event_hash = ? WHERE id = 1", strings.Repeat("a", 64)).Error; err != nil {
			t.Fatal(err)
		}
		if err := db.Exec("CREATE TRIGGER audit_events_no_update BEFORE UPDATE ON audit_events BEGIN SELECT RAISE(ABORT, 'AUDIT_EVENT_IMMUTABLE'); END").Error; err != nil {
			t.Fatal(err)
		}
	case "state":
		if err := db.Exec("UPDATE audit_chain_states SET head_hash = ? WHERE id = 1", strings.Repeat("b", 64)).Error; err != nil {
			t.Fatal(err)
		}
	case "trigger":
		if err := db.Exec("DROP TRIGGER audit_events_no_update").Error; err != nil {
			t.Fatal(err)
		}
	default:
		t.Fatalf("unknown corruption %q", corruption)
	}
	if sqlDB, err := db.DB(); err == nil {
		_ = sqlDB.Close()
	}
	beforeDB, err = os.ReadFile(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	beforeAudit = readS7ResetAuditSnapshot(t, dbPath)
	return configPath, dbPath, token, passwordHash, beforeDB, beforeAudit
}

func readS7ResetAuditSnapshot(t *testing.T, dbPath string) resetAuditSnapshot {
	t.Helper()
	db, err := database.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	var snapshot resetAuditSnapshot
	if err := db.Order("id ASC").Find(&snapshot.Events).Error; err != nil {
		t.Fatal(err)
	}
	var state models.AuditChainState
	if err := db.Where("id = ?", 1).First(&state).Error; err != nil {
		t.Fatal(err)
	}
	snapshot.Head = state.HeadHash
	if sqlDB, err := db.DB(); err == nil {
		_ = sqlDB.Close()
	}
	return snapshot
}

func assertS7ResetCorruptionFailsClosed(t *testing.T, corruption string) {
	t.Helper()
	configPath, dbPath, token, passwordHash, beforeDB, beforeAudit := newS7CorruptResetFixture(t, corruption)
	canary := "P108B-S7-RESET-CORRUPTION-PASSWORD"
	beforeConfig, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	err = runResetAdminPassword(configPath, newAdminPasswordReader(strings.NewReader(canary+"\n"), true), &out)
	if err == nil {
		t.Fatal("corrupt current audit was accepted")
	}
	if out.Len() != 0 {
		t.Fatalf("failed reset wrote success output: %q", out.String())
	}
	if strings.Contains(err.Error()+out.String(), canary) {
		t.Fatal("reset failure leaked password material")
	}
	afterConfig, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(afterConfig, beforeConfig) {
		t.Fatal("config changed after corrupt-audit rejection")
	}
	cfgAfter, err := config.LoadExistingForMigration(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if cfgAfter.Admin.PasswordHash != passwordHash {
		t.Fatal("password hash changed after corrupt-audit rejection")
	}
	afterAudit := readS7ResetAuditSnapshot(t, dbPath)
	if !reflect.DeepEqual(afterAudit, beforeAudit) {
		t.Fatalf("audit events/state changed after corrupt-audit rejection: before=%+v after=%+v", beforeAudit, afterAudit)
	}
	afterDB, err := os.ReadFile(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(afterDB, beforeDB) {
		t.Fatal("corrupt audit was repaired or database changed")
	}
	db, err := database.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := auth.NewSQLiteStore(db).Validate(context.Background(), token); err != nil {
		t.Fatalf("session changed after corrupt-audit rejection: %v", err)
	}
	if sqlDB, err := db.DB(); err == nil {
		_ = sqlDB.Close()
	}
	for _, pattern := range []string{".config.yaml.tmp-*", ".config.yaml.audit-mutation-lock"} {
		matches, err := filepath.Glob(filepath.Join(filepath.Dir(configPath), pattern))
		if err != nil || len(matches) != 0 {
			t.Fatalf("temporary artifacts remain for %s: %v err=%v", pattern, matches, err)
		}
	}
}

func TestP108B_S7_ResetCurrentEventCorruptionFailsClosed(t *testing.T) {
	assertS7ResetCorruptionFailsClosed(t, "event")
}

func TestP108B_S7_ResetCurrentStateCorruptionFailsClosed(t *testing.T) {
	assertS7ResetCorruptionFailsClosed(t, "state")
}

func TestP108B_S7_ResetCurrentTriggerCorruptionFailsClosed(t *testing.T) {
	assertS7ResetCorruptionFailsClosed(t, "trigger")
}
