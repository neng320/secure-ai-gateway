package handlers

import (
	"bytes"
	"context"
	"errors"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"ai-gateway/internal/audit"
	"ai-gateway/internal/auth"
	"ai-gateway/internal/config"
	"ai-gateway/internal/models"
)

const s5SetupPasswordCanary = "P108B-S5-CONFIG-SECRET-CANARY"

func s5WriteSetupConfig(t *testing.T, env *authEnv, path string) []byte {
	t.Helper()
	data, err := config.MarshalYAML(env.cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	return data
}

func s5SetupPost(t *testing.T, setupH *SetupHandler, form url.Values) *http.Response {
	t.Helper()
	router := setupEnvRouter(nil)
	setupH.RegisterRoutes(router)
	return setupCSRFDance(t, router, form)
}

func s5SetupEvent(t *testing.T, env *authEnv) []models.AuditEvent {
	t.Helper()
	var events []models.AuditEvent
	if err := env.db.Where("action = ?", audit.ActionSetupCompleted).Order("id ASC").Find(&events).Error; err != nil {
		t.Fatal(err)
	}
	return events
}

func TestP108B_S5_SetupSuccessAudited(t *testing.T) {
	env := newAuthEnvWithHash(t, "__SETUP_REQUIRED__")
	var logOutput strings.Builder
	previousLogWriter := log.Writer()
	log.SetOutput(&logOutput)
	t.Cleanup(func() { log.SetOutput(previousLogWriter) })
	env.cfg.Providers["openai"] = config.ProviderConfig{Type: "openai", APIKeyEncrypted: "enc:v1:P108B-S5-EXTERNAL-PROVIDER"}
	path := filepath.Join(t.TempDir(), "config.yaml")
	s5WriteSetupConfig(t, env, path)
	oldSession, err := env.store.Create(context.Background(), "old-admin", time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	setupH := NewSetupHandler(env.cfg, true, env.limiter, path, env.db)
	resp := s5SetupPost(t, setupH, url.Values{"username": {"new-admin"}, "password": {s5SetupPasswordCanary}, "confirm_password": {s5SetupPasswordCanary}})
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("setup status=%d body=%q", resp.StatusCode, readBody(resp))
	}
	if env.cfg.Admin.Username != "new-admin" || env.limiter.ProtectedUser() != "new-admin" {
		t.Fatalf("setup did not apply trusted runtime identity: cfg=%q limiter=%q", env.cfg.Admin.Username, env.limiter.ProtectedUser())
	}
	if _, err := env.store.Validate(context.Background(), oldSession); !errors.Is(err, auth.ErrSessionRevoked) {
		t.Fatalf("setup did not revoke existing session: %v", err)
	}
	persisted, err := config.LoadExistingForMigration(path)
	if err != nil {
		t.Fatal(err)
	}
	if persisted.Admin.Username != "new-admin" || persisted.Providers["openai"].APIKeyEncrypted != "enc:v1:P108B-S5-EXTERNAL-PROVIDER" {
		t.Fatalf("setup did not preserve authoritative provider/config state: %+v", persisted)
	}
	events := s5SetupEvent(t, env)
	if len(events) != 1 || events[0].ActorType != "setup" || events[0].ActorID != "setup-wizard" || events[0].TargetType != "admin" || events[0].TargetID != "admin" || events[0].Reason != "" {
		t.Fatalf("setup audit event mismatch: %+v", events)
	}
	if strings.Contains(events[0].Action+events[0].ActorType+events[0].ActorID+events[0].TargetType+events[0].TargetID+events[0].Reason, s5SetupPasswordCanary) {
		t.Fatal("setup password canary reached audit metadata")
	}
	if raw, err := os.ReadFile(path); err != nil {
		t.Fatal(err)
	} else if bytes.Contains(raw, []byte(s5SetupPasswordCanary)) {
		t.Fatal("setup password canary reached config storage")
	}
	if sqlDB, err := env.db.DB(); err == nil {
		_ = sqlDB.Close()
	}
	s5AssertNoCanaryInSQLiteFiles(t, env.dbPath, s5SetupPasswordCanary)
	if strings.Contains(logOutput.String(), s5SetupPasswordCanary) {
		t.Fatal("setup password canary reached runtime logs")
	}
}

func TestP108B_S5_SetupRevokesExistingSessions(t *testing.T) {
	env := newAuthEnvWithHash(t, "__SETUP_REQUIRED__")
	path := filepath.Join(t.TempDir(), "config.yaml")
	s5WriteSetupConfig(t, env, path)
	first, err := env.store.Create(context.Background(), "admin", time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	second, err := env.store.Create(context.Background(), "other-admin", time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	setupH := NewSetupHandler(env.cfg, true, env.limiter, path, env.db)
	resp := s5SetupPost(t, setupH, url.Values{"username": {"admin"}, "password": {"Setup-New-Password"}, "confirm_password": {"Setup-New-Password"}})
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("setup status=%d", resp.StatusCode)
	}
	for _, token := range []string{first, second} {
		if _, err := env.store.Validate(context.Background(), token); !errors.Is(err, auth.ErrSessionRevoked) {
			t.Fatalf("setup left active session: %v", err)
		}
	}
}

func TestP108B_S5_SetupAuditFailureRollsBackEverything(t *testing.T) {
	env := newAuthEnvWithHash(t, "__SETUP_REQUIRED__")
	path := filepath.Join(t.TempDir(), "config.yaml")
	beforeFile := s5WriteSetupConfig(t, env, path)
	oldAdmin := env.cfg.Admin
	oldPrometheus := env.cfg.Prometheus
	oldProtected := env.limiter.ProtectedUser()
	oldSession, err := env.store.Create(context.Background(), "admin", time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	countBefore, headBefore := s5AuditState(t, env)
	if err := env.db.Exec("CREATE TRIGGER s5_reject_setup BEFORE INSERT ON audit_events WHEN NEW.action = 'SETUP_COMPLETED' BEGIN SELECT RAISE(ABORT, 'TEST_SETUP_AUDIT_FAILED'); END").Error; err != nil {
		t.Fatal(err)
	}
	setupH := NewSetupHandler(env.cfg, true, env.limiter, path, env.db)
	resp := s5SetupPost(t, setupH, url.Values{"username": {"new-admin"}, "password": {s5SetupPasswordCanary}, "confirm_password": {s5SetupPasswordCanary}})
	if resp.StatusCode == http.StatusFound {
		t.Fatal("setup audit failure reported success")
	}
	afterFile, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(afterFile, beforeFile) || !reflect.DeepEqual(env.cfg.Admin, oldAdmin) || !reflect.DeepEqual(env.cfg.Prometheus, oldPrometheus) || env.limiter.ProtectedUser() != oldProtected {
		t.Fatal("setup audit failure changed config or runtime state")
	}
	if _, err := env.store.Validate(context.Background(), oldSession); err != nil {
		t.Fatalf("setup audit failure revoked existing session: %v", err)
	}
	countAfter, headAfter := s5AuditState(t, env)
	if countAfter != countBefore || headAfter != headBefore || len(s5SetupEvent(t, env)) != 0 {
		t.Fatal("setup audit failure changed audit state")
	}
	if strings.Contains(readBody(resp), s5SetupPasswordCanary) {
		t.Fatal("setup password canary reached error response")
	}
}

func TestP108B_S5_SetupDatabasePathMismatchFailsClosed(t *testing.T) {
	env := newAuthEnvWithHash(t, "__SETUP_REQUIRED__")
	path := filepath.Join(t.TempDir(), "config.yaml")
	s5WriteSetupConfig(t, env, path)
	diskCfg, err := config.LoadExistingForMigration(path)
	if err != nil {
		t.Fatal(err)
	}
	diskCfg.Database.Path = filepath.Join(t.TempDir(), "different.db")
	diskBefore, err := config.MarshalYAML(diskCfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, diskBefore, 0600); err != nil {
		t.Fatal(err)
	}
	oldAdmin := env.cfg.Admin
	oldProtected := env.limiter.ProtectedUser()
	countBefore, headBefore := s5AuditState(t, env)
	setupH := NewSetupHandler(env.cfg, true, env.limiter, path, env.db)
	resp := s5SetupPost(t, setupH, url.Values{"username": {"new-admin"}, "password": {"Setup-New-Password"}, "confirm_password": {"Setup-New-Password"}})
	if resp.StatusCode == http.StatusFound {
		t.Fatal("database path mismatch setup reported success")
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(after, diskBefore) || !reflect.DeepEqual(env.cfg.Admin, oldAdmin) || env.limiter.ProtectedUser() != oldProtected {
		t.Fatal("database path mismatch changed setup state")
	}
	countAfter, headAfter := s5AuditState(t, env)
	if countAfter != countBefore || headAfter != headBefore || len(s5SetupEvent(t, env)) != 0 {
		t.Fatal("database path mismatch appended audit")
	}
}
