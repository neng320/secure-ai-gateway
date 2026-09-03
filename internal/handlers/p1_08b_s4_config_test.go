package handlers

// Slice 4 config-mutation inventory:
//   - in scope: UpdateServerTools and -set-provider-key/replacement
//   - deferred: Setup and -reset-password
//   - existing offline migration: -migrate-provider-secrets and request-log scrub

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
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
	"ai-gateway/internal/services"

	"github.com/go-chi/chi/v5"
	"gorm.io/gorm"
)

type s4AdminEnv struct {
	base       *p105Env
	admin      http.Handler
	configPath string
}

func newS4AdminEnv(t *testing.T) *s4AdminEnv {
	t.Helper()
	base := newP105Env(t)
	base.cfg.Database.Path = base.dbPath
	configPath := filepath.Join(t.TempDir(), "config.yaml")
	data, err := config.MarshalYAML(base.cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, data, 0600); err != nil {
		t.Fatal(err)
	}
	stats := services.NewStatsService(base.db)
	store := auth.NewSQLiteStore(base.db)
	limiter := auth.NewLoginRateLimiter()
	limiter.Configure(5, 15*time.Minute, base.cfg.Admin.Username)
	adminH, err := NewAdminHandler(base.cfg, base.clientSvc, stats, base.gemini, services.NewDashboardHub(stats), services.NewToolService(nil), store, limiter, nil, configPath, nil, base.rateLimiter)
	if err != nil {
		t.Fatal(err)
	}
	router := chi.NewRouter()
	adminH.RegisterRoutes(router)
	return &s4AdminEnv{base: base, admin: router, configPath: configPath}
}

func s4Session(t *testing.T, env *s4AdminEnv) string {
	t.Helper()
	token, err := auth.NewSQLiteStore(env.base.db).Create(context.Background(), "trusted-server-tools-admin", time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	return token
}

func s4Post(t *testing.T, env *s4AdminEnv, token, target, form string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, target, strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-Actor", "evil-header")
	req.AddCookie(&http.Cookie{Name: auth.SessionCookieName, Value: token})
	req.Header.Set("X-CSRF-Token", auth.CSRFToken(env.base.cfg.Admin.SessionSecret, token))
	w := httptest.NewRecorder()
	env.admin.ServeHTTP(w, req)
	return w
}

func TestP108B_ServerToolsPageRenders(t *testing.T) {
	env := newS4AdminEnv(t)
	token := s4Session(t, env)
	req := httptest.NewRequest(http.MethodGet, "/admin/server-tools", nil)
	req.AddCookie(&http.Cookie{Name: auth.SessionCookieName, Value: token})
	w := httptest.NewRecorder()

	env.admin.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("server tools page status=%d body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "Server Tools") {
		t.Fatalf("server tools page did not render its title: %s", w.Body.String())
	}
}

func s4AuditState(t *testing.T, db *gorm.DB) (int64, string) {
	t.Helper()
	var count int64
	if err := db.Model(&models.AuditEvent{}).Count(&count).Error; err != nil {
		t.Fatal(err)
	}
	var state models.AuditChainState
	if err := db.First(&state, 1).Error; err != nil {
		t.Fatal(err)
	}
	return count, state.HeadHash
}

func TestP108B_S4_ServerToolsSuccessTrustedActorAndDeterministicInput(t *testing.T) {
	env := newS4AdminEnv(t)
	token := s4Session(t, env)
	before, err := os.ReadFile(env.configPath)
	if err != nil {
		t.Fatal(err)
	}
	w := s4Post(t, env, token, "/admin/server-tools?actor=evil-query", "tool=get_time&tool=get_date&tool=get_time&actor=evil-form")
	if w.Result().StatusCode != http.StatusFound {
		t.Fatalf("server tools status=%d body=%s", w.Result().StatusCode, w.Body.String())
	}
	cfg, err := config.LoadExistingForMigration(env.configPath)
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.ServerTools.Enabled || !bytes.Equal([]byte(strings.Join(cfg.ServerTools.Tools, "|")), []byte("get_date|get_time")) {
		t.Fatalf("unexpected persisted server tools: %+v", cfg.ServerTools)
	}
	if !env.base.cfg.ServerTools.Enabled || strings.Join(env.base.cfg.ServerTools.Tools, "|") != "get_date|get_time" {
		t.Fatalf("live server tools were not applied after success: %+v", env.base.cfg.ServerTools)
	}
	var event models.AuditEvent
	if err := env.base.db.Where("action = ?", audit.ActionServerToolsUpdated).First(&event).Error; err != nil {
		t.Fatal(err)
	}
	if event.ActorType != "admin" || event.ActorID != "trusted-server-tools-admin" || event.TargetType != "server" || event.TargetID != "server-tools" || event.Reason != "" {
		t.Fatalf("unexpected server-tools audit event: %+v", event)
	}
	if strings.Contains(event.ActorID+event.TargetID+event.Reason, "evil-") {
		t.Fatal("forged actor material reached audit event")
	}
	if after, _ := os.ReadFile(env.configPath); bytes.Equal(after, before) {
		t.Fatal("successful server-tools update did not persist candidate config")
	}
}

func TestP108B_S4_ServerToolsUnknownToolRejectedBeforeMutation(t *testing.T) {
	env := newS4AdminEnv(t)
	token := s4Session(t, env)
	before, err := os.ReadFile(env.configPath)
	if err != nil {
		t.Fatal(err)
	}
	countBefore, headBefore := s4AuditState(t, env.base.db)
	w := s4Post(t, env, token, "/admin/server-tools", "tool=definitely-unknown")
	if w.Result().StatusCode != http.StatusBadRequest {
		t.Fatalf("unknown tool status=%d body=%s", w.Result().StatusCode, w.Body.String())
	}
	if after, _ := os.ReadFile(env.configPath); !bytes.Equal(after, before) {
		t.Fatal("unknown tool changed config")
	}
	if env.base.cfg.ServerTools.Enabled || len(env.base.cfg.ServerTools.Tools) != 0 {
		t.Fatalf("unknown tool changed live config: %+v", env.base.cfg.ServerTools)
	}
	countAfter, headAfter := s4AuditState(t, env.base.db)
	if countAfter != countBefore || headAfter != headBefore {
		t.Fatal("unknown tool changed audit state")
	}
}

func TestP108B_S4_ServerToolsAuditFailureRestoresConfigAndLiveState(t *testing.T) {
	env := newS4AdminEnv(t)
	token := s4Session(t, env)
	beforeFile, err := os.ReadFile(env.configPath)
	if err != nil {
		t.Fatal(err)
	}
	beforeLive := env.base.cfg.ServerTools
	countBefore, headBefore := s4AuditState(t, env.base.db)
	if err := env.base.db.Exec("CREATE TRIGGER s4_reject_server_tools BEFORE INSERT ON audit_events WHEN NEW.action = 'SERVER_TOOLS_UPDATED' BEGIN SELECT RAISE(ABORT, 'TEST_AUDIT_INSERT_FAILED'); END").Error; err != nil {
		t.Fatal(err)
	}
	w := s4Post(t, env, token, "/admin/server-tools", "tool=get_time")
	if w.Result().StatusCode != http.StatusInternalServerError {
		t.Fatalf("audit failure status=%d body=%s", w.Result().StatusCode, w.Body.String())
	}
	if after, _ := os.ReadFile(env.configPath); !bytes.Equal(after, beforeFile) {
		t.Fatal("audit failure did not restore exact config bytes")
	}
	if !reflect.DeepEqual(env.base.cfg.ServerTools, beforeLive) {
		t.Fatalf("audit failure changed live config: before=%+v after=%+v", beforeLive, env.base.cfg.ServerTools)
	}
	countAfter, headAfter := s4AuditState(t, env.base.db)
	if countAfter != countBefore || headAfter != headBefore {
		t.Fatal("audit failure changed audit state")
	}
	if leftovers, err := filepath.Glob(filepath.Join(filepath.Dir(env.configPath), ".config.yaml.tmp-*")); err != nil || len(leftovers) != 0 {
		t.Fatalf("audit failure left temporary files: %v err=%v", leftovers, err)
	}
}

func TestP108B_S41_StaleRuntimeDoesNotOverwriteProviderSecret(t *testing.T) {
	env := newS4AdminEnv(t)
	diskCfg, err := config.LoadExistingForMigration(env.configPath)
	if err != nil {
		t.Fatal(err)
	}
	diskCfg.Providers["openai"] = config.ProviderConfig{
		Type:            "openai",
		APIKeyEncrypted: "enc:v1:EXTERNAL_PROVIDER_ENVELOPE_CANARY",
		BaseURL:         "https://provider.example.invalid/v1",
	}
	diskBefore, err := config.MarshalYAML(diskCfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(env.configPath, diskBefore, 0600); err != nil {
		t.Fatal(err)
	}

	token := s4Session(t, env)
	w := s4Post(t, env, token, "/admin/server-tools", "tool=get_time")
	if w.Result().StatusCode != http.StatusFound {
		t.Fatalf("server tools status=%d body=%s", w.Result().StatusCode, w.Body.String())
	}
	persisted, err := config.LoadExistingForMigration(env.configPath)
	if err != nil {
		t.Fatal(err)
	}
	provider := persisted.Providers["openai"]
	if provider.APIKeyEncrypted != "enc:v1:EXTERNAL_PROVIDER_ENVELOPE_CANARY" || provider.BaseURL != "https://provider.example.invalid/v1" {
		t.Fatalf("locked disk snapshot did not preserve external provider mutation: %+v", provider)
	}
	if !persisted.ServerTools.Enabled || len(persisted.ServerTools.Tools) != 1 || persisted.ServerTools.Tools[0] != "get_time" {
		t.Fatalf("server-tools mutation was not applied to locked snapshot: %+v", persisted.ServerTools)
	}
	var events []models.AuditEvent
	if err := env.base.db.Order("id ASC").Find(&events).Error; err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || events[0].Action != audit.ActionServerToolsUpdated {
		t.Fatalf("stale runtime update produced unexpected audit history: %+v", events)
	}
}

func TestP108B_S41_RuntimeDatabasePathMismatchFailsClosed(t *testing.T) {
	env := newS4AdminEnv(t)
	diskCfg, err := config.LoadExistingForMigration(env.configPath)
	if err != nil {
		t.Fatal(err)
	}
	diskCfg.Database.Path = filepath.Join(t.TempDir(), "different.db")
	diskBefore, err := config.MarshalYAML(diskCfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(env.configPath, diskBefore, 0600); err != nil {
		t.Fatal(err)
	}
	liveBefore := env.base.cfg.ServerTools
	countBefore, headBefore := s4AuditState(t, env.base.db)

	token := s4Session(t, env)
	w := s4Post(t, env, token, "/admin/server-tools", "tool=get_time")
	if w.Result().StatusCode != http.StatusInternalServerError {
		t.Fatalf("database path mismatch status=%d body=%s", w.Result().StatusCode, w.Body.String())
	}
	diskAfter, err := os.ReadFile(env.configPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(diskAfter, diskBefore) {
		t.Fatal("runtime database path mismatch changed authoritative config")
	}
	if !reflect.DeepEqual(env.base.cfg.ServerTools, liveBefore) {
		t.Fatalf("runtime database path mismatch changed live config: before=%+v after=%+v", liveBefore, env.base.cfg.ServerTools)
	}
	countAfter, headAfter := s4AuditState(t, env.base.db)
	if countAfter != countBefore || headAfter != headBefore {
		t.Fatal("runtime database path mismatch changed audit state")
	}
}
