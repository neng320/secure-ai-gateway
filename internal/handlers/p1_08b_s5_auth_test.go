package handlers

import (
	"bytes"
	"context"
	"errors"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"ai-gateway/internal/audit"
	"ai-gateway/internal/auth"
	"ai-gateway/internal/models"
)

func s5AuditEvents(t *testing.T, env *authEnv) []models.AuditEvent {
	t.Helper()
	var events []models.AuditEvent
	if err := env.db.Order("id ASC").Find(&events).Error; err != nil {
		t.Fatal(err)
	}
	return events
}

func s5AuditState(t *testing.T, env *authEnv) (int64, string) {
	t.Helper()
	var count int64
	if err := env.db.Model(&models.AuditEvent{}).Count(&count).Error; err != nil {
		t.Fatal(err)
	}
	var state models.AuditChainState
	if err := env.db.First(&state, 1).Error; err != nil {
		t.Fatal(err)
	}
	return count, state.HeadHash
}

func s5SessionCount(t *testing.T, env *authEnv) int64 {
	t.Helper()
	var count int64
	if err := env.db.Model(&models.AdminSession{}).Count(&count).Error; err != nil {
		t.Fatal(err)
	}
	return count
}

func s5AssertNoCanaryInSQLiteFiles(t *testing.T, dbPath string, canaries ...string) {
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

func s5Logout(t *testing.T, env *authEnv, rawToken string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/admin/logout", nil)
	req.AddCookie(&http.Cookie{Name: auth.SessionCookieName, Value: rawToken})
	req.Header.Set("X-CSRF-Token", csrfFor(env, rawToken))
	w := httptest.NewRecorder()
	env.router.ServeHTTP(w, req)
	return w
}

func TestP108B_S5_LoginSuccessAuditedAtomically(t *testing.T) {
	env := newAuthEnv(t)
	var logOutput bytes.Buffer
	previousLogWriter := log.Writer()
	log.SetOutput(&logOutput)
	t.Cleanup(func() { log.SetOutput(previousLogWriter) })
	resp := login(t, env.router, testAdminUser, testAdminPassword)
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("login status=%d", resp.StatusCode)
	}
	cookie := getSessionCookie(resp)
	if cookie == nil || cookie.Value == "" {
		t.Fatal("successful audited login did not issue a session cookie")
	}
	if _, err := env.store.Validate(context.Background(), cookie.Value); err != nil {
		t.Fatalf("committed session is not valid: %v", err)
	}
	events := s5AuditEvents(t, env)
	if len(events) != 1 || events[0].Action != audit.ActionAdminLoginSucceeded || events[0].ActorType != "admin" || events[0].ActorID != testAdminUser || events[0].TargetType != "admin" || events[0].TargetID != "admin" || events[0].Reason != "" {
		t.Fatalf("unexpected login audit event: %+v", events)
	}
	if strings.Contains(events[0].ActorID+events[0].TargetID+events[0].Reason, cookie.Value) {
		t.Fatal("raw session token reached audit metadata")
	}
	if strings.Contains(logOutput.String(), cookie.Value) {
		t.Fatal("raw session token reached runtime logs")
	}
	if sqlDB, err := env.db.DB(); err == nil {
		_ = sqlDB.Close()
	}
	s5AssertNoCanaryInSQLiteFiles(t, env.dbPath, cookie.Value)
}

func TestP108B_S5_LoginAuditFailureCreatesNoSession(t *testing.T) {
	env := newAuthEnv(t)
	sessionsBefore := s5SessionCount(t, env)
	countBefore, headBefore := s5AuditState(t, env)
	if err := env.db.Exec("CREATE TRIGGER s5_reject_login BEFORE INSERT ON audit_events WHEN NEW.action = 'ADMIN_LOGIN_SUCCEEDED' BEGIN SELECT RAISE(ABORT, 'TEST_LOGIN_AUDIT_FAILED'); END").Error; err != nil {
		t.Fatal(err)
	}
	resp := login(t, env.router, testAdminUser, testAdminPassword)
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("audit failure login status=%d", resp.StatusCode)
	}
	if getSessionCookie(resp) != nil {
		t.Fatal("audit failure issued a session cookie")
	}
	if got := s5SessionCount(t, env); got != sessionsBefore {
		t.Fatalf("audit failure changed session count: before=%d after=%d", sessionsBefore, got)
	}
	countAfter, headAfter := s5AuditState(t, env)
	if countAfter != countBefore || headAfter != headBefore {
		t.Fatalf("audit failure changed audit state: before=(%d,%q) after=(%d,%q)", countBefore, headBefore, countAfter, headAfter)
	}
}

func TestP108B_S5_LoginFailureNotPersisted(t *testing.T) {
	env := newAuthEnv(t)
	resp := login(t, env.router, testAdminUser, "wrong-password")
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("wrong login status=%d", resp.StatusCode)
	}
	if got := s5SessionCount(t, env); got != 0 {
		t.Fatalf("failed login created %d session(s)", got)
	}
	if events := s5AuditEvents(t, env); len(events) != 0 {
		t.Fatalf("failed login was persisted into audit chain: %+v", events)
	}
}

func TestP108B_S5_LoginActorTrusted(t *testing.T) {
	env := newAuthEnv(t)
	pre := httptest.NewRequest(http.MethodGet, "/admin/login", nil)
	preW := httptest.NewRecorder()
	env.router.ServeHTTP(preW, pre)
	token := extractPreAuthCSRF(t, readBody(preW.Result()))
	csrfCookie := findCookie(preW.Result(), auth.PreAuthCSRFCookie)
	if csrfCookie == nil {
		t.Fatal("missing pre-auth csrf cookie")
	}
	form := url.Values{"username": {testAdminUser}, "password": {testAdminPassword}, "actor": {"evil-form"}, "actor_id": {"evil-form-id"}, "csrf_token": {token}}
	req := httptest.NewRequest(http.MethodPost, "/admin/login?actor=evil-query", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-Actor", "evil-header")
	req.AddCookie(csrfCookie)
	w := httptest.NewRecorder()
	env.router.ServeHTTP(w, req)
	if w.Result().StatusCode != http.StatusFound {
		t.Fatalf("trusted login status=%d", w.Result().StatusCode)
	}
	events := s5AuditEvents(t, env)
	if len(events) != 1 || events[0].ActorID != testAdminUser || events[0].ActorType != "admin" {
		t.Fatalf("untrusted login actor reached audit event: %+v", events)
	}
}

func TestP108B_S5_LogoutAuditedAtomically(t *testing.T) {
	env := newAuthEnv(t)
	loginResp := login(t, env.router, testAdminUser, testAdminPassword)
	cookie := getSessionCookie(loginResp)
	if cookie == nil {
		t.Fatal("login did not issue session")
	}
	resp := s5Logout(t, env, cookie.Value)
	if resp.Result().StatusCode != http.StatusFound {
		t.Fatalf("logout status=%d", resp.Result().StatusCode)
	}
	clear := getSessionCookie(resp.Result())
	if clear == nil || clear.Value != "" {
		t.Fatalf("logout did not clear cookie: %+v", clear)
	}
	if _, err := env.store.Validate(context.Background(), cookie.Value); !errors.Is(err, auth.ErrSessionRevoked) {
		t.Fatalf("logout did not revoke session: %v", err)
	}
	events := s5AuditEvents(t, env)
	if len(events) != 2 || events[1].Action != audit.ActionAdminLogout || events[1].ActorType != "admin" || events[1].ActorID != testAdminUser || events[1].TargetType != "admin" || events[1].TargetID != "admin" || events[1].Reason != "" {
		t.Fatalf("unexpected logout audit event: %+v", events)
	}
}

func TestP108B_S5_LogoutAuditFailureKeepsSessionActive(t *testing.T) {
	env := newAuthEnv(t)
	loginResp := login(t, env.router, testAdminUser, testAdminPassword)
	cookie := getSessionCookie(loginResp)
	if cookie == nil {
		t.Fatal("login did not issue session")
	}
	countBefore, headBefore := s5AuditState(t, env)
	if err := env.db.Exec("CREATE TRIGGER s5_reject_logout BEFORE INSERT ON audit_events WHEN NEW.action = 'ADMIN_LOGOUT' BEGIN SELECT RAISE(ABORT, 'TEST_LOGOUT_AUDIT_FAILED'); END").Error; err != nil {
		t.Fatal(err)
	}
	resp := s5Logout(t, env, cookie.Value)
	if resp.Result().StatusCode != http.StatusInternalServerError {
		t.Fatalf("audit failure logout status=%d", resp.Result().StatusCode)
	}
	if getSessionCookie(resp.Result()) != nil {
		t.Fatal("audit failure cleared the session cookie")
	}
	if _, err := env.store.Validate(context.Background(), cookie.Value); err != nil {
		t.Fatalf("audit failure revoked active session: %v", err)
	}
	countAfter, headAfter := s5AuditState(t, env)
	if countAfter != countBefore || headAfter != headBefore {
		t.Fatalf("audit failure changed audit state: before=(%d,%q) after=(%d,%q)", countBefore, headBefore, countAfter, headAfter)
	}
	if err := env.db.Exec("DROP TRIGGER s5_reject_logout").Error; err != nil {
		t.Fatal(err)
	}
	if resp = s5Logout(t, env, cookie.Value); resp.Result().StatusCode != http.StatusFound {
		t.Fatalf("logout after removing trigger status=%d", resp.Result().StatusCode)
	}
	if events := s5AuditEvents(t, env); len(events) != 2 || events[1].Action != audit.ActionAdminLogout {
		t.Fatalf("successful retry should append one logout event: %+v", events)
	}
}

func TestP108B_S5_UnknownLogoutNoAudit(t *testing.T) {
	env := newAuthEnv(t)
	countBefore, headBefore := s5AuditState(t, env)
	revokedToken, err := env.store.Create(context.Background(), "admin", time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if err := env.store.Revoke(context.Background(), revokedToken); err != nil {
		t.Fatal(err)
	}
	expiredToken, err := env.store.Create(context.Background(), "admin", time.Now().Add(-time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	for _, token := range []string{strings.Repeat("ff", 32), revokedToken, expiredToken} {
		resp := s5Logout(t, env, token)
		if resp.Result().StatusCode != http.StatusFound {
			t.Fatalf("unknown logout status=%d", resp.Result().StatusCode)
		}
	}
	countAfter, headAfter := s5AuditState(t, env)
	if countAfter != countBefore || headAfter != headBefore {
		t.Fatalf("unknown logout changed audit state")
	}
}

func TestP108B_S5_LogoutActorFromSession(t *testing.T) {
	env := newAuthEnv(t)
	rawToken, err := env.store.Create(context.Background(), "session-owner", time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	resp := s5Logout(t, env, rawToken)
	if resp.Result().StatusCode != http.StatusFound {
		t.Fatalf("logout status=%d", resp.Result().StatusCode)
	}
	events := s5AuditEvents(t, env)
	if len(events) != 1 || events[0].Action != audit.ActionAdminLogout || events[0].ActorID != "session-owner" {
		t.Fatalf("logout actor did not come from authoritative session: %+v", events)
	}
}
