package handlers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"ai-gateway/internal/audit"
	"ai-gateway/internal/auth"
	"ai-gateway/internal/models"
)

func recordS6ViewerEvent(t *testing.T, env *authEnv, event models.AuditEvent) {
	t.Helper()
	if err := audit.NewService(env.db).Record(event); err != nil {
		t.Fatal(err)
	}
}

func s6ViewerGet(t *testing.T, env *authEnv, target, rawToken string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, target, nil)
	if rawToken != "" {
		req.AddCookie(&http.Cookie{Name: auth.SessionCookieName, Value: rawToken})
	}
	w := httptest.NewRecorder()
	env.router.ServeHTTP(w, req)
	return w
}

func s6ViewerLogin(t *testing.T, env *authEnv) string {
	t.Helper()
	resp := login(t, env.router, testAdminUser, testAdminPassword)
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("login status=%d", resp.StatusCode)
	}
	cookie := getSessionCookie(resp)
	if cookie == nil || cookie.Value == "" {
		t.Fatal("login did not return session cookie")
	}
	return cookie.Value
}

func s6ViewerState(t *testing.T, env *authEnv) (int64, string) {
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

func TestP108B_S6_ViewerAuthenticated(t *testing.T) {
	env := newAuthEnv(t)
	token := s6ViewerLogin(t, env)
	recordS6ViewerEvent(t, env, models.AuditEvent{
		Action: audit.ActionClientCreated, ActorType: "admin", ActorID: "viewer-admin",
		TargetType: "client", TargetID: "viewer-client", Reason: "viewer event",
	})

	w := s6ViewerGet(t, env, "/admin/audit?limit=1", token)
	if w.Code != http.StatusOK {
		t.Fatalf("viewer status=%d body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), audit.ActionClientCreated) || !strings.Contains(w.Body.String(), "viewer event") {
		t.Fatalf("viewer did not render audit metadata: %s", w.Body.String())
	}
}

func TestP108B_S6_ViewerUnauthenticated(t *testing.T) {
	env := newAuthEnv(t)
	recordS6ViewerEvent(t, env, models.AuditEvent{
		Action: audit.ActionClientCreated, ActorType: "admin", ActorID: "private-admin",
		TargetType: "client", TargetID: "private-client", Reason: "private reason",
	})
	w := s6ViewerGet(t, env, "/admin/audit", "")
	if w.Code != http.StatusFound || w.Header().Get("Location") != "/admin/login" {
		t.Fatalf("unauthenticated viewer response=%d location=%q", w.Code, w.Header().Get("Location"))
	}
	if w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("Pragma") != "no-cache" {
		t.Fatalf("unauthenticated viewer response is cacheable: cache-control=%q pragma=%q", w.Header().Get("Cache-Control"), w.Header().Get("Pragma"))
	}
	if strings.Contains(w.Body.String(), "private reason") || strings.Contains(w.Body.String(), audit.ActionClientCreated) {
		t.Fatal("unauthenticated response disclosed audit metadata")
	}
}

func TestP108B_S6_ViewerNoStore(t *testing.T) {
	env := newAuthEnv(t)
	token := s6ViewerLogin(t, env)
	for _, target := range []string{"/admin/audit", "/admin/audit?limit=abc"} {
		w := s6ViewerGet(t, env, target, token)
		if got := w.Header().Get("Cache-Control"); got != "no-store" {
			t.Errorf("%s Cache-Control=%q", target, got)
		}
		if got := w.Header().Get("Pragma"); got != "no-cache" {
			t.Errorf("%s Pragma=%q", target, got)
		}
	}
}

func TestP108B_S6_ViewerHTMLEscapesReason(t *testing.T) {
	env := newAuthEnv(t)
	token := s6ViewerLogin(t, env)
	recordS6ViewerEvent(t, env, models.AuditEvent{
		Action: audit.ActionClientCreated, ActorType: "admin", ActorID: "escape-admin",
		TargetType: "client", TargetID: "escape-client", Reason: "<script>alert(1)</script>",
	})
	w := s6ViewerGet(t, env, "/admin/audit?limit=1", token)
	if w.Code != http.StatusOK {
		t.Fatalf("viewer status=%d", w.Code)
	}
	if strings.Contains(w.Body.String(), "<script>alert(1)</script>") || !strings.Contains(w.Body.String(), "&lt;script&gt;alert(1)&lt;/script&gt;") {
		t.Fatalf("viewer did not HTML-escape reason: %s", w.Body.String())
	}
}

func TestP108B_S6_ViewerPrivacyCanary(t *testing.T) {
	env := newAuthEnv(t)
	token := s6ViewerLogin(t, env)
	canaries := []string{
		"P108B-S6-PROVIDER-SECRET-CANARY",
		"P108B-S6-CLIENT-SECRET-CANARY",
		"P108B-S6-CAPTURE-BODY-CANARY",
		"P108B-S6-SESSION-TOKEN-CANARY",
		"P108B-S6-CONFIG-CANARY",
	}
	if err := env.db.Create(&models.Client{ID: "privacy-client", Name: canaries[1], CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC()}).Error; err != nil {
		t.Fatal(err)
	}
	if err := env.db.Create(&models.AdminSession{Username: canaries[3], TokenHash: []byte(canaries[3]), CreatedAt: time.Now().UTC(), ExpiresAt: time.Now().UTC().Add(time.Hour)}).Error; err != nil {
		t.Fatal(err)
	}
	w := s6ViewerGet(t, env, "/admin/audit", token)
	if w.Code != http.StatusOK {
		t.Fatalf("viewer status=%d", w.Code)
	}
	for _, canary := range canaries {
		if strings.Contains(w.Body.String(), canary) {
			t.Fatalf("viewer disclosed canary %q", canary)
		}
	}
}

func TestP108B_S6_ViewerDoesNotMutateAudit(t *testing.T) {
	env := newAuthEnv(t)
	token := s6ViewerLogin(t, env)
	recordS6ViewerEvent(t, env, models.AuditEvent{
		Action: audit.ActionClientCreated, ActorType: "admin", ActorID: "stable-admin",
		TargetType: "client", TargetID: "stable-client",
	})
	countBefore, headBefore := s6ViewerState(t, env)
	for _, target := range []string{"/admin/audit", "/admin/audit?limit=0", "/admin/audit?actor_id=bad%0Aactor"} {
		_ = s6ViewerGet(t, env, target, token)
	}
	countAfter, headAfter := s6ViewerState(t, env)
	if countAfter != countBefore || headAfter != headBefore {
		t.Fatalf("viewer mutated audit state: before=(%d,%q) after=(%d,%q)", countBefore, headBefore, countAfter, headAfter)
	}
}

func TestP108B_S6_InvalidFiltersRejected(t *testing.T) {
	env := newAuthEnv(t)
	token := s6ViewerLogin(t, env)
	for _, target := range []string{
		"/admin/audit?limit=0", "/admin/audit?limit=-1", "/admin/audit?limit=101", "/admin/audit?limit=abc",
		"/admin/audit?before_id=abc", "/admin/audit?action=UNKNOWN", "/admin/audit?actor_type=operator",
		"/admin/audit?target_type=unknown", "/admin/audit?actor_id=bad%0Aactor", "/admin/audit?target_id=bad%09target",
	} {
		w := s6ViewerGet(t, env, target, token)
		if w.Code != http.StatusBadRequest {
			t.Errorf("%s status=%d body=%s", target, w.Code, w.Body.String())
		}
	}
}
