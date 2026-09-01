package handlers

import (
	"context"
	"math"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"ai-gateway/internal/audit"
	"ai-gateway/internal/auth"
	"ai-gateway/internal/capture"
	"ai-gateway/internal/config"
	"ai-gateway/internal/models"
)

func TestP108B_S61_BeforeIDHTTPValidation(t *testing.T) {
	env := newAuthEnv(t)
	token := s6ViewerLogin(t, env)
	const privateReason = "S61_PRIVATE_CURSOR_EVENT"
	recordS6ViewerEvent(t, env, models.AuditEvent{
		Action: audit.ActionClientCreated, ActorType: "admin", ActorID: "cursor-admin",
		TargetType: "client", TargetID: "cursor-client", Reason: privateReason,
	})

	valid := []string{"1", strconv.FormatInt(math.MaxInt64, 10)}
	for _, raw := range valid {
		w := s6ViewerGet(t, env, "/admin/audit?before_id="+url.QueryEscape(raw), token)
		if w.Code != http.StatusOK {
			t.Errorf("before_id=%q status=%d body=%s", raw, w.Code, w.Body.String())
		}
	}
	invalid := []string{
		"", "0", "-1", "abc",
		strconv.FormatUint(uint64(math.MaxInt64)+1, 10),
		strconv.FormatUint(^uint64(0), 10),
	}
	countBefore, headBefore := s6ViewerState(t, env)
	duplicate := s6ViewerGet(t, env, "/admin/audit?before_id=1&before_id=2", token)
	if duplicate.Code != http.StatusBadRequest || !strings.Contains(duplicate.Body.String(), "Invalid audit query") {
		t.Fatalf("duplicate before_id status=%d body=%s", duplicate.Code, duplicate.Body.String())
	}
	for _, raw := range invalid {
		target := "/admin/audit?before_id=" + url.QueryEscape(raw)
		if raw == "" {
			target = "/admin/audit?before_id="
		}
		w := s6ViewerGet(t, env, target, token)
		if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "Invalid audit query") {
			t.Errorf("before_id=%q status=%d body=%s", raw, w.Code, w.Body.String())
		}
		if w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("Pragma") != "no-cache" {
			t.Errorf("before_id=%q error response is cacheable", raw)
		}
		if strings.Contains(w.Body.String(), privateReason) || strings.Contains(w.Body.String(), audit.ActionClientCreated) {
			t.Errorf("before_id=%q disclosed audit metadata", raw)
		}
	}
	countAfter, headAfter := s6ViewerState(t, env)
	if countAfter != countBefore || headAfter != headBefore {
		t.Fatalf("invalid cursor changed audit state: before=(%d,%q) after=(%d,%q)", countBefore, headBefore, countAfter, headAfter)
	}
}

func TestP108B_S61_IDFilterHTTPBoundaries(t *testing.T) {
	env := newAuthEnv(t)
	token := s6ViewerLogin(t, env)
	for name, values := range map[string]url.Values{
		"actor 255": {"actor_id": {strings.Repeat("界", 255)}},
		"target 36": {"target_id": {strings.Repeat("界", 36)}},
	} {
		w := s6ViewerGet(t, env, "/admin/audit?"+values.Encode(), token)
		if w.Code != http.StatusOK {
			t.Errorf("%s status=%d body=%s", name, w.Code, w.Body.String())
		}
	}
	for name, values := range map[string]url.Values{
		"actor 256": {"actor_id": {strings.Repeat("界", 256)}},
		"target 37": {"target_id": {strings.Repeat("界", 37)}},
	} {
		w := s6ViewerGet(t, env, "/admin/audit?"+values.Encode(), token)
		if w.Code != http.StatusBadRequest {
			t.Errorf("%s status=%d body=%s", name, w.Code, w.Body.String())
		}
	}
}

func TestP108B_S61_ViewerAuthRejectionMatrix(t *testing.T) {
	env := newAuthEnv(t)
	activeToken := s6ViewerLogin(t, env)
	const privateReason = "S61_AUTH_PRIVATE_EVENT"
	recordS6ViewerEvent(t, env, models.AuditEvent{
		Action: audit.ActionClientCreated, ActorType: "admin", ActorID: "auth-admin",
		TargetType: "client", TargetID: "auth-client", Reason: privateReason,
	})
	revokedToken, err := env.store.Create(context.Background(), testAdminUser, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if err := env.store.Revoke(context.Background(), revokedToken); err != nil {
		t.Fatal(err)
	}
	expiredToken, err := env.store.Create(context.Background(), testAdminUser, time.Now().Add(-time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name  string
		token string
	}{
		{name: "missing", token: ""},
		{name: "forged", token: strings.Repeat("ff", auth.TokenBytes)},
		{name: "revoked", token: revokedToken},
		{name: "expired", token: expiredToken},
	}
	countBefore, headBefore := s6ViewerState(t, env)
	for _, tc := range cases {
		w := s6ViewerGet(t, env, "/admin/audit", tc.token)
		if w.Code != http.StatusFound || w.Header().Get("Location") != "/admin/login" {
			t.Errorf("%s status=%d location=%q", tc.name, w.Code, w.Header().Get("Location"))
		}
		if w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("Pragma") != "no-cache" {
			t.Errorf("%s rejection is cacheable", tc.name)
		}
		if strings.Contains(w.Body.String(), privateReason) || strings.Contains(w.Body.String(), audit.ActionClientCreated) {
			t.Errorf("%s rejection disclosed audit metadata", tc.name)
		}
		countAfter, headAfter := s6ViewerState(t, env)
		if countAfter != countBefore || headAfter != headBefore {
			t.Errorf("%s rejection changed audit state: before=(%d,%q) after=(%d,%q)", tc.name, countBefore, headBefore, countAfter, headAfter)
		}
	}
	if active := s6ViewerGet(t, env, "/admin/audit", activeToken); active.Code != http.StatusOK {
		t.Fatalf("active session status=%d", active.Code)
	}
}

func TestP108B_S61_PrivacyCanariesActuallySeeded(t *testing.T) {
	canaries := []string{
		"P108B-S6-PROVIDER-SECRET-CANARY",
		"P108B-S6-CLIENT-SECRET-CANARY",
		"P108B-S6-CAPTURE-BODY-CANARY",
		"P108B-S6-SESSION-TOKEN-CANARY",
		"P108B-S6-CONFIG-CANARY",
	}
	env := newP104EnvWithStore(t, nil, capture.NewStore(true, time.Now().Add(time.Hour), 4096, 10))
	env.cfg.Providers["openai"] = config.ProviderConfig{Type: "openai", APIKey: canaries[0]}
	env.cfg.Logging.Level = canaries[4]
	env.capture.Capture("s61-capture-canary", []byte(canaries[2]))
	if entry, ok := env.capture.Get("s61-capture-canary"); !ok || string(entry.Body) != canaries[2] {
		t.Fatal("capture canary was not seeded in memory capture store")
	}
	if err := env.db.Create(&models.Client{ID: "s61-client-canary", Name: canaries[1], BackendAPIKey: canaries[1], CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC()}).Error; err != nil {
		t.Fatal(err)
	}
	if err := env.db.Create(&models.AdminSession{Username: canaries[3], TokenHash: auth.HashToken(canaries[3]), CreatedAt: time.Now().UTC(), ExpiresAt: time.Now().UTC().Add(time.Hour)}).Error; err != nil {
		t.Fatal(err)
	}
	token := p104AdminSession(t, env)
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/admin/audit", nil)
	req.AddCookie(&http.Cookie{Name: auth.SessionCookieName, Value: token})
	env.admin.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("viewer status=%d body=%s", w.Code, w.Body.String())
	}
	for _, canary := range canaries {
		if strings.Contains(w.Body.String(), canary) {
			t.Fatalf("viewer disclosed canary %q", canary)
		}
	}
}
