package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"ai-gateway/internal/audit"
	"ai-gateway/internal/auth"
	"ai-gateway/internal/models"
)

func trustedS3Session(t *testing.T, env *p105Env) string {
	t.Helper()
	token, err := auth.NewSQLiteStore(env.db).Create(context.Background(), "trusted-session-admin", time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	return token
}

func trustedS3AdminPost(t *testing.T, env *p105Env, token, target string, form string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, target, strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-Actor", "evil-header-admin")
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: token})
	req.Header.Set("X-CSRF-Token", auth.CSRFToken(env.cfg.Admin.SessionSecret, token))
	w := httptest.NewRecorder()
	env.admin.ServeHTTP(w, req)
	return w
}

func TestP108B_S3_HTTPUsesValidatedSessionActor(t *testing.T) {
	env := newP105Env(t)
	client, _ := env.createTestClient(t, "s3-trusted-actor")
	token := trustedS3Session(t, env)
	w := trustedS3AdminPost(t, env, token, "/admin/clients?actor=evil-query-admin", "name=s3-http-created&backend=openai&actor=evil-form-admin")
	if w.Result().StatusCode != http.StatusOK {
		t.Fatalf("create status=%d body=%s", w.Result().StatusCode, w.Body.String())
	}
	var created models.Client
	if err := env.db.Where("name = ?", "s3-http-created").First(&created).Error; err != nil {
		t.Fatal(err)
	}
	w = trustedS3AdminPost(t, env, token, "/admin/clients/"+client.ID+"/update?actor=evil-query-admin", "name=trusted-update&actor=evil-form-admin&revoked_by=evil-revoked-by")
	if w.Result().StatusCode != http.StatusFound {
		t.Fatalf("settings update status=%d body=%s", w.Result().StatusCode, w.Body.String())
	}
	w = trustedS3AdminPost(t, env, token, "/admin/clients/"+client.ID+"/update-models?actor=evil-query-admin", "models=model-a&models=model-b&actor=evil-form-admin")
	if w.Result().StatusCode != http.StatusFound {
		t.Fatalf("models update status=%d body=%s", w.Result().StatusCode, w.Body.String())
	}
	form := "active=false&reason=trusted-suspend&actor=evil-form-admin"
	w = trustedS3AdminPost(t, env, token, "/admin/clients/"+client.ID+"/toggle?actor=evil-query-admin", form)
	if w.Result().StatusCode != http.StatusFound {
		t.Fatalf("suspend status=%d body=%s", w.Result().StatusCode, w.Body.String())
	}
	w = trustedS3AdminPost(t, env, token, "/admin/clients/"+client.ID+"/revoke?actor=evil-query-admin", "confirm_revoke=REVOKE&reason=trusted-revoke&actor=evil-form-admin")
	if w.Result().StatusCode != http.StatusFound {
		t.Fatalf("revoke status=%d body=%s", w.Result().StatusCode, w.Body.String())
	}
	var events []models.AuditEvent
	if err := env.db.Where("target_id = ?", client.ID).Order("id ASC").Find(&events).Error; err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, event := range events {
		if event.Action == audit.ActionClientCreated && event.TargetID != created.ID {
			continue
		}
		seen[event.Action] = true
		if event.Action == audit.ActionClientCreated || event.Action == audit.ActionClientSettingsUpdated || event.Action == audit.ActionClientModelsUpdated || event.Action == audit.ActionClientSuspended || event.Action == audit.ActionClientRevoked {
			if event.ActorType != "admin" || event.ActorID != "trusted-session-admin" {
				t.Fatalf("event %s used wrong actor: %+v", event.Action, event)
			}
		}
		if strings.Contains(event.ActorID+event.Reason+event.TargetID, "evil-") {
			t.Fatalf("attacker actor material persisted in audit event: %+v", event)
		}
	}
	for _, action := range []string{audit.ActionClientSettingsUpdated, audit.ActionClientModelsUpdated, audit.ActionClientSuspended, audit.ActionClientRevoked} {
		if !seen[action] {
			t.Fatalf("missing audited action %s", action)
		}
	}
	var createdEvent models.AuditEvent
	if err := env.db.Where("target_id = ? AND action = ?", created.ID, audit.ActionClientCreated).First(&createdEvent).Error; err != nil {
		t.Fatal(err)
	}
	if createdEvent.ActorID != "trusted-session-admin" {
		t.Fatalf("CLIENT_CREATED used wrong actor: %+v", createdEvent)
	}
}

func TestP108B_S3_FetchClientModelsGETIsReadOnly(t *testing.T) {
	env := newFallbackEnv(t)
	client := env.createFallbackClient(t, "", "")
	before, err := env.clientSvc.GetClientByID(client.ID)
	if err != nil || before == nil {
		t.Fatal("client missing before fetch")
	}
	resp := env.adminGet(t, "/admin/clients/"+client.ID+"/fetch-models")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("fetch models status=%d body=%s", resp.StatusCode, readBody(resp))
	}
	after, err := env.clientSvc.GetClientByID(client.ID)
	if err != nil || after == nil {
		t.Fatal("client missing after fetch")
	}
	if after.BackendModels != before.BackendModels {
		t.Fatalf("GET fetch-models persisted backend_models: before=%q after=%q", before.BackendModels, after.BackendModels)
	}
	var count int64
	if err := env.db.Model(&models.AuditEvent{}).Where("target_id = ? AND action = ?", client.ID, audit.ActionClientModelsUpdated).Count(&count).Error; err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("read-only GET appended %d CLIENT_MODELS_UPDATED event(s)", count)
	}
}

func TestP108B_S3_ProviderEncryptionFailureDoesNotMutate(t *testing.T) {
	env := newP105Env(t)
	client, _ := env.createTestClient(t, "s3-encryption-failure")
	before, err := env.clientSvc.GetClientByID(client.ID)
	if err != nil || before == nil {
		t.Fatal("client missing before encryption failure")
	}
	countBefore := env.countAll(t, "audit_events")
	token := trustedS3Session(t, env)
	w := trustedS3AdminPost(t, env, token, "/admin/clients/"+client.ID+"/update", "name=must-not-commit&backend_api_key=P108B-S3-PROVIDER-SECRET-CANARY")
	if w.Result().StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("provider encryption failure status=%d body=%s", w.Result().StatusCode, w.Body.String())
	}
	after, err := env.clientSvc.GetClientByID(client.ID)
	if err != nil || after == nil {
		t.Fatal("client missing after encryption failure")
	}
	if before.Name != after.Name || before.BackendAPIKeyEncrypted != after.BackendAPIKeyEncrypted || env.countAll(t, "audit_events") != countBefore {
		t.Fatalf("provider encryption failure leaked mutation: before=%+v after=%+v", before, after)
	}
}
