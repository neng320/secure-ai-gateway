package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"ai-gateway/internal/config"
	"ai-gateway/internal/database"
	"ai-gateway/internal/models"
	"ai-gateway/internal/services"
)

type p106b1PublicGateway struct {
	api      *httptest.Server
	deps     gatewayDeps
	calls    *int32
	lastSeen *testLastSeenPool
}

func newP106b1PublicGateway(t *testing.T) *p106b1PublicGateway {
	t.Helper()
	configPath := filepath.Join(t.TempDir(), "config.yaml")
	cfg, err := config.Load(configPath)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Admin.Username = "admin"
	cfg.Admin.PasswordHash = "__SETUP_REQUIRED__"
	cfg.Admin.SessionSecret = "p106b1-session-secret"
	cfg.Admin.CookieSecure = false

	var calls int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"candidates":[{}],"usageMetadata":{"promptTokenCount":1,"candidatesTokenCount":1}}`))
	}))
	t.Cleanup(upstream.Close)
	cfg.Providers = map[string]config.ProviderConfig{
		"gemini": {Type: "gemini", BaseURL: upstream.URL, APIKey: "p106b1-upstream", TimeoutSeconds: 5},
	}

	db, err := database.Open(filepath.Join(t.TempDir(), "p106b1-public.db"))
	if err != nil {
		t.Fatal(err)
	}
	if err := db.AutoMigrate(&models.Client{}, &models.RequestLog{}, &models.DailyUsage{}, &models.AdminSession{}); err != nil {
		t.Fatal(err)
	}
	migrateTestAudit(t, db)
	lastSeen := attachTestLastSeenPool(db)
	t.Cleanup(func() {
		if err := closeTestLastSeenDB(db, lastSeen); err != nil {
			t.Errorf("close p106b1 test database: %v", err)
		}
	})

	deps := newGatewayDeps(cfg, cfg, db, false, nil, nil)
	api := httptest.NewServer(buildAPIRouter(deps))
	t.Cleanup(api.Close)
	return &p106b1PublicGateway{api: api, deps: deps, calls: &calls, lastSeen: lastSeen}
}

func (e *p106b1PublicGateway) doPublicRequest(t *testing.T, request *http.Request) (*http.Response, error) {
	t.Helper()
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		return nil, err
	}
	if response.StatusCode != http.StatusUnauthorized {
		e.lastSeen.waitForCompletion(t)
	}
	return response, nil
}

func TestP106B1_PublicGenerativeRoutesBlockExhaustedRequestQuota(t *testing.T) {
	cases := []struct {
		name string
		path string
		body string
	}{
		{name: "openai", path: "/v1/chat/completions", body: `{"model":"gemini","messages":[{"role":"user","content":"x"}]}`},
		{name: "anthropic-compatible", path: "/v1/messages", body: `{"model":"gemini","messages":[{"role":"user","content":"x"}]}`},
		{name: "gemini", path: "/v1/models/gemini:generateContent", body: `{"contents":[{"parts":[{"text":"x"}]}]}`},
		{name: "gemini-stream", path: "/v1/models/gemini:streamGenerateContent", body: `{"contents":[{"parts":[{"text":"x"}]}]}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := newP106b1PublicGateway(t)
			client, apiKey, err := env.deps.clientService.CreateClient("p106b1-"+tc.name, "", "gemini", "sk-", env.deps.cfg, "test-admin")
			if err != nil {
				t.Fatal(err)
			}
			if err := env.deps.db.Model(&models.Client{}).Where("id = ?", client.ID).Update("quota_requests_day", 1).Error; err != nil {
				t.Fatal(err)
			}
			usage := &models.DailyUsage{ClientID: client.ID, Date: services.UsageDate(time.Now()), TotalRequests: 1}
			if err := env.deps.db.Create(usage).Error; err != nil {
				t.Fatal(err)
			}

			request, err := http.NewRequest(http.MethodPost, env.api.URL+tc.path, strings.NewReader(tc.body))
			if err != nil {
				t.Fatal(err)
			}
			request.Header.Set("Authorization", "Bearer "+apiKey)
			request.Header.Set("Content-Type", "application/json")
			response, err := env.doPublicRequest(t, request)
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			var payload struct {
				Error struct {
					Code string `json:"code"`
				} `json:"error"`
			}
			if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
				t.Fatal(err)
			}
			if response.StatusCode != http.StatusTooManyRequests || payload.Error.Code != "QUOTA_REQUESTS_EXCEEDED" {
				t.Fatalf("%s should be blocked before handler/upstream: status=%d code=%q", tc.path, response.StatusCode, payload.Error.Code)
			}
			if got := atomic.LoadInt32(env.calls); got != 0 {
				t.Fatalf("%s bypassed quota and called upstream %d time(s)", tc.path, got)
			}
		})
	}
}
