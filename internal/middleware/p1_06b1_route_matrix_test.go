package middleware

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"ai-gateway/internal/models"
	"ai-gateway/internal/services"
)

func TestP106B1_GenerativeQuotaRouteMatrix(t *testing.T) {
	cases := []struct {
		method string
		path   string
		want   bool
	}{
		{http.MethodPost, "/v1/chat/completions", true},
		{http.MethodPost, "/chat/completions", true},
		{http.MethodPost, "/v1/messages", true},
		{http.MethodPost, "/v1/messages/count_tokens", false},
		{http.MethodPost, "/v1/models/gemini:generateContent", true},
		{http.MethodPost, "/v1beta/models/gemini:generateContent", true},
		{http.MethodPost, "/v1/models/gemini:streamGenerateContent", true},
		{http.MethodPost, "/v1beta/models/gemini:streamGenerateContent", true},
		{http.MethodGet, "/v1/models", false},
		{http.MethodGet, "/v1/models/gemini", false},
		{http.MethodGet, "/v1beta/models/gemini", false},
	}
	for _, tc := range cases {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, tc.path, nil)
			if got := IsQuotaRequest(req); got != tc.want {
				t.Fatalf("IsQuotaRequest(%s %s)=%v, want %v", tc.method, tc.path, got, tc.want)
			}
		})
	}
}

func TestP106B1_ExhaustedQuotaBlocksEveryGenerativeRoute(t *testing.T) {
	routes := []string{
		"/v1/chat/completions",
		"/chat/completions",
		"/v1/messages",
		"/v1/models/gemini:generateContent",
		"/v1beta/models/gemini:generateContent",
		"/v1/models/gemini:streamGenerateContent",
		"/v1beta/models/gemini:streamGenerateContent",
	}
	for _, path := range routes {
		t.Run(path, func(t *testing.T) {
			env := newP106bQuotaEnv(t, 1, 100, 100, 10, 10)
			reservation, err := env.ledger.Reserve(env.client)
			if err != nil {
				t.Fatal(err)
			}
			if err := reservation.Finalize(1, 1); err != nil {
				t.Fatal(err)
			}

			calls := 0
			h := NewQuotaMiddleware(env.db)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				calls++
				w.WriteHeader(http.StatusOK)
			}))
			body := `{"model":"gemini","messages":[{"role":"user","content":"x"}]}`
			req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
			req = req.WithContext(context.WithValue(req.Context(), ClientContextKey, env.client))
			w := httptest.NewRecorder()
			h.ServeHTTP(w, req)

			if w.Code != http.StatusTooManyRequests || calls != 0 {
				t.Fatalf("exhausted quota on %s must stop before downstream: status=%d calls=%d body=%s", path, w.Code, calls, w.Body.String())
			}
			var response struct {
				Error struct {
					Code string `json:"code"`
				} `json:"error"`
			}
			if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
				t.Fatal(err)
			}
			if response.Error.Code != "QUOTA_REQUESTS_EXCEEDED" {
				t.Fatalf("exhausted quota on %s returned code %q", path, response.Error.Code)
			}
		})
	}
}

func TestP106B1_ExhaustedTokenQuotaBlocksPreviouslyMissedRoutes(t *testing.T) {
	cases := []struct {
		name              string
		path              string
		totalInputTokens  int
		totalOutputTokens int
		code              string
	}{
		{name: "messages input", path: "/v1/messages", totalInputTokens: 100, code: "QUOTA_INPUT_TOKENS_EXCEEDED"},
		{name: "messages output", path: "/v1/messages", totalOutputTokens: 100, code: "QUOTA_OUTPUT_TOKENS_EXCEEDED"},
		{name: "gemini stream input", path: "/v1/models/gemini:streamGenerateContent", totalInputTokens: 100, code: "QUOTA_INPUT_TOKENS_EXCEEDED"},
		{name: "gemini stream output", path: "/v1/models/gemini:streamGenerateContent", totalOutputTokens: 100, code: "QUOTA_OUTPUT_TOKENS_EXCEEDED"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := newP106bQuotaEnv(t, 10, 100, 100, 10, 10)
			if err := env.db.Model(&models.DailyUsage{}).Create(&models.DailyUsage{
				ClientID:          env.client.ID,
				Date:              services.UsageDate(time.Now()),
				TotalInputTokens:  tc.totalInputTokens,
				TotalOutputTokens: tc.totalOutputTokens,
			}).Error; err != nil {
				t.Fatal(err)
			}

			calls := 0
			h := NewQuotaMiddleware(env.db)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				calls++
				w.WriteHeader(http.StatusOK)
			}))
			req := httptest.NewRequest(http.MethodPost, tc.path, strings.NewReader(`{"contents":[{"parts":[{"text":"x"}]}]}`))
			req = req.WithContext(context.WithValue(req.Context(), ClientContextKey, env.client))
			w := httptest.NewRecorder()
			h.ServeHTTP(w, req)

			var response struct {
				Error struct {
					Code string `json:"code"`
				} `json:"error"`
			}
			if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
				t.Fatal(err)
			}
			if w.Code != http.StatusTooManyRequests || response.Error.Code != tc.code || calls != 0 {
				t.Fatalf("%s should block before downstream: status=%d code=%q calls=%d", tc.path, w.Code, response.Error.Code, calls)
			}
		})
	}
}
