package handlers

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"ai-gateway/internal/config"
	"ai-gateway/internal/database"
	"ai-gateway/internal/middleware"
	"ai-gateway/internal/models"
	"ai-gateway/internal/providers"
	"ai-gateway/internal/services"

	"gorm.io/gorm"
)

type p107aValidationFixture struct {
	db     *gorm.DB
	client *models.Client
	openai http.Handler
	proxy  http.Handler
	calls  *int32
}

func newP107aValidationFixture(t *testing.T) *p107aValidationFixture {
	t.Helper()
	db, err := database.Open(t.TempDir() + "/p107a-validation.db")
	if err != nil {
		t.Fatal(err)
	}
	if err := db.AutoMigrate(&models.Client{}, &models.RequestLog{}, &models.DailyUsage{}); err != nil {
		t.Fatal(err)
	}

	var calls int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(r.URL.Path, "generateContent") {
			_, _ = w.Write([]byte(`{"candidates":[{"content":{"parts":[{"text":"ok"}]}}],"usageMetadata":{"promptTokenCount":1,"candidatesTokenCount":1}}`))
			return
		}
		_, _ = w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":"ok"}}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}`))
	}))
	t.Cleanup(func() {
		upstream.Close()
		if sqlDB, err := db.DB(); err == nil {
			_ = sqlDB.Close()
		}
	})

	cfg := &config.Config{Providers: map[string]config.ProviderConfig{
		"openai": {Type: "openai", BaseURL: upstream.URL, APIKey: "p107a-openai", DefaultModel: "test-model", TimeoutSeconds: 5},
		"gemini": {Type: "gemini", BaseURL: upstream.URL, APIKey: "p107a-gemini", DefaultModel: "test-model", TimeoutSeconds: 5},
	}}
	client := &models.Client{
		ID:                   "p107a-validation-client",
		Name:                 "p107a-validation-client",
		Backend:              "openai",
		BackendModels:        `["test-model"]`,
		IsActive:             true,
		RateLimitMinute:      1000,
		RateLimitHour:        1000,
		RateLimitDay:         1000,
		QuotaRequestsDay:     1000,
		QuotaInputTokensDay:  1000000,
		QuotaOutputTokensDay: 500000,
		MaxInputTokens:       1000000,
		MaxOutputTokens:      8192,
		CreatedAt:            time.Now(),
		UpdatedAt:            time.Now(),
	}
	if err := db.Create(client).Error; err != nil {
		t.Fatal(err)
	}

	gemini := services.NewGeminiService(db, cfg)
	openai := NewOpenAIHandler(gemini, services.NewClientService(db), nil, providers.BuildRegistry(cfg), services.NewToolService(nil), nil, nil)
	proxy := NewProxyHandler(gemini, nil, nil)
	return &p107aValidationFixture{
		db:     db,
		client: client,
		openai: http.HandlerFunc(openai.ChatCompletions),
		proxy:  http.HandlerFunc(proxy.GenerateContent),
		calls:  &calls,
	}
}

func (f *p107aValidationFixture) openAIRequest(t *testing.T, body []byte, contentType, contentEncoding string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewReader(body))
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	if contentEncoding != "" {
		req.Header.Set("Content-Encoding", contentEncoding)
	}
	req = req.WithContext(context.WithValue(req.Context(), middleware.ClientContextKey, f.client))
	w := httptest.NewRecorder()
	f.openai.ServeHTTP(w, req)
	return w
}

func (f *p107aValidationFixture) geminiRequest(t *testing.T, body []byte) *httptest.ResponseRecorder {
	t.Helper()
	client := *f.client
	client.Backend = "gemini"
	req := httptest.NewRequest(http.MethodPost, "/v1/models/test-model:generateContent", bytes.NewReader(body))
	req = req.WithContext(context.WithValue(req.Context(), middleware.ClientContextKey, &client))
	w := httptest.NewRecorder()
	f.proxy.ServeHTTP(w, req)
	return w
}

func TestP107A_OpenAIRequestValidationCurrentBehavior(t *testing.T) {
	valid := []byte(`{"model":"test-model","messages":[{"role":"user","content":"hello"}]}`)
	deep := "0"
	for i := 0; i < 100; i++ {
		deep = `{"x":` + deep + `}`
	}
	largeMessages := make([]string, 5000)
	for i := range largeMessages {
		largeMessages[i] = `{"role":"user","content":"x"}`
	}
	cases := []struct {
		name          string
		body          []byte
		contentType   string
		contentEncode string
		wantStatus    int
		wantCalls     int32
		gap           string
	}{
		{name: "malformed json", body: []byte(`{"model":`), wantStatus: http.StatusBadRequest, wantCalls: 0},
		{name: "trailing second value", body: append(append([]byte{}, valid...), []byte(`{}`)...), wantStatus: http.StatusBadRequest, wantCalls: 0},
		{name: "top-level array", body: []byte(`[]`), wantStatus: http.StatusBadRequest, wantCalls: 0},
		{name: "top-level null", body: []byte(`null`), wantStatus: http.StatusBadRequest, wantCalls: 0},
		{name: "wrong messages type", body: []byte(`{"model":"test-model","messages":"bad"}`), wantStatus: http.StatusBadRequest, wantCalls: 0},
		{name: "empty messages", body: []byte(`{"model":"test-model","messages":[]}`), wantStatus: http.StatusBadRequest, wantCalls: 0},
		{name: "wrong content type accepted", body: valid, contentType: "text/plain", wantStatus: http.StatusOK, wantCalls: 1, gap: "no Content-Type enforcement"},
		{name: "unknown extension accepted", body: []byte(string(valid[:len(valid)-1]) + `,"vendor_extension":{"nested":true}}`), wantStatus: http.StatusOK, wantCalls: 1, gap: "unknown fields accepted"},
		{name: "duplicate messages last value wins", body: []byte(`{"model":"test-model","messages":[],"messages":[{"role":"user","content":"hello"}]}`), wantStatus: http.StatusOK, wantCalls: 1, gap: "duplicate fields accepted"},
		{name: "empty model falls back", body: []byte(`{"model":"","messages":[{"role":"user","content":"hello"}]}`), wantStatus: http.StatusOK, wantCalls: 1, gap: "empty model is not rejected"},
		{name: "control character model accepted", body: []byte(`{"model":"test\u0001model","messages":[{"role":"user","content":"hello"}]}`), wantStatus: http.StatusOK, wantCalls: 1, gap: "model control characters are not validated"},
		{name: "negative max tokens accepted", body: []byte(`{"model":"test-model","messages":[{"role":"user","content":"hello"}],"max_tokens":-1}`), wantStatus: http.StatusOK, wantCalls: 1, gap: "negative max_tokens is not rejected"},
		{name: "large max tokens rejected by P106B cap", body: []byte(`{"model":"test-model","messages":[{"role":"user","content":"hello"}],"max_tokens":999999999}`), wantStatus: http.StatusBadRequest, wantCalls: 0, gap: "validation has no bounded integer contract beyond client cap"},
		{name: "deep unknown value accepted", body: []byte(fmt.Sprintf(`{"model":"test-model","messages":[{"role":"user","content":"hello"}],"extra":%s}`, deep)), wantStatus: http.StatusOK, wantCalls: 1, gap: "no explicit JSON depth limit"},
		{name: "large messages array accepted", body: []byte(fmt.Sprintf(`{"model":"test-model","messages":[%s]}`, strings.Join(largeMessages, ","))), wantStatus: http.StatusOK, wantCalls: 1, gap: "no messages array-count limit within body cap"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newP107aValidationFixture(t)
			w := f.openAIRequest(t, tc.body, tc.contentType, tc.contentEncode)
			if w.Code != tc.wantStatus || atomic.LoadInt32(f.calls) != tc.wantCalls {
				t.Fatalf("[CURRENT] status/call mismatch: status=%d calls=%d want status=%d calls=%d body=%s", w.Code, atomic.LoadInt32(f.calls), tc.wantStatus, tc.wantCalls, w.Body.String())
			}
			if tc.gap != "" {
				t.Logf("[KNOWN-GAP] %s", tc.gap)
			}
		})
	}
}

func TestP107A_GzipRequestIsNotDecompressed(t *testing.T) {
	f := newP107aValidationFixture(t)
	var compressed bytes.Buffer
	writer := gzip.NewWriter(&compressed)
	if _, err := writer.Write([]byte(`{"model":"test-model","messages":[{"role":"user","content":"hello"}]}`)); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	w := f.openAIRequest(t, compressed.Bytes(), "application/json", "gzip")
	if w.Code != http.StatusBadRequest || atomic.LoadInt32(f.calls) != 0 {
		t.Fatalf("[CURRENT] gzip body should reach JSON parser as compressed bytes: status=%d calls=%d body=%s", w.Code, atomic.LoadInt32(f.calls), w.Body.String())
	}
	t.Log("[KNOWN-GAP] Content-Encoding gzip is not explicitly rejected or decompressed; parser returns generic invalid JSON")
}

func TestP107A_GeminiMalformedJSONReachesUpstream(t *testing.T) {
	f := newP107aValidationFixture(t)
	w := f.geminiRequest(t, []byte(`{"contents":`))
	if w.Code != http.StatusOK || atomic.LoadInt32(f.calls) != 1 {
		t.Fatalf("[CURRENT] Gemini malformed JSON behavior changed: status=%d calls=%d body=%s", w.Code, atomic.LoadInt32(f.calls), w.Body.String())
	}
	t.Log("[KNOWN-GAP] Gemini handler enforces byte-derived MaxInput only; malformed JSON reaches upstream")
}

func TestP107A_GeminiValidJSONWrongContentTypeReachesUpstream(t *testing.T) {
	f := newP107aValidationFixture(t)
	req := httptest.NewRequest(http.MethodPost, "/v1/models/test-model:generateContent", strings.NewReader(`{"contents":[{"parts":[{"text":"hello"}]}]}`))
	req.Header.Set("Content-Type", "text/plain")
	client := *f.client
	client.Backend = "gemini"
	req = req.WithContext(context.WithValue(req.Context(), middleware.ClientContextKey, &client))
	w := httptest.NewRecorder()
	f.proxy.ServeHTTP(w, req)
	if w.Code != http.StatusOK || atomic.LoadInt32(f.calls) != 1 {
		t.Fatalf("[CURRENT] Gemini wrong Content-Type behavior changed: status=%d calls=%d", w.Code, atomic.LoadInt32(f.calls))
	}
	t.Log("[KNOWN-GAP] Gemini valid JSON is accepted without Content-Type validation")
}

func TestP107A_GeminiGzipRequestIsForwardedAsCompressedBytes(t *testing.T) {
	f := newP107aValidationFixture(t)
	var compressed bytes.Buffer
	writer := gzip.NewWriter(&compressed)
	if _, err := writer.Write([]byte(`{"contents":[{"parts":[{"text":"hello"}]}]}`)); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	client := *f.client
	client.Backend = "gemini"
	req := httptest.NewRequest(http.MethodPost, "/v1/models/test-model:generateContent", bytes.NewReader(compressed.Bytes()))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Content-Encoding", "gzip")
	req = req.WithContext(context.WithValue(req.Context(), middleware.ClientContextKey, &client))
	w := httptest.NewRecorder()
	f.proxy.ServeHTTP(w, req)
	if w.Code != http.StatusOK || atomic.LoadInt32(f.calls) != 1 {
		t.Fatalf("[CURRENT] Gemini gzip behavior changed: status=%d calls=%d", w.Code, atomic.LoadInt32(f.calls))
	}
	t.Log("[KNOWN-GAP] Gemini does not reject or decompress gzip before forwarding")
}

func TestP107A_RequestBodyTokenEstimateIsNotExactTokenizer(t *testing.T) {
	if got := estimateInputTokens("你好"); got != len("你好") {
		t.Fatalf("[CURRENT] expected byte-length conservative estimate, got %d", got)
	}
	t.Log("[CURRENT] MaxInput gate uses conservative byte upper bound, not an exact tokenizer")
}

func TestP107A_ValidationDoesNotEchoBodyInOpenAIError(t *testing.T) {
	f := newP107aValidationFixture(t)
	canary := "validation-body-canary"
	w := f.openAIRequest(t, []byte(`{"model":"test-model","messages":"`+canary+`"}`), "application/json", "")
	if w.Code != http.StatusBadRequest || strings.Contains(w.Body.String(), canary) {
		t.Fatalf("[CURRENT] validation error should not echo complete body: status=%d body=%s", w.Code, w.Body.String())
	}
	t.Log("[CURRENT] OpenAI malformed/type errors return bounded generic messages")
}

func TestP107A_OpenAIRequestBodyIsJSONObjectContractOnlyByHandler(t *testing.T) {
	f := newP107aValidationFixture(t)
	var body map[string]interface{}
	if err := json.Unmarshal([]byte(`{"model":"test-model","messages":[{"role":"user","content":"hello"}]}`), &body); err != nil {
		t.Fatal(err)
	}
	if body["model"] != "test-model" {
		t.Fatalf("fixture malformed: %#v", body)
	}
	if w := f.openAIRequest(t, []byte(`{"model":"test-model","messages":[{"role":"user","content":"hello"}]}`), "application/json; charset=utf-8", ""); w.Code != http.StatusOK {
		t.Fatalf("[CURRENT] standard JSON content type should be accepted, got %d", w.Code)
	}
	t.Log("[CURRENT] JSON object parsing is protocol-specific and accepts charset parameter")
}

func TestP107A_CountTokensCurrentBehavior(t *testing.T) {
	h := &OpenAIHandler{}
	for _, tc := range []struct {
		name string
		body string
		want int
	}{
		{name: "prompt", body: `{"prompt":"abcdefgh"}`, want: 2},
		{name: "malformed", body: `{"prompt":`, want: 0},
		{name: "trailing value is ignored", body: `{"prompt":"abcdefgh"}{}`, want: 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/v1/messages/count_tokens", strings.NewReader(tc.body))
			w := httptest.NewRecorder()
			h.CountTokens(w, req)
			var response map[string]int
			if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
				t.Fatal(err)
			}
			if w.Code != http.StatusOK || response["tokens"] != tc.want {
				t.Fatalf("[CURRENT] count_tokens %s: status=%d tokens=%d body=%s", tc.name, w.Code, response["tokens"], w.Body.String())
			}
		})
	}
	t.Log("[KNOWN-GAP] count_tokens uses Decoder without error/trailing-value validation and returns len(prompt)/4")
}
