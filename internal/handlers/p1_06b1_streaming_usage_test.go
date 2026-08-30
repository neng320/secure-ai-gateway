package handlers

import (
	"context"
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
	"ai-gateway/internal/services"

	"gorm.io/gorm"
)

const p106b1StreamBody = `{"contents":[{"parts":[{"text":"hello"}]}]}`

type p106b1StreamFixture struct {
	db     *gorm.DB
	client *models.Client
	h      http.Handler
	calls  *int32
}

func newP106b1StreamFixture(t *testing.T, response string) *p106b1StreamFixture {
	t.Helper()
	db, err := database.Open(t.TempDir() + "/p106b1-stream.db")
	if err != nil {
		t.Fatal(err)
	}
	if err := db.AutoMigrate(&models.Client{}, &models.RequestLog{}, &models.DailyUsage{}); err != nil {
		t.Fatal(err)
	}
	client := &models.Client{
		ID:                   "p106b1-stream-client",
		Name:                 "p106b1-stream-client",
		IsActive:             true,
		RateLimitMinute:      1000,
		RateLimitHour:        1000,
		RateLimitDay:         1000,
		QuotaRequestsDay:     10,
		QuotaInputTokensDay:  1000,
		QuotaOutputTokensDay: 1000,
		MaxInputTokens:       1000,
		MaxOutputTokens:      7,
		CreatedAt:            time.Now(),
		UpdatedAt:            time.Now(),
	}
	if err := db.Create(client).Error; err != nil {
		t.Fatal(err)
	}

	var calls int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte(response))
	}))
	t.Cleanup(func() {
		upstream.Close()
		if sqlDB, err := db.DB(); err == nil {
			_ = sqlDB.Close()
		}
	})

	cfg := &config.Config{Providers: map[string]config.ProviderConfig{
		"gemini": {Type: "gemini", BaseURL: upstream.URL, APIKey: "p106b1-upstream", TimeoutSeconds: 5},
	}}
	proxy := NewProxyHandler(services.NewGeminiService(db, cfg), nil, nil)
	return &p106b1StreamFixture{
		db:     db,
		client: client,
		h:      middleware.NewQuotaMiddleware(db)(http.HandlerFunc(proxy.StreamGenerateContent)),
		calls:  &calls,
	}
}

func (f *p106b1StreamFixture) request(t *testing.T) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/v1/models/gemini:streamGenerateContent", strings.NewReader(p106b1StreamBody))
	req = req.WithContext(context.WithValue(req.Context(), middleware.ClientContextKey, f.client))
	w := httptest.NewRecorder()
	f.h.ServeHTTP(w, req)
	return w
}

func (f *p106b1StreamFixture) usage(t *testing.T) models.DailyUsage {
	t.Helper()
	var usage models.DailyUsage
	if err := f.db.Where("client_id = ? AND date = ?", f.client.ID, services.UsageDate(time.Now())).First(&usage).Error; err != nil {
		t.Fatal(err)
	}
	return usage
}

func TestP106B1_GeminiStreamingChargesActualUsageOnce(t *testing.T) {
	response := "data: {\"candidates\":[{}],\"usageMetadata\":{\"promptTokenCount\":3,\"candidatesTokenCount\":4}}\n\ndata: [DONE]\n\n"
	f := newP106b1StreamFixture(t, response)
	if w := f.request(t); w.Code != http.StatusOK {
		t.Fatalf("stream request should succeed, got %d: %s", w.Code, w.Body.String())
	}
	usage := f.usage(t)
	if atomic.LoadInt32(f.calls) != 1 {
		t.Fatalf("expected one upstream call, got %d", atomic.LoadInt32(f.calls))
	}
	if usage.TotalRequests != 1 || usage.TotalInputTokens != 3 || usage.TotalOutputTokens != 4 || usage.ReservedRequests != 0 || usage.ReservedInputTokens != 0 || usage.ReservedOutputTokens != 0 {
		t.Fatalf("stream usage should charge actual metadata exactly once and clear reservation: %+v", usage)
	}
}

func TestP106B1_GeminiStreamingMissingUsageChargesReservation(t *testing.T) {
	response := "data: {\"candidates\":[{}]}\n\ndata: [DONE]\n\n"
	f := newP106b1StreamFixture(t, response)
	if w := f.request(t); w.Code != http.StatusOK {
		t.Fatalf("stream request should succeed, got %d: %s", w.Code, w.Body.String())
	}
	usage := f.usage(t)
	if usage.TotalRequests != 1 || usage.TotalInputTokens != len(p106b1StreamBody) || usage.TotalOutputTokens != f.client.MaxOutputTokens || usage.ReservedRequests != 0 || usage.ReservedInputTokens != 0 || usage.ReservedOutputTokens != 0 {
		t.Fatalf("missing stream usage must conservatively charge reservation once: %+v body_len=%d", usage, len(p106b1StreamBody))
	}
	if atomic.LoadInt32(f.calls) != 1 {
		t.Fatalf("expected one upstream call, got %d", atomic.LoadInt32(f.calls))
	}
}

func TestP106B1_GeminiStreamingReservationFailureDoesNotDoubleCharge(t *testing.T) {
	response := "data: {\"candidates\":[{}],\"usageMetadata\":{\"promptTokenCount\":2,\"candidatesTokenCount\":2}}\n\ndata: [DONE]\n\n"
	f := newP106b1StreamFixture(t, response)
	if w := f.request(t); w.Code != http.StatusOK {
		t.Fatalf("stream request should succeed, got %d: %s", w.Code, w.Body.String())
	}
	usage := f.usage(t)
	if usage.TotalRequests != 1 {
		t.Fatalf("stream request must be counted exactly once, got %+v", usage)
	}
	var logs int64
	if err := f.db.Model(&models.RequestLog{}).Where("client_id = ?", f.client.ID).Count(&logs).Error; err != nil {
		t.Fatal(fmt.Errorf("count request logs: %w", err))
	}
	if logs != 1 {
		t.Fatalf("stream request must create exactly one log, got %d", logs)
	}
}
