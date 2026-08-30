package middleware

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"ai-gateway/internal/database"
	"ai-gateway/internal/models"
	"ai-gateway/internal/services"

	"gorm.io/gorm"
)

type p106bQuotaEnv struct {
	db     *gorm.DB
	ledger *services.UsageLedger
	client *models.Client
}

func newP106bQuotaEnv(t *testing.T, requestQuota, inputQuota, outputQuota, maxInput, maxOutput int) *p106bQuotaEnv {
	t.Helper()
	db, err := database.Open(t.TempDir() + "/p106b.db")
	if err != nil {
		t.Fatal(err)
	}
	if err := db.AutoMigrate(&models.Client{}, &models.RequestLog{}, &models.DailyUsage{}); err != nil {
		t.Fatal(err)
	}
	client := &models.Client{
		ID:                   "p106b-client",
		Name:                 "p106b-client",
		IsActive:             true,
		RateLimitMinute:      1000,
		RateLimitHour:        1000,
		RateLimitDay:         1000,
		QuotaRequestsDay:     requestQuota,
		QuotaInputTokensDay:  inputQuota,
		QuotaOutputTokensDay: outputQuota,
		MaxInputTokens:       maxInput,
		MaxOutputTokens:      maxOutput,
		CreatedAt:            time.Now(),
		UpdatedAt:            time.Now(),
	}
	if err := db.Create(client).Error; err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if sqlDB, err := db.DB(); err == nil {
			_ = sqlDB.Close()
		}
	})
	return &p106bQuotaEnv{db: db, ledger: services.NewUsageLedger(db), client: client}
}

func p106bRequest(client *models.Client) *http.Request {
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil)
	return req.WithContext(context.WithValue(req.Context(), ClientContextKey, client))
}

func p106bUsage(t *testing.T, db *gorm.DB, clientID string) models.DailyUsage {
	t.Helper()
	var usage models.DailyUsage
	if err := db.Where("client_id = ? AND date = ?", clientID, services.UsageDate(time.Now())).First(&usage).Error; err != nil {
		t.Fatal(err)
	}
	return usage
}

func TestP106B_RequestQuotaPreflightBlocksBeforeHandler(t *testing.T) {
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
	w := httptest.NewRecorder()
	h.ServeHTTP(w, p106bRequest(env.client))
	if w.Code != http.StatusTooManyRequests || calls != 0 {
		t.Fatalf("[Request quota] expected preflight 429 without downstream call, status=%d calls=%d", w.Code, calls)
	}
	var body struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Error.Code != "QUOTA_REQUESTS_EXCEEDED" || w.Header().Get("Retry-After") != "86400" {
		t.Fatalf("[Request quota] unstable error contract: body=%s headers=%v", w.Body.String(), w.Header())
	}
	t.Log("[P1-06B] reached request quota is rejected before downstream/upstream")
}

func TestP106B_ConcurrentReservationsDoNotExceedQuota(t *testing.T) {
	env := newP106bQuotaEnv(t, 4, 40, 40, 10, 10)
	const workers = 12
	var wg sync.WaitGroup
	results := make(chan *services.UsageReservation, workers)
	start := make(chan struct{})
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			reservation, _ := env.ledger.Reserve(env.client)
			results <- reservation
		}()
	}
	close(start)
	wg.Wait()
	close(results)

	passed := 0
	for reservation := range results {
		if reservation != nil {
			passed++
			if err := reservation.Release(); err != nil {
				t.Fatal(err)
			}
		}
	}
	if passed != 4 {
		t.Fatalf("[concurrency] expected exactly four in-flight reservations, got %d/%d", passed, workers)
	}
	usage := p106bUsage(t, env.db, env.client.ID)
	if usage.ReservedRequests != 0 || usage.ReservedInputTokens != 0 || usage.ReservedOutputTokens != 0 {
		t.Fatalf("[concurrency] deferred release must clear reservations: %+v", usage)
	}
	t.Log("[P1-06B] concurrent quota reservations admit exactly capacity and release on downstream completion")
}

func TestP106B_TokenQuotaFinalizeChargesActualAndClearsReservation(t *testing.T) {
	env := newP106bQuotaEnv(t, 10, 10, 10, 5, 5)
	reservation, err := env.ledger.Reserve(env.client)
	if err != nil {
		t.Fatal(err)
	}
	if err := reservation.Finalize(3, 4); err != nil {
		t.Fatal(err)
	}
	usage := p106bUsage(t, env.db, env.client.ID)
	if usage.TotalRequests != 1 || usage.TotalInputTokens != 3 || usage.TotalOutputTokens != 4 || usage.ReservedRequests != 0 || usage.ReservedInputTokens != 0 || usage.ReservedOutputTokens != 0 {
		t.Fatalf("[token quota] expected actual charge and zero reservations: %+v", usage)
	}

	if err := env.db.Model(&models.DailyUsage{}).Where("client_id = ?", env.client.ID).Updates(map[string]interface{}{"total_input_tokens": 10}).Error; err != nil {
		t.Fatal(err)
	}
	if _, err := env.ledger.Reserve(env.client); !errors.Is(err, services.ErrQuotaInputExceeded) {
		t.Fatalf("[token quota] reached input quota should reject before downstream, got %v", err)
	}
	t.Log("[P1-06B] token reservation finalizes actual usage atomically and blocks once daily input quota is reached")
}

func TestP106B_DynamicQuotaEditPreservesUsage(t *testing.T) {
	env := newP106bQuotaEnv(t, 1, 100, 100, 10, 10)
	first, err := env.ledger.Reserve(env.client)
	if err != nil {
		t.Fatal(err)
	}
	if err := first.Finalize(2, 2); err != nil {
		t.Fatal(err)
	}
	if err := env.db.Model(&models.Client{}).Where("id = ?", env.client.ID).Updates(map[string]interface{}{"quota_requests_day": 2}).Error; err != nil {
		t.Fatal(err)
	}
	env.client.QuotaRequestsDay = 2
	second, err := env.ledger.Reserve(env.client)
	if err != nil {
		t.Fatal("increasing quota should expose one remaining request:", err)
	}
	if err := second.Finalize(1, 1); err != nil {
		t.Fatal(err)
	}
	if err := env.db.Model(&models.Client{}).Where("id = ?", env.client.ID).Updates(map[string]interface{}{"quota_requests_day": 1}).Error; err != nil {
		t.Fatal(err)
	}
	env.client.QuotaRequestsDay = 1
	if _, err := env.ledger.Reserve(env.client); !errors.Is(err, services.ErrQuotaRequestsExceeded) {
		t.Fatalf("lowering below persisted usage must remain exhausted, got %v", err)
	}
	usage := p106bUsage(t, env.db, env.client.ID)
	if usage.TotalRequests != 2 {
		t.Fatalf("dynamic quota edit must not reset usage: %+v", usage)
	}
	t.Log("[P1-06B] quota edits apply on the next request without resetting persisted usage")
}

func TestP106B_InvalidQuotaConfigurationFailsClosed(t *testing.T) {
	for name, env := range map[string]*p106bQuotaEnv{
		"negative quota":              newP106bQuotaEnv(t, -1, 100, 100, 10, 10),
		"unbounded input reservation": newP106bQuotaEnv(t, 10, 100, 100, 0, 10),
	} {
		if name == "unbounded input reservation" {
			env.client.MaxInputTokens = 0
		}
		if _, err := env.ledger.Reserve(env.client); !errors.Is(err, services.ErrQuotaConfiguration) {
			t.Fatalf("[%s] expected ErrQuotaConfiguration, got %v", name, err)
		}
	}
	t.Log("[P1-06B] invalid quota/max-token combinations fail closed before upstream")
}

func TestP106B_QuotaStorageFailureIsNotReportedAsExhaustion(t *testing.T) {
	w := httptest.NewRecorder()
	writeQuotaError(w, errors.New("database unavailable"))
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("storage failure should be a server error, got %d", w.Code)
	}
	var body struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Error.Code != "QUOTA_UNAVAILABLE" {
		t.Fatalf("storage failure should use QUOTA_UNAVAILABLE, got %q", body.Error.Code)
	}
}
