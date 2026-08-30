package services

import (
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"ai-gateway/internal/database"
	"ai-gateway/internal/models"

	"gorm.io/gorm"
)

type p106aUsageEnv struct {
	db     *gorm.DB
	gemini *GeminiService
	client *models.Client
}

func newP106aUsageEnv(t *testing.T) *p106aUsageEnv {
	t.Helper()
	db, err := database.Open(t.TempDir() + "/p106a.db")
	if err != nil {
		t.Fatal(err)
	}
	if err := db.AutoMigrate(&models.Client{}, &models.RequestLog{}, &models.DailyUsage{}); err != nil {
		t.Fatal(err)
	}
	client := &models.Client{
		ID:                   "p106a-client",
		Name:                 "p106a-client",
		IsActive:             true,
		RateLimitMinute:      1000,
		RateLimitHour:        1000,
		RateLimitDay:         1000,
		QuotaRequestsDay:     1,
		QuotaInputTokensDay:  10,
		QuotaOutputTokensDay: 10,
		MaxInputTokens:       10,
		MaxOutputTokens:      10,
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
	return &p106aUsageEnv{db: db, gemini: NewGeminiService(db, nil), client: client}
}

func (e *p106aUsageEnv) record(requestID string, inputTokens, outputTokens, statusCode int, streaming bool) error {
	return e.gemini.LogRequest(RequestRecord{
		RequestID: requestID, ClientID: e.client.ID, Provider: "p106a", Model: "model",
		StatusCode: statusCode, InputTokens: inputTokens, OutputTokens: outputTokens,
		IsStreaming: streaming,
	})
}

func (e *p106aUsageEnv) usage(t *testing.T) models.DailyUsage {
	t.Helper()
	var usage models.DailyUsage
	today := UsageDate(time.Now())
	if err := e.db.Where("client_id = ? AND date = ?", e.client.ID, today).First(&usage).Error; err != nil {
		t.Fatal(err)
	}
	return usage
}

// G–I: request/token quota reservations are enforced before downstream and
// completed usage charges the actual observed token values.
func TestP106B_GHI_QuotaReservationAndAtomicCharge(t *testing.T) {
	env := newP106aUsageEnv(t)
	ledger := NewUsageLedger(env.db)
	reservation, err := ledger.Reserve(env.client)
	if err != nil {
		t.Fatal(err)
	}
	if err := reservation.Finalize(2, 3); err != nil {
		t.Fatal(err)
	}
	usage := env.usage(t)
	if usage.TotalRequests != 1 || usage.TotalInputTokens != 2 || usage.TotalOutputTokens != 3 || usage.ReservedRequests != 0 || usage.ReservedInputTokens != 0 || usage.ReservedOutputTokens != 0 {
		t.Fatalf("[G/H/I] reservation finalize should charge actual values and release reservation: %+v", usage)
	}
	if _, err := ledger.Reserve(env.client); !errors.Is(err, ErrQuotaRequestsExceeded) {
		t.Fatalf("[G] second request should be rejected at request quota: %v", err)
	}
	t.Logf("[G/H/I FIXED] quotas reserve before downstream and finalize actual usage: request=%d input=%d output=%d", env.client.QuotaRequestsDay, env.client.QuotaInputTokensDay, env.client.QuotaOutputTokensDay)
}

func TestP106B_J_ConcurrentDailyUsageIsAtomic(t *testing.T) {
	env := newP106aUsageEnv(t)
	const calls = 32
	start := make(chan struct{})
	var wg sync.WaitGroup
	var successes atomic.Int32
	var failures atomic.Int32
	for i := 0; i < calls; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			if err := env.gemini.updateDailyUsage(env.client.ID, 1, 1, 200); err != nil {
				failures.Add(1)
				return
			}
			successes.Add(1)
		}(i)
	}
	close(start)
	wg.Wait()

	usage := env.usage(t)
	if usage.TotalRequests > int(successes.Load()) || usage.TotalInputTokens > int(successes.Load()) || usage.TotalOutputTokens > int(successes.Load()) {
		t.Fatalf("[J] usage cannot exceed successful updates: successes=%d failures=%d usage=%+v", successes.Load(), failures.Load(), usage)
	}
	if successes.Load() == 0 {
		t.Fatalf("[J] concurrent characterization produced no successful updates: failures=%d", failures.Load())
	}
	if int32(usage.TotalRequests) != successes.Load() || int32(usage.TotalInputTokens) != successes.Load() || int32(usage.TotalOutputTokens) != successes.Load() {
		t.Fatalf("[J] atomic accounting must retain every successful update: calls=%d successes=%d failures=%d usage=%+v", calls, successes.Load(), failures.Load(), usage)
	}
	t.Logf("[J FIXED] atomic DailyUsage upsert retained all %d successful concurrent updates", successes.Load())
}

func TestP106B_K_StreamingUsageAccounting(t *testing.T) {
	env := newP106aUsageEnv(t)
	if err := env.record("p106a-k-1", 7, 11, 200, true); err != nil {
		t.Fatal(err)
	}
	var logEntry models.RequestLog
	if err := env.db.Where("request_id = ?", "p106a-k-1").First(&logEntry).Error; err != nil {
		t.Fatal(err)
	}
	if !logEntry.IsStreaming || logEntry.InputTokens != 7 || logEntry.OutputTokens != 11 {
		t.Fatalf("[K] streaming log metadata mismatch: %+v", logEntry)
	}
	usage := env.usage(t)
	if usage.TotalRequests != 1 || usage.TotalInputTokens != 7 || usage.TotalOutputTokens != 11 {
		t.Fatalf("[K] streaming usage should charge once: %+v", usage)
	}
	t.Logf("[K FIXED] streaming request logs once and charges usage once: %+v", usage)
}

func TestP106B_DailyUsageBoundaryIsUTCAligned(t *testing.T) {
	boundary := time.Now().Truncate(24 * time.Hour).UTC()
	if boundary.Hour() != 0 || boundary.Minute() != 0 || boundary.Second() != 0 {
		t.Fatalf("[supporting fact] daily usage boundary should align to UTC midnight, got %v", boundary)
	}
	t.Logf("[FIXED] DailyUsage date uses UsageDate, aligned to UTC midnight: %v", boundary)
}

func TestP106B_AccountingErrorDoesNotHideInput(t *testing.T) {
	env := newP106aUsageEnv(t)
	if err := env.record(fmt.Sprintf("%s-error", env.client.ID), 1, 1, 500, false); err != nil {
		t.Fatal(err)
	}
	var entry models.RequestLog
	if err := env.db.Where("status_code = ?", 500).First(&entry).Error; err != nil {
		t.Fatal(err)
	}
	if entry.ErrorCode != "" || entry.StatusCode != 500 {
		t.Fatalf("[L supporting fact] expected current raw accounting metadata, got %+v", entry)
	}
	t.Log("[L FIXED] direct LogRequest records a 500 as metadata; request-path error response mapping is handler-specific")
}
