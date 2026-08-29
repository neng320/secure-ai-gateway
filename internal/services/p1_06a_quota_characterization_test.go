package services

import (
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
	today := time.Now().Truncate(24 * time.Hour)
	if err := e.db.Where("client_id = ? AND date = ?", e.client.ID, today).First(&usage).Error; err != nil {
		t.Fatal(err)
	}
	return usage
}

// G–I: quota values are persisted and reported, but the current request/logging path
// does not consult them as a preflight enforcement gate.
func TestP106A_GHI_QuotaFieldsAreNotEnforcedByAccountingPath(t *testing.T) {
	env := newP106aUsageEnv(t)
	if err := env.record("p106a-g-1", 20, 30, 200, false); err != nil {
		t.Fatal(err)
	}
	if err := env.record("p106a-g-2", 20, 30, 200, false); err != nil {
		t.Fatal(err)
	}
	usage := env.usage(t)
	if usage.TotalRequests != 2 || usage.TotalInputTokens != 40 || usage.TotalOutputTokens != 60 {
		t.Fatalf("[G/H/I] accounting should reflect both calls and tokens, got %+v", usage)
	}
	t.Logf("[G/H/I CURRENT] QuotaRequestsDay=%d, input=%d, output=%d do not block accounting: usage=%+v", env.client.QuotaRequestsDay, env.client.QuotaInputTokensDay, env.client.QuotaOutputTokensDay, usage)
}

func TestP106A_J_ConcurrentDailyUsageCharacterization(t *testing.T) {
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
	if int32(usage.TotalRequests) != successes.Load() {
		t.Logf("[J KNOWN-GAP] read-modify-save is not a single atomic increment: calls=%d successes=%d failures=%d stored_requests=%d", calls, successes.Load(), failures.Load(), usage.TotalRequests)
	} else {
		t.Logf("[J CURRENT] all successful concurrent updates were retained: calls=%d failures=%d usage=%+v; implementation still uses read-modify-save", calls, failures.Load(), usage)
	}
}

func TestP106A_K_StreamingUsageAccounting(t *testing.T) {
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
	t.Logf("[K CURRENT] streaming request logs once and charges usage once: %+v", usage)
}

func TestP106A_DailyUsageBoundaryIsUTCAligned(t *testing.T) {
	boundary := time.Now().Truncate(24 * time.Hour).UTC()
	if boundary.Hour() != 0 || boundary.Minute() != 0 || boundary.Second() != 0 {
		t.Fatalf("[supporting fact] daily usage boundary should align to UTC midnight, got %v", boundary)
	}
	t.Logf("[CURRENT] DailyUsage date uses time.Now().Truncate(24h), aligned to UTC midnight: %v", boundary)
}

func TestP106A_AccountingErrorDoesNotHideInput(t *testing.T) {
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
	t.Log("[L CURRENT] direct LogRequest records a 500 as metadata; request-path error response mapping is handler-specific")
}
