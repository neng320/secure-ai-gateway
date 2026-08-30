package services

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"ai-gateway/internal/models"

	"gorm.io/gorm"
)

var (
	ErrQuotaRequestsExceeded = errors.New("quota requests exceeded")
	ErrQuotaInputExceeded    = errors.New("quota input tokens exceeded")
	ErrQuotaOutputExceeded   = errors.New("quota output tokens exceeded")
	ErrQuotaConfiguration    = errors.New("quota configuration invalid")
)

type UsageLedger struct {
	db *gorm.DB
}

func NewUsageLedger(db *gorm.DB) *UsageLedger {
	return &UsageLedger{db: db}
}

// UsageDate is the single date boundary used by reservation, accounting and stats.
func UsageDate(now time.Time) time.Time {
	return now.UTC().Truncate(24 * time.Hour)
}

type usageReservationKey struct{}

func WithUsageReservation(ctx context.Context, reservation *UsageReservation) context.Context {
	return context.WithValue(ctx, usageReservationKey{}, reservation)
}

func UsageReservationFromContext(ctx context.Context) *UsageReservation {
	reservation, _ := ctx.Value(usageReservationKey{}).(*UsageReservation)
	return reservation
}

type UsageReservation struct {
	ledger               *UsageLedger
	clientID             string
	date                 time.Time
	reservedRequests     int
	reservedInputTokens  int
	reservedOutputTokens int

	mu        sync.Mutex
	finalized bool
}

// ConservativeUsage returns the bounded token reservation for a successful
// request whose provider did not return usage metadata.
func (reservation *UsageReservation) ConservativeUsage() (int, int) {
	reservation.mu.Lock()
	defer reservation.mu.Unlock()
	return reservation.reservedInputTokens, reservation.reservedOutputTokens
}

func (l *UsageLedger) Reserve(client *models.Client, reservationLimits ...int) (*UsageReservation, error) {
	if client == nil || client.ID == "" {
		return nil, ErrQuotaConfiguration
	}
	if client.QuotaRequestsDay < 0 || client.QuotaInputTokensDay < 0 || client.QuotaOutputTokensDay < 0 || client.MaxInputTokens < 0 || client.MaxOutputTokens < 0 {
		return nil, ErrQuotaConfiguration
	}
	if client.QuotaRequestsDay == 0 {
		return nil, ErrQuotaRequestsExceeded
	}
	if client.QuotaInputTokensDay == 0 {
		return nil, ErrQuotaInputExceeded
	}
	if client.QuotaOutputTokensDay == 0 {
		return nil, ErrQuotaOutputExceeded
	}
	if client.MaxInputTokens <= 0 || client.MaxOutputTokens <= 0 {
		return nil, ErrQuotaConfiguration
	}
	if client.MaxInputTokens > client.QuotaInputTokensDay {
		return nil, ErrQuotaInputExceeded
	}
	if client.MaxOutputTokens > client.QuotaOutputTokensDay {
		return nil, ErrQuotaOutputExceeded
	}
	if len(reservationLimits) != 0 && len(reservationLimits) != 2 {
		return nil, ErrQuotaConfiguration
	}

	inputReservation := client.MaxInputTokens
	outputReservation := client.MaxOutputTokens
	if len(reservationLimits) == 2 {
		inputReservation = reservationLimits[0]
		outputReservation = reservationLimits[1]
	}
	if inputReservation < 0 || outputReservation < 0 || inputReservation > client.MaxInputTokens || outputReservation > client.MaxOutputTokens {
		return nil, ErrQuotaConfiguration
	}
	if inputReservation > client.QuotaInputTokensDay {
		return nil, ErrQuotaInputExceeded
	}
	if outputReservation > client.QuotaOutputTokensDay {
		return nil, ErrQuotaOutputExceeded
	}

	reservation := &UsageReservation{
		ledger:               l,
		clientID:             client.ID,
		date:                 UsageDate(time.Now()),
		reservedRequests:     1,
		reservedInputTokens:  inputReservation,
		reservedOutputTokens: outputReservation,
	}
	err := l.db.Transaction(func(tx *gorm.DB) error {
		result := tx.Exec(`
INSERT INTO daily_usages
		(client_id, date, total_requests, total_input_tokens, total_output_tokens,
		 reserved_requests, reserved_input_tokens, reserved_output_tokens)
VALUES (?, ?, 0, 0, 0, ?, ?, ?)
ON CONFLICT(client_id, date) DO UPDATE SET
		reserved_requests = daily_usages.reserved_requests + excluded.reserved_requests,
		reserved_input_tokens = daily_usages.reserved_input_tokens + excluded.reserved_input_tokens,
		reserved_output_tokens = daily_usages.reserved_output_tokens + excluded.reserved_output_tokens
WHERE daily_usages.total_requests + daily_usages.reserved_requests + excluded.reserved_requests <= ?
	AND daily_usages.total_input_tokens + daily_usages.reserved_input_tokens + excluded.reserved_input_tokens <= ?
	AND daily_usages.total_output_tokens + daily_usages.reserved_output_tokens + excluded.reserved_output_tokens <= ?`,
			reservation.clientID, reservation.date,
			reservation.reservedRequests, reservation.reservedInputTokens, reservation.reservedOutputTokens,
			client.QuotaRequestsDay, client.QuotaInputTokensDay, client.QuotaOutputTokensDay,
		)
		if result.Error != nil {
			return result.Error
		}
		if result.RowsAffected == 1 {
			return nil
		}

		var usage models.DailyUsage
		if err := tx.Where("client_id = ? AND date = ?", reservation.clientID, reservation.date).First(&usage).Error; err != nil {
			return err
		}
		switch {
		case usage.TotalRequests+usage.ReservedRequests+reservation.reservedRequests > client.QuotaRequestsDay:
			return ErrQuotaRequestsExceeded
		case usage.TotalInputTokens+usage.ReservedInputTokens+reservation.reservedInputTokens > client.QuotaInputTokensDay:
			return ErrQuotaInputExceeded
		default:
			return ErrQuotaOutputExceeded
		}
	})
	if err != nil {
		return nil, err
	}
	return reservation, nil
}

func (reservation *UsageReservation) finalizeTx(tx *gorm.DB, inputTokens, outputTokens int) error {
	if inputTokens < 0 || outputTokens < 0 {
		return fmt.Errorf("invalid usage values")
	}
	if inputTokens > reservation.reservedInputTokens || outputTokens > reservation.reservedOutputTokens {
		return fmt.Errorf("usage exceeds reservation")
	}
	result := tx.Model(&models.DailyUsage{}).
		Where("client_id = ? AND date = ? AND reserved_requests >= ? AND reserved_input_tokens >= ? AND reserved_output_tokens >= ?",
			reservation.clientID, reservation.date, reservation.reservedRequests, reservation.reservedInputTokens, reservation.reservedOutputTokens).
		Updates(map[string]interface{}{
			"total_requests":         gorm.Expr("total_requests + ?", 1),
			"total_input_tokens":     gorm.Expr("total_input_tokens + ?", inputTokens),
			"total_output_tokens":    gorm.Expr("total_output_tokens + ?", outputTokens),
			"reserved_requests":      gorm.Expr("reserved_requests - ?", reservation.reservedRequests),
			"reserved_input_tokens":  gorm.Expr("reserved_input_tokens - ?", reservation.reservedInputTokens),
			"reserved_output_tokens": gorm.Expr("reserved_output_tokens - ?", reservation.reservedOutputTokens),
		})
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected != 1 {
		return fmt.Errorf("usage reservation unavailable")
	}
	return nil
}

func (reservation *UsageReservation) markFinalized() {
	reservation.mu.Lock()
	reservation.finalized = true
	reservation.mu.Unlock()
}

func (reservation *UsageReservation) Finalize(inputTokens, outputTokens int) error {
	reservation.mu.Lock()
	defer reservation.mu.Unlock()
	if reservation.finalized {
		return nil
	}
	err := reservation.ledger.db.Transaction(func(tx *gorm.DB) error {
		return reservation.finalizeTx(tx, inputTokens, outputTokens)
	})
	if err == nil {
		reservation.finalized = true
	}
	return err
}

func (reservation *UsageReservation) releaseTx(tx *gorm.DB) error {
	result := tx.Model(&models.DailyUsage{}).
		Where("client_id = ? AND date = ? AND reserved_requests >= ? AND reserved_input_tokens >= ? AND reserved_output_tokens >= ?",
			reservation.clientID, reservation.date, reservation.reservedRequests, reservation.reservedInputTokens, reservation.reservedOutputTokens).
		Updates(map[string]interface{}{
			"reserved_requests":      gorm.Expr("reserved_requests - ?", reservation.reservedRequests),
			"reserved_input_tokens":  gorm.Expr("reserved_input_tokens - ?", reservation.reservedInputTokens),
			"reserved_output_tokens": gorm.Expr("reserved_output_tokens - ?", reservation.reservedOutputTokens),
		})
	return result.Error
}

func (reservation *UsageReservation) Release() error {
	reservation.mu.Lock()
	defer reservation.mu.Unlock()
	if reservation.finalized {
		return nil
	}
	err := reservation.ledger.db.Transaction(func(tx *gorm.DB) error {
		return reservation.releaseTx(tx)
	})
	if err == nil {
		reservation.finalized = true
	}
	return err
}

func (l *UsageLedger) addTx(tx *gorm.DB, clientID string, inputTokens, outputTokens int, date time.Time) error {
	result := tx.Exec(`
INSERT INTO daily_usages
	(client_id, date, total_requests, total_input_tokens, total_output_tokens,
	 reserved_requests, reserved_input_tokens, reserved_output_tokens)
VALUES (?, ?, 1, ?, ?, 0, 0, 0)
ON CONFLICT(client_id, date) DO UPDATE SET
	total_requests = daily_usages.total_requests + 1,
	total_input_tokens = daily_usages.total_input_tokens + excluded.total_input_tokens,
	total_output_tokens = daily_usages.total_output_tokens + excluded.total_output_tokens`,
		clientID, date, inputTokens, outputTokens)
	return result.Error
}

func (l *UsageLedger) Add(clientID string, inputTokens, outputTokens int) error {
	return l.db.Transaction(func(tx *gorm.DB) error {
		return l.addTx(tx, clientID, inputTokens, outputTokens, UsageDate(time.Now()))
	})
}
