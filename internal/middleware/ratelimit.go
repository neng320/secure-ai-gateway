package middleware

import (
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"sync"
	"time"

	"ai-gateway/internal/models"
)

type Clock func() time.Time

type RateLimiter struct {
	clock  Clock
	limits sync.Map // client ID -> *clientLimits
}

type clientLimits struct {
	mu     sync.Mutex
	minute rateWindow
	hour   rateWindow
	day    rateWindow
}

type rateWindow struct {
	capacity   int
	tokens     int
	window     time.Duration
	lastRefill time.Time
}

func newRateWindow(capacity int, window time.Duration, now time.Time) rateWindow {
	return rateWindow{capacity: capacity, tokens: capacity, window: window, lastRefill: now}
}

func NewRateLimiter() *RateLimiter {
	return NewRateLimiterWithClock(time.Now)
}

func NewRateLimiterWithClock(clock Clock) *RateLimiter {
	if clock == nil {
		clock = time.Now
	}
	return &RateLimiter{clock: clock}
}

func (rl *RateLimiter) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		client := GetClientFromContext(r.Context())
		if client == nil {
			next.ServeHTTP(w, r)
			return
		}

		limits, err := rl.getOrCreateLimits(client)
		if err != nil {
			writeRateLimitError(w, rateLimitError{code: "RATE_LIMIT_CONFIGURATION_INVALID", message: "rate limit configuration invalid", status: http.StatusInternalServerError})
			return
		}

		result := limits.tryConsume(client.RateLimitMinute, client.RateLimitHour, client.RateLimitDay, rl.clock())
		if !result.allowed {
			writeRateLimitError(w, result.err)
			return
		}

		setRateLimitHeaders(w, client, result.remaining)
		next.ServeHTTP(w, r)
	})
}

type rateLimitError struct {
	code       string
	message    string
	window     string
	reset      time.Time
	status     int
	limit      int
	remaining  rateLimitRemaining
	limits     rateLimitRemaining
	retryAfter int
}

type consumeResult struct {
	allowed   bool
	remaining rateLimitRemaining
	err       rateLimitError
}

type rateLimitRemaining struct {
	minute int
	hour   int
	day    int
}

func (limits *clientLimits) tryConsume(minuteCapacity, hourCapacity, dayCapacity int, now time.Time) consumeResult {
	limits.mu.Lock()
	defer limits.mu.Unlock()

	limits.minute.adjustCapacity(minuteCapacity, now)
	limits.hour.adjustCapacity(hourCapacity, now)
	limits.day.adjustCapacity(dayCapacity, now)
	limits.minute.refill(now)
	limits.hour.refill(now)
	limits.day.refill(now)

	windows := []*rateWindow{&limits.minute, &limits.hour, &limits.day}
	names := []string{"minute", "hour", "day"}
	for i, window := range windows {
		if window.capacity <= 0 || window.tokens <= 0 {
			for j := 0; j < i; j++ {
				windows[j].tokens++
			}
			reset := window.lastRefill.Add(window.window)
			retryAfter := int(math.Ceil(reset.Sub(now).Seconds()))
			if retryAfter < 1 {
				retryAfter = 1
			}
			return consumeResult{err: rateLimitError{
				code:    "RATE_LIMIT_EXCEEDED",
				message: "rate limit exceeded",
				window:  names[i],
				reset:   reset,
				status:  http.StatusTooManyRequests,
				limit:   window.capacity,
				remaining: rateLimitRemaining{
					minute: limits.minute.tokens,
					hour:   limits.hour.tokens,
					day:    limits.day.tokens,
				},
				limits: rateLimitRemaining{
					minute: limits.minute.capacity,
					hour:   limits.hour.capacity,
					day:    limits.day.capacity,
				},
				retryAfter: retryAfter,
			}}
		}
		window.tokens--
	}

	return consumeResult{
		allowed: true,
		remaining: rateLimitRemaining{
			minute: limits.minute.tokens,
			hour:   limits.hour.tokens,
			day:    limits.day.tokens,
		},
	}
}

func (window *rateWindow) adjustCapacity(capacity int, now time.Time) {
	if capacity == window.capacity {
		return
	}
	consumed := window.capacity - window.tokens
	if consumed < 0 {
		consumed = 0
	}
	window.capacity = capacity
	window.tokens = capacity - consumed
	if window.tokens < 0 {
		window.tokens = 0
	}
	if window.tokens > capacity {
		window.tokens = capacity
	}
	if window.lastRefill.IsZero() {
		window.lastRefill = now
	}
}

func (window *rateWindow) refill(now time.Time) {
	if now.Sub(window.lastRefill) >= window.window {
		window.tokens = window.capacity
		window.lastRefill = now
	}
}

func (rl *RateLimiter) getOrCreateLimits(client *models.Client) (*clientLimits, error) {
	if client == nil {
		return nil, fmt.Errorf("nil client")
	}
	now := rl.clock()
	candidate := &clientLimits{
		minute: newRateWindow(client.RateLimitMinute, time.Minute, now),
		hour:   newRateWindow(client.RateLimitHour, time.Hour, now),
		day:    newRateWindow(client.RateLimitDay, 24*time.Hour, now),
	}
	actual, _ := rl.limits.LoadOrStore(client.ID, candidate)
	return actual.(*clientLimits), nil
}

func (rl *RateLimiter) ResetClient(clientID string) {
	rl.limits.Delete(clientID)
}

func setRateLimitHeaders(w http.ResponseWriter, client *models.Client, remaining rateLimitRemaining) {
	w.Header().Set("X-RateLimit-Limit-Minute", fmt.Sprintf("%d", client.RateLimitMinute))
	w.Header().Set("X-RateLimit-Limit-Hour", fmt.Sprintf("%d", client.RateLimitHour))
	w.Header().Set("X-RateLimit-Limit-Day", fmt.Sprintf("%d", client.RateLimitDay))
	w.Header().Set("X-RateLimit-Remaining-Minute", fmt.Sprintf("%d", remaining.minute))
	w.Header().Set("X-RateLimit-Remaining-Hour", fmt.Sprintf("%d", remaining.hour))
	w.Header().Set("X-RateLimit-Remaining-Day", fmt.Sprintf("%d", remaining.day))
}

func writeRateLimitError(w http.ResponseWriter, err rateLimitError) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-RateLimit-Remaining", fmt.Sprintf("%d", rateLimitErrorRemaining(err)))
	w.Header().Set("X-RateLimit-Remaining-Minute", fmt.Sprintf("%d", err.remaining.minute))
	w.Header().Set("X-RateLimit-Remaining-Hour", fmt.Sprintf("%d", err.remaining.hour))
	w.Header().Set("X-RateLimit-Remaining-Day", fmt.Sprintf("%d", err.remaining.day))
	if !err.reset.IsZero() {
		w.Header().Set("X-RateLimit-Reset", fmt.Sprintf("%d", err.reset.Unix()))
		retryAfter := err.retryAfter
		if retryAfter < 1 {
			retryAfter = 1
		}
		w.Header().Set("Retry-After", fmt.Sprintf("%d", retryAfter))
	}
	if err.limit >= 0 {
		w.Header().Set("X-RateLimit-Limit-Minute", fmt.Sprintf("%d", err.limits.minute))
		w.Header().Set("X-RateLimit-Limit-Hour", fmt.Sprintf("%d", err.limits.hour))
		w.Header().Set("X-RateLimit-Limit-Day", fmt.Sprintf("%d", err.limits.day))
	}
	if err.status == 0 {
		err.status = http.StatusTooManyRequests
	}
	w.WriteHeader(err.status)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"error": map[string]string{
			"code":    err.code,
			"message": err.message,
			"window":  err.window,
		},
	})
}

func rateLimitErrorRemaining(err rateLimitError) int {
	switch err.window {
	case "minute":
		return err.remaining.minute
	case "hour":
		return err.remaining.hour
	case "day":
		return err.remaining.day
	default:
		return 0
	}
}
