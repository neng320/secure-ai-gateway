package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"ai-gateway/internal/models"
)

type p106aFakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func newP106aFakeClock() *p106aFakeClock {
	return &p106aFakeClock{now: time.Unix(1000, 0)}
}

func (c *p106aFakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *p106aFakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	c.mu.Unlock()
}

func p106aClient(id string, minute, hour, day int) *models.Client {
	return &models.Client{ID: id, Name: id, IsActive: true, RateLimitMinute: minute, RateLimitHour: hour, RateLimitDay: day}
}

func p106aLimiterRequest(client *models.Client) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "/p106a", nil)
	return req.WithContext(context.WithValue(req.Context(), ClientContextKey, client))
}

func p106aRunLimiter(rl *RateLimiter, client *models.Client) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	h := rl.Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	h.ServeHTTP(w, p106aLimiterRequest(client))
	return w
}

func TestP106B_A_MinuteLimitCurrentBehavior(t *testing.T) {
	rl := NewRateLimiter()
	client := p106aClient("p106a-minute", 2, 100, 100)

	for i := 0; i < 2; i++ {
		resp := p106aRunLimiter(rl, client)
		if resp.Code != http.StatusOK {
			t.Fatalf("[A] request %d should pass, got %d", i+1, resp.Code)
		}
	}
	resp := p106aRunLimiter(rl, client)
	if resp.Code != http.StatusTooManyRequests || !strings.Contains(resp.Body.String(), "minute") {
		t.Fatalf("[A] third request should be minute 429, got status=%d body=%q", resp.Code, resp.Body.String())
	}
	if resp.Header().Get("X-RateLimit-Remaining") != "0" {
		t.Fatalf("[A] exhausted response should expose generic remaining=0, got %q", resp.Header().Get("X-RateLimit-Remaining"))
	}
	reset, err := strconv.ParseInt(resp.Header().Get("X-RateLimit-Reset"), 10, 64)
	if err != nil || reset <= time.Now().Unix() {
		t.Fatalf("[A] exhausted response should expose a future reset, got %q", resp.Header().Get("X-RateLimit-Reset"))
	}
	t.Log("[A FIXED] minute bucket allows capacity then returns HTTP 429")
}

func TestP106B_RateWindowsRollbackEarlierConsumptionOnLaterFailure(t *testing.T) {
	rl := NewRateLimiter()
	client := p106aClient("p106b-atomic-rate", 10, 1, 10)
	if resp := p106aRunLimiter(rl, client); resp.Code != http.StatusOK {
		t.Fatal("[atomic rate] first request should pass")
	}
	if resp := p106aRunLimiter(rl, client); resp.Code != http.StatusTooManyRequests || !strings.Contains(resp.Body.String(), "hour") {
		t.Fatalf("[atomic rate] second request should fail at hour window, got %d %q", resp.Code, resp.Body.String())
	}
	limits, _ := rl.getOrCreateLimits(client)
	limits.mu.Lock()
	minuteRemaining := limits.minute.tokens
	hourRemaining := limits.hour.tokens
	limits.mu.Unlock()
	if minuteRemaining != 9 || hourRemaining != 0 {
		t.Fatalf("[atomic rate] later-window failure must rollback minute only: minute=%d hour=%d", minuteRemaining, hourRemaining)
	}
	t.Log("[atomic rate FIXED] later-window rejection does not consume earlier-window capacity")
}

func TestP106B_B_HourLimitUsesRealWindowAndHeaders(t *testing.T) {
	clock := newP106aFakeClock()
	rl := NewRateLimiterWithClock(clock.Now)
	client := p106aClient("p106a-hour", 100, 2, 100)
	for i := 0; i < 2; i++ {
		if resp := p106aRunLimiter(rl, client); resp.Code != http.StatusOK {
			t.Fatalf("[B] request %d should pass, got %d", i+1, resp.Code)
		}
	}
	resp := p106aRunLimiter(rl, client)
	if resp.Code != http.StatusTooManyRequests || !strings.Contains(resp.Body.String(), "hour") {
		t.Fatalf("[B] third request should be hour 429, got status=%d body=%q", resp.Code, resp.Body.String())
	}
	if resp.Header().Get("Retry-After") != "3600" || resp.Header().Get("X-RateLimit-Limit-Hour") != "2" {
		t.Fatalf("[B] hour 429 should expose Retry-After/limit metadata: headers=%v", resp.Header())
	}
	clock.Advance(time.Hour - time.Nanosecond)
	if resp := p106aRunLimiter(rl, client); resp.Code != http.StatusTooManyRequests {
		t.Fatalf("[B] hour bucket should remain exhausted before one hour, got %d", resp.Code)
	}
	clock.Advance(time.Nanosecond)
	if resp := p106aRunLimiter(rl, client); resp.Code != http.StatusOK {
		t.Fatalf("[B] hour bucket should refill at one hour, got %d", resp.Code)
	}
	t.Log("[B FIXED] hour bucket has a real one-hour fixed window and stable 429 metadata")
}

func TestP106B_C_DayLimitUsesRealWindow(t *testing.T) {
	clock := newP106aFakeClock()
	rl := NewRateLimiterWithClock(clock.Now)
	client := p106aClient("p106a-day", 100, 100, 2)
	for i := 0; i < 2; i++ {
		if resp := p106aRunLimiter(rl, client); resp.Code != http.StatusOK {
			t.Fatalf("[C] request %d should pass, got %d", i+1, resp.Code)
		}
	}
	resp := p106aRunLimiter(rl, client)
	if resp.Code != http.StatusTooManyRequests || !strings.Contains(resp.Body.String(), "day") {
		t.Fatalf("[C] third request should be day 429, got status=%d body=%q", resp.Code, resp.Body.String())
	}
	clock.Advance(24*time.Hour - time.Nanosecond)
	if resp := p106aRunLimiter(rl, client); resp.Code != http.StatusTooManyRequests {
		t.Fatalf("[C] day bucket should remain exhausted before 24 hours, got %d", resp.Code)
	}
	clock.Advance(time.Nanosecond)
	if resp := p106aRunLimiter(rl, client); resp.Code != http.StatusOK {
		t.Fatalf("[C] day bucket should refill at 24 hours, got %d", resp.Code)
	}
	t.Log("[C FIXED] day bucket has a real 24-hour fixed window")
}

func TestP106B_D_ConcurrentWarmBucketDoesNotExceedCapacity(t *testing.T) {
	rl := NewRateLimiter()
	client := p106aClient("p106a-concurrent", 32, 1000, 1000)
	if _, err := rl.getOrCreateLimits(client); err != nil {
		t.Fatal(err)
	}

	const requests = 128
	start := make(chan struct{})
	results := make(chan int, requests)
	var wg sync.WaitGroup
	for i := 0; i < requests; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			results <- p106aRunLimiter(rl, client).Code
		}()
	}
	close(start)
	wg.Wait()
	close(results)

	passed := 0
	for status := range results {
		if status == http.StatusOK {
			passed++
		}
	}
	if passed != client.RateLimitMinute {
		t.Fatalf("[D] warm cached bucket should admit exactly capacity=%d, got %d/%d", client.RateLimitMinute, passed, requests)
	}
	t.Logf("[D FIXED] warm cached bucket admits exactly %d concurrent requests", passed)
}

func TestP106B_D_ConcurrentColdCacheCharacterization(t *testing.T) {
	const (
		rounds   = 32
		capacity = 8
		workers  = 64
	)
	violations := 0
	for round := 0; round < rounds; round++ {
		rl := NewRateLimiter()
		client := p106aClient("p106a-cold-"+strconv.Itoa(round), capacity, 1000, 1000)
		start := make(chan struct{})
		results := make(chan int, workers)
		var wg sync.WaitGroup
		for i := 0; i < workers; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				results <- p106aRunLimiter(rl, client).Code
			}()
		}
		close(start)
		wg.Wait()
		close(results)

		passed := 0
		for status := range results {
			if status == http.StatusOK {
				passed++
			}
		}
		if passed != capacity {
			violations++
		}
	}
	if violations != 0 {
		t.Fatalf("[D] cold-cache burst should admit exactly capacity in every round, violations=%d/%d", violations, rounds)
	}
	t.Logf("[D FIXED] cold-cache burst admitted exactly capacity in all %d rounds via atomic LoadOrStore", rounds)
}

func TestP106B_E_DynamicLimitEditPreservesConsumption(t *testing.T) {
	rl := NewRateLimiter()
	client := p106aClient("p106a-dynamic", 1, 100, 100)
	if resp := p106aRunLimiter(rl, client); resp.Code != http.StatusOK {
		t.Fatal("[E] first request should pass")
	}
	if resp := p106aRunLimiter(rl, client); resp.Code != http.StatusTooManyRequests {
		t.Fatal("[E] second request should exhaust old limit")
	}
	updated := *client
	updated.RateLimitMinute = 10
	resp := p106aRunLimiter(rl, &updated)
	if resp.Code != http.StatusOK || resp.Header().Get("X-RateLimit-Remaining-Minute") != "8" {
		t.Fatalf("[E] increasing limit should preserve one consumed token, got status=%d remaining=%q", resp.Code, resp.Header().Get("X-RateLimit-Remaining-Minute"))
	}
	updated.RateLimitMinute = 1
	if resp := p106aRunLimiter(rl, &updated); resp.Code != http.StatusTooManyRequests {
		t.Fatal("[E] lowering limit below prior consumption should not grant a free token")
	}
	t.Log("[E FIXED] dynamic limit edits take effect and preserve prior consumption")
}

func TestP106B_F_RestartClearsInMemoryLimiterState(t *testing.T) {
	client := p106aClient("p106a-restart", 1, 100, 100)
	rl := NewRateLimiter()
	if resp := p106aRunLimiter(rl, client); resp.Code != http.StatusOK {
		t.Fatal("[F] first request should pass")
	}
	if resp := p106aRunLimiter(rl, client); resp.Code != http.StatusTooManyRequests {
		t.Fatal("[F] second request should be rate-limited")
	}
	if resp := p106aRunLimiter(NewRateLimiter(), client); resp.Code != http.StatusOK {
		t.Fatal("[F] a new limiter instance should start with a full in-memory bucket")
	}
	t.Log("[F FIXED] restart/new RateLimiter clears all consumption state; no persistence")
}

func TestP106B_ZeroAndNegativeLimitsFailClosed(t *testing.T) {
	for _, limit := range []int{0, -1} {
		rl := NewRateLimiter()
		client := p106aClient("p106a-invalid-"+strconv.Itoa(limit), limit, 100, 100)
		resp := p106aRunLimiter(rl, client)
		if resp.Code != http.StatusTooManyRequests {
			t.Fatalf("invalid minute limit %d should fail closed with 429, got %d", limit, resp.Code)
		}
	}
	t.Log("[FIXED] zero and negative rate limits reject immediately; no unlimited interpretation")
}

func TestP106B_L_RateLimitErrorContract(t *testing.T) {
	rl := NewRateLimiter()
	client := p106aClient("p106a-error", 1, 100, 100)
	if resp := p106aRunLimiter(rl, client); resp.Code != http.StatusOK {
		t.Fatal("[L] first request should pass")
	}
	resp := p106aRunLimiter(rl, client)
	if resp.Code != http.StatusTooManyRequests {
		t.Fatalf("[L] exhausted limiter should return 429, got %d", resp.Code)
	}
	if got := resp.Header().Get("Content-Type"); got != "application/json" {
		t.Fatalf("[L] limiter error should use JSON content type, got %q", got)
	}
	if resp.Header().Get("Retry-After") == "" || resp.Header().Get("X-RateLimit-Limit-Minute") != "1" {
		t.Fatalf("[L] limiter error should include Retry-After and minute limit metadata: headers=%v", resp.Header())
	}
	if resp.Header().Get("X-RateLimit-Remaining-Minute") != "0" || resp.Header().Get("X-RateLimit-Remaining-Hour") != "99" || resp.Header().Get("X-RateLimit-Remaining-Day") != "99" {
		t.Fatalf("[L] limiter error should expose all window remaining values: headers=%v", resp.Header())
	}
	if !strings.Contains(resp.Body.String(), `"code":"RATE_LIMIT_EXCEEDED"`) || !strings.Contains(resp.Body.String(), `"window":"minute"`) {
		t.Fatalf("[L] unexpected stable error body: %q", resp.Body.String())
	}
	t.Log("[L FIXED] rate limit response is stable JSON 429 with Retry-After and window metadata")
}
