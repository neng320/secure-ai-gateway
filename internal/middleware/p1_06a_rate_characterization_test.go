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

func TestP106A_A_MinuteLimitCurrentBehavior(t *testing.T) {
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
	t.Log("[A CURRENT] minute bucket allows capacity then returns HTTP 429")
}

func TestP106A_B_HourLimitUsesSameOneMinuteRefillAndHeaders(t *testing.T) {
	rl := NewRateLimiter()
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
	if resp.Header().Get("Retry-After") != "" || resp.Header().Get("X-RateLimit-Limit-Hour") != "" {
		t.Fatalf("[B] current hour 429 contract has no Retry-After/limit header: headers=%v", resp.Header())
	}
	limits, _ := rl.getOrCreateLimits(client)
	limits.hour.lastRefill = time.Now().Add(-time.Minute - time.Nanosecond)
	if !limits.hour.tryConsume() {
		t.Fatal("[B] current hour bucket should refill after one minute")
	}
	t.Log("[B CURRENT] hour bucket is capacity-limited but refills after one minute; failure has no Retry-After")
}

func TestP106A_C_DayLimitUsesSameOneMinuteRefill(t *testing.T) {
	rl := NewRateLimiter()
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
	limits, _ := rl.getOrCreateLimits(client)
	limits.day.lastRefill = time.Now().Add(-time.Minute - time.Nanosecond)
	if !limits.day.tryConsume() {
		t.Fatal("[C] current day bucket should refill after one minute")
	}
	t.Log("[C CURRENT] day bucket is capacity-limited but refills after one minute, not 24 hours")
}

func TestP106A_D_ConcurrentWarmBucketDoesNotExceedCapacity(t *testing.T) {
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
	t.Logf("[D CURRENT] warm cached bucket admits exactly %d concurrent requests", passed)
}

func TestP106A_D_ConcurrentColdCacheCharacterization(t *testing.T) {
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
		if passed > capacity {
			violations++
		}
	}
	t.Logf("[D CURRENT] cold-cache burst exceeded capacity in %d/%d rounds; get-or-create is not an atomic LoadOrStore", violations, rounds)
}

func TestP106A_E_DynamicLimitEditDoesNotRefreshCachedBucket(t *testing.T) {
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
	if resp := p106aRunLimiter(rl, &updated); resp.Code != http.StatusTooManyRequests {
		t.Fatal("[E] changing the client limit without ResetClient should not replace the cached bucket")
	}
	t.Log("[E KNOWN-GAP] Admin limit edits do not take effect for an existing 24-hour limiter cache entry")
}

func TestP106A_F_RestartClearsInMemoryLimiterState(t *testing.T) {
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
	t.Log("[F CURRENT] restart/new RateLimiter clears all consumption state; no persistence")
}

func TestP106A_ZeroAndNegativeLimitsFailClosed(t *testing.T) {
	for _, limit := range []int{0, -1} {
		rl := NewRateLimiter()
		client := p106aClient("p106a-invalid-"+strconv.Itoa(limit), limit, 100, 100)
		resp := p106aRunLimiter(rl, client)
		if resp.Code != http.StatusTooManyRequests {
			t.Fatalf("invalid minute limit %d should fail closed with 429, got %d", limit, resp.Code)
		}
	}
	t.Log("[CURRENT] zero and negative rate limits reject immediately; no explicit configuration validation exists")
}

func TestP106A_L_RateLimitErrorContract(t *testing.T) {
	rl := NewRateLimiter()
	client := p106aClient("p106a-error", 1, 100, 100)
	if resp := p106aRunLimiter(rl, client); resp.Code != http.StatusOK {
		t.Fatal("[L] first request should pass")
	}
	resp := p106aRunLimiter(rl, client)
	if resp.Code != http.StatusTooManyRequests {
		t.Fatalf("[L] exhausted limiter should return 429, got %d", resp.Code)
	}
	if got := resp.Header().Get("Content-Type"); got != "text/plain; charset=utf-8" {
		t.Fatalf("[L] current limiter error is plain text despite JSON-shaped body, got content-type=%q", got)
	}
	if resp.Header().Get("Retry-After") != "" || resp.Header().Get("X-RateLimit-Limit-Minute") != "" {
		t.Fatalf("[L] current limiter error omits Retry-After and limit metadata: headers=%v", resp.Header())
	}
	if !strings.Contains(resp.Body.String(), `{"error": "Rate limit exceeded (minute)"}`) {
		t.Fatalf("[L] unexpected current error body: %q", resp.Body.String())
	}
	t.Log("[L CURRENT] rate limit response is HTTP 429 with JSON-shaped plain-text body, generic reset/remaining only, no Retry-After")
}
