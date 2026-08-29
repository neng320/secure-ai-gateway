package auth

// P1-02D · LoginRateLimiter 单元测试（TTL 用注入时钟验证，不依赖真实等待）

import (
	"testing"
	"time"
)

func newTestLimiter() (*LoginRateLimiter, *time.Time) {
	l := NewLoginRateLimiter()
	current := time.Now()
	l.now = func() time.Time { return current }
	return l, &current
}

func advance(t *testing.T, current *time.Time, d time.Duration) {
	t.Helper()
	*current = current.Add(d)
}

func TestLimiter_WithinThreshold_AllowsAll(t *testing.T) {
	l, _ := newTestLimiter()
	for i := 0; i < DefaultLoginMaxFailures-1; i++ {
		if !l.Allow("admin") {
			t.Fatalf("第 %d 次失败前应允许登录", i+1)
		}
		l.RecordFailure("admin")
	}
	if !l.Allow("admin") {
		t.Fatal("达到阈值-1 次失败时仍应允许")
	}
}

func TestLimiter_ExceedThreshold_Locks(t *testing.T) {
	l, _ := newTestLimiter()
	for i := 0; i < DefaultLoginMaxFailures; i++ {
		l.RecordFailure("admin")
	}
	if l.Allow("admin") {
		t.Fatal("达到阈值后应锁定")
	}
	if ra := l.RetryAfter("admin"); ra <= 0 || ra > int(DefaultLoginLockout.Seconds())+1 {
		t.Fatalf("Retry-After 应在 (0, lockout] 内，实际 %d", ra)
	}
}

func TestLimiter_LockoutExpires_AfterTTL(t *testing.T) {
	l, cur := newTestLimiter()
	for i := 0; i < DefaultLoginMaxFailures; i++ {
		l.RecordFailure("admin")
	}
	if l.Allow("admin") {
		t.Fatal("锁定期内应拒绝")
	}
	advance(t, cur, DefaultLoginLockout+time.Second)
	if !l.Allow("admin") {
		t.Fatal("TTL 过后应解锁")
	}
	if l.RetryAfter("admin") != 0 {
		t.Fatal("解锁后 Retry-After 应为 0")
	}
}

func TestLimiter_SuccessResetsFailures(t *testing.T) {
	l, _ := newTestLimiter()
	for i := 0; i < DefaultLoginMaxFailures-2; i++ {
		l.RecordFailure("admin")
	}
	l.RecordSuccess("admin")
	for i := 0; i < DefaultLoginMaxFailures; i++ {
		if !l.Allow("admin") {
			t.Fatalf("成功清零后第 %d 次失败前不应锁定", i+1)
		}
		l.RecordFailure("admin")
	}
	// 重新累计满阈值才锁定
	if l.Allow("admin") {
		t.Fatal("重置后再次累计满阈值应锁定")
	}
}

func TestLimiter_UnknownUsername_NoState(t *testing.T) {
	l, _ := newTestLimiter()
	if !l.Allow("nobody") {
		t.Fatal("未知用户名默认应允许")
	}
	if l.RetryAfter("nobody") != 0 {
		t.Fatal("未知用户名 RetryAfter 应为 0")
	}
}

func TestLimiter_PerUsernameIsolation(t *testing.T) {
	l, _ := newTestLimiter()
	for i := 0; i < DefaultLoginMaxFailures; i++ {
		l.RecordFailure("userA")
	}
	if l.Allow("userA") {
		t.Fatal("userA 应锁定")
	}
	if !l.Allow("userB") {
		t.Fatal("userA 锁定不应影响 userB")
	}
}

func TestLimiter_WindowExpiryResetsCount(t *testing.T) {
	l, cur := newTestLimiter()
	for i := 0; i < DefaultLoginMaxFailures-1; i++ {
		l.RecordFailure("admin")
	}
	advance(t, cur, DefaultLoginLockout+time.Minute) // 失败窗口过期
	l.RecordFailure("admin")                         // 只算 1 次
	if !l.Allow("admin") {
		t.Fatal("窗口过期后计数应重置，1 次失败不应锁定")
	}
}
