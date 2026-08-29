package auth

// P1-02D · LoginRateLimiter 单元测试（TTL 用注入时钟验证，不依赖真实等待）

import (
	"fmt"
	"strings"
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

// [P1-02.1 安全回归] 容量打满后，真实管理员的失败必须仍被追踪（禁止 fail-open）。
func TestLimiter_CapacityFull_ProtectedAccountStillTracked(t *testing.T) {
	l, _ := newTestLimiter()
	l.Configure(DefaultLoginMaxFailures, DefaultLoginLockout, "admin")

	// 刷满容量
	for i := 0; i < maxTrackedUsernames; i++ {
		l.RecordFailure(fmt.Sprintf("user%06d", i))
	}

	// 攻击真实 admin：达到阈值必须锁定
	for i := 0; i < DefaultLoginMaxFailures; i++ {
		l.RecordFailure("admin")
	}
	if l.Allow("admin") {
		t.Fatal("[安全回归失败] 容量打满后 admin 防爆破失效（fail-open）")
	}
	if ra := l.RetryAfter("admin"); ra <= 0 {
		t.Fatalf("[安全回归失败] admin 锁定后 Retry-After 应 > 0，实际 %d", ra)
	}
}

// [P1-02.1 回归] 超长 username 截断为固定 key（防巨型 map key），行为精确断言：
//   - 255 字节规范化 key 与 long 共享失败状态 → 同样锁定
//   - 254 字节不同 key → 无失败记录 → 允许
func TestLimiter_LongUsername_Truncated(t *testing.T) {
	l, _ := newTestLimiter()
	l.Configure(DefaultLoginMaxFailures, DefaultLoginLockout, "admin")
	long := strings.Repeat("x", 10000)
	for i := 0; i < DefaultLoginMaxFailures; i++ {
		l.RecordFailure(long)
	}
	if l.Allow(long) {
		t.Fatal("超长用户名达到阈值后应锁定")
	}
	if l.Allow(long[:maxTrackedUsernameLen]) {
		t.Fatal("[安全回归失败] 255 字节规范化 key 应与 long 共享失败状态并锁定")
	}
	if !l.Allow(long[:maxTrackedUsernameLen-1]) {
		t.Fatal("[安全回归失败] 254 字节不同 key 应独立计算并允许")
	}
}

// [P1-02.2 回归] 容量满后 SetProtectedUser 切换的新账号必须被继续追踪。
func TestLimiter_SetProtectedUser_TrackedUnderFullCapacity(t *testing.T) {
	l, _ := newTestLimiter()
	l.Configure(DefaultLoginMaxFailures, DefaultLoginLockout, "oldadmin")
	for i := 0; i < maxTrackedUsernames; i++ {
		l.RecordFailure(fmt.Sprintf("user%06d", i))
	}
	l.SetProtectedUser("newadmin")
	for i := 0; i < DefaultLoginMaxFailures; i++ {
		l.RecordFailure("newadmin")
	}
	if l.Allow("newadmin") {
		t.Fatal("[安全回归失败] 容量满 + SetProtectedUser 后新管理员仍 fail-open")
	}
}

// [P1-02.2 回归] SetProtectedUser 清除新账号已有失败状态（干净起点）。
func TestLimiter_SetProtectedUser_ClearsNewUserFailures(t *testing.T) {
	l, _ := newTestLimiter()
	l.Configure(DefaultLoginMaxFailures, DefaultLoginLockout, "oldadmin")
	for i := 0; i < 3; i++ {
		l.RecordFailure("newadmin")
	}
	l.SetProtectedUser("newadmin")
	// 清零后：再累计 2 次（合计不足阈值）不应锁定
	l.RecordFailure("newadmin")
	l.RecordFailure("newadmin")
	if !l.Allow("newadmin") {
		t.Fatal("[安全回归失败] SetProtectedUser 未清除新账号失败状态（应从干净起点累计）")
	}
}
