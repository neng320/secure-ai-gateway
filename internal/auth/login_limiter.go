package auth

// P1-02D · Admin Login Brute-force Protection
//
// 设计（按 scope 约束）：
// - 单管理员/username 维度，本地内存状态，不依赖 Redis
// - 不信任 X-Forwarded-For（生产在 Caddy 之后，可伪造）
// - 连续失败 ≥ 阈值 → 锁定窗口内返回 429 + Retry-After
// - 成功登录清除该 username 的失败状态
// - 状态带 TTL，惰性过期 + 容量上限（防内存无限增长）
// - 服务重启清零（V1 可接受）
// - 对外不区分"用户不存在"与"密码错误"

import (
	"sync"
	"time"
)

const (
	// DefaultLoginMaxFailures: 触发锁定的连续失败次数
	DefaultLoginMaxFailures = 5
	// DefaultLoginLockout: 锁定时长（同时是失败窗口：窗口外失败自动过期重计）
	DefaultLoginLockout = 15 * time.Minute
	// maxTrackedUsernames: 追踪条目上限（防恶意刷不同用户名撑爆内存）
	maxTrackedUsernames = 10000
)

type loginFailure struct {
	count       int
	lastFailure time.Time // 窗口起点（滑动按 lastFailure 推进）
	lockedUntil time.Time
}

// LoginRateLimiter: 按 username 维度限制登录失败。
type LoginRateLimiter struct {
	mu          sync.Mutex
	failures    map[string]*loginFailure
	maxFailures int
	lockout     time.Duration
	now         func() time.Time // 可注入时钟（测试用）
}

func NewLoginRateLimiter() *LoginRateLimiter {
	return &LoginRateLimiter{
		failures:    make(map[string]*loginFailure),
		maxFailures: DefaultLoginMaxFailures,
		lockout:     DefaultLoginLockout,
		now:         time.Now,
	}
}

// Configure 覆盖默认阈值（来自 admin.login_max_failures / login_lockout_minutes）。
func (l *LoginRateLimiter) Configure(maxFailures int, lockout time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if maxFailures > 0 {
		l.maxFailures = maxFailures
	}
	if lockout > 0 {
		l.lockout = lockout
	}
}

// Allow 判断该 username 当前是否允许尝试登录（未锁定）。
func (l *LoginRateLimiter) Allow(username string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	f, ok := l.failures[username]
	if !ok {
		return true
	}
	now := l.now()
	if f.lockedUntil.IsZero() || now.After(f.lockedUntil) {
		return true
	}
	return false
}

// RetryAfter: 锁定剩余秒数（未锁定返回 0）。
func (l *LoginRateLimiter) RetryAfter(username string) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	f, ok := l.failures[username]
	if !ok {
		return 0
	}
	now := l.now()
	if f.lockedUntil.IsZero() || now.After(f.lockedUntil) {
		return 0
	}
	return int(f.lockedUntil.Sub(now).Seconds()) + 1
}

// RecordFailure 记录一次失败；达到阈值即进入锁定窗口。
func (l *LoginRateLimiter) RecordFailure(username string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()

	if len(l.failures) >= maxTrackedUsernames {
		// 容量保护：先清过期；仍满则拒绝追踪新条目（该用户名走普通失败流）
		l.trimExpiredLocked(now)
		if len(l.failures) >= maxTrackedUsernames {
			return
		}
	}

	f, ok := l.failures[username]
	if !ok {
		l.failures[username] = &loginFailure{count: 1, lastFailure: now}
		return
	}
	// 窗口过期则重置计数
	if now.Sub(f.lastFailure) > l.lockout {
		f.count = 0
	}
	f.count++
	f.lastFailure = now
	if f.count >= l.maxFailures {
		f.lockedUntil = now.Add(l.lockout)
	}
}

// RecordSuccess: 登录成功即清除该 username 的失败状态。
func (l *LoginRateLimiter) RecordSuccess(username string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.failures, username)
}

// trimExpiredLocked: 清理锁定与窗口均已过期的条目（调用方持锁）。
func (l *LoginRateLimiter) trimExpiredLocked(now time.Time) {
	for k, f := range l.failures {
		if now.After(f.lockedUntil) && now.Sub(f.lastFailure) > l.lockout {
			delete(l.failures, k)
		}
	}
}
