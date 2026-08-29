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
	// maxTrackedUsernames: 非 保护账号 的追踪条目上限（防恶意刷不同用户名撑爆内存）
	maxTrackedUsernames = 10000
	// maxTrackedUsernameLen: 追踪 key 的最大长度（超长用户名截断，防止巨型 map key）
	maxTrackedUsernameLen = 255
)

type loginFailure struct {
	count       int
	lastFailure time.Time // 窗口起点（滑动按 lastFailure 推进）
	lockedUntil time.Time
}

// LoginRateLimiter: 按 username 维度限制登录失败。
//
// protectedUsername（受保护账号，即真实管理员）享有硬保障：
// 容量满时其失败记录仍被追踪，攻击者无法通过刷满随机用户名关闭对它的防爆破。
type LoginRateLimiter struct {
	mu            sync.Mutex
	failures      map[string]*loginFailure
	maxFailures   int
	lockout       time.Duration
	now           func() time.Time // 可注入时钟（测试用）
	protectedUser string
}

func NewLoginRateLimiter() *LoginRateLimiter {
	return &LoginRateLimiter{
		failures:    make(map[string]*loginFailure),
		maxFailures: DefaultLoginMaxFailures,
		lockout:     DefaultLoginLockout,
		now:         time.Now,
	}
}

// Configure 覆盖默认阈值并指定受保护账号（来自 admin.* 配置）。
func (l *LoginRateLimiter) Configure(maxFailures int, lockout time.Duration, protectedUsername string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if maxFailures > 0 {
		l.maxFailures = maxFailures
	}
	if lockout > 0 {
		l.lockout = lockout
	}
	l.protectedUser = l.normalize(protectedUsername)
}

// normalize: 追踪 key 截断（安全方向：截断碰撞只会累计更保守的失败计数）
func (l *LoginRateLimiter) normalize(username string) string {
	if len(username) > maxTrackedUsernameLen {
		return username[:maxTrackedUsernameLen]
	}
	return username
}

// Allow 判断该 username 当前是否允许尝试登录（未锁定）。
func (l *LoginRateLimiter) Allow(username string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	f, ok := l.failures[l.normalize(username)]
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
	f, ok := l.failures[l.normalize(username)]
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
//
// 容量语义（P1-02.1 修正）：受保护账号不受容量限制——攻击者刷满随机用户名
// 也绝不能关闭对真实管理员的防爆破；仅对非保护账号应用容量上限。
func (l *LoginRateLimiter) RecordFailure(username string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	username = l.normalize(username)

	if username != l.protectedUser && len(l.failures) >= maxTrackedUsernames {
		// 容量保护（仅非保护账号）：先清过期；仍满则放弃追踪该随机用户名
		l.trimExpiredLocked(now)
		if _, isProtected := l.failures[username]; !isProtected && len(l.failures) >= maxTrackedUsernames {
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
	delete(l.failures, l.normalize(username))
}

// SetProtectedUser: 运行时切换受保护账号（Setup 完成修改用户名后同步，P1-02.2）。
// - 立即生效：新受保护账号不受容量上限约束（容量满仍被追踪）
// - 清除新账号已有失败状态：成功的 Setup 从干净登录状态开始
// - 旧账号的失败条目保留，交给惰性过期/容量淘汰（有界，不无限增长）
func (l *LoginRateLimiter) SetProtectedUser(username string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	normalized := l.normalize(username)
	l.protectedUser = normalized
	delete(l.failures, normalized)
}

// trimExpiredLocked: 清理锁定与窗口均已过期的条目（调用方持锁）。
func (l *LoginRateLimiter) trimExpiredLocked(now time.Time) {
	for k, f := range l.failures {
		if now.After(f.lockedUntil) && now.Sub(f.lastFailure) > l.lockout {
			delete(l.failures, k)
		}
	}
}
