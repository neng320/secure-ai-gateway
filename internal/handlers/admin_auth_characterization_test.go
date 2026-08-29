package handlers

// P1-01A · Admin Authentication Characterization & Security Tests
//
// 本文件固化 tag secure-gateway-p0（2026-08-28）时点的 Admin 认证行为。
//
// 标记约定：
//   [NORMAL]                 —— 正确行为，重构后必须保持。
//   [KNOWN-VULN: SEC-00x]    —— baseline-audit.md 已确认的危险行为，
//                               测试断言的是"当前就是这个坏样子"。
//                               P1-01B~01D 重构时必须反转这些断言，
//                               并将测试改写为安全行为的回归测试。
//
// 依据：docs/baseline-audit.md §1.3 §1.4；docs/scope-v1.md SEC-001/004。
// 本文件不修复任何漏洞、不触碰 Provider Key / 日志 / 限流代码。

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"ai-gateway/internal/auth"
	"ai-gateway/internal/config"
	"ai-gateway/internal/models"
	"ai-gateway/internal/services"

	"github.com/go-chi/chi/v5"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

const (
	testAdminUser     = "admin"
	testAdminPassword = "CorrectHorse-Battery-Staple-01"
	sessionCookieName = "admin_session"
	// baseline-audit §1.3：登录成功后 Cookie 的值是这一静态字面量
	staticSessionValue = "authenticated"
)

// bcrypt 计一次，避免每个用例重复开销
var testPasswordHash = func() string {
	h, err := bcrypt.GenerateFromPassword([]byte(testAdminPassword), bcrypt.DefaultCost)
	if err != nil {
		panic(err)
	}
	return string(h)
}()

// authEnv 承载一个独立的 handler + 内存级路由；DB 用临时文件避免 :memory: 连接池陷阱
type authEnv struct {
	cfg    *config.Config
	router http.Handler
	db     *gorm.DB
	store  *auth.SQLiteStore
}

func newAuthEnv(t *testing.T) *authEnv {
	t.Helper()
	return newAuthEnvWithHash(t, testPasswordHash)
}

func newAuthEnvWithHash(t *testing.T, passwordHash string) *authEnv {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(filepath.Join(t.TempDir(), "gw.db")), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.AutoMigrate(&models.Client{}, &models.RequestLog{}, &models.DailyUsage{}, &models.AdminSession{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	// Windows 下 TempDir 清理需要先释放 SQLite 文件句柄
	t.Cleanup(func() {
		if sqlDB, err := db.DB(); err == nil {
			_ = sqlDB.Close()
		}
	})
	cfg := &config.Config{
		Server: config.ServerConfig{Host: "127.0.0.1", Port: 8090},
		Admin: config.AdminConfig{
			Username:      testAdminUser,
			PasswordHash:  passwordHash,
			SessionSecret: "test-session-secret-not-used-anywhere",
		},
		Providers: map[string]config.ProviderConfig{},
	}
	clientSvc := services.NewClientService(db)
	statsSvc := services.NewStatsService(db)
	geminiSvc := services.NewGeminiService(db, cfg)
	hub := services.NewDashboardHub(statsSvc)
	toolSvc := services.NewToolService(nil)

	store := auth.NewSQLiteStore(db)
	adminH, err := NewAdminHandler(cfg, clientSvc, statsSvc, geminiSvc, hub, toolSvc, store, auth.NewLoginRateLimiter())
	if err != nil {
		t.Fatalf("NewAdminHandler: %v", err)
	}
	r := chi.NewRouter()
	adminH.RegisterRoutes(r)
	return &authEnv{cfg: cfg, router: r, db: db, store: store}
}

func doReq(r http.Handler, method, target string, cookies []*http.Cookie) *http.Response {
	req := httptest.NewRequest(method, target, nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w.Result()
}

// extractPreAuthCSRF: 从 login/setup 页面 HTML 解析 pre-auth csrf token
func extractPreAuthCSRF(t *testing.T, body string) string {
	t.Helper()
	m := regexp.MustCompile(`name="csrf_token" value="([0-9a-f]{64})"`).FindStringSubmatch(body)
	if m == nil {
		t.Fatal("page missing pre-auth csrf token (SEC-004 wiring broken)")
	}
	return m[1]
}

func readBody(resp *http.Response) string {
	b, _ := io.ReadAll(resp.Body)
	resp.Body = io.NopCloser(strings.NewReader(string(b)))
	return string(b)
}

func findCookie(resp *http.Response, name string) *http.Cookie {
	for _, c := range resp.Cookies() {
		if c.Name == name {
			return c
		}
	}
	return nil
}

// csrfFor: 计算会话绑定 CSRF token（测试知道 SessionSecret；真实客户端由页面渲染获得）
func csrfFor(env *authEnv, rawToken string) string {
	return auth.CSRFToken(env.cfg.Admin.SessionSecret, rawToken)
}

// login: 完整 CSRF 流程——GET 登录页取 pre-auth token/Cookie，再提交
func login(t *testing.T, r http.Handler, user, pass string) *http.Response {
	t.Helper()
	pre := httptest.NewRequest("GET", "/admin/login", nil)
	w1 := httptest.NewRecorder()
	r.ServeHTTP(w1, pre)
	resp1 := w1.Result()
	token := extractPreAuthCSRF(t, readBody(resp1))
	pc := findCookie(resp1, auth.PreAuthCSRFCookie)
	if pc == nil {
		t.Fatal("login page did not set preauth_csrf cookie")
	}

	form := url.Values{"username": {user}, "password": {pass}, "csrf_token": {token}}
	req := httptest.NewRequest("POST", "/admin/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(pc)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w.Result()
}

func getSessionCookie(resp *http.Response) *http.Cookie {
	for _, c := range resp.Cookies() {
		if c.Name == sessionCookieName {
			return c
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// 登录
// ---------------------------------------------------------------------------

// [NORMAL] 正确凭据登录成功并种下会话 Cookie。
func TestAuthChar_Login_ValidCredentials_SetsSessionCookie(t *testing.T) {
	env := newAuthEnv(t)
	resp := login(t, env.router, testAdminUser, testAdminPassword)

	if resp.StatusCode != http.StatusFound {
		t.Fatalf("[NORMAL] 期望登录成功后 302 跳转 dashboard，实际 %d", resp.StatusCode)
	}
	if loc := resp.Header.Get("Location"); loc != "/admin/dashboard" {
		t.Errorf("[NORMAL] 期望跳转 /admin/dashboard，实际 %q", loc)
	}
	c := getSessionCookie(resp)
	if c == nil {
		t.Fatal("[NORMAL] 登录成功但未设置会话 Cookie")
	}
	if !c.HttpOnly {
		t.Errorf("[NORMAL] Cookie 应为 HttpOnly")
	}
	if c.SameSite != http.SameSiteStrictMode {
		t.Errorf("[NORMAL] Cookie 应为 SameSite=Strict，实际 %v", c.SameSite)
	}
	if c.Expires.Before(time.Now().Add(23 * time.Hour)) {
		t.Errorf("[NORMAL] Cookie 有效期应约 24h，实际 %v", c.Expires)
	}
}

// [P1-01C 修复后回归]（反转自 KNOWN-VULN "会话值为静态字面量"）
// 会话值必须是每次登录随机生成的高熵 token：64 位小写 hex，两次登录必不相同，
// 且绝不可能是旧的静态 "authenticated"。
func TestAuthChar_Fixed_SessionTokenIsRandomPerLogin(t *testing.T) {
	env1 := newAuthEnv(t)
	env2 := newAuthEnvWithHash(t, func() string {
		h, _ := bcrypt.GenerateFromPassword([]byte("Another-Password-42"), bcrypt.DefaultCost)
		return string(h)
	}())

	resp1 := login(t, env1.router, testAdminUser, testAdminPassword)
	resp2 := login(t, env2.router, testAdminUser, "Another-Password-42")

	c1, c2 := getSessionCookie(resp1), getSessionCookie(resp2)
	if c1 == nil || c2 == nil {
		t.Fatal("两个环境登录均未获得 Cookie")
	}
	if c1.Value == staticSessionValue || c2.Value == staticSessionValue {
		t.Fatal("[SEC-001 回退?] 会话值又变成了静态字面量")
	}
	if c1.Value == c2.Value {
		t.Fatal("[安全回归失败] 不同实例两次登录得到相同会话值")
	}
	if len(c1.Value) != 64 || strings.ToLower(c1.Value) != c1.Value ||
		strings.ContainsAny(c1.Value, "ghijklmnopqrstuvwxyz") {
		t.Fatalf("[安全回归失败] 会话值应为 64 位小写 hex（256-bit），实际 %q（len=%d）", c1.Value, len(c1.Value))
	}
	t.Logf("会话 token 已随机化：%s... / %s...", c1.Value[:8], c2.Value[:8])
}

// [NORMAL] 错误密码拒绝。
func TestAuthChar_Login_WrongPassword_401(t *testing.T) {
	env := newAuthEnv(t)
	resp := login(t, env.router, testAdminUser, "wrong-password")
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("[NORMAL] 错误密码期望 401，实际 %d", resp.StatusCode)
	}
}

// [NORMAL] 未知用户拒绝。
func TestAuthChar_Login_UnknownUser_401(t *testing.T) {
	env := newAuthEnv(t)
	resp := login(t, env.router, "nosuchuser", testAdminPassword)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("[NORMAL] 未知用户期望 401，实际 %d", resp.StatusCode)
	}
}

// ---------------------------------------------------------------------------
// 受保护路由的访问控制
// ---------------------------------------------------------------------------

// [NORMAL] 无 Cookie 访问受保护路由 → 302 到登录页。
func TestAuthChar_Protected_NoCookie_RedirectsToLogin(t *testing.T) {
	env := newAuthEnv(t)
	resp := doReq(env.router, "GET", "/admin/clients", nil)
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("[NORMAL] 无 Cookie 期望 302，实际 %d", resp.StatusCode)
	}
	if loc := resp.Header.Get("Location"); loc != "/admin/login" {
		t.Errorf("[NORMAL] 期望跳转 /admin/login，实际 %q", loc)
	}
}

// [NORMAL] Cookie 值为空串视同未携带。
func TestAuthChar_Protected_EmptyCookieValue_RedirectsToLogin(t *testing.T) {
	env := newAuthEnv(t)
	resp := doReq(env.router, "GET", "/admin/clients",
		[]*http.Cookie{{Name: sessionCookieName, Value: ""}})
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("[NORMAL] 空 Cookie 期望 302，实际 %d", resp.StatusCode)
	}
}

// [P1-01D 修复后回归]（反转自 KNOWN-VULN "任意非空 Cookie 放行"）
// 伪造/随机/历史静态值一律 302 → /admin/login。
func TestSEC001_Fixed_ForgedCookieValue_Denied(t *testing.T) {
	env := newAuthEnv(t)
	forgeries := []string{"x", "totally-forged", "authenticated", "anything-goes", strings.Repeat("ab", 32)}
	for _, v := range forgeries {
		resp := doReq(env.router, "GET", "/admin/clients",
			[]*http.Cookie{{Name: sessionCookieName, Value: v}})
		if resp.StatusCode != http.StatusFound || resp.Header.Get("Location") != "/admin/login" {
			t.Fatalf("[安全回归失败] 伪造 Cookie %q 期望 302 → /admin/login，实际 %d %q", v, resp.StatusCode, resp.Header.Get("Location"))
		}
	}
}

// [P1-01D 修复后回归]（反转自 KNOWN-VULN "伪造 Cookie 读到 JSON 统计"）
func TestSEC001_Fixed_ForgedCookie_StatsAPIDenied(t *testing.T) {
	env := newAuthEnv(t)
	resp := doReq(env.router, "GET", "/admin/stats/api",
		[]*http.Cookie{{Name: sessionCookieName, Value: "forged"}})
	if resp.StatusCode != http.StatusFound || resp.Header.Get("Location") != "/admin/login" {
		t.Fatalf("[安全回归失败] 伪造 Cookie 期望 302 → /admin/login，实际 %d %q", resp.StatusCode, resp.Header.Get("Location"))
	}
}

// [P1-01D 修复后回归]（反转自 KNOWN-VULN "过期 Cookie 仍放行"）
// 两层语义：
//
//	a) 服务端已过期的真实 token → 拒绝（服务端权威）
//	b) Cookie Expires 已过期但服务端仍有效 → 放行（同样证明权威在服务端）
func TestSEC001_Fixed_SessionExpiry_ServerAuthoritative(t *testing.T) {
	env := newAuthEnv(t)
	ctx := context.Background()

	// a) 服务端过期
	expiredToken, err := env.store.Create(ctx, "admin", time.Now().Add(-time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	resp := doReq(env.router, "GET", "/admin/clients",
		[]*http.Cookie{{Name: sessionCookieName, Value: expiredToken}})
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("[安全回归失败] 服务端过期会话期望 302，实际 %d", resp.StatusCode)
	}

	// b) 服务端有效、Cookie 侧 Expires 过期 → 放行
	validToken, err := env.store.Create(ctx, "admin", time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	staleCookie := &http.Cookie{Name: sessionCookieName, Value: validToken, Expires: time.Now().Add(-72 * time.Hour)}
	resp2 := doReq(env.router, "GET", "/admin/clients", []*http.Cookie{staleCookie})
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("[安全回归失败] 服务端有效会话应放行（Cookie 过期属性无权威性），实际 %d", resp2.StatusCode)
	}
}

// ---------------------------------------------------------------------------
// 登出
// ---------------------------------------------------------------------------

// [P1-01E 修复后回归]（反转自 KNOWN-VULN "登出不吊销"）
// 登出必须：服务端吊销会话 + 清浏览器 Cookie；登出后重放真实 token 一律拒绝。
func TestAuthChar_Fixed_Logout_RevokesServerSide(t *testing.T) {
	env := newAuthEnv(t)
	ctx := context.Background()

	loginResp := login(t, env.router, testAdminUser, testAdminPassword)
	c := getSessionCookie(loginResp)
	if c == nil {
		t.Fatal("登录未获得 Cookie")
	}

	// 登出前真实 token 可访问
	before := doReq(env.router, "GET", "/admin/clients",
		[]*http.Cookie{{Name: sessionCookieName, Value: c.Value}})
	if before.StatusCode != http.StatusOK {
		t.Fatalf("[NORMAL] 登出前合法会话应可访问，实际 %d", before.StatusCode)
	}

	// 登出
	logoutReq := httptest.NewRequest("POST", "/admin/logout", nil)
	logoutReq.AddCookie(c)
	logoutReq.Header.Set("X-CSRF-Token", csrfFor(env, c.Value))
	w := httptest.NewRecorder()
	env.router.ServeHTTP(w, logoutReq)
	logoutResp := w.Result()

	clearCookie := getSessionCookie(logoutResp)
	if clearCookie == nil || clearCookie.Value != "" {
		t.Errorf("[NORMAL] 期望登出时下发清空 Cookie，实际 %v", clearCookie)
	}

	// 重放真实 token → 拒绝
	after := doReq(env.router, "GET", "/admin/clients",
		[]*http.Cookie{{Name: sessionCookieName, Value: c.Value}})
	if after.StatusCode != http.StatusFound || after.Header.Get("Location") != "/admin/login" {
		t.Fatalf("[安全回归失败] 登出后重放会话期望 302 → /admin/login，实际 %d %q", after.StatusCode, after.Header.Get("Location"))
	}

	// DB 权威状态为已吊销
	if _, err := env.store.Validate(ctx, c.Value); err != auth.ErrSessionRevoked {
		t.Fatalf("[安全回归失败] 服务端会话状态期望 ErrSessionRevoked，实际 %v", err)
	}
}

// [P1-01E+P1-02B 回归] 登出携带未知/伪造 token：CSRF 先行拦截（403），绝无 500。
// 持有该 token 页面缓存的旧 csrf 仍可通过（HMAC 确定性），吊销为幂等 no-op。
func TestAuthChar_Fixed_Logout_UnknownToken_ForbiddenOrIdempotent(t *testing.T) {
	env := newAuthEnv(t)
	dead := strings.Repeat("ff", 32)
	// 无 CSRF → 403
	req := httptest.NewRequest("POST", "/admin/logout", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: dead})
	w := httptest.NewRecorder()
	env.router.ServeHTTP(w, req)
	if w.Result().StatusCode != http.StatusForbidden {
		t.Fatalf("unknown-token logout without CSRF expect 403, got %d", w.Result().StatusCode)
	}
	// 带该 token 派生的 csrf（模拟页面缓存）→ 幂等 302，无 500
	req2 := httptest.NewRequest("POST", "/admin/logout", nil)
	req2.AddCookie(&http.Cookie{Name: sessionCookieName, Value: dead})
	req2.Header.Set("X-CSRF-Token", csrfFor(env, dead))
	w2 := httptest.NewRecorder()
	env.router.ServeHTTP(w2, req2)
	if code := w2.Result().StatusCode; code != http.StatusFound {
		t.Fatalf("dead-token logout with derived csrf expect 302, got %d", code)
	}
}

// ---------------------------------------------------------------------------
// Setup 向导（未设密码时的认证面）
// ---------------------------------------------------------------------------

// chdir 到临时目录运行 fn（setup 会按硬编码相对路径 "config.yaml" 写文件）
func withTempWorkingDir(t *testing.T, fn func()) {
	t.Helper()
	orig, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	tmp := t.TempDir()
	if err := os.Chdir(tmp); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Chdir(orig) }()
	fn()
}

// [NORMAL] 未设密码时 setup 向导必须可达（首次部署引导）。
// 风险备注（P1-01F）：该页无认证，叠加公网监听即形成抢注窗口；生产必须 loopback。
func TestSetupChar_UnsetPassword_SetupReachableWithoutAuth(t *testing.T) {
	withTempWorkingDir(t, func() {
		env := newAuthEnvWithHash(t, "__SETUP_REQUIRED__")
		setupH := NewSetupHandler(env.cfg, false)
		r := setupEnvRouter(env)
		setupH.RegisterRoutes(r)

		resp := doReq(r, "GET", "/setup", nil)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("[NORMAL] 密码未设时 /setup 期望 200，实际 %d", resp.StatusCode)
		}
	})
}

// [NORMAL] 已设密码后 setup 必须关闭。
func TestSetupChar_PasswordSet_SetupRedirectsAway(t *testing.T) {
	env := newAuthEnv(t)
	setupH := NewSetupHandler(env.cfg, false)
	r := setupEnvRouter(env)
	setupH.RegisterRoutes(r)
	resp := doReq(r, "GET", "/setup", nil)
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("[NORMAL] 密码已设时 /setup 期望 302，实际 %d", resp.StatusCode)
	}
}

// [NORMAL] setup 完成后可用新凭据登录（并再次验证会话仍为静态值）。
func TestSetupChar_CompletesAndThenLoginWorks(t *testing.T) {
	withTempWorkingDir(t, func() {
		env := newAuthEnvWithHash(t, "__SETUP_REQUIRED__")
		setupH := NewSetupHandler(env.cfg, false)
		r := setupEnvRouter(env)
		setupH.RegisterRoutes(r)

		// 先 GET /setup 取 pre-auth CSRF（Cookie+token）
		preReq := httptest.NewRequest("GET", "/setup", nil)
		preW := httptest.NewRecorder()
		r.ServeHTTP(preW, preReq)
		preResp := preW.Result()
		token := extractPreAuthCSRF(t, readBody(preResp))
		pc := findCookie(preResp, auth.PreAuthCSRFCookie)
		if pc == nil {
			t.Fatal("setup page did not set preauth_csrf cookie")
		}

		form := url.Values{
			"username":         {"admin"},
			"password":         {"NewPass-Setup-99"},
			"confirm_password": {"NewPass-Setup-99"},
			"csrf_token":       {token},
		}
		req := httptest.NewRequest("POST", "/setup", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.AddCookie(pc)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		if w.Result().StatusCode != http.StatusFound {
			t.Fatalf("[NORMAL] setup complete expect 302, got %d", w.Result().StatusCode)
		}

		// 登录走 admin 路由（env.router），setup 走 setup 路由（r），与 main.go 的挂载方式一致
		resp := login(t, env.router, "admin", "NewPass-Setup-99")
		if resp.StatusCode != http.StatusFound {
			t.Fatalf("[NORMAL] setup 后新凭据登录期望 302，实际 %d", resp.StatusCode)
		}
		c := getSessionCookie(resp)
		if c == nil {
			t.Fatal("setup 后登录未获得 Cookie")
		}
		if c.Value == staticSessionValue || len(c.Value) != 64 {
			t.Fatalf("[安全回归失败] setup 后登录应获得 64 位随机会话 token，实际 %q", c.Value)
		}
	})
}

// setupEnvRouter: setup 路由需挂在独立的干净 router 上，避免与 admin 路由互相污染
func setupEnvRouter(env *authEnv) *chi.Mux {
	return chi.NewRouter()
}

// ---------------------------------------------------------------------------
// CSRF 面（仅固化现状，修复属 P1-02 / SEC-004）
// ---------------------------------------------------------------------------

// [P1-02B 修复后回归]（反转自 KNOWN-VULN "登录不做 CSRF 校验"）
// 缺 token / 伪造 token → 403；正确 pre-auth 流程 → 302。
func TestSEC004_Fixed_LoginCSRFEnforced(t *testing.T) {
	env := newAuthEnv(t)

	// 缺 token → 403
	form := url.Values{"username": {testAdminUser}, "password": {testAdminPassword}}
	req := httptest.NewRequest("POST", "/admin/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	env.router.ServeHTTP(w, req)
	if w.Result().StatusCode != http.StatusForbidden {
		t.Fatalf("[安全回归失败] missing CSRF token expect 403, got %d", w.Result().StatusCode)
	}

	// 伪造 token（无对应 Cookie）→ 403
	form.Set("csrf_token", strings.Repeat("ab", 32))
	req2 := httptest.NewRequest("POST", "/admin/login", strings.NewReader(form.Encode()))
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w2 := httptest.NewRecorder()
	env.router.ServeHTTP(w2, req2)
	if w2.Result().StatusCode != http.StatusForbidden {
		t.Fatalf("[安全回归失败] forged CSRF token expect 403, got %d", w2.Result().StatusCode)
	}

	// 正确 pre-auth 流程 → 302
	if resp := login(t, env.router, testAdminUser, testAdminPassword); resp.StatusCode != http.StatusFound {
		t.Fatalf("[安全回归失败] valid CSRF flow login expect 302, got %d", resp.StatusCode)
	}
	t.Log("SEC-004: login now enforces pre-auth CSRF")
}

// [P1-02B 回归] 跨会话 CSRF token 必须被拒绝（token 与会话绑定）。
func TestSEC004_Fixed_CrossSessionCSRFTokenRejected(t *testing.T) {
	env := newAuthEnv(t)
	c1 := getSessionCookie(login(t, env.router, testAdminUser, testAdminPassword))
	c2 := getSessionCookie(login(t, env.router, testAdminUser, testAdminPassword))
	if c1 == nil || c2 == nil || c1.Value == c2.Value {
		t.Fatal("two logins should yield different sessions")
	}

	// 用 t2 的 csrf 对 t1 的会话执行受保护写操作 → 403
	form := url.Values{"name": {"x"}}
	req := httptest.NewRequest("POST", "/admin/clients", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: c1.Value})
	req.Header.Set("X-CSRF-Token", csrfFor(env, c2.Value))
	w := httptest.NewRecorder()
	env.router.ServeHTTP(w, req)
	if w.Result().StatusCode != http.StatusForbidden {
		t.Fatalf("[安全回归失败] cross-session CSRF token expect 403, got %d", w.Result().StatusCode)
	}
}
