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
	"bytes"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
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

	adminH, err := NewAdminHandler(cfg, clientSvc, statsSvc, geminiSvc, hub, toolSvc, auth.NewSQLiteStore(db))
	if err != nil {
		t.Fatalf("NewAdminHandler: %v", err)
	}
	r := chi.NewRouter()
	adminH.RegisterRoutes(r)
	return &authEnv{cfg: cfg, router: r, db: db}
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

func login(t *testing.T, r http.Handler, user, pass string) *http.Response {
	t.Helper()
	form := url.Values{"username": {user}, "password": {pass}}
	req := httptest.NewRequest("POST", "/admin/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
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

// [KNOWN-VULN: SEC-001] ★漏洞复现★ 任意非空 Cookie 值即可通过管理认证。
// 当前 RequireAuth 仅检查 Cookie 存在性与非空（admin.go:126-143），
// 因此伪造 `Cookie: admin_session=x` 即可获得全部管理能力。
// 断言精确到当前已实证的行为：HTTP 200。
// P1-01D 修复为 302/401/403 任意一种时，本测试都会 FAIL 并提示改写。
func TestSEC001_VULN_ForgedCookieValue_GrantsAdminAccess(t *testing.T) {
	env := newAuthEnv(t)
	forgeries := []string{"x", "totally-forged", "authenticated", "anything-goes"}
	for _, v := range forgeries {
		resp := doReq(env.router, "GET", "/admin/clients",
			[]*http.Cookie{{Name: sessionCookieName, Value: v}})
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("[CURRENT BEHAVIOR CHANGED] 期望漏洞状态 HTTP 200，伪造 Cookie %q 实际 %d —— 认证行为已变化，请核对 P1-01D 是否完成并将本测试改写为安全回归断言", v, resp.StatusCode)
		}
		t.Logf("复现 SEC-001：伪造 Cookie %q → HTTP 200（绕过认证访问 /admin/clients）", v)
	}
}

// [KNOWN-VULN: SEC-001] 代表性受保护路由之二：JSON API 面同样可被伪造 Cookie 绕过。
// 三重验证确保"真的进入了受保护资源"而非碰巧的 200 错误页：
// 状态码 200 + Content-Type: application/json + 响应体含固定字段 total_requests。
func TestSEC001_VULN_ForgedCookie_AccessStatsAPI(t *testing.T) {
	env := newAuthEnv(t)
	resp := doReq(env.router, "GET", "/admin/stats/api",
		[]*http.Cookie{{Name: sessionCookieName, Value: "forged"}})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("[CURRENT BEHAVIOR CHANGED] 期望漏洞状态 HTTP 200，实际 %d —— 认证行为已变化，请核对 P1-01D 是否完成并将本测试改写为安全回归断言", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.Contains(ct, "application/json") {
		t.Fatalf("[CURRENT BEHAVIOR CHANGED] 期望 application/json，实际 %q", ct)
	}
	body := new(bytes.Buffer)
	if _, err := body.ReadFrom(resp.Body); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(body.String(), `"total_requests":`) {
		t.Fatalf("[CURRENT BEHAVIOR CHANGED] 响应体缺少受保护资源特征字段 total_requests: %s", body.String())
	}
	t.Log("复现 SEC-001：伪造 Cookie → HTTP 200 + JSON 统计数据（/admin/stats/api 泄露面）")
}

// [KNOWN-VULN: SEC-001] 服务端不校验任何过期时间：浏览器侧 Expires 已过期仍放行。
func TestSEC001_VULN_ExpiredCookieAttribute_StillAccepted(t *testing.T) {
	env := newAuthEnv(t)
	expired := &http.Cookie{
		Name:    sessionCookieName,
		Value:   "expired-long-ago",
		Expires: time.Now().Add(-72 * time.Hour), // 明确过期
	}
	resp := doReq(env.router, "GET", "/admin/clients", []*http.Cookie{expired})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("[CURRENT BEHAVIOR CHANGED] 期望漏洞状态 HTTP 200，实际 %d —— 认证行为已变化，请核对 P1-01D 是否完成并将本测试改写为安全回归断言", resp.StatusCode)
	}
	t.Log("复现 SEC-001：Expires 已过期 72h 的 Cookie → HTTP 200（服务端从不校验有效期）")
}

// ---------------------------------------------------------------------------
// 登出
// ---------------------------------------------------------------------------

// [NORMAL + KNOWN-VULN] 登出只清浏览器 Cookie，无服务端吊销：
// 持有旧 Cookie 的一方在"他人登出"后仍可继续访问。
func TestAuthChar_VULN_Logout_DoesNotRevokeServerSide(t *testing.T) {
	env := newAuthEnv(t)
	loginResp := login(t, env.router, testAdminUser, testAdminPassword)
	c := getSessionCookie(loginResp)
	if c == nil {
		t.Fatal("登录未获得 Cookie")
	}

	logoutReq := httptest.NewRequest("POST", "/admin/logout", nil)
	logoutReq.AddCookie(c)
	w := httptest.NewRecorder()
	env.router.ServeHTTP(w, logoutReq)
	logoutResp := w.Result()

	clearCookie := getSessionCookie(logoutResp)
	if clearCookie == nil || clearCookie.Value != "" {
		t.Errorf("[NORMAL] 期望登出时下发清空 Cookie，实际 %v", clearCookie)
	}

	// [KNOWN-VULN] 旧值依旧有效——因为服务端根本没有会话存储。
	// 精确断言漏洞状态 HTTP 200：修复为 302/401/403 时本测试 FAIL。
	after := doReq(env.router, "GET", "/admin/clients",
		[]*http.Cookie{{Name: sessionCookieName, Value: staticSessionValue}})
	if after.StatusCode != http.StatusOK {
		t.Fatalf("[CURRENT BEHAVIOR CHANGED] 期望漏洞状态 HTTP 200，实际 %d —— 认证行为已变化，请核对 P1-01D 是否完成并将本测试改写为安全回归断言", after.StatusCode)
	}
	t.Log("复现 SEC-001：登出后旧 Cookie 仍可访问（HTTP 200），无服务端吊销")
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

		form := url.Values{
			"username":         {"admin"},
			"password":         {"NewPass-Setup-99"},
			"confirm_password": {"NewPass-Setup-99"},
		}
		req := httptest.NewRequest("POST", "/setup", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		if w.Result().StatusCode != http.StatusFound {
			t.Fatalf("[NORMAL] setup 完成期望 302，实际 %d", w.Result().StatusCode)
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

// [KNOWN-VULN: SEC-004] 登录表单中的 csrf_token 是静态字面量，且服务端不校验：
// 带任意/缺失 token 的登录 POST 都被正常处理。
func TestSEC004_VULN_LoginIgnoresCSRFToken(t *testing.T) {
	env := newAuthEnv(t)
	// 不带任何 token 的裸表单
	resp := login(t, env.router, testAdminUser, testAdminPassword)
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("[SEC-004 已被修复?] 缺失 CSRF token 的登录被拒绝（%d）", resp.StatusCode)
	}
	// 伪造 token
	form := url.Values{
		"username":   {testAdminUser},
		"password":   {testAdminPassword},
		"csrf_token": {"forged-token"},
	}
	req := httptest.NewRequest("POST", "/admin/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	env.router.ServeHTTP(w, req)
	if w.Result().StatusCode != http.StatusFound {
		t.Fatal("[SEC-004 已被修复?] 伪造 CSRF token 的登录被拒绝")
	}
	t.Log("复现 SEC-004：登录端点完全不做 CSRF token 校验")
}
