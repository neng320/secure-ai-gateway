package main

// P1-01F · Listener Security Regression Gate
//
// 验证三监听面拆分后的网络暴露面收敛：
//   Public API   —— 仅 API + health；任何管理面路径 404
//   Private Admin —— 管理面可达（含 setup 条件注册）；API/Metrics 路径 404
//   Private Metrics —— /metrics 可达且保持 Basic Auth；其他面 404
// 外加：默认绑定 loopback、bind 失败快速失败、优雅关停。

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"ai-gateway/internal/auth"
	"ai-gateway/internal/config"
	"ai-gateway/internal/models"

	"github.com/go-chi/chi/v5"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// chiRouter 简写别名（与 server.go 中 startListeners 签名一致）
type chiRouter = chi.Router

type gatewayEnv struct {
	cfg     *config.Config
	deps    gatewayDeps
	api     *httptest.Server
	admin   *httptest.Server
	metrics *httptest.Server // prometheus 未启用时为 nil
	store   *auth.SQLiteStore
}

func newTestGateway(t *testing.T, prometheusEnabled, setupRequired bool) *gatewayEnv {
	t.Helper()
	// P1-02.3：buildAdminRouter 需要 config.SourcePath()——先落一个临时配置文件再 Load
	cfgPath := filepath.Join(t.TempDir(), "config.yaml")
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatalf("load temp config: %v", err)
	}
	cfg.Admin.Username = "admin"
	cfg.Admin.PasswordHash = "$2a$10$7EqJtq98hPqEX7fNZaFWoOhi5B0X0ME0wUoAg8ZlLlZ7m0D0lCL9a" // 合法 bcrypt 形态；登录测试不走这里
	cfg.Admin.SessionSecret = "listener-gate-test-secret"
	cfg.Admin.CookieSecure = false
	cfg.Prometheus = config.PrometheusConfig{Enabled: prometheusEnabled, Username: "prom", Password: "prompass"}
	if cfg.Providers == nil {
		cfg.Providers = map[string]config.ProviderConfig{}
	}
	if setupRequired {
		cfg.Admin.PasswordHash = "__SETUP_REQUIRED__"
	}

	db, err := gorm.Open(sqlite.Open(filepath.Join(t.TempDir(), "gw.db")), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.AutoMigrate(&models.Client{}, &models.RequestLog{}, &models.DailyUsage{}, &models.AdminSession{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	t.Cleanup(func() {
		if sqlDB, e := db.DB(); e == nil {
			_ = sqlDB.Close()
		}
	})

	deps := newGatewayDeps(cfg, cfg, db, false, nil, nil) // listener gate：无 Provider Secret 场景，运行时视图==持久化视图
	apiMux := buildAPIRouter(deps)
	adminMux, err := buildAdminRouter(deps)
	if err != nil {
		t.Fatalf("buildAdminRouter: %v", err)
	}
	metricsMux := buildMetricsRouter(deps)

	env := &gatewayEnv{cfg: cfg, deps: deps, api: httptest.NewServer(apiMux), admin: httptest.NewServer(adminMux), store: deps.sessionStore.(*auth.SQLiteStore)}
	if metricsMux != nil {
		env.metrics = httptest.NewServer(metricsMux)
	}
	t.Cleanup(func() {
		env.api.Close()
		env.admin.Close()
		if env.metrics != nil {
			env.metrics.Close()
		}
	})
	return env
}

// noRedirectClient: 不跟随重定向，断言真实状态码
var noRedirectClient = &http.Client{CheckRedirect: func(req *http.Request, via []*http.Request) error {
	return http.ErrUseLastResponse
}}

func get(t *testing.T, url string, headers ...string) int {
	t.Helper()
	req, _ := http.NewRequest("GET", url, nil)
	for i := 0; i+1 < len(headers); i += 2 {
		req.Header.Set(headers[i], headers[i+1])
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer resp.Body.Close()
	return resp.StatusCode
}

func post(t *testing.T, url string, headers ...string) int {
	t.Helper()
	req, _ := http.NewRequest("POST", url, strings.NewReader("{}"))
	for i := 0; i+1 < len(headers); i += 2 {
		req.Header.Set(headers[i], headers[i+1])
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST %s: %v", url, err)
	}
	defer resp.Body.Close()
	return resp.StatusCode
}

// [P1-01F Gate] Public API 面收敛：API + health 可用；一切管理面路径 404。
func TestGateListener_PublicAPI(t *testing.T) {
	env := newTestGateway(t, false, false)

	if got := get(t, env.api.URL+"/health"); got != http.StatusOK {
		t.Fatalf("public /health 期望 200，实际 %d", got)
	}
	if got := get(t, env.api.URL+"/v1/models"); got != http.StatusUnauthorized {
		t.Fatalf("public /v1/models 无 key 期望 401，实际 %d", got)
	}

	client, apiKey, err := env.deps.clientService.CreateClient("gate", "", "openai", "sk-", env.cfg)
	if err != nil {
		t.Fatal(err)
	}
	_ = client
	if got := get(t, env.api.URL+"/v1/models", "Authorization", "Bearer "+apiKey); got != http.StatusOK {
		t.Fatalf("public /v1/models 合法 key 期望 200，实际 %d", got)
	}

	for _, p := range []string{"/admin", "/admin/login", "/admin/ws", "/setup", "/metrics"} {
		if got := get(t, env.api.URL+p); got != http.StatusNotFound {
			t.Fatalf("[暴露面收敛失败] public %s 期望 404，实际 %d", p, got)
		}
	}
}

// [P1-01F Gate] Private Admin 面：管理可达 + API/Metrics 不可达 + 认证仍生效。
func TestGateListener_Admin(t *testing.T) {
	env := newTestGateway(t, false, false)

	if got := get(t, env.admin.URL+"/admin/login"); got != http.StatusOK {
		t.Fatalf("admin /admin/login 期望 200，实际 %d", got)
	}

	// 伪造会话 → 302 登录页（沿用 P1-01D 语义）
	resp, err := noRedirectClient.Get(env.admin.URL + "/admin/clients")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("admin /admin/clients 伪造访问期望 302，实际 %d", resp.StatusCode)
	}

	// 合法服务端会话 → 200
	ctx := context.Background()
	token, err := env.store.Create(ctx, "admin", time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest("GET", env.admin.URL+"/admin/clients", nil)
	req.AddCookie(&http.Cookie{Name: auth.SessionCookieName, Value: token})
	resp2, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("admin /admin/clients 合法会话期望 200，实际 %d", resp2.StatusCode)
	}

	// API / Metrics 路径在 Admin 面不可达
	if got := post(t, env.admin.URL+"/v1/chat/completions", "Authorization", "Bearer x"); got != http.StatusNotFound {
		t.Fatalf("[暴露面收敛失败] admin /v1/chat/completions 期望 404，实际 %d", got)
	}
	if got := get(t, env.admin.URL+"/metrics"); got != http.StatusNotFound {
		t.Fatalf("[暴露面收敛失败] admin /metrics 期望 404，实际 %d", got)
	}

	// 密码已设时 /setup 不注册 → 404
	if got := get(t, env.admin.URL+"/setup"); got != http.StatusNotFound {
		t.Fatalf("[暴露面收敛失败] admin /setup（已设密码）期望 404，实际 %d", got)
	}
}

// [P1-01F Gate] Setup 模式：/setup 仅此时可达，管理面仍受保护。
func TestGateListener_Admin_SetupMode(t *testing.T) {
	env := newTestGateway(t, false, true)

	if got := get(t, env.admin.URL+"/setup"); got != http.StatusOK {
		t.Fatalf("setup 模式 /setup 期望 200，实际 %d", got)
	}
	resp, err := noRedirectClient.Get(env.admin.URL + "/admin/clients")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("setup 模式 /admin/clients 无会话期望 302，实际 %d", resp.StatusCode)
	}
}

// [P1-01F Gate] Metrics 面：/metrics 可达且保持认证；其他面 404。
func TestGateListener_Metrics(t *testing.T) {
	env := newTestGateway(t, true, false)

	if got := get(t, env.metrics.URL+"/metrics"); got != http.StatusUnauthorized {
		t.Fatalf("metrics /metrics 无认证期望 401，实际 %d", got)
	}
	req, _ := http.NewRequest("GET", env.metrics.URL+"/metrics", nil)
	req.SetBasicAuth("prom", "prompass")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("metrics /metrics 认证后期望 200，实际 %d", resp.StatusCode)
	}

	if got := get(t, env.metrics.URL+"/admin"); got != http.StatusNotFound {
		t.Fatalf("[暴露面收敛失败] metrics /admin 期望 404，实际 %d", got)
	}
	if got := post(t, env.metrics.URL+"/v1/chat/completions"); got != http.StatusNotFound {
		t.Fatalf("[暴露面收敛失败] metrics /v1/chat/completions 期望 404，实际 %d", got)
	}
}

// [P1-01F Gate] 默认绑定必须 loopback（Admin/Metrics 绝不默认公网）。
func TestGateListener_DefaultsAreLoopback(t *testing.T) {
	dir := t.TempDir()
	orig, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Chdir(orig) }()

	cfg, err := config.Load(filepath.Join(dir, "config.yaml")) // 文件不存在 → 生成默认
	if err != nil {
		t.Fatalf("Load default config: %v", err)
	}
	if cfg.Server.Host != "127.0.0.1" || cfg.Server.Port != 8090 {
		t.Fatalf("API 默认期望 127.0.0.1:8090，实际 %s:%d", cfg.Server.Host, cfg.Server.Port)
	}
	if cfg.Server.Admin.Host != "127.0.0.1" || cfg.Server.Admin.Port != 8091 {
		t.Fatalf("[安全回归失败] Admin 默认必须 loopback 127.0.0.1:8091，实际 %s:%d", cfg.Server.Admin.Host, cfg.Server.Admin.Port)
	}
	if cfg.Server.Metrics.Host != "127.0.0.1" || cfg.Server.Metrics.Port != 9090 {
		t.Fatalf("[安全回归失败] Metrics 默认必须 loopback 127.0.0.1:9090，实际 %s:%d", cfg.Server.Metrics.Host, cfg.Server.Metrics.Port)
	}
}

// [P1-01F Gate] bind 失败必须快速失败，且先建立的监听被关闭（不留半启动）。
func TestGateListener_BindFailureFailsFast(t *testing.T) {
	blocker, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer blocker.Close()
	occupiedPort := blocker.Addr().(*net.TCPAddr).Port

	deps := newTestGateway(t, false, false)
	cfg := *deps.cfg
	cfg.Server.Admin.Port = occupiedPort // API 正常，Admin 撞占端口

	servers, err := startListeners(&cfg, buildAPIRouter(deps.deps), mustBuildAdmin(t, deps.deps), nil)
	if err == nil {
		for _, s := range servers {
			_ = s.ln.Close()
		}
		t.Fatal("Admin 端口被占用时期望 startListeners 返回错误，实际成功（静默假成功）")
	}
	if !strings.Contains(err.Error(), "admin listener bind") {
		t.Fatalf("错误应指明 admin listener，实际 %v", err)
	}

	// API 端口已被回滚释放：应可重新绑定
	rebind, err := net.Listen("tcp", net.JoinHostPort(cfg.Server.Host, strconv.Itoa(cfg.Server.Port)))
	if err != nil {
		t.Fatalf("[安全回归失败] 失败后 API 端口未释放: %v", err)
	}
	rebind.Close()
}

// [P1-01F Gate] 三监听面优雅关停：全部 Serve 退出、无悬挂。
func TestGateListener_GracefulShutdown(t *testing.T) {
	env := newTestGateway(t, true, false)
	cfg := *env.cfg
	cfg.Server.Port = 0 // 临时端口
	cfg.Server.Admin.Port = 0
	cfg.Server.Metrics.Port = 0

	servers, err := startListeners(&cfg, buildAPIRouter(env.deps), mustBuildAdmin(t, env.deps), buildMetricsRouter(env.deps))
	if err != nil {
		t.Fatalf("startListeners: %v", err)
	}
	if len(servers) != 3 {
		t.Fatalf("期望 3 个监听面，实际 %d", len(servers))
	}

	errCh := make(chan error, 1)
	serveAll(servers, errCh)

	if err := shutdownAll(servers, 3*time.Second); err != nil {
		t.Fatalf("优雅关停失败: %v", err)
	}
	select {
	case e := <-errCh:
		t.Fatalf("关停后不应有监听错误: %v", e)
	case <-time.After(200 * time.Millisecond):
		// 干净退出
	}
}

func mustBuildAdmin(t *testing.T, deps gatewayDeps) chiRouter {
	t.Helper()
	r, err := buildAdminRouter(deps)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// [P1-02.1 Gate] Admin 面请求体上限恢复：超大 POST 必须被拒（413/400/401 类），正常路径不受影响。
func TestGateListener_AdminBodyLimit(t *testing.T) {
	env := newTestGateway(t, false, false)

	big := strings.Repeat("A", (10<<20)+1024) // 10MiB + 1KB
	req, _ := http.NewRequest("POST", env.admin.URL+"/admin/login", strings.NewReader(big))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("oversize request: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusFound {
		t.Fatalf("[安全回归失败] 超限 body 未被拒绝: %d", resp.StatusCode)
	}

	// 对照：正常小请求路径仍可用（登录页 200）
	if got := get(t, env.admin.URL+"/admin/login"); got != http.StatusOK {
		t.Fatalf("对照请求期望 200，实际 %d", got)
	}
}
