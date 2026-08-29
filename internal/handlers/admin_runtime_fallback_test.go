package handlers

// P1-03C3.1 · Final Staging Corrections — Admin Test/Fetch runtime fallback Gate
//
// 修复回归：/admin/clients/{id}/test 与 /fetch-models 此前在 client 无 per-client key
// 时使用空 key，丢失了 runtime global fallback（Public API 的 resolveProvider 有，Admin 没有）。
//
// 环境设计（证明 handler 用的是运行时视图而非持久化视图）：
//   AdminHandler.cfg       = 持久化视图（key 只有信封，无明文）
//   GeminiService.cfg      = 运行时视图（全局 key 明文）
// 若 handler 误读 h.cfg 的 provider，global fallback 用例立即失败。
//
// 用例矩阵（全部本地 httptest，禁止出外网）：
//   A. global key + client 无 key        → TestConnection 使用 global 明文 key
//   B. global key + client 无 key        → FetchClientModels 使用 global 明文 key
//   C. client 密文 override              → client key 覆盖 global key
//   D. client 仅 BaseURL override        → 走 client BaseURL，key 仍为 global
//
// Canary 约束：仅使用明显的测试标记串；禁止真实 API Key。

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"ai-gateway/internal/auth"
	"ai-gateway/internal/config"
	"ai-gateway/internal/models"
	"ai-gateway/internal/secrets"
	"ai-gateway/internal/services"

	"github.com/go-chi/chi/v5"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

const (
	fallbackCanaryGlobal = "P103C31GATE_CANARY_GLOBAL_RUNTIME_SECRET"
	fallbackCanaryClient = "P103C31GATE_CANARY_CLIENT_OVERRIDE_SECRET"
)

type fallbackUpstream struct {
	URL   string
	Auths *[]string
}

func newFallbackUpstream(t *testing.T) *fallbackUpstream {
	t.Helper()
	auths := []string{}
	up := &fallbackUpstream{Auths: &auths}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*up.Auths = append(*up.Auths, r.Header.Get("Authorization"))
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":[{"id":"model-a"},{"id":"model-b"}]}`))
	}))
	t.Cleanup(srv.Close)
	up.URL = srv.URL
	return up
}

func (u *fallbackUpstream) lastAuth(t *testing.T) string {
	t.Helper()
	if len(*u.Auths) == 0 {
		t.Fatal("upstream 未收到任何请求")
	}
	return (*u.Auths)[len(*u.Auths)-1]
}

type fallbackEnv struct {
	cfgPersist *config.Config
	db         *gorm.DB
	admin      http.Handler
	manager    *secrets.Manager
	clientSvc  *services.ClientService
	upGlobal   *fallbackUpstream
	upOverride *fallbackUpstream
}

func newFallbackEnv(t *testing.T) *fallbackEnv {
	t.Helper()
	upG := newFallbackUpstream(t)
	upO := newFallbackUpstream(t)

	db, err := gorm.Open(sqlite.Open(filepath.Join(t.TempDir(), "fb.db")), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.AutoMigrate(&models.Client{}, &models.RequestLog{}, &models.DailyUsage{}, &models.AdminSession{}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if sqlDB, e := db.DB(); e == nil {
			_ = sqlDB.Close()
		}
	})

	adminBase := config.AdminConfig{Username: testAdminUser, PasswordHash: testPasswordHash, SessionSecret: "fallback-session-secret", CookieSecure: false}

	// 运行时视图：全局 key 明文（生产中由 buildRuntimeConfig 解密得到）
	cfgRuntime := &config.Config{
		Server:    config.ServerConfig{Host: "127.0.0.1", Port: 8090},
		Admin:     adminBase,
		Providers: map[string]config.ProviderConfig{"openai": {Type: "openai", APIKey: fallbackCanaryGlobal, BaseURL: upG.URL + "/v1"}},
	}
	// 持久化视图：key 只有信封（handler 若误读此视图，global fallback 用例立即失败）
	mgr := secrets.NewManager(mustKFCipher(t))
	envG, err := mgr.EncryptGlobalProviderKey("openai", []byte(fallbackCanaryGlobal))
	if err != nil {
		t.Fatal(err)
	}
	cfgPersist := &config.Config{
		Server:    config.ServerConfig{Host: "127.0.0.1", Port: 8090},
		Admin:     adminBase,
		Providers: map[string]config.ProviderConfig{"openai": {Type: "openai", APIKeyEncrypted: envG, BaseURL: upG.URL + "/v1"}},
	}

	clientSvc := services.NewClientService(db)
	geminiSvc := services.NewGeminiService(db, cfgRuntime)
	statsSvc := services.NewStatsService(db)
	hub := services.NewDashboardHub(statsSvc)
	toolSvc := services.NewToolService(nil)
	store := auth.NewSQLiteStore(db)
	limiter := auth.NewLoginRateLimiter()
	limiter.Configure(5, 15*time.Minute, adminBase.Username)

	adminH, err := NewAdminHandler(cfgPersist, clientSvc, statsSvc, geminiSvc, hub, toolSvc, store, limiter, mgr, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	mux := chi.NewRouter()
	adminH.RegisterRoutes(mux)

	return &fallbackEnv{
		cfgPersist: cfgPersist, db: db, admin: mux, manager: mgr,
		clientSvc: clientSvc, upGlobal: upG, upOverride: upO,
	}
}

// createFallbackClient: 建 client 并按需设置 encrypted override / BaseURL override
func (e *fallbackEnv) createFallbackClient(t *testing.T, overrideKey string, overrideBase string) *models.Client {
	t.Helper()
	client, _, err := e.clientSvc.CreateClient("fb", "", "openai", "sk-", e.cfgPersist)
	if err != nil {
		t.Fatal(err)
	}
	client.Backend = "openai"
	if overrideBase != "" {
		client.BackendBaseURL = overrideBase
	}
	if overrideKey != "" {
		env, encErr := e.manager.EncryptClientBackendKey(client.ID, []byte(overrideKey))
		if encErr != nil {
			t.Fatal(encErr)
		}
		client.BackendAPIKeyEncrypted = env
	}
	if err := e.clientSvc.UpdateClient(client); err != nil {
		t.Fatal(err)
	}
	return client
}

func (e *fallbackEnv) adminGet(t *testing.T, path string) *http.Response {
	t.Helper()
	resp := login(t, e.admin, testAdminUser, testAdminPassword)
	c := getSessionCookie(resp)
	if c == nil {
		t.Fatal("admin login did not set session cookie")
	}
	req := httptest.NewRequest("GET", path, nil)
	req.AddCookie(c)
	w := httptest.NewRecorder()
	e.admin.ServeHTTP(w, req)
	return w.Result()
}

// A：global key + client 无 key → TestConnection 使用 runtime global 明文 key
func TestC31_AdminTestConnection_GlobalFallback(t *testing.T) {
	e := newFallbackEnv(t)
	client := e.createFallbackClient(t, "", "")

	resp := e.adminGet(t, "/admin/clients/"+client.ID+"/test")
	body := readBody(resp)
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, `"success":true`) {
		t.Fatalf("[功能回归失败] TestConnection 应成功，实际 %d body=%s", resp.StatusCode, body)
	}
	if got := e.upGlobal.lastAuth(t); got != "Bearer "+fallbackCanaryGlobal {
		t.Fatalf("[安全回归失败] 应使用 runtime global key，实际 %q", got)
	}
	if len(*e.upOverride.Auths) != 0 {
		t.Fatal("client 无 BaseURL override 时不应请求 override upstream")
	}
	// 防线：持久化视图不可被写入明文
	if e.cfgPersist.Providers["openai"].APIKey != "" {
		t.Fatal("[安全回归失败] 运行态明文写回了持久化 cfg")
	}
}

// B：global key + client 无 key → FetchClientModels 使用 runtime global 明文 key
func TestC31_AdminFetchModels_GlobalFallback(t *testing.T) {
	e := newFallbackEnv(t)
	client := e.createFallbackClient(t, "", "")

	resp := e.adminGet(t, "/admin/clients/"+client.ID+"/fetch-models")
	body := readBody(resp)
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, `"success":true`) {
		t.Fatalf("[功能回归失败] FetchClientModels 应成功，实际 %d body=%s", resp.StatusCode, body)
	}
	if got := e.upGlobal.lastAuth(t); got != "Bearer "+fallbackCanaryGlobal {
		t.Fatalf("[安全回归失败] 应使用 runtime global key，实际 %q", got)
	}
}

// C：client 密文 override 存在 → client key 覆盖 global key
func TestC31_AdminTestConnection_ClientEncryptedOverrides(t *testing.T) {
	e := newFallbackEnv(t)
	client := e.createFallbackClient(t, fallbackCanaryClient, e.upOverride.URL+"/v1")

	resp := e.adminGet(t, "/admin/clients/"+client.ID+"/test")
	body := readBody(resp)
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, `"success":true`) {
		t.Fatalf("[功能回归失败] TestConnection 应成功，实际 %d body=%s", resp.StatusCode, body)
	}
	if got := e.upOverride.lastAuth(t); got != "Bearer "+fallbackCanaryClient {
		t.Fatalf("[安全回归失败] client 密文 override 应覆盖 global key，实际 %q", got)
	}
	if len(*e.upGlobal.Auths) != 0 {
		t.Fatal("client 有 BaseURL override 时不应请求 global upstream")
	}
}

// D：client 仅 BaseURL override（无 key）→ 走 client BaseURL，key 仍为 global
func TestC31_AdminTestConnection_BaseURLOverride_GlobalKey(t *testing.T) {
	e := newFallbackEnv(t)
	client := e.createFallbackClient(t, "", e.upOverride.URL+"/v1")

	resp := e.adminGet(t, "/admin/clients/"+client.ID+"/test")
	body := readBody(resp)
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, `"success":true`) {
		t.Fatalf("[功能回归失败] TestConnection 应成功，实际 %d body=%s", resp.StatusCode, body)
	}
	if got := e.upOverride.lastAuth(t); got != "Bearer "+fallbackCanaryGlobal {
		t.Fatalf("[安全回归失败] BaseURL override 下 key 仍应为 global，实际 %q", got)
	}
	if len(*e.upGlobal.Auths) != 0 {
		t.Fatal("BaseURL override 时不应请求 global upstream")
	}
}

// Gate 8 · 静态 footgun 防线：
//  1. 可达 Admin 路由中不存在 /admin/settings（dead plaintext persistence handler 已删除）
//  2. handlers 源码无 config.Save( 调用、无 new_provider plaintext 表单、UpdateSettings 不存在
//
// 本测试是对"复活路径"的 tripwire；若未来重建 Global Settings UI，必须走
// SetupHandler 式 candidate 原子保存 + P1-03C3 key 语义，并同步更新本防线。
func TestC31_NoReachablePlaintextPersistence(t *testing.T) {
	env := newKeyFlowEnv(t, "")
	var routes []string
	chi.Walk(env.adminMux, func(method, route string, handler http.Handler, middlewares ...func(http.Handler) http.Handler) error {
		routes = append(routes, method+" "+route)
		return nil
	})
	if len(routes) == 0 {
		t.Fatal("Admin 路由枚举为空——测试自身问题")
	}
	for _, r := range routes {
		if strings.Contains(r, "/admin/settings") {
			t.Fatalf("[安全回归失败] settings 路由不应注册: %s", r)
		}
	}

	sources, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range sources {
		if strings.HasSuffix(f, "_test.go") {
			continue // 只扫描生产源码；测试文件合法地引用被禁字符串本身
		}
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		s := string(src)
		switch {
		case strings.Contains(s, "func (h *AdminHandler) UpdateSettings"):
			t.Fatalf("[安全回归失败] UpdateSettings 明文持久化 handler 不得回归: %s", f)
		case strings.Contains(s, "config.Save("):
			t.Fatalf("[安全回归失败] handlers 源码不得直接 config.Save（吞错误的明文持久化模式）: %s", f)
		case strings.Contains(s, "new_provider_api_key"):
			t.Fatalf("[安全回归失败] new provider 明文表单模式不得回归: %s", f)
		}
	}
}
