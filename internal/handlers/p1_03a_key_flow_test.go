package handlers

// P1-03A · Provider Key Flow Characterization Tests
//
// 固化当前（tag secure-gateway-p1-admin-security.3 时点）Provider Secret 的真实行为。
//
// 标记约定：
//   [CURRENT]                     —— 当前行为，SEC-002 修复后按设计决定保留或调整
//   [KNOWN-VULN: SEC-002]         —— 明文暴露事实，AEAD 落地后必须翻红并改写
//
// Canary 约束：仅使用明显的测试标记串，绝不使用疑似真实 Key 的字符串
//（避免 secret scanner 误报）。禁止使用真实 API Key 作为测试数据。

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"ai-gateway/internal/auth"
	"ai-gateway/internal/config"
	"ai-gateway/internal/models"
	"ai-gateway/internal/providers"
	"ai-gateway/internal/services"

	mw "ai-gateway/internal/middleware"
	"github.com/go-chi/chi/v5"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

const (
	canaryGlobal = "P103A_CANARY_GLOBAL_PROVIDER_SECRET"
	canaryClient = "P103A_CANARY_CLIENT_PROVIDER_SECRET"
	canaryGemini = "P103A_CANARY_GEMINI_PROVIDER_SECRET"
)

// keyFlowEnv: 密钥流测试环境（本地 upstream 捕获 Authorization，不出外网）
type keyFlowEnv struct {
	cfg           *config.Config
	db            *gorm.DB
	clientService *services.ClientService
	limiter       *auth.LoginRateLimiter
	store         *auth.SQLiteStore
	openai        http.Handler // /v1/* 路由（含 client key 认证中间件）
	admin         http.Handler // /admin/* 路由（含 RequireAuth/CSRF）
	upstreamURL   string
	upstreamAuths *[]string
}

func newKeyFlowEnv(t *testing.T, globalAPIKey string) *keyFlowEnv {
	t.Helper()

	// 本地 upstream：捕获 Authorization，返回合法 OpenAI 形态响应
	var auths []string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auths = append(auths, r.Header.Get("Authorization"))
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"choices": []map[string]interface{}{
				{"message": map[string]string{"role": "assistant", "content": "pong"}},
			},
			"usage": map[string]int{"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
		})
	}))
	t.Cleanup(upstream.Close)

	db, err := gorm.Open(sqlite.Open(filepath.Join(t.TempDir(), "kf.db")), &gorm.Config{})
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

	cfg := &config.Config{
		Server: config.ServerConfig{Host: "127.0.0.1", Port: 8090},
		Admin:  config.AdminConfig{Username: "admin", SessionSecret: "kf-secret", CookieSecure: false},
		Providers: map[string]config.ProviderConfig{
			"openai": {Type: "openai", APIKey: globalAPIKey, BaseURL: upstream.URL + "/v1"},
		},
	}
	hash, _ := bcrypt.GenerateFromPassword([]byte(testAdminPassword), bcrypt.DefaultCost)
	cfg.Admin.PasswordHash = string(hash)

	clientService := services.NewClientService(db)
	geminiService := services.NewGeminiService(db, cfg)
	statsService := services.NewStatsService(db)
	toolService := services.NewToolService(nil)
	registry := providers.BuildRegistry(cfg)
	dashboardHub := services.NewDashboardHub(statsService)
	store := auth.NewSQLiteStore(db)
	limiter := auth.NewLoginRateLimiter()

	// Public API 路由（与 buildAPIRouter 同构）
	openaiHandler := NewOpenAIHandler(geminiService, clientService, statsService, registry, toolService)
	apiMux := chi.NewRouter()
	apiMux.Use(mw.NewAuthMiddleware(clientService).Handler)
	openaiHandler.RegisterRoutes(apiMux)

	// Admin 路由（与 buildAdminRouter 同构）
	adminHandler, err := NewAdminHandler(cfg, clientService, statsService, geminiService, dashboardHub, toolService, store, limiter)
	if err != nil {
		t.Fatal(err)
	}
	adminMux := chi.NewRouter()
	adminHandler.RegisterRoutes(adminMux)

	return &keyFlowEnv{
		cfg: cfg, db: db, clientService: clientService, limiter: limiter, store: store,
		openai: apiMux, admin: adminMux, upstreamURL: upstream.URL, upstreamAuths: &auths,
	}
}

// lastUpstreamAuth: 最近一次 upstream 收到的 Authorization
func (e *keyFlowEnv) lastUpstreamAuth(t *testing.T) string {
	t.Helper()
	if len(*e.upstreamAuths) == 0 {
		t.Fatal("upstream 未收到任何请求")
	}
	return (*e.upstreamAuths)[len(*e.upstreamAuths)-1]
}

func (e *keyFlowEnv) doChat(t *testing.T, clientAPIKey, model string) {
	t.Helper()
	body := `{"model":"` + model + `","messages":[{"role":"user","content":"ping"}]}`
	req := httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+clientAPIKey)
	w := httptest.NewRecorder()
	e.openai.ServeHTTP(w, req)
	if w.Result().StatusCode != http.StatusOK {
		t.Fatalf("chat 期望 200，实际 %d body=%s", w.Result().StatusCode, w.Body.String())
	}
}

// createClientWithKey: 建一个 backend=openai 的 client
func (e *keyFlowEnv) createClientWithKey(t *testing.T, backendAPIKey string) *models.Client {
	t.Helper()
	client, _, err := e.clientService.CreateClient("kf", "", "openai", "sk-", e.cfg)
	if err != nil {
		t.Fatal(err)
	}
	client.Backend = "openai" // service 层 CreateClient 不设 Backend（DB 默认 gemini），显式指定
	client.BackendAPIKey = backendAPIKey
	client.BackendBaseURL = e.upstreamURL + "/v1" // openai_compat 约定：base 已含 /v1
	if err := e.clientService.UpdateClient(client); err != nil {
		t.Fatal(err)
	}
	return client
}

// ---------------------------------------------------------------------------
// 1) [KNOWN-VULN: SEC-002] 全局 Provider Key 明文落 YAML（保存 + 回读双确认）
// ---------------------------------------------------------------------------
func TestP103A_GlobalKey_PlaintextInSavedYAML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	cfg := minimalSetupCfg()
	cfg.Providers = map[string]config.ProviderConfig{
		"openai": {Type: "openai", APIKey: canaryGlobal, BaseURL: "https://api.openai.example/v1"},
	}

	if err := config.SaveConfig(cfg, path); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), canaryGlobal) {
		t.Fatal("[CURRENT BEHAVIOR CHANGED] YAML 中未找到明文 canary——若 AEAD 已落地，请改写为密文形态断言")
	}
	t.Log("[KNOWN-VULN: SEC-002] 确认：全局 Provider Key 明文写入 YAML")

	// 回读：运行时配置同样持有明文（Runtime plaintext boundary）
	cfg2, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg2.Providers["openai"].APIKey != canaryGlobal {
		t.Fatal("回读后 APIKey 应为明文 canary")
	}
}

// ---------------------------------------------------------------------------
// 2) [KNOWN-VULN: SEC-002] Client BackendAPIKey 明文落 SQLite
// ---------------------------------------------------------------------------
func TestP103A_ClientKey_PlaintextInSQLite(t *testing.T) {
	env := newKeyFlowEnv(t, canaryGlobal)
	client := env.createClientWithKey(t, canaryClient)

	var stored string
	if err := env.db.Raw("SELECT backend_api_key FROM clients WHERE id = ?", client.ID).Scan(&stored).Error; err != nil {
		t.Fatal(err)
	}
	if stored != canaryClient {
		t.Fatalf("[CURRENT BEHAVIOR CHANGED] backend_api_key 不再是明文（%q）——若 AEAD 已落地，请改写为密文形态断言", stored)
	}
	t.Log("[KNOWN-VULN: SEC-002] 确认：Client BackendAPIKey 明文存于 SQLite")
}

// ---------------------------------------------------------------------------
//  3. [CURRENT] Key 优先级：client key > 全局 key；client key 空（BaseURL 保留）→ 全局回退；
//     client key 与 BaseURL 都空 → registry 全局 provider
//
// ---------------------------------------------------------------------------
func TestP103A_KeyPrecedence_ClientKeyWins_ThenGlobalFallback(t *testing.T) {
	env := newKeyFlowEnv(t, canaryGlobal)
	client := env.createClientWithKey(t, canaryClient)

	// a) client key 有值 → client key 优先
	env.doChat(t, clientAPIKeyOf(t, env, client), "test-model")
	if got := env.lastUpstreamAuth(t); got != "Bearer "+canaryClient {
		t.Fatalf("[优先级回归失败] 期望 client key，实际 %q", got)
	}

	// b) client key 清空 + BaseURL 保留 → 全局 key 回退
	client.BackendAPIKey = ""
	if err := env.clientService.UpdateClient(client); err != nil {
		t.Fatal(err)
	}
	env.doChat(t, clientAPIKeyOf(t, env, client), "test-model")
	if got := env.lastUpstreamAuth(t); got != "Bearer "+canaryGlobal {
		t.Fatalf("[优先级回归失败] 期望全局 key 回退，实际 %q", got)
	}

	// c) client key 与 BaseURL 都空 → registry 全局 provider（其 BaseURL 亦为 upstream）
	client.BackendBaseURL = ""
	if err := env.clientService.UpdateClient(client); err != nil {
		t.Fatal(err)
	}
	env.doChat(t, clientAPIKeyOf(t, env, client), "test-model")
	if got := env.lastUpstreamAuth(t); got != "Bearer "+canaryGlobal {
		t.Fatalf("[优先级回归失败] 期望 registry 全局 provider 的 key，实际 %q", got)
	}
}

// clientAPIKeyOf: 重新载入 client 拿其网关 API Key
func clientAPIKeyOf(t *testing.T, env *keyFlowEnv, client *models.Client) string {
	t.Helper()
	c, err := env.clientService.GetClientByID(client.ID)
	if err != nil || c == nil {
		t.Fatal("client 不存在")
	}
	// Client 的网关 API Key 只有哈希入库；此处重新签发并返回明文
	newKey, err := env.clientService.RegenerateAPIKey(client.ID, "openai", "sk-")
	if err != nil {
		t.Fatal(err)
	}
	return newKey
}

// ---------------------------------------------------------------------------
//  4. [CURRENT] Admin 写入语义：Update 表单 blank key = 清空（无条件覆盖）
//     （编辑表单靠 value 预填回传实现"保留"，API 层无保留语义——迁移设计必须显式决定）
//
// ---------------------------------------------------------------------------
func TestP103A_UpdateClient_BlankKeyClears(t *testing.T) {
	env := newKeyFlowEnv(t, canaryGlobal)
	client := env.createClientWithKey(t, canaryClient)
	clientToken := adminSessionToken(t, env)

	form := url.Values{
		"name":                  {client.Name},
		"backend":               {"openai"},
		"backend_api_key":       {""}, // 留空
		"backend_base_url":      {env.upstreamURL},
		"backend_default_model": {"test-model"},
	}
	req := httptest.NewRequest("POST", "/admin/clients/"+client.ID+"/update", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: clientToken})
	req.Header.Set("X-CSRF-Token", auth.CSRFToken(env.cfg.Admin.SessionSecret, clientToken))
	w := httptest.NewRecorder()
	env.admin.ServeHTTP(w, req)
	if w.Result().StatusCode == http.StatusForbidden {
		t.Fatal("测试自身问题：合法 CSRF 被拒")
	}

	reloaded, err := env.clientService.GetClientByID(client.ID)
	if err != nil || reloaded == nil {
		t.Fatal("client 不存在")
	}
	if reloaded.BackendAPIKey != "" {
		t.Fatalf("[行为变化] blank key 不再清空（实际 %q）——AEAD 迁移设计时必须显式决定语义并更新文档", reloaded.BackendAPIKey)
	}
	t.Log("[CURRENT] 确认：Update 表单 blank key = 清空（UI 靠 value 预填回传实现保留）")
}

// ---------------------------------------------------------------------------
//  5. [KNOWN-VULN: SEC-002] 编辑表单把明文 Provider Key 回填进 HTML
//     （type=password 只遮显示，value 属性源码可见）
//
// ---------------------------------------------------------------------------
func TestP103A_ClientKey_ReDisplayedInEditFormHTML(t *testing.T) {
	env := newKeyFlowEnv(t, canaryGlobal)
	client := env.createClientWithKey(t, canaryClient)
	clientToken := adminSessionToken(t, env)

	req := httptest.NewRequest("GET", "/admin/clients/"+client.ID, nil)
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: clientToken})
	w := httptest.NewRecorder()
	env.admin.ServeHTTP(w, req)
	if w.Result().StatusCode != http.StatusOK {
		t.Fatalf("ShowClient 期望 200，实际 %d", w.Result().StatusCode)
	}
	body := w.Body.String()
	if !strings.Contains(body, canaryClient) {
		t.Fatal("[CURRENT BEHAVIOR CHANGED] 编辑页不再回显明文 key——若已做遮罩，请改写为遮罩断言")
	}
	t.Log("[KNOWN-VULN: SEC-002] 确认：编辑表单 value 属性回填明文 Provider Key")
}

// ---------------------------------------------------------------------------
//  6. [KNOWN-VULN: SEC-002] Gemini 把 ?key=<secret> 拼进 URL，
//     网络错误时 *url.Error 把完整 URL（含密钥）带进 error 字符串。
//
// ---------------------------------------------------------------------------
func TestP103A_Gemini_URLContainsKey_InErrorPath(t *testing.T) {
	provider, err := providers.BuildSingleProvider("gemini", config.ProviderConfig{
		Type:    "gemini",
		APIKey:  canaryGemini,
		BaseURL: "http://127.0.0.1:1", // 必然连接失败 → 触发 url.Error 路径
	})
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = provider.ChatCompletion(&providers.ChatRequest{
		Model:    "test-model",
		Messages: []providers.ChatMessage{{Role: "user", Content: "ping"}},
	})
	if err == nil {
		t.Fatal("closed port 应产生错误")
	}
	// [P1-03C3 修复后回归]（反转自 KNOWN-VULN "?key= 进错误串"）：
	// 错误串不含 ?key=、不含明文 key；key 只经 header 传输（由 providers 实现保证）
	if strings.Contains(err.Error(), "?key=") || strings.Contains(err.Error(), canaryGemini) {
		t.Fatalf("[安全回归失败] 错误串泄露 key 材料: %v", err)
	}
	t.Log("确认：Gemini 错误路径不再泄露 key（header 传输）")
}

// ---------------------------------------------------------------------------
// 7) [CURRENT] Gemini TestConnection 硬编码 googleapis（不可注入）；空 key 明确拒绝。
// ---------------------------------------------------------------------------
func TestP103A_Gemini_TestConnection_EmptyKeyClearMessage(t *testing.T) {
	provider, err := providers.BuildSingleProvider("gemini", config.ProviderConfig{Type: "gemini", APIKey: ""})
	if err != nil {
		t.Fatal(err)
	}
	msg, ok, err := provider.TestConnection()
	if ok || err != nil || !strings.Contains(msg, "API key not configured") {
		t.Fatalf("[行为变化] 空 key 期望 'API key not configured'，实际 msg=%q ok=%v err=%v", msg, ok, err)
	}
}

// ---------------------------------------------------------------------------
// 8) [CURRENT] Config Save 往返：明文进明文出（未来加密配置设计的硬约束）
// ---------------------------------------------------------------------------
func TestP103A_GlobalKey_SaveRoundTrip_PlaintextOut(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cfg.yaml")
	cfg := minimalSetupCfg()
	cfg.Providers = map[string]config.ProviderConfig{
		"openai": {Type: "openai", APIKey: canaryGlobal},
	}
	if err := config.SaveConfig(cfg, path); err != nil {
		t.Fatal(err)
	}
	// 模拟运行态被解密后的场景：运行时字段是明文 → Save 会把明文写回磁盘
	cfg.Providers["openai"] = config.ProviderConfig{Type: "openai", APIKey: canaryGlobal + "-RUNTIME"}
	if err := config.SaveConfig(cfg, path); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(path)
	if !strings.Contains(string(raw), canaryGlobal+"-RUNTIME") {
		t.Fatal("[行为变化] SaveConfig 不再直写明文——加密配置设计已改变保存路径，更新本约束")
	}
	t.Log("[设计约束确认] 运行态明文 + SaveConfig = 明文落盘；AEAD 迁移必须改造保存路径")
}

// ---------------------------------------------------------------------------
// 9) [CURRENT] json:"-" 生效：BackendAPIKey 不进 API JSON 响应
// ---------------------------------------------------------------------------
func TestP103A_ClientKey_NotInJSONMarshaling(t *testing.T) {
	c := models.Client{BackendAPIKey: canaryClient}
	b, _ := json.Marshal(c)
	if strings.Contains(string(b), canaryClient) {
		t.Fatal("[行为变化] BackendAPIKey 出现在 JSON 序列化中——回归检查 json:\"-\" 标注")
	}
	t.Log("[CURRENT] 确认：json:\"-\" 生效，API JSON 响应不含 BackendAPIKey")
}

// ---------------------------------------------------------------------------
// 辅助：admin 会话 + handler 构造（与本包其他测试同构）
// ---------------------------------------------------------------------------
func adminSessionToken(t *testing.T, env *keyFlowEnv) string {
	t.Helper()
	resp := login(t, env.admin, env.cfg.Admin.Username, testAdminPassword)
	c := getSessionCookie(resp)
	if c == nil {
		t.Fatal("admin login did not set session cookie")
	}
	return c.Value
}
