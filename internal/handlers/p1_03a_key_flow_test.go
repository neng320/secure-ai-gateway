package handlers

// P1-03A · Provider Key Flow Characterization Tests
//
// 固化 tag secure-gateway-p1-admin-security.3 时点的 Provider Secret 行为。
//
// 标记约定：
//   [CURRENT]                     —— 当时行为，SEC-002 修复后按设计决定保留或调整
//   [KNOWN-VULN: SEC-002]         —— 明文暴露事实，AEAD 落地后翻红并改写
//   [P1-03C3 安全回归]             —— 反转后的安全行为回归（原文保留在注释里）
//
// Canary 约束：仅使用明显的测试标记串，绝不使用疑似真实 Key 的字符串
//（避免 secret scanner 误报）。禁止使用真实 API Key 作为测试数据。

import (
	"encoding/base64"
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
	"ai-gateway/internal/secrets"
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
	// kfMasterKeyB64: 本文件专用的测试 Master Key（32 字节，非真实凭证）
	kfMasterKeyB64 = "GROnfCSaRXSkQ9VpR8kjD9Xc1vLGZ0zGKivSgNzTuw0="
)

func mustKFCipher(t *testing.T) *secrets.AESGCMCipher {
	t.Helper()
	key, err := base64.StdEncoding.DecodeString(kfMasterKeyB64)
	if err != nil {
		t.Fatal(err)
	}
	c, err := secrets.NewAESGCMCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// keyFlowEnv: 密钥流测试环境（本地 upstream 捕获 Authorization，不出外网）
type keyFlowEnv struct {
	cfg           *config.Config
	db            *gorm.DB
	clientService *services.ClientService
	limiter       *auth.LoginRateLimiter
	store         *auth.SQLiteStore
	manager       *secrets.Manager
	openai        http.Handler // /v1/* 路由（含 client key 认证中间件）
	admin         http.Handler // /admin/* 路由（含 RequireAuth/CSRF）
	adminMux      *chi.Mux     // 同 admin，保留具体类型供 chi.Walk 路由枚举（静态防线用）
	upstreamURL   string
	upstreamAuths *[]string
}

func newKeyFlowEnv(t *testing.T, globalAPIKey string) *keyFlowEnv {
	t.Helper()
	return newKeyFlowEnvWithManager(t, globalAPIKey, secrets.NewManager(mustKFCipher(t)))
}

// newKeyFlowEnvWithManager: 允许注入 nil Manager（模拟未配置 Master Key 的空系统）
func newKeyFlowEnvWithManager(t *testing.T, globalAPIKey string, manager *secrets.Manager) *keyFlowEnv {
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
	if err := db.AutoMigrate(&models.Client{}, &models.RequestLog{}, &models.DailyUsage{}, &models.AdminSession{}, &models.AuditEvent{}); err != nil {
		t.Fatal(err)
	}
	migrateHandlerAudit(t, db)
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
	openaiHandler := NewOpenAIHandler(geminiService, clientService, statsService, registry, toolService, manager, nil)
	apiMux := chi.NewRouter()
	apiMux.Use(mw.NewAuthMiddleware(clientService).Handler)
	openaiHandler.RegisterRoutes(apiMux)

	// Admin 路由（与 buildAdminRouter 同构）
	adminHandler, err := NewAdminHandler(cfg, clientService, statsService, geminiService, dashboardHub, toolService, store, limiter, manager, "", nil, mw.NewRateLimiter())
	if err != nil {
		t.Fatal(err)
	}
	adminMux := chi.NewRouter()
	adminHandler.RegisterRoutes(adminMux)

	return &keyFlowEnv{
		cfg: cfg, db: db, clientService: clientService, limiter: limiter, store: store,
		manager: manager, openai: apiMux, admin: adminMux, adminMux: adminMux, upstreamURL: upstream.URL, upstreamAuths: &auths,
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

// createClientWithKey: 建一个 backend=openai 的 client。
// P1-03C3 起 key 只存密文（与 Admin CreateClient 同语义）：明文参数即刻转为信封。
func (e *keyFlowEnv) createClientWithKey(t *testing.T, backendAPIKey string) *models.Client {
	t.Helper()
	client, _, err := e.clientService.CreateClient("kf", "", "openai", "sk-", e.cfg, "test-admin")
	if err != nil {
		t.Fatal(err)
	}
	updates := map[string]interface{}{
		"backend":          "openai",              // service 层 CreateClient 不设 Backend（DB 默认 gemini），显式指定
		"backend_base_url": e.upstreamURL + "/v1", // openai_compat 约定：base 已含 /v1
	}
	if backendAPIKey != "" {
		env, encErr := e.manager.EncryptClientBackendKey(client.ID, []byte(backendAPIKey))
		if encErr != nil {
			t.Fatal(encErr)
		}
		updates["backend_api_key_encrypted"] = env
	}
	if err := e.clientService.UpdateClientSettings(client.ID, updates); err != nil {
		t.Fatal(err)
	}
	return client
}

// ---------------------------------------------------------------------------
//  1. [P1-03C3 安全回归]（反转自 KNOWN-VULN: SEC-002 "全局 Provider Key 明文落 YAML"）
//     持久化层保存 AEAD 信封：YAML 不含明文；Load 回读后 legacy 字段为空、信封保留
//     （运行态明文仅经 cmd/server buildRuntimeConfig 进入一次性副本，绝不回流持久化视图）。
//
// ---------------------------------------------------------------------------
func TestP103A_GlobalKey_PlaintextInSavedYAML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	cfg := minimalSetupCfg()
	mgr := secrets.NewManager(mustKFCipher(t))
	env, err := mgr.EncryptGlobalProviderKey("openai", []byte(canaryGlobal))
	if err != nil {
		t.Fatal(err)
	}
	cfg.Providers = map[string]config.ProviderConfig{
		"openai": {Type: "openai", APIKeyEncrypted: env, BaseURL: "https://api.openai.example/v1"},
	}

	if err := config.SaveConfig(cfg, path); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	saved := string(raw)
	if strings.Contains(saved, canaryGlobal) {
		t.Fatal("[安全回归失败] YAML 中出现明文 canary")
	}
	if !strings.Contains(saved, "api_key_encrypted: "+env) {
		t.Fatalf("[安全回归失败] YAML 未按信封形态保存 api_key_encrypted:\n%s", saved)
	}

	// 回读：持久化视图 legacy 为空、信封保留
	cfg2, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	p := cfg2.Providers["openai"]
	if p.APIKey != "" {
		t.Fatalf("[安全回归失败] 回读后 legacy APIKey 应为空，实际 %q", p.APIKey)
	}
	if p.APIKeyEncrypted != env {
		t.Fatalf("[安全回归失败] 回读后信封不符: %q", p.APIKeyEncrypted)
	}
}

// ---------------------------------------------------------------------------
//  2. [P1-03C3 安全回归]（反转自 KNOWN-VULN: SEC-002 "Client BackendAPIKey 明文落 SQLite"）
//     legacy 列保持空；密文在 additive encrypted 列且解密可还原原明文。
//
// ---------------------------------------------------------------------------
func TestP103A_ClientKey_PlaintextInSQLite(t *testing.T) {
	env := newKeyFlowEnv(t, canaryGlobal)
	client := env.createClientWithKey(t, canaryClient)

	var row struct {
		Legacy    string
		Encrypted string
	}
	if err := env.db.Raw("SELECT backend_api_key AS legacy, backend_api_key_encrypted AS encrypted FROM clients WHERE id = ?", client.ID).Scan(&row).Error; err != nil {
		t.Fatal(err)
	}
	if row.Legacy != "" {
		t.Fatalf("[安全回归失败] legacy backend_api_key 应为空，实际 %q", row.Legacy)
	}
	if !secrets.IsEncryptedEnvelope(row.Encrypted) {
		t.Fatalf("[安全回归失败] backend_api_key_encrypted 应为 enc:v1 信封，实际 %q", row.Encrypted)
	}
	pt, err := env.manager.DecryptClientBackendKey(client.ID, row.Encrypted)
	if err != nil || string(pt) != canaryClient {
		t.Fatalf("[安全回归失败] 解密应还原原明文，实际 %q err=%v", string(pt), err)
	}
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

	// b) client key 清空（encrypted 字段清空，BaseURL 保留）→ 全局 key 回退
	if err := env.clientService.UpdateClientSettings(client.ID, map[string]interface{}{"backend_api_key_encrypted": ""}); err != nil {
		t.Fatal(err)
	}
	env.doChat(t, clientAPIKeyOf(t, env, client), "test-model")
	if got := env.lastUpstreamAuth(t); got != "Bearer "+canaryGlobal {
		t.Fatalf("[优先级回归失败] 期望全局 key 回退，实际 %q", got)
	}

	// c) client key 与 BaseURL 都空 → registry 全局 provider（其 BaseURL 亦为 upstream）
	if err := env.clientService.UpdateClientSettings(client.ID, map[string]interface{}{"backend_base_url": ""}); err != nil {
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
	newKey, err := env.clientService.RegenerateAPIKey(client.ID, "openai", "sk-", "test-admin", "P105C rotate reason")
	if err != nil {
		t.Fatal(err)
	}
	return newKey
}

// ---------------------------------------------------------------------------
//  4. [P1-03C3 安全回归]（反转自 [CURRENT] "Update 表单 blank key = 清空"）
//     决策后的新语义：
//     blank key            → 保留现有 key（表单不再回填明文，旧行为会静默清掉）
//     填入新 key           → 加密替换（解密 == 新 key，legacy 保持空）
//     clear_backend_api_key → 显式清除
//
// ---------------------------------------------------------------------------
func TestP103A_Fixed_UpdateClient_KeySemantics(t *testing.T) {
	env := newKeyFlowEnv(t, canaryGlobal)
	client := env.createClientWithKey(t, canaryClient)
	clientToken := adminSessionToken(t, env)
	// P1-05C：createClientWithKey 经 UpdateClientSettings（allowlist map）落库，
	// 返回对象不携带信封——originalEnvelope 必须从库重载
	orig, err := env.clientService.GetClientByID(client.ID)
	if err != nil || orig == nil {
		t.Fatal("client 不存在")
	}
	originalEnvelope := orig.BackendAPIKeyEncrypted

	postUpdate := func(extra map[string]string) *http.Response {
		form := url.Values{
			"name":                  {client.Name},
			"backend":               {"openai"},
			"backend_base_url":      {env.upstreamURL + "/v1"},
			"backend_default_model": {"test-model"},
		}
		for k, v := range extra {
			form.Set(k, v)
		}
		req := httptest.NewRequest("POST", "/admin/clients/"+client.ID+"/update", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: clientToken})
		req.Header.Set("X-CSRF-Token", auth.CSRFToken(env.cfg.Admin.SessionSecret, clientToken))
		w := httptest.NewRecorder()
		env.admin.ServeHTTP(w, req)
		return w.Result()
	}
	reload := func(t *testing.T) *models.Client {
		t.Helper()
		c, err := env.clientService.GetClientByID(client.ID)
		if err != nil || c == nil {
			t.Fatal("client 不存在")
		}
		return c
	}

	// a) blank → 保留原信封
	if resp := postUpdate(map[string]string{"backend_api_key": ""}); resp.StatusCode == http.StatusForbidden {
		t.Fatal("测试自身问题：合法 CSRF 被拒")
	}
	c := reload(t)
	if c.BackendAPIKeyEncrypted != originalEnvelope {
		t.Fatalf("[安全回归失败] blank update 应保留信封，实际 %q", c.BackendAPIKeyEncrypted)
	}
	if c.BackendAPIKey != "" {
		t.Fatalf("[安全回归失败] legacy 字段应保持空，实际 %q", c.BackendAPIKey)
	}

	// b) 填入新 key → 加密替换，解密 == 新 key
	rotated := canaryClient + "-ROTATED"
	if resp := postUpdate(map[string]string{"backend_api_key": rotated}); resp.StatusCode != http.StatusFound {
		t.Fatalf("替换 key 应 302，实际 %d", resp.StatusCode)
	}
	c = reload(t)
	if c.BackendAPIKeyEncrypted == "" || c.BackendAPIKeyEncrypted == originalEnvelope {
		t.Fatalf("[安全回归失败] 新 key 应产生新信封，实际 %q", c.BackendAPIKeyEncrypted)
	}
	pt, err := env.manager.DecryptClientBackendKey(client.ID, c.BackendAPIKeyEncrypted)
	if err != nil || string(pt) != rotated {
		t.Fatalf("[安全回归失败] 新信封应解密为新 key，实际 %q err=%v", string(pt), err)
	}
	if c.BackendAPIKey != "" {
		t.Fatalf("[安全回归失败] 替换后 legacy 字段应保持空，实际 %q", c.BackendAPIKey)
	}

	// c) clear_backend_api_key=on → 显式清除
	if resp := postUpdate(map[string]string{"clear_backend_api_key": "on"}); resp.StatusCode != http.StatusFound {
		t.Fatalf("显式清除应 302，实际 %d", resp.StatusCode)
	}
	c = reload(t)
	if c.BackendAPIKeyEncrypted != "" || c.BackendAPIKey != "" {
		t.Fatalf("[安全回归失败] 显式清除后两字段应为空，实际 legacy=%q encrypted=%q", c.BackendAPIKey, c.BackendAPIKeyEncrypted)
	}
}

// ---------------------------------------------------------------------------
//  5. [P1-03C3 安全回归]（反转自 KNOWN-VULN: SEC-002 "编辑表单把明文 Provider Key 回填进 HTML"）
//     要求四重：无明文、无信封（enc:v1:）、有"已配置"指示、有显式清除复选框，
//     且 backend_api_key 输入框 value 恒为空。
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
	if strings.Contains(body, canaryClient) {
		t.Fatal("[安全回归失败] 编辑页回显了明文 Provider Key")
	}
	if strings.Contains(body, "enc:v1:") {
		t.Fatal("[安全回归失败] 编辑页回显了密文信封（信封同样不得进入 HTML）")
	}
	if !strings.Contains(body, "Provider key configured") {
		t.Fatal("[安全回归失败] 已配置状态指示缺失")
	}
	if !strings.Contains(body, `name="clear_backend_api_key"`) {
		t.Fatal("[安全回归失败] 显式清除复选框缺失")
	}
	if !strings.Contains(body, `name="backend_api_key" value=""`) {
		t.Fatal("[安全回归失败] backend_api_key 输入框应为空值（不回填任何材料）")
	}
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
//  8. [CURRENT] Config Save 机制：struct 里有什么就写什么（P1-03C3 机制保持不变）
//     该机制正是"运行时/持久化双视图"必须存在的原因：系统级保障是
//     明文只进 buildRuntimeConfig 的一次性副本，持久化 cfg 永不含运行态明文
//     （由 cmd/server Migration Simulation Gate 的 persistence-isolation 用例回归）。
//
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
	// 机制确认：把明文放回 struct 再 Save，就会落盘——所以运行态明文绝不允许进入持久化 struct
	cfg.Providers["openai"] = config.ProviderConfig{Type: "openai", APIKey: canaryGlobal + "-RUNTIME"}
	if err := config.SaveConfig(cfg, path); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(path)
	if !strings.Contains(string(raw), canaryGlobal+"-RUNTIME") {
		t.Fatal("[机制变化] SaveConfig 不再直写 struct 中的明文——若如此，更新本机制说明")
	}
	t.Log("[设计约束确认] 持久化隔离依赖双视图纪律：明文只存在于 runtimeCfg 副本")
}

// ---------------------------------------------------------------------------
// 9) [CURRENT] json:"-" 生效：legacy 与 encrypted 两个 key 字段都不进 API JSON 响应
// ---------------------------------------------------------------------------
func TestP103A_ClientKey_NotInJSONMarshaling(t *testing.T) {
	c := models.Client{BackendAPIKey: canaryClient, BackendAPIKeyEncrypted: "enc:v1:deadbeef:QUJDREVGRw"}
	b, _ := json.Marshal(c)
	out := string(b)
	if strings.Contains(out, canaryClient) || strings.Contains(out, "enc:v1:") {
		t.Fatal("[行为变化] key 字段出现在 JSON 序列化中——回归检查 json:\"-\" 标注")
	}
	t.Log("[CURRENT] 确认：json:\"-\" 生效，API JSON 响应不含 legacy/encrypted key 字段")
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
