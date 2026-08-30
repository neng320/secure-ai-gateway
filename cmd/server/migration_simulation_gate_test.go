package main

// P1-03C3 · Migration Simulation Security Gate（全栈部分）
//
// 矩阵索引（任务卡 9 项 → 覆盖位置）：
//   1. C2 preconditions          → internal/secretmigration/preconditions_test.go（缺 config/DB/解析失败不落盘、备份先行、旧 schema additive）
//   2. JSON exposure             → internal/config/secret_json_exposure_test.go + handlers TestP103A_ClientKey_NotInJSONMarshaling
//   3. Empty-secret Manager      → preflight_gate_test.go（AllEmpty×{无key,合法key,冲突,非法}）+ handlers migration_ui_gate_test.go（Admin 新增 fail-closed）
//   4. Runtime persistence isolation → 本文件 TestMigrationGate_RuntimePersistenceIsolation
//   5. Client key 矩阵           → handlers TestP103A_Fixed_UpdateClient_KeySemantics（blank保留/替换/显式清除）+ migration_ui_gate_test.go（Admin Create 流）
//   6. Gemini sink               → 本文件 TestMigrationGate_GeminiService_KeyOnlyInHeader + providers 侧 TestP103A_Gemini_URLContainsKey_InErrorPath
//   7. KNOWN-VULN 翻红改写       → handlers p1_03a_key_flow_test.go（YAML/SQLite/HTML 三处已反转为安全回归）
//   8. Fixture A-F/幂等/不匹配/错误AAD → internal/secretmigration/migrate_test.go（9 用例）
//   9. 原有 Gate（Auth/Admin/Listener）→ 各包既有回归随全量 go test ./... 执行
//
// Canary 约束：仅使用明显的测试标记串；禁止真实 API Key。

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"ai-gateway/internal/config"
	"ai-gateway/internal/models"
	"ai-gateway/internal/secrets"
	"ai-gateway/internal/services"

	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

const (
	gateCanaryGlobal = "P103C3GATE_CANARY_GLOBAL_PROVIDER_SECRET"
	gateCanaryClient = "P103C3GATE_CANARY_CLIENT_PROVIDER_SECRET"
	gateCanaryGemini = "P103C3GATE_CANARY_GEMINI_PROVIDER_SECRET"
)

type gateUpstream struct {
	URL     string
	Auths   *[]string
	Queries *[]string
	Paths   *[]string
}

func newGateUpstream(t *testing.T) *gateUpstream {
	t.Helper()
	auths := []string{}
	queries := []string{}
	paths := []string{}
	up := &gateUpstream{Auths: &auths, Queries: &queries, Paths: &paths}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*up.Auths = append(*up.Auths, r.Header.Get("Authorization"))
		*up.Queries = append(*up.Queries, r.URL.RawQuery)
		*up.Paths = append(*up.Paths, r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"choices": []map[string]interface{}{{"message": map[string]string{"role": "assistant", "content": "pong"}}},
			"usage":   map[string]int{"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
		})
	}))
	t.Cleanup(srv.Close)
	up.URL = srv.URL
	return up
}

func (u *gateUpstream) lastAuth(t *testing.T) string {
	t.Helper()
	if len(*u.Auths) == 0 {
		t.Fatal("upstream 未收到任何请求")
	}
	return (*u.Auths)[len(*u.Auths)-1]
}

func (u *gateUpstream) lastQuery(t *testing.T) string {
	t.Helper()
	if len(*u.Queries) == 0 {
		t.Fatal("upstream 未收到任何请求")
	}
	return (*u.Queries)[len(*u.Queries)-1]
}

// gateEnv: 全栈环境——走真实生产装配路径（preflight → buildRuntimeConfig → newGatewayDeps）
type gateEnv struct {
	cfg        *config.Config
	runtimeCfg *config.Config
	mgr        *secrets.Manager
	db         *gorm.DB
	api        http.Handler
	admin      http.Handler
	upstream   *gateUpstream
	cfgPath    string
	clientSvc  *services.ClientService
	lastSeen   *testLastSeenPool
}

func newGateEnv(t *testing.T, encryptedGlobal bool) *gateEnv {
	t.Helper()
	t.Setenv("AIGATEWAY_MASTER_KEY", testMasterKeyB64)

	up := newGateUpstream(t)

	cfgPath := filepath.Join(t.TempDir(), "config.yaml")
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatalf("load temp config: %v", err)
	}
	hash, err := bcrypt.GenerateFromPassword([]byte("migration-gate-password"), bcrypt.DefaultCost)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Admin.Username = "admin"
	cfg.Admin.PasswordHash = string(hash)
	cfg.Admin.SessionSecret = "migration-gate-session-secret"
	cfg.Admin.CookieSecure = false

	mgr0 := secrets.NewManager(mustCipherForTest(t))
	pcfg := config.ProviderConfig{Type: "openai", BaseURL: up.URL + "/v1"}
	if encryptedGlobal {
		env, encErr := mgr0.EncryptGlobalProviderKey("openai", []byte(gateCanaryGlobal))
		if encErr != nil {
			t.Fatal(encErr)
		}
		pcfg.APIKeyEncrypted = env
	} else {
		pcfg.APIKey = gateCanaryGlobal
	}
	cfg.Providers = map[string]config.ProviderConfig{"openai": pcfg}

	db, err := gorm.Open(sqlite.Open(filepath.Join(t.TempDir(), "gate.db")), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.AutoMigrate(&models.Client{}, &models.RequestLog{}, &models.DailyUsage{}, &models.AdminSession{}, &models.AuditEvent{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	migrateTestAudit(t, db)
	lastSeen := attachTestLastSeenPool(db)
	t.Cleanup(func() {
		if err := closeTestLastSeenDB(db, lastSeen); err != nil {
			t.Errorf("close migration test database: %v", err)
		}
	})

	// 生产同序：preflight → 运行时视图派生 → deps
	mgr, err := ensureProviderSecretsRunnable(cfg, db)
	if err != nil {
		t.Fatalf("preflight: %v", err)
	}
	runtimeCfg, err := buildRuntimeConfig(cfg, mgr)
	if err != nil {
		t.Fatalf("buildRuntimeConfig: %v", err)
	}

	deps := newGatewayDeps(cfg, runtimeCfg, db, false, mgr, nil)
	apiMux := buildAPIRouter(deps)
	adminMux, err := buildAdminRouter(deps)
	if err != nil {
		t.Fatalf("buildAdminRouter: %v", err)
	}

	return &gateEnv{
		cfg: cfg, runtimeCfg: runtimeCfg, mgr: mgr, db: db,
		api: apiMux, admin: adminMux, upstream: up, cfgPath: cfgPath,
		clientSvc: services.NewClientService(db), lastSeen: lastSeen,
	}
}

// createGateClient: 建一个网关 client 并返回其网关 API Key（明文）
func (e *gateEnv) createGateClient(t *testing.T, backend, overrideBaseURL string, overrideKeyEnv string) (string, string) {
	t.Helper()
	client, gwKey, err := e.clientSvc.CreateClient("gate-client", "", "openai", "sk-", e.cfg, "test-admin")
	if err != nil {
		t.Fatal(err)
	}
	updates := map[string]interface{}{"backend": backend} // service 层默认 gemini，显式指定
	if overrideBaseURL != "" {
		updates["backend_base_url"] = overrideBaseURL
	}
	if overrideKeyEnv != "" {
		updates["backend_api_key_encrypted"] = overrideKeyEnv
	}
	if err := e.clientSvc.UpdateClientSettings(client.ID, updates); err != nil {
		t.Fatal(err)
	}
	return client.ID, gwKey
}

func (e *gateEnv) doChat(t *testing.T, gwKey string) {
	t.Helper()
	body := `{"model":"test-model","messages":[{"role":"user","content":"ping"}]}`
	req := httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+gwKey)
	w := httptest.NewRecorder()
	e.api.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		e.lastSeen.waitForCompletion(t)
	}
	if w.Code != http.StatusOK {
		t.Fatalf("chat 期望 200，实际 %d body=%s", w.Code, w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// Gate 4 · Runtime persistence isolation（encrypted-only 全局 provider 全链路）
// ---------------------------------------------------------------------------
func TestMigrationGate_RuntimePersistenceIsolation(t *testing.T) {
	e := newGateEnv(t, true)
	persisted := e.cfg.Providers["openai"]

	// 启动后持久化视图必须仍是 envelope-only
	if persisted.APIKey != "" {
		t.Fatalf("[安全回归失败] 持久化 cfg 出现明文 APIKey: %q", persisted.APIKey)
	}
	if !secrets.IsEncryptedEnvelope(persisted.APIKeyEncrypted) {
		t.Fatalf("[安全回归失败] 持久化 cfg 信封缺失: %q", persisted.APIKeyEncrypted)
	}

	// client 无 override → registry 全局 provider（runtimeCfg 已解密）→ 上游收到明文
	_, gwKey := e.createGateClient(t, "openai", "", "")
	e.doChat(t, gwKey)
	if got := e.upstream.lastAuth(t); got != "Bearer "+gateCanaryGlobal {
		t.Fatalf("[功能回归失败] 上游应收到解密后的全局 key，实际 %q", got)
	}
	if q := e.upstream.lastQuery(t); strings.Contains(q, gateCanaryGlobal) || strings.Contains(q, "key=") {
		t.Fatalf("[安全回归失败] URL query 携带 key 材料: %q", q)
	}

	// 请求后持久化视图仍不变（运行态明文绝不回流）
	if e.cfg.Providers["openai"].APIKey != "" {
		t.Fatal("[安全回归失败] 请求后持久化 cfg 被写入明文")
	}

	// SaveConfig 后文件无明文、保留信封
	if err := config.SaveConfig(e.cfg, e.cfgPath); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(e.cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	saved := string(raw)
	if strings.Contains(saved, gateCanaryGlobal) {
		t.Fatal("[安全回归失败] SaveConfig 后配置文件含明文 canary")
	}
	if !strings.Contains(saved, "api_key_encrypted: enc:v1:") {
		t.Fatal("[安全回归失败] SaveConfig 后配置文件未保留信封字段")
	}
}

// ---------------------------------------------------------------------------
// Gate 5 · Client override 密文经公网 API 正常工作（解密 → 上游明文）
// ---------------------------------------------------------------------------
func TestMigrationGate_ClientEncryptedOverride_E2E(t *testing.T) {
	e := newGateEnv(t, true)

	id, gwKey := e.createGateClient(t, "openai", "", "")
	client, err := e.clientSvc.GetClientByID(id)
	if err != nil || client == nil {
		t.Fatalf("client 不存在: %v", err)
	}
	envC, err := e.mgr.EncryptClientBackendKey(client.ID, []byte(gateCanaryClient))
	if err != nil {
		t.Fatal(err)
	}
	if err := e.clientSvc.UpdateClientSettings(client.ID, map[string]interface{}{
		"backend_base_url":          e.upstream.URL + "/v1",
		"backend_api_key_encrypted": envC,
	}); err != nil {
		t.Fatal(err)
	}

	e.doChat(t, gwKey)
	if got := e.upstream.lastAuth(t); got != "Bearer "+gateCanaryClient {
		t.Fatalf("[功能回归失败] client 密文 override 未生效，上游实际 %q", got)
	}
}

// ---------------------------------------------------------------------------
// Gate 6 · Gemini service sink：key 只在 x-goog-api-key header；
// query/error 不含 key 材料；BaseURL 可注入（不出外网）
// ---------------------------------------------------------------------------
func TestMigrationGate_GeminiService_KeyOnlyInHeader(t *testing.T) {
	var googHeaders []string
	queries := []string{}
	paths := []string{}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		googHeaders = append(googHeaders, r.Header.Get("x-goog-api-key"))
		queries = append(queries, r.URL.RawQuery)
		paths = append(paths, r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{}`))
	}))
	t.Cleanup(upstream.Close)

	cfg := &config.Config{
		Providers: map[string]config.ProviderConfig{
			"gemini": {Type: "gemini", APIKey: gateCanaryGemini, BaseURL: upstream.URL},
		},
	}
	db, err := gorm.Open(sqlite.Open(filepath.Join(t.TempDir(), "gem.db")), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if sqlDB, e := db.DB(); e == nil {
			_ = sqlDB.Close()
		}
	})
	svc := services.NewGeminiService(db, cfg)

	// 非流式：header 携带，query 干净
	if _, status, err := svc.ForwardRequest("gemini-2.0-flash", []byte(`{}`)); err != nil || status != 200 {
		t.Fatalf("ForwardRequest 失败: status=%d err=%v", status, err)
	}
	if last := googHeaders[len(googHeaders)-1]; last != gateCanaryGemini {
		t.Fatalf("[安全回归失败] x-goog-api-key 应为 canary，实际 %q", last)
	}
	if q := queries[len(queries)-1]; q != "" {
		t.Fatalf("[安全回归失败] 非流式 query 应为空，实际 %q", q)
	}
	if p := paths[len(paths)-1]; !strings.Contains(p, "/models/gemini-2.0-flash:generateContent") {
		t.Fatalf("[功能回归失败] 非流式路径不符: %q", p)
	}

	// 流式：header 携带，query 仅 alt=sse
	resp, _, err := svc.ForwardStreamRequest("gemini-2.0-flash", []byte(`{}`))
	if err != nil {
		t.Fatalf("ForwardStreamRequest 失败: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("[功能回归失败] 流式状态码 %d", resp.StatusCode)
	}
	if last := googHeaders[len(googHeaders)-1]; last != gateCanaryGemini {
		t.Fatalf("[安全回归失败] 流式 x-goog-api-key 应为 canary，实际 %q", last)
	}
	if q := queries[len(queries)-1]; q != "alt=sse" {
		t.Fatalf("[安全回归失败] 流式 query 应仅为 alt=sse，实际 %q", q)
	}

	// 错误路径：连接失败错误串不含 key 材料、不含 key= 形态
	badCfg := &config.Config{
		Providers: map[string]config.ProviderConfig{
			"gemini": {Type: "gemini", APIKey: gateCanaryGemini, BaseURL: "http://127.0.0.1:1"},
		},
	}
	badSvc := services.NewGeminiService(db, badCfg)
	_, _, err = badSvc.ForwardRequest("gemini-2.0-flash", []byte(`{}`))
	if err == nil {
		t.Fatal("closed port 应产生错误")
	}
	if strings.Contains(err.Error(), gateCanaryGemini) || strings.Contains(err.Error(), "key=") {
		t.Fatalf("[安全回归失败] 错误串泄露 key 材料: %v", err)
	}
}
