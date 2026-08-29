package main

// P1-03D1B · Fresh-Install Secret-at-Rest Gate（隔离 staging 实例 + canary）
//
// 场景：全新安装从第一天起就不产生明文 Provider Secret at rest。
// 全程使用明显 canary 串（P103D1B_*），绝不使用真实供应商密钥。
//
// 链路（全部在 t.TempDir()（repo 外）执行）：
//   fresh config + fresh SQLite
//   → Master Key file（0600，repo 外）
//   → Global canary 经安全 CLI（-set-provider-key 语义）写入
//   → Client canary 经 Admin 表单写入（at-rest 加密路径）
//   → 启动 gateway（生产同序装配）→ 本地 mock provider 功能验证（global fallback + client override）
//   → 停止 gateway
//   → YAML 检查：无明文 api_key 键、api_key_encrypted 为 enc:v1 信封
//   → SQLite 检查：backend_api_key 非空计数=0、encrypted 非空
//   → raw scan 全部落盘文件（config + gateway.db*）：两个 canary 命中=0
//   → 缺失/错误 Master Key 启动拒绝
//   → 正确 Master Key 重启成功（再功能验证）

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"ai-gateway/internal/auth"
	"ai-gateway/internal/config"
	"ai-gateway/internal/models"
	"ai-gateway/internal/services"

	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

const (
	freshCanaryGlobal = "P103D1B_CANARY_GLOBAL_FRESH_INSTALL_SECRET"
	freshCanaryClient = "P103D1B_CANARY_CLIENT_FRESH_INSTALL_SECRET"

	freshAdminUser     = "admin"
	freshAdminPass     = "fresh-install-password"
	freshSessionSecret = "fresh-install-session-secret"
)

// noRedirectClient: 不跟随重定向——302 的 Set-Cookie 才能被读取
var freshNoRedirectClient = &http.Client{CheckRedirect: func(req *http.Request, via []*http.Request) error {
	return http.ErrUseLastResponse
}}

type freshUpstream struct {
	URL   string
	Auths *[]string
}

func newFreshUpstream(t *testing.T) *freshUpstream {
	t.Helper()
	auths := []string{}
	up := &freshUpstream{Auths: &auths}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*up.Auths = append(*up.Auths, r.Header.Get("Authorization"))
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

func (u *freshUpstream) lastAuth(t *testing.T) string {
	t.Helper()
	if len(*u.Auths) == 0 {
		t.Fatal("upstream 未收到任何请求")
	}
	return (*u.Auths)[len(*u.Auths)-1]
}

func TestFreshInstall_SecretAtRest_Gate(t *testing.T) {
	dir := t.TempDir() // repo 外
	cfgPath := filepath.Join(dir, "config.yaml")
	dataDir := filepath.Join(dir, "data")
	dbPath := filepath.Join(dataDir, "gateway.db")
	up := newFreshUpstream(t)

	// ---- fresh config：完整管理段（避免 Load 触发写回）+ provider 骨架（无任何 key）----
	hash, err := bcrypt.GenerateFromPassword([]byte(freshAdminPass), bcrypt.DefaultCost)
	if err != nil {
		t.Fatal(err)
	}
	freshCfg := "server:\n  host: 127.0.0.1\n  port: 8090\n  admin:\n    host: 127.0.0.1\n    port: 8091\nadmin:\n  username: " + freshAdminUser + "\n  password_hash: " + string(hash) + "\n  session_secret: " + freshSessionSecret + "\n  cookie_secure: false\ndatabase:\n  path: " + dbPath + "\nproviders:\n  openai:\n    type: openai\n    base_url: " + up.URL + "/v1\n"
	if err := os.WriteFile(cfgPath, []byte(freshCfg), 0600); err != nil {
		t.Fatal(err)
	}

	// ---- Master Key file（0600，repo 外）----
	masterKeyPath := filepath.Join(dir, "master.key")
	if err := os.WriteFile(masterKeyPath, []byte(testMasterKeyB64), 0600); err != nil {
		t.Fatal(err)
	}
	_ = os.Chmod(masterKeyPath, 0600) // Windows 上为 best-effort；POSIX 语义由部署规范保证
	t.Setenv("AIGATEWAY_MASTER_KEY_FILE", masterKeyPath)

	// ---- Global canary 经安全 CLI 写入（stdin 模式；无 argv/明文落盘）----
	var cliOut bytes.Buffer
	reader := newProviderKeyReader(strings.NewReader(freshCanaryGlobal+"\n"), true)
	if _, err := runSetProviderKey(cfgPath, "openai", false, reader, &cliOut); err != nil {
		t.Fatalf("provisioning 失败: %v", err)
	}
	if strings.Contains(cliOut.String(), freshCanaryGlobal) || strings.Contains(cliOut.String(), "enc:v1:") {
		t.Fatal("[安全回归失败] provisioning stdout 泄露 secret 材料")
	}

	// ---- 启动 gateway（生产同序：Load → DB/AutoMigrate → preflight → runtime 视图 → deps）----
	if err := os.MkdirAll(dataDir, 0700); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	db, err := gorm.Open(sqlite.Open(dbPath), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.AutoMigrate(&models.Client{}, &models.RequestLog{}, &models.DailyUsage{}, &models.AdminSession{}); err != nil {
		t.Fatal(err)
	}

	mgr, err := ensureProviderSecretsRunnable(cfg, db)
	if err != nil {
		t.Fatalf("preflight: %v", err)
	}
	runtimeCfg, err := buildRuntimeConfig(cfg, mgr)
	if err != nil {
		t.Fatal(err)
	}
	deps := newGatewayDeps(cfg, runtimeCfg, db, false, mgr, nil)
	apiMux := buildAPIRouter(deps)
	adminMux, err := buildAdminRouter(deps)
	if err != nil {
		t.Fatal(err)
	}

	// ---- Client canary 经 Admin 表单写入（at-rest 路径）+ 无 key client（global fallback）----
	adminSrv := httptest.NewServer(adminMux)
	session := freshAdminLogin(t, adminSrv.URL, freshAdminUser, freshAdminPass)
	freshAdminCreateClient(t, adminSrv.URL, session, "fresh-client-global", "", "")
	freshAdminCreateClient(t, adminSrv.URL, session, "fresh-client-override", freshCanaryClient, up.URL+"/v1")

	// ---- 功能验证（经真实 public 路由到本地 mock provider）----
	apiSrv := httptest.NewServer(apiMux)
	clientSvc := services.NewClientService(db)

	freshDoChat(t, apiSrv.URL, freshGatewayKeyOf(t, clientSvc, "fresh-client-global"))
	if got := up.lastAuth(t); got != "Bearer "+freshCanaryGlobal {
		t.Fatalf("[功能回归失败] global fallback 应携带解密后的全局 key，实际 %q", got)
	}
	freshDoChat(t, apiSrv.URL, freshGatewayKeyOf(t, clientSvc, "fresh-client-override"))
	if got := up.lastAuth(t); got != "Bearer "+freshCanaryClient {
		t.Fatalf("[功能回归失败] client 密文 override 应生效，实际 %q", got)
	}

	// ---- 停止 gateway（httptest close + SQLite 干净关闭）----
	apiSrv.Close()
	adminSrv.Close()
	if err := closeSQLDB(db); err != nil {
		t.Fatal(err)
	}

	// ---- YAML 检查 ----
	rawCfg, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(rawCfg), "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "api_key:") {
			t.Fatalf("[安全回归失败] YAML 出现明文 api_key 键: %q", trimmed)
		}
	}
	if !strings.Contains(string(rawCfg), "api_key_encrypted: enc:v1:") {
		t.Fatal("[安全回归失败] YAML 未含信封形态的 api_key_encrypted")
	}

	// ---- SQLite 检查（只读语义：检查后关闭）----
	dbCheck, err := gorm.Open(sqlite.Open(dbPath), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	var legacyCount, encCount int64
	if err := dbCheck.Raw("SELECT count(*) FROM clients WHERE backend_api_key != ''").Scan(&legacyCount).Error; err != nil {
		t.Fatal(err)
	}
	if err := dbCheck.Raw("SELECT count(*) FROM clients WHERE backend_api_key_encrypted != ''").Scan(&encCount).Error; err != nil {
		t.Fatal(err)
	}
	if legacyCount != 0 {
		t.Fatalf("[安全回归失败] backend_api_key 非空计数=%d，应为 0", legacyCount)
	}
	if encCount < 1 {
		t.Fatal("[安全回归失败] backend_api_key_encrypted 应非空（client canary 已加密入库）")
	}

	// ---- raw scan：全部落盘文件（config + gateway.db*，含 WAL/journal 若存在）不含任何 canary ----
	scanTargets := []string{cfgPath}
	entries, err := os.ReadDir(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		scanTargets = append(scanTargets, filepath.Join(dataDir, e.Name()))
	}
	for _, target := range scanTargets {
		data, err := os.ReadFile(target)
		if err != nil {
			t.Fatal(err)
		}
		for _, canary := range []string{freshCanaryGlobal, freshCanaryClient} {
			if n := bytes.Count(data, []byte(canary)); n != 0 {
				t.Fatalf("[安全回归失败] 落盘文件 %s 含 canary（%d 处）——明文泄漏到磁盘", filepath.Base(target), n)
			}
		}
	}

	// ---- 缺失 Master Key → 启动拒绝 ----
	os.Unsetenv("AIGATEWAY_MASTER_KEY_FILE")
	os.Unsetenv("AIGATEWAY_MASTER_KEY")
	if _, err := ensureProviderSecretsRunnable(cfg, dbCheck); err == nil {
		t.Fatal("[安全回归失败] 密文存在但无 Master Key 应拒绝启动")
	}

	// ---- 错误 Master Key → 启动拒绝 ----
	if err := os.Setenv("AIGATEWAY_MASTER_KEY", testMasterKeyB64Alt); err != nil {
		t.Fatal(err)
	}
	if _, err := ensureProviderSecretsRunnable(cfg, dbCheck); err == nil {
		t.Fatal("[安全回归失败] 错误 Master Key 应拒绝启动")
	}
	os.Unsetenv("AIGATEWAY_MASTER_KEY")

	// ---- 正确 Master Key → 重启成功（preflight + runtime 解密 + 再功能验证）----
	t.Setenv("AIGATEWAY_MASTER_KEY_FILE", masterKeyPath)
	mgr2, err := ensureProviderSecretsRunnable(cfg, dbCheck)
	if err != nil {
		t.Fatalf("[安全回归失败] 正确 Master Key 重启应通过，实际 %v", err)
	}
	runtimeCfg2, err := buildRuntimeConfig(cfg, mgr2)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Providers["openai"].APIKey != "" {
		t.Fatal("[安全回归失败] 重启后持久化 cfg 出现明文")
	}
	deps2 := newGatewayDeps(cfg, runtimeCfg2, dbCheck, false, mgr2, nil)
	apiSrv2 := httptest.NewServer(buildAPIRouter(deps2))
	defer apiSrv2.Close()
	clientSvc2 := services.NewClientService(dbCheck) // 重启后的新句柄（db 已在停服时关闭）
	freshDoChat(t, apiSrv2.URL, freshGatewayKeyOf(t, clientSvc2, "fresh-client-global"))
	if got := up.lastAuth(t); got != "Bearer "+freshCanaryGlobal {
		t.Fatalf("[功能回归失败] 重启后 global key 未恢复，实际 %q", got)
	}

	_ = closeSQLDB(dbCheck)
}

func closeSQLDB(db *gorm.DB) error {
	if db == nil {
		return nil
	}
	if sqlDB, err := db.DB(); err == nil {
		return sqlDB.Close()
	}
	return nil
}

func freshDoChat(t *testing.T, baseURL, gwKey string) {
	t.Helper()
	body := `{"model":"test-model","messages":[{"role":"user","content":"ping"}]}`
	req, err := http.NewRequest("POST", baseURL+"/v1/chat/completions", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+gwKey)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("chat 期望 200，实际 %d body=%s", resp.StatusCode, string(b))
	}
}

func freshGatewayKeyOf(t *testing.T, svc *services.ClientService, name string) string {
	t.Helper()
	clients, err := svc.GetAllClients()
	if err != nil {
		t.Fatal(err)
	}
	id := ""
	for _, c := range clients {
		if c.Name == name {
			id = c.ID
		}
	}
	if id == "" {
		t.Fatalf("client %q 不存在", name)
	}
	key, err := svc.RegenerateAPIKey(id, "openai", "sk-")
	if err != nil {
		t.Fatal(err)
	}
	return key
}

// freshAdminLogin: GET /admin/login（pre-auth CSRF）→ POST 登录 → 返回 session token
func freshAdminLogin(t *testing.T, baseURL, user, pass string) string {
	t.Helper()
	resp, err := freshNoRedirectClient.Get(baseURL + "/admin/login")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	m := regexp.MustCompile(`name="csrf_token" value="([0-9a-f]{64})"`).FindStringSubmatch(string(b))
	if m == nil {
		t.Fatal("login 页缺少 pre-auth csrf token")
	}
	token := m[1]
	var preauthCookie *http.Cookie
	for _, c := range resp.Cookies() {
		if c.Name == auth.PreAuthCSRFCookie {
			preauthCookie = c
		}
	}
	if preauthCookie == nil {
		t.Fatal("login 页未设置 preauth cookie")
	}

	form := url.Values{"username": {user}, "password": {pass}, "csrf_token": {token}}
	req, _ := http.NewRequest("POST", baseURL+"/admin/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(preauthCookie)
	resp2, err := freshNoRedirectClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusFound {
		t.Fatalf("登录应 302，实际 %d", resp2.StatusCode)
	}
	for _, c := range resp2.Cookies() {
		if c.Name == auth.SessionCookieName {
			return c.Value
		}
	}
	t.Fatal("登录未获得 session cookie")
	return ""
}

// freshAdminCreateClient: 经 Admin 表单创建 client（key 走 at-rest 加密路径）
func freshAdminCreateClient(t *testing.T, baseURL, session, name, providerKey, baseURLOverride string) {
	t.Helper()
	form := url.Values{
		"name":             {name},
		"backend":          {"openai"},
		"backend_api_key":  {providerKey},
		"backend_base_url": {baseURLOverride},
	}
	req, _ := http.NewRequest("POST", baseURL+"/admin/clients", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: auth.SessionCookieName, Value: session})
	req.Header.Set("X-CSRF-Token", auth.CSRFToken(freshSessionSecret, session))
	resp, err := freshNoRedirectClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("admin 创建 client %s 期望 200，实际 %d body=%s", name, resp.StatusCode, string(b))
	}
	if strings.Contains(string(b), freshCanaryClient) || strings.Contains(string(b), "enc:v1:") {
		t.Fatalf("[安全回归失败] 创建页回显 key 材料: %s", name)
	}
}
