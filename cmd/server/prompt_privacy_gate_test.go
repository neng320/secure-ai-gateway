package main

// Prompt Privacy Security Gate（SEC-003 / P1-04 终验）
//
// 隔离 staging + canary，覆盖任务卡 12 项矩阵中可在全栈环境验证的部分：
//   1  DEFAULT MODE：capture 关闭下三类请求（openai 非流/流式、gemini native）
//      全链路后 SQLite/config/WAL/journal + runtime log raw scan canary=0
//   2  DB LOGICAL：每条新 RequestLog metadata-only 且字段齐全
//   3  REQUEST ID：HTTP X-Request-ID == SQLite RequestID（逐请求唯一）
//   4  HTML：Dashboard/Client Detail 无 prompt/raw-error canary、无 showRequestBody
//      （细粒度回归见 internal/handlers p1_04 测试；此处全栈复核）
//   5  JSON：RequestLog JSON 无 request_body/error_message（WS 负载见
//      internal/services/wshub_p104_test.go）
//   6  RUNTIME LOG：不可信 upstream error body 不回显（bounded code only）
//   7  DIAGNOSTIC MODE：显式启用 → Admin 端点按需可读；磁盘 0；缺失 404
//   8  BOUNDS：64KiB 硬上限截断经端点验证
//   9  LEGACY：启动拒绝 + fixture scrub（privacy_preflight_gate_test.go 与
//      internal/requestlogscrub 已覆盖，不重复）
//   10 RESPONSE：provider response body 无持久层字段（编译期保证）+ JSON 形态固化
//   11 Existing Gates：全量 go test ./... 覆盖
//   12 DW-01：本 PR 走 task branch → verify.sh → PR → required CI → merge
//
// Canary：P104_FINAL_DISK_CANARY / P104_CANARY_UPSTREAM_ERROR_DO_NOT_LOG（明显标记串）。

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"ai-gateway/internal/auth"
	"ai-gateway/internal/capture"
	"ai-gateway/internal/config"
	"ai-gateway/internal/models"
	"ai-gateway/internal/services"

	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

const (
	gateCanaryPrompt = "P104_FINAL_DISK_CANARY"
	gateCanaryUPErr  = "P104_CANARY_UPSTREAM_ERROR_DO_NOT_LOG"

	gateAdminUser = "admin"
	gateAdminPass = "privacy-gate-password"
)

type syncBuffer struct {
	mu  sync.Mutex
	buf strings.Builder
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

type privacyUpstream struct {
	URL string
	mu  sync.Mutex
	h   http.HandlerFunc
}

func newPrivacyUpstream(t *testing.T, h http.HandlerFunc) *privacyUpstream {
	t.Helper()
	up := &privacyUpstream{h: h}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		up.mu.Lock()
		handler := up.h
		up.mu.Unlock()
		if handler != nil {
			handler(w, r)
			return
		}
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

func (u *privacyUpstream) setBehavior(h http.HandlerFunc) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.h = h
}

type privacyEnv struct {
	cfgPath  string
	dbPath   string
	cfg      *config.Config
	db       *gorm.DB
	api      http.Handler
	admin    http.Handler
	upstream *privacyUpstream
	logBuf   syncBuffer
	lastSeen *testLastSeenPool
}

func (e *privacyEnv) closeDB(t *testing.T) {
	if e.lastSeen != nil {
		if err := closeTestLastSeenDB(e.db, e.lastSeen); err != nil {
			t.Errorf("close privacy test database: %v", err)
		}
		e.lastSeen = nil
		return
	}
	if e.db != nil {
		if sqlDB, err := e.db.DB(); err == nil {
			_ = sqlDB.Close()
		}
	}
}

func newPrivacyEnv(t *testing.T, captureOn bool) *privacyEnv {
	t.Helper()
	dir := t.TempDir()
	env := &privacyEnv{cfgPath: filepath.Join(dir, "config.yaml"), dbPath: filepath.Join(dir, "data", "gateway.db")}

	up := newPrivacyUpstream(t, nil)
	env.upstream = up

	if err := os.MkdirAll(filepath.Dir(env.dbPath), 0700); err != nil {
		t.Fatal(err)
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(gateAdminPass), bcrypt.DefaultCost)
	if err != nil {
		t.Fatal(err)
	}
	captureYaml := "  request_body_capture:\n    enabled: false\n"
	if captureOn {
		// 显式取硬上限（bounds 用例验证 64KiB 截断；默认 16KiB 由单元回归覆盖）
		captureYaml = "  request_body_capture:\n    enabled: true\n    expires_at: " + time.Now().Add(10*time.Minute).UTC().Format("2006-01-02T15:04:05Z") + "\n    max_bytes: 65536\n    max_entries: 1000\n"
	}
	freshCfg := "server:\n  host: 127.0.0.1\n  port: 8090\n  admin:\n    host: 127.0.0.1\n    port: 8091\nadmin:\n  username: " + gateAdminUser + "\n  password_hash: " + string(hash) + "\n  session_secret: privacy-gate-session-secret\n  cookie_secure: false\ndatabase:\n  path: " + env.dbPath + "\nlogging:\n  level: info\n" + captureYaml + "providers:\n  openai:\n    type: openai\n    base_url: " + up.URL + "/v1\n  gemini:\n    type: gemini\n    base_url: " + up.URL + "\n"
	if err := os.WriteFile(env.cfgPath, []byte(freshCfg), 0600); err != nil {
		t.Fatal(err)
	}

	cfg, err := config.Load(env.cfgPath)
	if err != nil {
		t.Fatal(err)
	}

	// 生产同序：privacy preflight → provider preflight → runtime 视图 → deps（capture 按 config）
	db, err := gorm.Open(sqlite.Open(env.dbPath), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.AutoMigrate(&models.Client{}, &models.RequestLog{}, &models.DailyUsage{}, &models.AdminSession{}); err != nil {
		t.Fatal(err)
	}
	migrateTestAudit(t, db)
	if err := ensureRequestLogPrivacyRunnable(db); err != nil {
		t.Fatalf("privacy preflight: %v", err)
	}
	mgr, err := ensureProviderSecretsRunnable(cfg, db)
	if err != nil {
		t.Fatalf("preflight: %v", err)
	}
	runtimeCfg, err := buildRuntimeConfig(cfg, mgr)
	if err != nil {
		t.Fatal(err)
	}
	settings, err := cfg.Logging.ResolveRequestBodyCapture(time.Now())
	if err != nil {
		t.Fatalf("capture config: %v", err)
	}
	captureStore := capture.NewStore(settings.Enabled, settings.ExpiresAt, settings.MaxBytes, settings.MaxEntries)

	deps := newGatewayDeps(cfg, runtimeCfg, db, false, mgr, captureStore)
	env.api = buildAPIRouter(deps)
	adminMux, err := buildAdminRouter(deps)
	if err != nil {
		t.Fatal(err)
	}
	env.admin = adminMux
	env.cfg = cfg
	env.db = db
	env.lastSeen = attachTestLastSeenPool(db)

	// runtime log 捕获（log 包默认 writer；handlers 的日志都经 log.Printf）
	log.SetOutput(&env.logBuf)
	t.Cleanup(func() {
		log.SetOutput(os.Stderr)
		// 关闭【当前】句柄（rawScanCanaryHits 会重开 DB 并替换 e.db）
		env.closeDB(t)
	})
	return env
}

// rawScanCanaryHits: 关闭 DB → 扫描 config/db/WAL/journal → 重开 DB
func (e *privacyEnv) rawScanCanaryHits(t *testing.T, canaries ...string) int {
	t.Helper()
	e.closeDB(t)
	hits := 0
	for _, p := range []string{e.cfgPath, e.dbPath, e.dbPath + "-wal", e.dbPath + "-shm", e.dbPath + "-journal"} {
		raw, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		for _, c := range canaries {
			hits += strings.Count(string(raw), c)
		}
	}
	db, err := gorm.Open(sqlite.Open(e.dbPath), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	e.db = db
	e.lastSeen = nil
	return hits
}

func newGateClientSvc(env *privacyEnv) *services.ClientService {
	return services.NewClientService(env.db)
}

func privacyChat(t *testing.T, env *privacyEnv, gwKey, body string, target string) string {
	t.Helper()
	req := httptest.NewRequest("POST", target, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+gwKey)
	w := httptest.NewRecorder()
	env.api.ServeHTTP(w, req)
	env.lastSeen.waitForCompletion(t)
	resp := w.Result()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("请求期望 200，实际 %d body=%s", resp.StatusCode, string(b))
	}
	return resp.Header.Get("X-Request-ID")
}

func rowOf(t *testing.T, db *gorm.DB, requestID string) models.RequestLog {
	t.Helper()
	var row models.RequestLog
	if err := db.Raw("SELECT * FROM request_logs WHERE request_id = ?", requestID).Scan(&row).Error; err != nil {
		t.Fatal(err)
	}
	return row
}

func privacyAdminLogin(t *testing.T, admin http.Handler) string {
	t.Helper()
	srv := httptest.NewServer(admin)
	t.Cleanup(srv.Close)

	resp, err := freshNoRedirectClient.Get(srv.URL + "/admin/login")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	tokenRe := "name=\"csrf_token\" value=\"([0-9a-f]{64})\""
	m := regexpMustFind(tokenRe, string(b))
	if m == "" {
		t.Fatal("login 页缺少 pre-auth csrf token")
	}
	var preauth *http.Cookie
	for _, c := range resp.Cookies() {
		if c.Name == auth.PreAuthCSRFCookie {
			preauth = c
		}
	}
	if preauth == nil {
		t.Fatal("login 页未设置 preauth cookie")
	}
	form := "username=" + gateAdminUser + "&password=" + gateAdminPass + "&csrf_token=" + m
	req, _ := http.NewRequest("POST", srv.URL+"/admin/login", strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(preauth)
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

func regexpMustFind(pattern, s string) string {
	re := regexp.MustCompile(pattern)
	m := re.FindStringSubmatch(s)
	if len(m) < 2 {
		return ""
	}
	return m[1]
}

// ---------------------------------------------------------------------------
// Gate 1+2+3+10 · DEFAULT MODE 全链路
// ---------------------------------------------------------------------------
func TestPromptPrivacyGate_DefaultMode_NoPlaintextAnywhere(t *testing.T) {
	env := newPrivacyEnv(t, false)
	svc := newGateClientSvc(env)

	// client A：无 override → global fallback；client B：openai override
	cA, gwA, err := svc.CreateClient("pp-global", "", "openai", "sk-", env.cfg, "test-admin")
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.UpdateClientSettings(cA.ID, "test-admin", map[string]interface{}{"backend": "openai"}); err != nil {
		t.Fatal(err)
	}
	cB, gwB, err := svc.CreateClient("pp-override", "", "openai", "sk-", env.cfg, "test-admin")
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.UpdateClientSettings(cB.ID, "test-admin", map[string]interface{}{
		"backend":          "openai",
		"backend_base_url": env.upstream.URL + "/v1",
	}); err != nil {
		t.Fatal(err)
	}

	promptBody := `{"model":"test-model","messages":[{"role":"user","content":"` + gateCanaryPrompt + `"}]}`

	// a) openai 非流式（global fallback）
	idA := privacyChat(t, env, gwA, promptBody, "/v1/chat/completions")
	// b) openai 流式（client override）
	env.upstream.setBehavior(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte("data: {\"choices\":[{\"delta\":{\"content\":\"hi\"}}]}\n\ndata: [DONE]\n\n"))
	})
	idB := privacyChat(t, env, gwB, `{"model":"test-model","stream":true,"messages":[{"role":"user","content":"`+gateCanaryPrompt+`"}]}`, "/v1/chat/completions")
	// c) gemini native（global）
	idC := privacyChat(t, env, gwA, `{"contents":[{"parts":[{"text":"`+gateCanaryPrompt+`"}]}]}`, "/v1/models/test-model:generateContent")

	// Gate 3：唯一性
	if idA == idB || idB == idC || idA == "" {
		t.Fatalf("[安全回归失败] RequestID 唯一性破坏: %q %q %q", idA, idB, idC)
	}

	// Gate 2：metadata-only + 字段齐全
	for _, rid := range []string{idA, idB, idC} {
		row := rowOf(t, env.db, rid)
		if row.RequestID == "" || row.Provider == "" || row.Model == "" || row.StatusCode == 0 {
			t.Fatalf("[安全回归失败] 行 %s 元数据不全: %+v", rid, row)
		}
		if row.RequestBody != "" || row.ErrorMessage != "" {
			t.Fatalf("[安全回归失败] 行 %s 携带正文/错误文本: %q", rid, row.RequestBody)
		}
	}
	if !rowOf(t, env.db, idB).IsStreaming {
		t.Fatal("[安全回归失败] 流式行 IsStreaming 应为 true")
	}

	// Gate 1：磁盘 + runtime log raw scan
	if hits := env.rawScanCanaryHits(t, gateCanaryPrompt); hits != 0 {
		t.Fatalf("[安全回归失败] 磁盘文件含 prompt canary（%d 处）", hits)
	}
	if strings.Contains(env.logBuf.String(), gateCanaryPrompt) {
		t.Fatal("[安全回归失败] runtime log 含 prompt canary")
	}

	// Gate 10 + 5：RequestLog JSON 形态（legacy 键不存在）
	b, _ := json.Marshal(models.RequestLog{RequestBody: "x", ErrorMessage: "y"})
	if out := string(b); strings.Contains(out, "request_body") || strings.Contains(out, "error_message") {
		t.Fatalf("[安全回归失败] RequestLog JSON 暴露 legacy 字段: %s", out)
	}
	t.Log("[SEC-003] DEFAULT MODE：三类请求全链路后磁盘/日志 0 canary，元数据齐全")
}

// ---------------------------------------------------------------------------
// Gate 6 · RUNTIME LOG
// ---------------------------------------------------------------------------
func TestPromptPrivacyGate_RuntimeUpstreamError_BoundedOnly(t *testing.T) {
	env := newPrivacyEnv(t, false)
	env.upstream.setBehavior(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte(`{"error":{"message":"` + gateCanaryUPErr + `"}}`))
	})
	svc := newGateClientSvc(env)
	c, gwKey, err := svc.CreateClient("pp-fb", "", "openai", "sk-", env.cfg, "test-admin")
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.UpdateClientSettings(c.ID, "test-admin", map[string]interface{}{
		"backend":         "openai",
		"fallback_models": "fallback-x",
	}); err != nil {
		t.Fatal(err)
	}

	body := `{"model":"test-model","messages":[{"role":"user","content":"ping"}]}`
	req := httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+gwKey)
	w := httptest.NewRecorder()
	env.api.ServeHTTP(w, req)
	env.lastSeen.waitForCompletion(t)

	if strings.Contains(env.logBuf.String(), gateCanaryUPErr) {
		t.Fatal("[安全回归失败] runtime log 回显 upstream error body")
	}
	if !strings.Contains(env.logBuf.String(), "UPSTREAM_RATE_LIMIT") {
		t.Fatalf("[安全回归失败] runtime log 应含 bounded 错误码，实际 %q", env.logBuf.String())
	}
	t.Log("[SEC-003] RUNTIME LOG：bounded code only")
}

// ---------------------------------------------------------------------------
// Gate 7 · DIAGNOSTIC MODE
// ---------------------------------------------------------------------------
func TestPromptPrivacyGate_DiagnosticMode_MemoryOnly(t *testing.T) {
	env := newPrivacyEnv(t, true) // capture 显式启用 10 分钟
	svc := newGateClientSvc(env)
	c, gwKey, err := svc.CreateClient("pp-cap", "", "gemini", "sk-", env.cfg, "test-admin")
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.UpdateClientSettings(c.ID, "test-admin", map[string]interface{}{}); err != nil {
		t.Fatal(err)
	}

	id := privacyChat(t, env, gwKey, `{"contents":[{"parts":[{"text":"`+gateCanaryPrompt+`"}]}]}`, "/v1/models/test-model:generateContent")

	// Admin 端点按需可读
	token := privacyAdminLogin(t, env.admin)
	adminReq := httptest.NewRequest("GET", "/admin/request-bodies/"+id, nil)
	adminReq.AddCookie(&http.Cookie{Name: auth.SessionCookieName, Value: token})
	w2 := httptest.NewRecorder()
	env.admin.ServeHTTP(w2, adminReq)
	if w2.Result().StatusCode != http.StatusOK || !strings.Contains(w2.Body.String(), gateCanaryPrompt) {
		t.Fatalf("[功能回归失败] 诊断读取应可用且含 canary，实际 %d", w2.Result().StatusCode)
	}

	// 缺失 id → 404（在 raw scan 之前——scan 会重建 DB 句柄，session 失效）
	adminReq2 := httptest.NewRequest("GET", "/admin/request-bodies/reqabsent12345678901234567890", nil)
	adminReq2.AddCookie(&http.Cookie{Name: auth.SessionCookieName, Value: token})
	w3 := httptest.NewRecorder()
	env.admin.ServeHTTP(w3, adminReq2)
	if w3.Result().StatusCode != http.StatusNotFound {
		t.Fatalf("[安全回归失败] 不存在的 requestID 应 404，实际 %d", w3.Result().StatusCode)
	}

	// 磁盘 raw scan = 0（最后执行；此后不再走 admin/session 路径）
	if hits := env.rawScanCanaryHits(t, gateCanaryPrompt); hits != 0 {
		t.Fatalf("[安全回归失败] 诊断模式下磁盘含 canary（%d 处）", hits)
	}
	t.Log("[SEC-003] DIAGNOSTIC MODE：按需可读 + 磁盘 0 canary + 缺失 404")
}

// ---------------------------------------------------------------------------
// Gate 8 · BOUNDS
// ---------------------------------------------------------------------------
func TestPromptPrivacyGate_Bounds_TruncationThroughEndpoint(t *testing.T) {
	env := newPrivacyEnv(t, true)
	svc := newGateClientSvc(env)
	c, gwKey, err := svc.CreateClient("pp-big", "", "gemini", "sk-", env.cfg, "test-admin")
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.UpdateClientSettings(c.ID, "test-admin", map[string]interface{}{}); err != nil {
		t.Fatal(err)
	}

	big := strings.Repeat("P", 100*1024)
	id := privacyChat(t, env, gwKey, `{"contents":[{"parts":[{"text":"`+big+`"}]}]}`, "/v1/models/test-model:generateContent")

	token := privacyAdminLogin(t, env.admin)
	adminReq := httptest.NewRequest("GET", "/admin/request-bodies/"+id, nil)
	adminReq.AddCookie(&http.Cookie{Name: auth.SessionCookieName, Value: token})
	w2 := httptest.NewRecorder()
	env.admin.ServeHTTP(w2, adminReq)
	resp := w2.Result()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("端点应 200，实际 %d", resp.StatusCode)
	}
	b, _ := io.ReadAll(resp.Body)
	if len(b) != 64*1024 {
		t.Fatalf("[安全回归失败] 捕获应截断至 64KiB 硬上限，实际 %d 字节", len(b))
	}
	if v := resp.Header.Get("X-Body-Truncated"); v != "true" {
		t.Fatalf("[安全回归失败] X-Body-Truncated 标记缺失: %q", v)
	}
	t.Log("[SEC-003] BOUNDS：64KiB 硬上限截断生效")
}

// ---------------------------------------------------------------------------
// 静态 tripwire：模板不得引用正文/错误字段；legacy JSON 键不得回归
// ---------------------------------------------------------------------------
func TestPromptPrivacyGate_StaticTripwire(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "internal", "handlers", "admin.go"))
	if err != nil {
		t.Fatal(err)
	}
	src := string(raw)
	for _, banned := range []string{".RequestBody", ".ErrorMessage", "showRequestBody"} {
		if strings.Contains(src, banned) {
			t.Fatalf("[安全回归失败] Admin 模板引用 %s", banned)
		}
	}
	b, _ := json.Marshal(models.RequestLog{RequestBody: gateCanaryPrompt})
	if strings.Contains(string(b), "request_body") || strings.Contains(string(b), gateCanaryPrompt) {
		t.Fatal("[安全回归失败] RequestLog JSON 键回归")
	}
	t.Log("[SEC-003] 静态 tripwire 通过")
}
