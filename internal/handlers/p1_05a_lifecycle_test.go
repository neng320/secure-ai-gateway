package handlers

// P1-05A · Client Key Lifecycle Characterization（零生产行为修改）
//
// 固化 tag secure-gateway-p1-request-log-privacy.5（develop 55f258e）时点的
// Client Key 生命周期真实行为。所有断言服务【精确回答】而非"不是 200 就过"。
//
// Canary：P105_CLIENT_KEY_ORIGINAL / P105_CLIENT_KEY_ROTATED（明显测试串，非真实凭证）。
//
// P1-05B 修正结果（本文件内 4 项已从 [KNOWN-GAP] 转为 [P1-05B FIXED]）：
//   [P1-05B FIXED: ROTATE-NOTFOUND]   RegenerateAPIKey 检查 RowsAffected → ErrClientNotFound
//   [P1-05B FIXED: ORPHAN-DATA]       DeleteClient 事务内清理 + FK CASCADE → 三表全 0
//   [P1-05B FIXED: METRICS-COMPARE]   Metrics Basic Auth 改为 SHA-256 + ConstantTimeCompare
//   [P1-05B FIXED: TOGGLE-ERR-SWALLOW] ToggleClient 经 SetClientActive 并检查错误
//
// 仍留待 P1-05C：REVOKED 状态 / RevokedAt / RevokedBy / Reason / append-only AuditEvent。

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"

	"ai-gateway/internal/auth"
	"ai-gateway/internal/config"
	"ai-gateway/internal/database"
	mw "ai-gateway/internal/middleware"
	"ai-gateway/internal/models"
	"ai-gateway/internal/services"

	"github.com/go-chi/chi/v5"
	"gorm.io/gorm"
)

const (
	p105OriginalKey = "P105_CLIENT_KEY_ORIGINAL"
	p105RotatedKey  = "P105_CLIENT_KEY_ROTATED"
	p105Envelope    = "enc:v1:deadbeef:P105_ENVELOPE_CANARY"
)

type p105Env struct {
	db          *gorm.DB
	dbPath      string
	cfg         *config.Config
	clientSvc   *services.ClientService
	gemini      *services.GeminiService
	rateLimiter *mw.RateLimiter
	api         http.Handler // auth middleware + rate limiter + 200 next
	admin       http.Handler
}

func newP105Env(t *testing.T) *p105Env {
	t.Helper()
	// P1-05B：与生产 initDatabase 一致的打开路径——DSN _foreign_keys=on
	// （连接池所有连接强制外键；late-write / ORPHAN-DATA 判定依赖它）
	dbPath := filepath.Join(t.TempDir(), "p105.db")
	db, err := database.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.AutoMigrate(&models.Client{}, &models.RequestLog{}, &models.DailyUsage{}, &models.AdminSession{}, &models.AuditEvent{}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if sqlDB, e := db.DB(); e == nil {
			_ = sqlDB.Close()
		}
	})

	cfg := &config.Config{
		Server: config.ServerConfig{Host: "127.0.0.1", Port: 8090},
		Admin: config.AdminConfig{
			Username: "admin", PasswordHash: testPasswordHash,
			SessionSecret: "p105-session-secret", CookieSecure: false,
		},
		Providers: map[string]config.ProviderConfig{},
	}
	clientSvc := services.NewClientService(db)
	geminiSvc := services.NewGeminiService(db, cfg)
	// P1-05B：API 面与 Admin 面共享同一 RateLimiter 实例（生产=gatewayDeps.rateLimiter）
	sharedLimiter := mw.NewRateLimiter()

	// 公开 API：auth + rate limit + 200 next（认证通过即成功）
	authMw := mw.NewAuthMiddleware(clientSvc)
	apiMux := chi.NewRouter()
	apiMux.Use(authMw.Handler)
	apiMux.Use(sharedLimiter.Middleware)
	apiMux.Get("/v1/echo", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	// Admin：与 buildAdminRouter 同构（复用于 regenerate/delete/toggle 路由测试）
	statsSvc := services.NewStatsService(db)
	store := auth.NewSQLiteStore(db)
	limiter := auth.NewLoginRateLimiter()
	limiter.Configure(5, 15*time.Minute, cfg.Admin.Username)
	adminH, err := NewAdminHandler(cfg, clientSvc, statsSvc, geminiSvc, services.NewDashboardHub(statsSvc), services.NewToolService(nil), store, limiter, nil, "", nil, sharedLimiter)
	if err != nil {
		t.Fatal(err)
	}
	adminMux := chi.NewRouter()
	adminH.RegisterRoutes(adminMux)

	return &p105Env{db: db, dbPath: dbPath, cfg: cfg, clientSvc: clientSvc, gemini: geminiSvc, rateLimiter: sharedLimiter, api: apiMux, admin: adminMux}
}

// insertClientWithKey: 以指定 key 的 SHA-256 直接入库（控制 key 值为 canary）
func (e *p105Env) insertClientWithKey(t *testing.T, name, key string, active bool) *models.Client {
	t.Helper()
	sum := sha256.Sum256([]byte(key))
	c := &models.Client{
		ID:         name + "-id",
		Name:       name,
		APIKeyHash: sum[:],
		IsActive:   active,
		CreatedAt:  time.Now(),
		UpdatedAt:  time.Now(),
	}
	if err := e.db.Create(c).Error; err != nil {
		t.Fatal(err)
	}
	return c
}

func (e *p105Env) doAuth(t *testing.T, key string) *http.Response {
	t.Helper()
	req := httptest.NewRequest("GET", "/v1/echo", nil)
	req.Header.Set("Authorization", "Bearer "+key)
	w := httptest.NewRecorder()
	e.api.ServeHTTP(w, req)
	return w.Result()
}

func (e *p105Env) countAll(t *testing.T, table string) int64 {
	t.Helper()
	var n int64
	if err := e.db.Raw("SELECT count(*) FROM " + table).Scan(&n).Error; err != nil {
		t.Fatalf("count %s: %v", table, err)
	}
	return n
}

// ---------------------------------------------------------------------------
// A. Create：plaintext 一次返回；SQLite 只存 hash；JSON 不暴露
// ---------------------------------------------------------------------------
func TestP105A_Create_PlaintextOneTime_HashOnly(t *testing.T) {
	env := newP105Env(t)
	c, key, err := env.clientSvc.CreateClient("p105-create", "desc", "openai", "sk-", env.cfg, "test-admin")
	if err != nil {
		t.Fatal(err)
	}
	if key == "" || !strings.HasPrefix(key, "sk-") {
		t.Fatalf("CreateClient 应返回带前缀的明文 key，实际 %q", key)
	}

	var row struct {
		APIKeyHash    []byte
		BackendAPIKey string
	}
	if err := env.db.Raw("SELECT api_key_hash, backend_api_key FROM clients WHERE id = ?", c.ID).Scan(&row).Error; err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(key))
	if string(row.APIKeyHash) != string(sum[:]) {
		t.Fatal("[固化失败] SQLite 应只存 SHA-256 hash")
	}
	if row.BackendAPIKey != "" {
		t.Fatal("[固化失败] client row 不应含明文 key（provider key 语义亦同）")
	}

	b, _ := json.Marshal(c)
	out := string(b)
	if strings.Contains(out, key) || strings.Contains(out, "api_key_hash") {
		t.Fatalf("[安全回归失败] JSON 暴露 key/hash: %s", out)
	}
	t.Log("[CURRENT] 固化：Create 返回一次明文；库内仅 hash；JSON 无 key/hash")
}

// ---------------------------------------------------------------------------
// B. Rotation（既有 client）：旧 key 立即失效，新 key 立即生效（零 sleep）
// ---------------------------------------------------------------------------
func TestP105A_Rotate_ExistingClient_Immediate(t *testing.T) {
	env := newP105Env(t)
	c := env.insertClientWithKey(t, "p105-rot", p105OriginalKey, true)

	if resp := env.doAuth(t, p105OriginalKey); resp.StatusCode != http.StatusOK {
		t.Fatalf("rotate 前原 key 应 200，实际 %d", resp.StatusCode)
	}

	newKey, err := env.clientSvc.RegenerateAPIKey(c.ID, "openai", "sk-", "test-admin", "P105C rotate reason")
	if err != nil || newKey == "" || newKey == p105OriginalKey {
		t.Fatalf("RegenerateAPIKey 应返回新 key: err=%v key=%q", err, newKey)
	}

	// 下一请求（无 sleep）：旧 key 立即 401
	respOld := env.doAuth(t, p105OriginalKey)
	if respOld.StatusCode != http.StatusUnauthorized {
		t.Fatalf("[安全回归失败] rotate 后旧 key 应立即 401，实际 %d", respOld.StatusCode)
	}
	b, _ := ioReadAll(respOld.Body)
	respOld.Body.Close()
	if !strings.Contains(string(b), "Invalid API key") {
		t.Fatalf("旧 key 失败体应匹配 invalid-key 语义，实际 %s", string(b))
	}
	// 新 key 立即可用
	if resp := env.doAuth(t, newKey); resp.StatusCode != http.StatusOK {
		t.Fatalf("[安全回归失败] rotate 后新 key 应立即 200，实际 %d", resp.StatusCode)
	}
	// 旧 hash 已不存在于库
	var n int64
	oldSum := sha256.Sum256([]byte(p105OriginalKey))
	_ = env.db.Raw("SELECT count(*) FROM clients WHERE api_key_hash = ?", string(oldSum[:])).Scan(&n).Error
	if n != 0 {
		t.Fatal("[固化失败] rotate 后旧 hash 应被覆盖（旧 key 永久失效）")
	}
	t.Log("[CURRENT] 固化：Rotation 立即生效（旧 401 新 200），旧 hash 被覆盖")
}

// ---------------------------------------------------------------------------
// C. Rotation（不存在 client）：[P1-05B FIXED: ROTATE-NOTFOUND]
// 现在返回 ErrClientNotFound + 空 key（不再 false-success 生成无主 key）
// ---------------------------------------------------------------------------
func TestP105A_Rotate_Nonexistent_FalseSuccess(t *testing.T) {
	env := newP105Env(t)
	key, err := env.clientSvc.RegenerateAPIKey("nonexistent-client-id", "openai", "sk-", "test-admin", "P105C rotate reason")
	if !errors.Is(err, services.ErrClientNotFound) {
		t.Fatalf("[P1-05B FIXED] 不存在 client 应返回 ErrClientNotFound，实际 err=%v", err)
	}
	if key != "" {
		t.Fatalf("[P1-05B FIXED] 失败路径绝不得返回未入库的明文 key，实际 %q", key)
	}
	var n int64
	_ = env.db.Raw("SELECT count(*) FROM clients WHERE id = 'nonexistent-client-id'").Scan(&n).Error
	if n != 0 {
		t.Fatal("[固化失败] 该 id 不应存在任何行")
	}
	t.Log("[P1-05B FIXED: ROTATE-NOTFOUND] 不存在 client → ErrClientNotFound + key==\"\"（UI 侧 404，见 H 测试）")
}

// ---------------------------------------------------------------------------
// D. Disable：实际返回 401（非 403）；403 分支已删除（不可达死分支）
// ---------------------------------------------------------------------------
func TestP105A_Disable_ActualStatus_401_Not403(t *testing.T) {
	env := newP105Env(t)
	c := env.insertClientWithKey(t, "p105-dis", p105OriginalKey, true)
	if resp := env.doAuth(t, p105OriginalKey); resp.StatusCode != http.StatusOK {
		t.Fatalf("disable 前应 200，实际 %d", resp.StatusCode)
	}

	if err := env.clientSvc.SuspendClient(c.ID, "test-admin", "P105C suspend reason"); err != nil {
		t.Fatal(err)
	}

	resp := env.doAuth(t, p105OriginalKey)
	b, _ := ioReadAll(resp.Body)
	resp.Body.Close()
	// GetClientByAPIKey 过滤 is_active=true → client==nil → invalid-key 401（非 403）
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("disabled client 应表现为 401，实际 %d", resp.StatusCode)
	}
	if !strings.Contains(string(b), "Invalid API key") {
		t.Fatalf("disabled client 响应体应为 invalid-key 语义，实际 %s", string(b))
	}
	if strings.Contains(string(b), "Client is disabled") {
		t.Fatal("[安全回归失败] 403 'Client is disabled' 分支必须已删除")
	}
	t.Log("[CURRENT] 固化：Disable 实际语义 = 401 invalid-key；403 死分支已删除（P1-05B）")
}

// ---------------------------------------------------------------------------
// E. Re-enable：原 key 恢复 → SUSPEND/RESUME 语义（非永久吊销）
// ---------------------------------------------------------------------------
func TestP105A_ReEnable_OriginalKeyResumes(t *testing.T) {
	env := newP105Env(t)
	c := env.insertClientWithKey(t, "p105-res", p105OriginalKey, true)

	if err := env.clientSvc.SuspendClient(c.ID, "test-admin", "P105C suspend reason"); err != nil {
		t.Fatal(err)
	}
	if resp := env.doAuth(t, p105OriginalKey); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("suspend 后应 401，实际 %d", resp.StatusCode)
	}

	if err := env.clientSvc.ResumeClient(c.ID, "test-admin", ""); err != nil {
		t.Fatal(err)
	}
	if resp := env.doAuth(t, p105OriginalKey); resp.StatusCode != http.StatusOK {
		t.Fatalf("resume 后【原 key】应恢复 200，实际 %d", resp.StatusCode)
	}
	t.Log("[CURRENT] 固化：Disable/Enable = SUSPEND/RESUME（原 key 原样恢复，不是吊销）")
}

// ---------------------------------------------------------------------------
// F. Delete：[P1-05B FIXED: ORPHAN-DATA] 三表全 0（事务内清理 + FK CASCADE）
// ---------------------------------------------------------------------------
func TestP105A_Delete_OrphanData(t *testing.T) {
	env := newP105Env(t)
	client, _, err := env.clientSvc.CreateClient("p105-del", "", "openai", "sk-", env.cfg, "test-admin")
	if err != nil {
		t.Fatal(err)
	}
	// 真实写入路径（LogRequest）+ 直接插入，覆盖两种来源的孤儿候选
	if err := env.gemini.LogRequest(services.RequestRecord{
		RequestID: "p105b-seed-1", ClientID: client.ID, Provider: "gemini",
		Model: "m", StatusCode: 200, InputTokens: 10,
	}); err != nil {
		t.Fatal(err)
	}
	if err := env.db.Create(&models.RequestLog{ClientID: client.ID, Model: "m", StatusCode: 429}).Error; err != nil {
		t.Fatal(err)
	}
	if err := env.db.Create(&models.DailyUsage{ClientID: client.ID, Date: time.Now()}).Error; err != nil {
		t.Fatal(err)
	}

	if err := env.clientSvc.DeleteClient(client.ID, "test-admin", "P105C delete reason"); err != nil {
		t.Fatal(err)
	}

	if env.countAll(t, "clients") != 0 || env.countAll(t, "request_logs") != 0 || env.countAll(t, "daily_usages") != 0 {
		t.Fatalf("[P1-05B FIXED] Delete 后三表应全 0：clients=%d request_logs=%d daily_usages=%d",
			env.countAll(t, "clients"), env.countAll(t, "request_logs"), env.countAll(t, "daily_usages"))
	}
	t.Log("[P1-05B FIXED: ORPHAN-DATA] Delete 后 clients/request_logs/daily_usages 全 0（事务 + FK CASCADE）")
}

// ---------------------------------------------------------------------------
// G. Delete 与 client-owned encrypted 材料：envelope 随行消失（不解密/不输出）
// ---------------------------------------------------------------------------
func TestP105A_Delete_RemovesEncryptedMaterial(t *testing.T) {
	env := newP105Env(t)
	c := env.insertClientWithKey(t, "p105-enc", p105OriginalKey, true)
	if err := env.db.Model(&models.Client{}).Where("id = ?", c.ID).
		Update("backend_api_key_encrypted", p105Envelope).Error; err != nil {
		t.Fatal(err)
	}
	if err := env.clientSvc.DeleteClient(c.ID, "test-admin", "P105C delete reason"); err != nil {
		t.Fatal(err)
	}
	var n int64
	_ = env.db.Raw("SELECT count(*) FROM clients WHERE backend_api_key_encrypted = ?", p105Envelope).Scan(&n).Error
	if n != 0 {
		t.Fatalf("[固化失败] 加密材料应随 client 行消失，实际残留 %d", n)
	}
	t.Log("[CURRENT] 固化：DeleteClient 后 encrypted 材料随行消失（本测试不解密、不输出 envelope）")
}

// ---------------------------------------------------------------------------
// H. Admin regenerate 路由：Auth+CSRF 必需；明文仅一次展示；不存在 client → 404
//
//	[P1-05B FIXED: ROTATE-NOTFOUND UI 侧]
//
// ---------------------------------------------------------------------------
func TestP105A_AdminRegenerate_HappyPath_OneTimeDisplay(t *testing.T) {
	env := newP105Env(t)
	client, _, err := env.clientSvc.CreateClient("p105-hreg", "", "openai", "sk-", env.cfg, "test-admin")
	if err != nil {
		t.Fatal(err)
	}
	token := p105AdminSessionOf(t, env)

	// 无 CSRF → 403
	noCsrf := httptest.NewRequest("POST", "/admin/clients/"+client.ID+"/regenerate", strings.NewReader("key_type=openai&key_prefix=sk-"))
	noCsrf.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	noCsrf.AddCookie(&http.Cookie{Name: sessionCookieName, Value: token})
	w0 := httptest.NewRecorder()
	env.admin.ServeHTTP(w0, noCsrf)
	if w0.Result().StatusCode != http.StatusForbidden {
		t.Fatalf("无 CSRF 应 403，实际 %d", w0.Result().StatusCode)
	}

	// 合法 POST → 200，页面出现新明文 key
	form := url.Values{"key_type": {"openai"}, "key_prefix": {"sk-"}, "reason": {"P105C rotate reason"}}
	req := httptest.NewRequest("POST", "/admin/clients/"+client.ID+"/regenerate", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: token})
	req.Header.Set("X-CSRF-Token", auth.CSRFToken(env.cfg.Admin.SessionSecret, token))
	w := httptest.NewRecorder()
	env.admin.ServeHTTP(w, req)
	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("regenerate 期望 200，实际 %d", resp.StatusCode)
	}
	page := w.Body.String()
	keyRe := regexp.MustCompile(`sk-[0-9a-f-]{35,}`)
	m := keyRe.FindString(page)
	if m == "" {
		t.Fatalf("[固化失败] regenerate 结果页应含新明文 key，实际页面前 %d 字", len(page))
	}

	// 后续 ShowClient 不再展示该明文
	show := httptest.NewRequest("GET", "/admin/clients/"+client.ID, nil)
	show.AddCookie(&http.Cookie{Name: sessionCookieName, Value: token})
	w2 := httptest.NewRecorder()
	env.admin.ServeHTTP(w2, show)
	if w2.Result().StatusCode != http.StatusOK {
		t.Fatalf("ShowClient 期望 200，实际 %d", w2.Result().StatusCode)
	}
	if strings.Contains(w2.Body.String(), m) {
		t.Fatal("[安全回归失败] ShowClient 再次展示明文 key")
	}
	t.Log("[CURRENT] 固化：Regenerate 需 Auth+CSRF；明文仅结果页一次性展示；ShowClient 不重现")
}

func TestP105A_AdminRegenerate_NonexistentClient_404(t *testing.T) {
	env := newP105Env(t)
	token := p105AdminSessionOf(t, env)

	form := url.Values{"key_type": {"openai"}, "key_prefix": {"sk-"}, "reason": {"P105C rotate reason"}}
	req := httptest.NewRequest("POST", "/admin/clients/nonexistent-id/regenerate", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: token})
	req.Header.Set("X-CSRF-Token", auth.CSRFToken(env.cfg.Admin.SessionSecret, token))
	w := httptest.NewRecorder()
	env.admin.ServeHTTP(w, req)
	resp := w.Result()
	// [P1-05B FIXED: ROTATE-NOTFOUND] UI 侧：404 + 正常错误响应，无截断页/模板错误/无主 key
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("[P1-05B FIXED] 不存在 client 的 regenerate 应 404，实际 %d", resp.StatusCode)
	}
	page := w.Body.String()
	if strings.Contains(page, "Template error") {
		t.Fatal("[P1-05B FIXED] 不应再出现截断模板错误文本")
	}
	if strings.Contains(page, "nil pointer evaluating") {
		t.Fatal("[P1-05B FIXED] 不应再出现 nil Client 渲染")
	}
	if strings.Contains(page, "sk-") {
		t.Fatal("[P1-05B FIXED] 不应渲染任何明文 key（无主 key 展示必须杜绝）")
	}
	t.Log("[P1-05B FIXED: ROTATE-NOTFOUND UI 侧] 不存在 client 的 regenerate → 404 + 无模板错误 + 无 key 渲染")
}

// ---------------------------------------------------------------------------
// Audit / 吊销字段：P1-05C —— Revoked* 三字段已加入；仍无 Status/AuditEvents 持久字段
// ---------------------------------------------------------------------------
func TestP105A_AuditAndRevocationAbsent(t *testing.T) {
	var model models.Client
	typ := reflect.TypeOf(model)
	have := map[string]bool{}
	for i := 0; i < typ.NumField(); i++ {
		have[typ.Field(i).Name] = true
	}
	// P1-05C（§1）：RevokedAt/RevokedBy/RevocationReason 存在（additive nullable）
	for _, present := range []string{"RevokedAt", "RevokedBy", "RevocationReason"} {
		if !have[present] {
			t.Fatalf("[P1-05C FIXED] Client 模型应有 %s", present)
		}
	}
	// 不新增持久化 Status 字段（状态必须从 RevokedAt+IsActive 派生，§1 冻结设计）；
	// AuditEvents 关联字段也不在（审计走独立 audit_events 表）
	for _, absent := range []string{"Status", "AuditEvents"} {
		if have[absent] {
			t.Fatalf("[固化失败] Client 模型不应有 %s（无第二份状态真相/无嵌入事件）", absent)
		}
	}
	t.Log("[P1-05C FIXED] RevokedAt/RevokedBy/RevocationReason 已加入（additive）；仍无 Status 持久字段")
}

// ---------------------------------------------------------------------------
// 辅助
// ---------------------------------------------------------------------------
func p105AdminSessionOf(t *testing.T, env *p105Env) string {
	t.Helper()
	resp := login(t, env.admin, env.cfg.Admin.Username, testAdminPassword)
	c := getSessionCookie(resp)
	if c == nil {
		t.Fatal("admin login did not set session cookie")
	}
	return c.Value
}
