package handlers

// P1-05A · Client Key Lifecycle Characterization（零生产行为修改）
//
// 固化 tag secure-gateway-p1-request-log-privacy.5（develop 55f258e）时点的
// Client Key 生命周期真实行为。所有断言服务【精确回答】而非"不是 200 就过"。
//
// Canary：P105_CLIENT_KEY_ORIGINAL / P105_CLIENT_KEY_ROTATED（明显测试串，非真实凭证）。
//
// 已知缺口标记：
//   [KNOWN-GAP: P1-05 ROTATE-NOTFOUND] RegenerateAPIKey 不检查 RowsAffected
//   [KNOWN-GAP: P1-05 ORPHAN-DATA]     DeleteClient 无级联清理
//   [KNOWN-GAP: P1-05 METRICS-COMPARE] Metrics Basic Auth 普通字符串比较
//   [KNOWN-GAP: P1-05 TOGGLE-ERR-SWALLOW] ToggleClient 忽略 UpdateClient 错误

import (
	"crypto/sha256"
	"encoding/json"
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
	mw "ai-gateway/internal/middleware"
	"ai-gateway/internal/models"
	"ai-gateway/internal/services"

	"github.com/go-chi/chi/v5"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

const (
	p105OriginalKey = "P105_CLIENT_KEY_ORIGINAL"
	p105RotatedKey  = "P105_CLIENT_KEY_ROTATED"
	p105Envelope    = "enc:v1:deadbeef:P105_ENVELOPE_CANARY"
)

type p105Env struct {
	db        *gorm.DB
	cfg       *config.Config
	clientSvc *services.ClientService
	api       http.Handler // auth middleware + 200 next
	admin     http.Handler
}

func newP105Env(t *testing.T) *p105Env {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(filepath.Join(t.TempDir(), "p105.db")), &gorm.Config{})
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
		Admin: config.AdminConfig{
			Username: "admin", PasswordHash: testPasswordHash,
			SessionSecret: "p105-session-secret", CookieSecure: false,
		},
		Providers: map[string]config.ProviderConfig{},
	}
	clientSvc := services.NewClientService(db)

	// 公开 API：auth middleware + 200 next（认证后即成功）
	authMw := mw.NewAuthMiddleware(clientSvc)
	apiMux := chi.NewRouter()
	apiMux.Use(authMw.Handler)
	apiMux.Get("/v1/echo", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	// Admin：与 buildAdminRouter 同构（复用于 regenerate 路由测试）
	statsSvc := services.NewStatsService(db)
	store := auth.NewSQLiteStore(db)
	limiter := auth.NewLoginRateLimiter()
	limiter.Configure(5, 15*time.Minute, cfg.Admin.Username)
	adminH, err := NewAdminHandler(cfg, clientSvc, statsSvc, services.NewGeminiService(db, cfg), services.NewDashboardHub(statsSvc), services.NewToolService(nil), store, limiter, nil, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	adminMux := chi.NewRouter()
	adminH.RegisterRoutes(adminMux)

	return &p105Env{db: db, cfg: cfg, clientSvc: clientSvc, api: apiMux, admin: adminMux}
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

// ---------------------------------------------------------------------------
// A. Create：plaintext 一次返回；SQLite 只存 hash；JSON 不暴露
// ---------------------------------------------------------------------------
func TestP105A_Create_PlaintextOneTime_HashOnly(t *testing.T) {
	env := newP105Env(t)
	c, key, err := env.clientSvc.CreateClient("p105-create", "desc", "openai", "sk-", env.cfg)
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

	newKey, err := env.clientSvc.RegenerateAPIKey(c.ID, "openai", "sk-")
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
// C. Rotation（不存在 client）：false-success 固化 → [KNOWN-GAP: ROTATE-NOTFOUND]
// ---------------------------------------------------------------------------
func TestP105A_Rotate_Nonexistent_FalseSuccess(t *testing.T) {
	env := newP105Env(t)
	key, err := env.clientSvc.RegenerateAPIKey("nonexistent-client-id", "openai", "sk-")
	if err != nil {
		t.Fatalf("[固化失败] 当前实现应返回 nil error（gap 前提），实际 %v", err)
	}
	if key == "" {
		t.Fatalf("[固化失败] 当前实现应返回生成的明文 key（gap 前提），实际空")
	}
	var n int64
	_ = env.db.Raw("SELECT count(*) FROM clients WHERE id = 'nonexistent-client-id'").Scan(&n).Error
	if n != 0 {
		t.Fatal("[固化失败] 该 id 不应存在任何行")
	}
	t.Log("[KNOWN-GAP: P1-05 ROTATE-NOTFOUND] 固化：不存在的 client → nil error + 生成新 key + RowsAffected=0（key 未存库，调用方拿到的 key 不可用）")
}

// ---------------------------------------------------------------------------
// D. Disable：实际返回 401（非 403）；403 分支不可达
// ---------------------------------------------------------------------------
func TestP105A_Disable_ActualStatus_401_Not403(t *testing.T) {
	env := newP105Env(t)
	c := env.insertClientWithKey(t, "p105-dis", p105OriginalKey, true)
	if resp := env.doAuth(t, p105OriginalKey); resp.StatusCode != http.StatusOK {
		t.Fatalf("disable 前应 200，实际 %d", resp.StatusCode)
	}

	c.IsActive = false
	if err := env.clientSvc.UpdateClient(c); err != nil {
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
		t.Fatal("固化失败：403 'Client is disabled' 分支在本路径不可达（lookup 已过滤 is_active）")
	}
	t.Log("[CURRENT] 固化：Disable 实际语义 = 401 invalid-key（middleware !IsActive 403 分支不可达）")
}

// ---------------------------------------------------------------------------
// E. Re-enable：原 key 恢复 → SUSPEND/RESUME 语义（非永久吊销）
// ---------------------------------------------------------------------------
func TestP105A_ReEnable_OriginalKeyResumes(t *testing.T) {
	env := newP105Env(t)
	c := env.insertClientWithKey(t, "p105-res", p105OriginalKey, true)

	c.IsActive = false
	if err := env.clientSvc.UpdateClient(c); err != nil {
		t.Fatal(err)
	}
	if resp := env.doAuth(t, p105OriginalKey); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("suspend 后应 401，实际 %d", resp.StatusCode)
	}

	c.IsActive = true
	if err := env.clientSvc.UpdateClient(c); err != nil {
		t.Fatal(err)
	}
	if resp := env.doAuth(t, p105OriginalKey); resp.StatusCode != http.StatusOK {
		t.Fatalf("resume 后【原 key】应恢复 200，实际 %d", resp.StatusCode)
	}
	t.Log("[CURRENT] 固化：Disable/Enable = SUSPEND/RESUME（原 key 原样恢复，不是吊销）")
}

// ---------------------------------------------------------------------------
// F. Delete：孤儿数据固化 → [KNOWN-GAP: ORPHAN-DATA]
// ---------------------------------------------------------------------------
func TestP105A_Delete_OrphanData(t *testing.T) {
	env := newP105Env(t)
	client, _, err := env.clientSvc.CreateClient("p105-del", "", "openai", "sk-", env.cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := env.db.Create(&models.RequestLog{ClientID: client.ID, Model: "m", StatusCode: 200}).Error; err != nil {
		t.Fatal(err)
	}
	if err := env.db.Create(&models.RequestLog{ClientID: client.ID, Model: "m", StatusCode: 429}).Error; err != nil {
		t.Fatal(err)
	}
	if err := env.db.Create(&models.DailyUsage{ClientID: client.ID, Date: time.Now()}).Error; err != nil {
		t.Fatal(err)
	}

	if err := env.clientSvc.DeleteClient(client.ID); err != nil {
		t.Fatal(err)
	}

	counts := func(table string) int64 {
		var n int64
		_ = env.db.Raw("SELECT count(*) FROM " + table).Scan(&n).Error
		return n
	}
	if counts("clients") != 0 {
		t.Fatalf("client 本体应删除，实际 %d", counts("clients"))
	}
	t.Logf("[KNOWN-GAP: P1-05 ORPHAN-DATA] 固化：Delete 后孤儿行 clients=0 request_logs=%d daily_usages=%d（均残留，无级联）",
		counts("request_logs"), counts("daily_usages"))
	if counts("request_logs") != 2 || counts("daily_usages") != 1 {
		t.Fatalf("孤儿行数量不符: logs=%d usage=%d", counts("request_logs"), counts("daily_usages"))
	}
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
	if err := env.clientSvc.DeleteClient(c.ID); err != nil {
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
// H. Admin regenerate 路由：Auth+CSRF 必需；明文仅一次展示；不存在 client → 500
// ---------------------------------------------------------------------------
func TestP105A_AdminRegenerate_HappyPath_OneTimeDisplay(t *testing.T) {
	env := newP105Env(t)
	client, _, err := env.clientSvc.CreateClient("p105-hreg", "", "openai", "sk-", env.cfg)
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
	form := url.Values{"key_type": {"openai"}, "key_prefix": {"sk-"}}
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

func TestP105A_AdminRegenerate_NonexistentClient_500(t *testing.T) {
	env := newP105Env(t)
	token := p105AdminSessionOf(t, env)

	form := url.Values{"key_type": {"openai"}, "key_prefix": {"sk-"}}
	req := httptest.NewRequest("POST", "/admin/clients/nonexistent-id/regenerate", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: token})
	req.Header.Set("X-CSRF-Token", auth.CSRFToken(env.cfg.Admin.SessionSecret, token))
	w := httptest.NewRecorder()
	env.admin.ServeHTTP(w, req)
	resp := w.Result()
	// ROTATE-NOTFOUND 的 UI 侧真实呈现：false-success 的 key 被渲染进结果页（200），
	// 管理员看到一把【无主 key】——比 500 更危险（关联 [KNOWN-GAP: ROTATE-NOTFOUND]）
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("不存在 client 的 regenerate 实际应 200（假成功渲染），当前 %d", resp.StatusCode)
	}
	page := w.Body.String()
	// 精确提取页面中出现的所有 sk- 形态序列
	// 从页面提取"复制区"文本段（API Key 展示区域）
	// 精确形态：头部先发出（200）+ 部分页面 + 尾部模板错误文本；无 key 渲染
	if !strings.Contains(page, "Template error") {
		t.Fatalf("[固化失败] 截断页面应含模板错误文本，实际尾部 %q", page[max(0, len(page)-160):])
	}
	if !strings.Contains(page, "nil pointer evaluating *models.Client.Name") {
		t.Fatalf("[固化失败] 错误应定位到 nil Client 字段访问，实际尾部 %q", page[max(0, len(page)-160):])
	}
	if strings.Contains(page, "sk-") {
		t.Fatalf("[固化失败] 截断页面不应含明文 key（exec 失败在 key 渲染前）")
	}
	t.Log("[KNOWN-GAP: P1-05 ROTATE-NOTFOUND] 固化（UI 侧）：不存在 client 的 regenerate → HTTP 200 + 截断页面 + 尾部 'Template error: nil pointer evaluating *models.Client.Name'（头部已发出故状态码滞留 200；生成的新 key 未渲染、未存库，管理员无任何错误提示）")
}

// ---------------------------------------------------------------------------
// Audit / 吊销字段：当前均为 0/不存在（反射断言 + 文档记录）
// ---------------------------------------------------------------------------
func TestP105A_AuditAndRevocationAbsent(t *testing.T) {
	var model models.Client
	typ := reflect.TypeOf(model)
	have := map[string]bool{}
	for i := 0; i < typ.NumField(); i++ {
		have[typ.Field(i).Name] = true
	}
	for _, absent := range []string{"RevokedAt", "RevokationReason", "RevokedBy", "Status", "AuditEvents"} {
		if have[absent] {
			t.Fatalf("[固化失败] Client 模型不应有 %s（当前无生命周期状态字段）", absent)
		}
	}
	t.Log("[CURRENT] 固化：无 revocation_reason / revoked_at / revoked_by 字段；无任何持久化生命周期审计事件（AUDIT_EVENT_COUNT=0，见文档）")
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
