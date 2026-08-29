package handlers

// P1-05B · Lifecycle Consistency & Delete Safety 验收测试
//
// 关闭 5 项：
//   ROTATE-NOTFOUND / ORPHAN-DATA / TOGGLE-ERR-SWALLOW / METRICS-COMPARE /
//   delete 后 late-write orphan race（IN_FLIGHT_DELETE_LATE_WRITE）
//
// 设计约束：
//   - 全部在 t.TempDir() fixture 上执行；canary 仅用 P105B_* 明显测试串
//   - Delete 后的 in-flight late-write gate 用 channel barrier 显式同步，禁止 sleep
//   - 生产路径打开（internal/database.Open，DSN _foreign_keys=on）——
//     外键是 late-write 防线，测试必须与部署行为一致
//
// 对应验收 A–J：A regen-nonexistent / B delete-nonexistent / C delete-全0 /
// D delete-tx-rollback / E late-write-barrier / F suspend-resume /
// G rotate-继承限流 / H delete-重置bucket / I toggle-不吞错 / J metrics-常量时间

import (
	"context"
	"crypto/sha256"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"ai-gateway/internal/auth"
	"ai-gateway/internal/database"
	"ai-gateway/internal/models"
	"ai-gateway/internal/services"

	"github.com/go-chi/chi/v5"
)

// ---------------------------------------------------------------------------
// 前置证明：外键约束真实存在，且连接池新建连接均强制执行
// ---------------------------------------------------------------------------
func TestP105B_ForeignKeys_OnAllPooledConnections(t *testing.T) {
	db, err := database.Open(filepath.Join(t.TempDir(), "fk.db"))
	if err != nil {
		t.Fatal(err)
	}
	if err := db.AutoMigrate(&models.Client{}, &models.RequestLog{}, &models.DailyUsage{}); err != nil {
		t.Fatal(err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatal(err)
	}
	defer sqlDB.Close()

	// 强制每次取新连接（不保留 idle），逐个验证 PRAGMA foreign_keys=1
	sqlDB.SetMaxIdleConns(0)
	sqlDB.SetMaxOpenConns(1)
	for i := 0; i < 5; i++ {
		conn, err := sqlDB.Conn(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		var fk int
		if err := conn.QueryRowContext(context.Background(), "PRAGMA foreign_keys").Scan(&fk); err != nil {
			t.Fatal(err)
		}
		_ = conn.Close()
		if fk != 1 {
			t.Fatalf("[P1-05B] 连接 #%d PRAGMA foreign_keys=%d，应恒为 1（DSN 级开启）", i, fk)
		}
	}

	// FK 定义真实存在：request_logs / daily_usages → clients，ON DELETE CASCADE
	for _, table := range []string{"request_logs", "daily_usages"} {
		rows, err := sqlDB.QueryContext(context.Background(),
			"SELECT \"table\", on_delete FROM pragma_foreign_key_list(?)", table)
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for rows.Next() {
			var refTable, onDelete string
			if err := rows.Scan(&refTable, &onDelete); err != nil {
				t.Fatal(err)
			}
			if refTable == "clients" && onDelete == "CASCADE" {
				found = true
			}
		}
		rows.Close()
		if !found {
			t.Fatalf("[P1-05B] %s 缺 FK → clients(id) ON DELETE CASCADE（AutoMigrate 未产出约束）", table)
		}
	}

	// 行为证明：直接 DELETE clients（不经 service）也应级联清空 children
	clientID := "fk-probe-client"
	if err := db.Create(&models.Client{ID: clientID, Name: "fk", APIKeyHash: []byte("hash"), IsActive: true}).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Create(&models.RequestLog{ClientID: clientID, Model: "m", StatusCode: 200}).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Delete(&models.Client{}, "id = ?", clientID).Error; err != nil {
		t.Fatal(err)
	}
	var n int64
	_ = db.Raw("SELECT count(*) FROM request_logs WHERE client_id = ?", clientID).Scan(&n).Error
	if n != 0 {
		t.Fatalf("[P1-05B] FK CASCADE 未生效：client 删除后 request_logs 残留 %d 行", n)
	}
	t.Log("[P1-05B] FK 证明：连接池全部连接 foreign_keys=1；两表 FK CASCADE 存在且行为生效")
}

// ---------------------------------------------------------------------------
// A. Regenerate 不存在 client：service ErrClientNotFound + key==""；Admin 404
// ---------------------------------------------------------------------------
func TestP105B_Regenerate_Nonexistent_ErrAnd404(t *testing.T) {
	env := newP105Env(t)

	newKey, err := env.clientSvc.RegenerateAPIKey("p105b-no-such-id", "openai", "sk-")
	if !errors.Is(err, services.ErrClientNotFound) {
		t.Fatalf("[A] 应返回 ErrClientNotFound，实际 %v", err)
	}
	if newKey != "" {
		t.Fatalf("[A] 失败路径不得返回明文 key，实际 %q", newKey)
	}

	// Admin 路由 → 404，无截断模板/无 key
	token := p105AdminSessionOf(t, env)
	form := url.Values{"key_type": {"openai"}, "key_prefix": {"sk-"}}
	req := httptest.NewRequest("POST", "/admin/clients/p105b-no-such-id/regenerate", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: token})
	req.Header.Set("X-CSRF-Token", auth.CSRFToken(env.cfg.Admin.SessionSecret, token))
	w := httptest.NewRecorder()
	env.admin.ServeHTTP(w, req)
	resp := w.Result()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("[A] Admin regenerate 不存在 client 应 404，实际 %d", resp.StatusCode)
	}
	body := w.Body.String()
	if strings.Contains(body, "Template error") || strings.Contains(body, "nil pointer") || strings.Contains(body, "sk-") {
		t.Fatalf("[A] 404 页不应含模板错误/无主 key，实际 %q", body[:min(200, len(body))])
	}
	t.Log("[A PASS] Regenerate nonexistent: ErrClientNotFound + key==\"\" + Admin 404 无模板错误")
}

// ---------------------------------------------------------------------------
// B. Delete 不存在 client：service ErrClientNotFound；Admin 404
// ---------------------------------------------------------------------------
func TestP105B_Delete_Nonexistent_ErrAnd404(t *testing.T) {
	env := newP105Env(t)

	if err := env.clientSvc.DeleteClient("p105b-no-such-id"); !errors.Is(err, services.ErrClientNotFound) {
		t.Fatalf("[B] 应返回 ErrClientNotFound，实际 %v", err)
	}

	token := p105AdminSessionOf(t, env)
	req := httptest.NewRequest("POST", "/admin/clients/p105b-no-such-id/delete", strings.NewReader(""))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: token})
	req.Header.Set("X-CSRF-Token", auth.CSRFToken(env.cfg.Admin.SessionSecret, token))
	w := httptest.NewRecorder()
	env.admin.ServeHTTP(w, req)
	if w.Result().StatusCode != http.StatusNotFound {
		t.Fatalf("[B] Admin delete 不存在 client 应 404，实际 %d", w.Result().StatusCode)
	}
	t.Log("[B PASS] Delete nonexistent: ErrClientNotFound + Admin 404（不再静默假成功）")
}

// ---------------------------------------------------------------------------
// C. Delete 已有 client：clients/request_logs/daily_usages 三表全 0（Admin 路由级）
// ---------------------------------------------------------------------------
func TestP105B_Delete_Existing_AllTablesZero(t *testing.T) {
	env := newP105Env(t)
	client, key, err := env.clientSvc.CreateClient("p105b-del", "", "openai", "sk-", env.cfg)
	if err != nil {
		t.Fatal(err)
	}
	// 产生真实持久化行（认证 + LogRequest 路径）
	if resp := env.doAuth(t, key); resp.StatusCode != http.StatusOK {
		t.Fatalf("[C] 认证应 200，实际 %d", resp.StatusCode)
	}
	if err := env.gemini.LogRequest(services.RequestRecord{
		RequestID: "p105b-c-1", ClientID: client.ID, Provider: "gemini",
		Model: "m", StatusCode: 200, InputTokens: 3,
	}); err != nil {
		t.Fatal(err)
	}

	token := p105AdminSessionOf(t, env)
	req := httptest.NewRequest("POST", "/admin/clients/"+client.ID+"/delete", strings.NewReader(""))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: token})
	req.Header.Set("X-CSRF-Token", auth.CSRFToken(env.cfg.Admin.SessionSecret, token))
	w := httptest.NewRecorder()
	env.admin.ServeHTTP(w, req)
	if w.Result().StatusCode != http.StatusFound {
		t.Fatalf("[C] delete 成功应 302，实际 %d", w.Result().StatusCode)
	}
	if env.countAll(t, "clients") != 0 || env.countAll(t, "request_logs") != 0 || env.countAll(t, "daily_usages") != 0 {
		t.Fatalf("[C] 三表应全 0：clients=%d logs=%d usage=%d",
			env.countAll(t, "clients"), env.countAll(t, "request_logs"), env.countAll(t, "daily_usages"))
	}
	t.Log("[C PASS] Delete existing（Admin 路由）→ 三表全 0")
}

// ---------------------------------------------------------------------------
// D. Delete 事务失败 → 整体 rollback：client 行保留，operational data 原值保留
// ---------------------------------------------------------------------------
func TestP105B_Delete_TransactionFailure_Rollback(t *testing.T) {
	env := newP105Env(t)
	client, _, err := env.clientSvc.CreateClient("p105b-tx", "", "openai", "sk-", env.cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := env.gemini.LogRequest(services.RequestRecord{
		RequestID: "p105b-d-1", ClientID: client.ID, Provider: "gemini",
		Model: "m", StatusCode: 200,
	}); err != nil {
		t.Fatal(err)
	}

	// 记录删除前的“原值”作为 rollback 对照
	preClients, preLogs, preUsage := env.countAll(t, "clients"), env.countAll(t, "request_logs"), env.countAll(t, "daily_usages")

	// 注入依赖清理失败：request_logs DELETE 时 RAISE(ABORT) → 整个事务必须回滚
	if err := env.db.Exec(`CREATE TRIGGER p105b_fail_cleanup AFTER DELETE ON request_logs BEGIN SELECT RAISE(ABORT, 'injected P1-05B cleanup failure'); END`).Error; err != nil {
		t.Fatal(err)
	}

	err = env.clientSvc.DeleteClient(client.ID)
	if err == nil {
		t.Fatal("[D] 注入清理失败后 DeleteClient 应返回 error")
	}

	if env.countAll(t, "clients") != preClients || env.countAll(t, "request_logs") != preLogs || env.countAll(t, "daily_usages") != preUsage {
		t.Fatalf("[D] rollback 后应全部保留原值：clients=%d(pre %d) logs=%d(pre %d) usage=%d(pre %d)",
			env.countAll(t, "clients"), preClients,
			env.countAll(t, "request_logs"), preLogs,
			env.countAll(t, "daily_usages"), preUsage)
	}
	t.Log("[D PASS] Delete tx 失败 → 整体 rollback（client 未删、children 原值保留）")
}

// ---------------------------------------------------------------------------
// E. In-Flight Late-Write Gate（IN_FLIGHT_DELETE_LATE_WRITE）
//
//	已认证请求阻塞在日志写入前 → Admin Delete 成功 → 放行 → 三表仍为 0
//
// ---------------------------------------------------------------------------
func TestP105B_Delete_InFlightLateWrite_Barrier(t *testing.T) {
	env := newP105Env(t)
	client, key, err := env.clientSvc.CreateClient("p105b-late", "", "openai", "sk-", env.cfg)
	if err != nil {
		t.Fatal(err)
	}

	// Gate step 2: request 已通过 Auth
	if resp := env.doAuth(t, key); resp.StatusCode != http.StatusOK {
		t.Fatalf("[E] 认证应 200，实际 %d", resp.StatusCode)
	}

	started := make(chan struct{})
	release := make(chan struct{})
	done := make(chan struct{})
	var lateErr error

	// Gate step 3: 模拟已认证但尚未完成的旧请求——阻塞在持久化写入前
	go func() {
		close(started)
		<-release
		lateErr = env.gemini.LogRequest(services.RequestRecord{
			RequestID: "p105b-late-write", ClientID: client.ID, Provider: "gemini",
			Model: "m", StatusCode: 200, InputTokens: 7,
		})
		close(done)
	}()
	<-started // 确认旧请求已停在 barrier 上（channel 同步，禁止 sleep）

	// Gate step 4: Admin Delete 成功（含事务提交 + bucket reset）
	token := p105AdminSessionOf(t, env)
	req := httptest.NewRequest("POST", "/admin/clients/"+client.ID+"/delete", strings.NewReader(""))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: token})
	req.Header.Set("X-CSRF-Token", auth.CSRFToken(env.cfg.Admin.SessionSecret, token))
	w := httptest.NewRecorder()
	env.admin.ServeHTTP(w, req)
	if w.Result().StatusCode != http.StatusFound {
		t.Fatalf("[E] Admin delete 应 302，实际 %d", w.Result().StatusCode)
	}

	// Gate step 5: 放行旧请求完成其写入
	close(release)
	<-done
	if lateErr != nil {
		t.Fatalf("[E] 旧请求应正常结束（late-write 静默跳过），实际 err=%v", lateErr)
	}

	// Gate step 6: 最终持久状态——绝无孤儿重建
	if env.countAll(t, "clients") != 0 || env.countAll(t, "request_logs") != 0 || env.countAll(t, "daily_usages") != 0 {
		t.Fatalf("[E] late-write 后三表应全 0：clients=%d logs=%d usage=%d",
			env.countAll(t, "clients"), env.countAll(t, "request_logs"), env.countAll(t, "daily_usages"))
	}
	t.Log("[E PASS] 已认证旧请求在 Delete 后完成 → 请求正常结束但零孤儿行（FK 拦截）")
}

// ---------------------------------------------------------------------------
// F. Suspend/Resume：SetClientActive(false)→401；恢复原 key→200
// ---------------------------------------------------------------------------
func TestP105B_SuspendResume_Contract(t *testing.T) {
	env := newP105Env(t)
	c := env.insertClientWithKey(t, "p105b-sr", p105OriginalKey, true)

	if err := env.clientSvc.SetClientActive(c.ID, false); err != nil {
		t.Fatal(err)
	}
	if resp := env.doAuth(t, p105OriginalKey); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("[F] suspend 后应 401（SUSPENDED 统一 invalid-key 语义），实际 %d", resp.StatusCode)
	}

	if err := env.clientSvc.SetClientActive(c.ID, true); err != nil {
		t.Fatal(err)
	}
	if resp := env.doAuth(t, p105OriginalKey); resp.StatusCode != http.StatusOK {
		t.Fatalf("[F] resume 后【原 key】应 200，实际 %d", resp.StatusCode)
	}

	// 不存在 id → ErrClientNotFound
	if err := env.clientSvc.SetClientActive("p105b-no-such", true); !errors.Is(err, services.ErrClientNotFound) {
		t.Fatalf("[F] SetClientActive 不存在 client 应 ErrClientNotFound，实际 %v", err)
	}
	t.Log("[F PASS] Suspend→401 / Resume 原 key→200 / 不存在→ErrClientNotFound")
}

// ---------------------------------------------------------------------------
// G. Rotate：old 401 / new 200；rate-limit 状态【继承不重置】
// ---------------------------------------------------------------------------
func TestP105B_Rotate_InheritsRateLimitState(t *testing.T) {
	env := newP105Env(t)
	client, key, err := env.clientSvc.CreateClient("p105b-rot", "", "openai", "sk-", env.cfg)
	if err != nil {
		t.Fatal(err)
	}
	// 桶容量 2：认证会消耗 token；rotate 后状态必须原样延续
	if err := env.db.Model(&models.Client{}).Where("id = ?", client.ID).Update("rate_limit_minute", 2).Error; err != nil {
		t.Fatal(err)
	}

	resp1 := env.doAuth(t, key)
	if resp1.StatusCode != http.StatusOK {
		t.Fatalf("[G] 首请求应 200，实际 %d", resp1.StatusCode)
	}
	if got := resp1.Header.Get("X-RateLimit-Remaining-Minute"); got != "1" {
		t.Fatalf("[G] 消耗 1 后 remaining 应为 1，实际 %q", got)
	}

	newKey, err := env.clientSvc.RegenerateAPIKey(client.ID, "openai", "sk-")
	if err != nil {
		t.Fatal(err)
	}
	if resp := env.doAuth(t, key); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("[G] rotate 后 old key 应 401，实际 %d", resp.StatusCode)
	}

	// 新 key 200 且继承上一请求后的剩余额度（1→0），NOT 重置回容量 2
	resp2 := env.doAuth(t, newKey)
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("[G] rotate 后 new key 应 200，实际 %d", resp2.StatusCode)
	}
	if got := resp2.Header.Get("X-RateLimit-Remaining-Minute"); got != "0" {
		t.Fatalf("[G] rotate 不得重置限流：remaining 应继承为 0，实际 %q", got)
	}

	if resp := env.doAuth(t, newKey); resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("[G] 继承后桶耗尽应 429（证明未重置），实际 %d", resp.StatusCode)
	}
	t.Log("[G PASS] Rotate：old 401 / new 200 / 限流状态继承不重置")
}

// ---------------------------------------------------------------------------
// H. Delete：下一 auth 401；rate-limit bucket 被 reset（经 Admin 路由接线）
// ---------------------------------------------------------------------------
func TestP105B_Delete_ResetsRateLimitBucket(t *testing.T) {
	env := newP105Env(t)
	client, key, err := env.clientSvc.CreateClient("p105b-rst", "", "openai", "sk-", env.cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := env.db.Model(&models.Client{}).Where("id = ?", client.ID).Update("rate_limit_minute", 2).Error; err != nil {
		t.Fatal(err)
	}
	// 先消耗到耗尽（证明桶确实被用空）
	if r := env.doAuth(t, key); r.StatusCode != http.StatusOK {
		t.Fatalf("[H] 消耗 1 应 200，实际 %d", r.StatusCode)
	}
	if r := env.doAuth(t, key); r.StatusCode != http.StatusOK {
		t.Fatalf("[H] 消耗 2 应 200，实际 %d", r.StatusCode)
	}
	if r := env.doAuth(t, key); r.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("[H] 桶耗尽应 429，实际 %d", r.StatusCode)
	}

	// Admin Delete（handler 内完成 tx 成功 → ResetClient）
	token := p105AdminSessionOf(t, env)
	req := httptest.NewRequest("POST", "/admin/clients/"+client.ID+"/delete", strings.NewReader(""))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: token})
	req.Header.Set("X-CSRF-Token", auth.CSRFToken(env.cfg.Admin.SessionSecret, token))
	w := httptest.NewRecorder()
	env.admin.ServeHTTP(w, req)
	if w.Result().StatusCode != http.StatusFound {
		t.Fatalf("[H] delete 应 302，实际 %d", w.Result().StatusCode)
	}

	// Delete 后原 key 下一 auth 立即 401
	if resp := env.doAuth(t, key); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("[H] delete 后原 key 应 401，实际 %d", resp.StatusCode)
	}

	// 同 ID 重建 client（直接插入）：若 bucket 已被 reset → 200（新桶满额）；
	// 若未 reset → 继承耗尽桶 → 429
	sum := sha256.Sum256([]byte(key))
	if err := env.db.Create(&models.Client{
		ID: client.ID, Name: "p105b-rst2", APIKeyHash: sum[:],
		IsActive: true, RateLimitMinute: 2,
		CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}).Error; err != nil {
		t.Fatal(err)
	}
	resp := env.doAuth(t, key)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("[H] delete 后 bucket 应已 reset（重建同 ID 首请求 200），实际 %d", resp.StatusCode)
	}
	t.Log("[H PASS] Delete：原 key 401 + 限流 bucket 已 reset（事务成功后才 reset）")
}

// ---------------------------------------------------------------------------
// I. Toggle：正常路径 302；DB 错误不再被吞 → 500 generic
// ---------------------------------------------------------------------------
func TestP105B_Toggle_DbErrorNotSwallowed(t *testing.T) {
	env := newP105Env(t)
	// P1-05C §0 correction：必须保存真实 generated key——禁止用固定无效 key 证明 401
	client, generatedKey, err := env.clientSvc.CreateClient("p105b-tog", "", "openai", "sk-", env.cfg)
	if err != nil {
		t.Fatal(err)
	}
	token := p105AdminSessionOf(t, env)

	// 正常路径：generated key 全链路——200 → active=false(302) → 401 → active=true(302) → 200
	if resp := env.doAuth(t, generatedKey); resp.StatusCode != http.StatusOK {
		t.Fatalf("[I] toggle 前 generated key 应 200，实际 %d", resp.StatusCode)
	}
	form := url.Values{"active": {"false"}}
	req := httptest.NewRequest("POST", "/admin/clients/"+client.ID+"/toggle", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: token})
	req.Header.Set("X-CSRF-Token", auth.CSRFToken(env.cfg.Admin.SessionSecret, token))
	w := httptest.NewRecorder()
	env.admin.ServeHTTP(w, req)
	if w.Result().StatusCode != http.StatusFound {
		t.Fatalf("[I] toggle 成功应 302，实际 %d", w.Result().StatusCode)
	}
	if resp := env.doAuth(t, generatedKey); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("[I] suspend 后 generated key 应 401，实际 %d", resp.StatusCode)
	}

	formOn := url.Values{"active": {"true"}}
	reqOn := httptest.NewRequest("POST", "/admin/clients/"+client.ID+"/toggle", strings.NewReader(formOn.Encode()))
	reqOn.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	reqOn.AddCookie(&http.Cookie{Name: sessionCookieName, Value: token})
	reqOn.Header.Set("X-CSRF-Token", auth.CSRFToken(env.cfg.Admin.SessionSecret, token))
	wOn := httptest.NewRecorder()
	env.admin.ServeHTTP(wOn, reqOn)
	if wOn.Result().StatusCode != http.StatusFound {
		t.Fatalf("[I] resume toggle 应 302，实际 %d", wOn.Result().StatusCode)
	}
	if resp := env.doAuth(t, generatedKey); resp.StatusCode != http.StatusOK {
		t.Fatalf("[I] resume 后同一 generated key 应 200，实际 %d", resp.StatusCode)
	}

	// 不存在 id → 404（显式状态路径经 SetClientActive ErrClientNotFound）
	req404 := httptest.NewRequest("POST", "/admin/clients/p105b-no-such/toggle", strings.NewReader(url.Values{"active": {"true"}}.Encode()))
	req404.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req404.AddCookie(&http.Cookie{Name: sessionCookieName, Value: token})
	req404.Header.Set("X-CSRF-Token", auth.CSRFToken(env.cfg.Admin.SessionSecret, token))
	w404 := httptest.NewRecorder()
	env.admin.ServeHTTP(w404, req404)
	if w404.Result().StatusCode != http.StatusNotFound {
		t.Fatalf("[I] toggle 不存在 client 应 404，实际 %d", w404.Result().StatusCode)
	}

	// DB 错误注入：DROP clients 表 → SetClientActive 必然失败 → handler 必须 500
	// （旧实现吞掉 UpdateClient 错误并 302 redirect）
	if err := env.db.Exec("DROP TABLE clients").Error; err != nil {
		t.Fatal(err)
	}
	reqErr := httptest.NewRequest("POST", "/admin/clients/"+client.ID+"/toggle", strings.NewReader(url.Values{"active": {"true"}}.Encode()))
	reqErr.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	reqErr.AddCookie(&http.Cookie{Name: sessionCookieName, Value: token})
	reqErr.Header.Set("X-CSRF-Token", auth.CSRFToken(env.cfg.Admin.SessionSecret, token))
	wErr := httptest.NewRecorder()
	env.admin.ServeHTTP(wErr, reqErr)
	respErr := wErr.Result()
	if respErr.StatusCode != http.StatusInternalServerError {
		t.Fatalf("[I] toggle DB 错误应 500（不再吞错），实际 %d。body=%q", respErr.StatusCode, wErr.Body.String())
	}
	if strings.Contains(wErr.Body.String(), "no such table") {
		t.Fatalf("[I] 500 响应必须是 generic message，不得泄露 raw DB error")
	}
	t.Log("[I PASS] Toggle：成功 302 / 不存在 404 / DB 错误 500 generic（错误不再被吞）")
}

// ---------------------------------------------------------------------------
// J. Metrics Basic Auth：常量时间比较 + 功能契约
// ---------------------------------------------------------------------------
func TestP105B_MetricsBasicAuth_ConstantTimeContract(t *testing.T) {
	const (
		metricsUser = "P105B_METRICS_USER"
		metricsPass = "P105B_METRICS_PASS"
	)
	h := NewMetricsHandler(services.NewStatsService(nil), metricsUser, metricsPass)
	mux := chi.NewRouter()
	h.RegisterRoutes(mux)

	do := func(user, pass string, present bool) *http.Response {
		req := httptest.NewRequest("GET", "/metrics", nil)
		if present {
			req.SetBasicAuth(user, pass)
		}
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)
		return w.Result()
	}

	if resp := do(metricsUser, metricsPass, true); resp.StatusCode != http.StatusOK {
		t.Fatalf("[J] 正确凭据应 200，实际 %d", resp.StatusCode)
	}
	if resp := do("P105B_WRONG_USER", metricsPass, true); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("[J] 错误 username 应 401，实际 %d", resp.StatusCode)
	}
	if resp := do(metricsUser, "P105B_WRONG_PASS", true); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("[J] 错误 password 应 401，实际 %d", resp.StatusCode)
	}
	if resp := do("", "", false); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("[J] 缺失 BasicAuth 应 401，实际 %d", resp.StatusCode)
	}
	t.Log("[J PASS] Metrics Basic Auth：200/401 功能契约全部满足（常量时间实现见 static gate）")
}

// ---------------------------------------------------------------------------
// FK violation 在 LogRequest 写路径上的显式行为（非 barrier 的精简证明）
// ---------------------------------------------------------------------------
func TestP105B_LogRequest_FKViolation_GracefulSkip(t *testing.T) {
	env := newP105Env(t)
	client, _, err := env.clientSvc.CreateClient("p105b-fk", "", "openai", "sk-", env.cfg)
	if err != nil {
		t.Fatal(err)
	}
	// 不经 service 直接删除 client（级联清空 children，触发 FK 状态）
	if err := env.db.Delete(&models.Client{}, "id = ?", client.ID).Error; err != nil {
		t.Fatal(err)
	}

	// late-write 必须静默跳过（nil error），且绝不产生新行
	if err := env.gemini.LogRequest(services.RequestRecord{
		RequestID: "p105b-fk-1", ClientID: client.ID, Provider: "gemini",
		Model: "m", StatusCode: 200,
	}); err != nil {
		t.Fatalf("[FK] LogRequest 遇 FK violation 应静默返回 nil，实际 %v", err)
	}
	if env.countAll(t, "request_logs") != 0 || env.countAll(t, "daily_usages") != 0 {
		t.Fatalf("[FK] late-write 不得产生任何行：logs=%d usage=%d",
			env.countAll(t, "request_logs"), env.countAll(t, "daily_usages"))
	}
	t.Log("[FK PASS] LogRequest late-write：FK violation 静默跳过，零孤儿")
}
