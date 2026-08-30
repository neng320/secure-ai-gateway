package handlers

// P1-05C · Permanent Revocation & Audit Foundation 验收测试（A–Z）
//
// 对应卡片 §21：A LifecycleState 三态 / B Revoke-ACTIVE / C Revoke-SUSPENDED /
// D hash→NULL / E 双 revoked NULL / F key 401 / G rotate-revoked 409 / H resume-revoked 409 /
// I settings 无法复活 / J forged actor 忽略 / K reason 400 / L~P 事件恰 1 条与保留 /
// Q~U audit 失败 → 全 rollback / V rotate×revoke race invariant / W canary=0。
// X（P1-05B in-flight Delete Gate）由 TestP105B_Delete_InFlightLateWrite_Barrier 原样继续；
// Y/Z（privacy/security gates）由既有套件覆盖。
//
// Canary：P105C_CLIENT_KEY_CANARY / P105C_PROVIDER_SECRET_CANARY（明显测试串）。

import (
	"bytes"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"ai-gateway/internal/auth"
	"ai-gateway/internal/database"
	"ai-gateway/internal/models"
	"ai-gateway/internal/secrets"
	"ai-gateway/internal/services"
)

const (
	p105cClientKey    = "P105C_CLIENT_KEY_CANARY"
	p105cProviderSec  = "P105C_PROVIDER_SECRET_CANARY"
	p105cActor        = "admin"
	p105cReasonRotate = "P105C rotation reason"
	p105cReasonRevoke = "P105C revocation reason"
)

// ---------------------------------------------------------------------------
// 辅助
// ---------------------------------------------------------------------------

func (e *p105Env) createTestClient(t *testing.T, name string) (*models.Client, string) {
	t.Helper()
	c, key, err := e.clientSvc.CreateClient(name, "", "openai", "sk-", e.cfg, p105cActor)
	if err != nil {
		t.Fatal(err)
	}
	return c, key
}

func (e *p105Env) auditEvents(t *testing.T, targetID string) []models.AuditEvent {
	t.Helper()
	var evs []models.AuditEvent
	if err := e.db.Where("target_type = ? AND target_id = ?", "client", targetID).
		Order("id ASC").Find(&evs).Error; err != nil {
		t.Fatal(err)
	}
	return evs
}

func (e *p105Env) auditCount(t *testing.T, targetID, action string) int {
	t.Helper()
	var n int64
	if err := e.db.Model(&models.AuditEvent{}).
		Where("target_type = ? AND target_id = ? AND action = ?", "client", targetID, action).
		Count(&n).Error; err != nil {
		t.Fatal(err)
	}
	return int(n)
}

func (e *p105Env) hashIsNull(t *testing.T, id string) bool {
	t.Helper()
	var n int64
	if err := e.db.Raw("SELECT count(*) FROM clients WHERE id = ? AND api_key_hash IS NULL", id).Scan(&n).Error; err != nil {
		t.Fatal(err)
	}
	return n == 1
}

func (e *p105Env) adminPost(t *testing.T, token, path string, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest("POST", path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: token})
	req.Header.Set("X-CSRF-Token", auth.CSRFToken(e.cfg.Admin.SessionSecret, token))
	w := httptest.NewRecorder()
	e.admin.ServeHTTP(w, req)
	return w
}

// injectAuditFailure: audit_events INSERT 失败注入（Q–U 回滚 gate）。
// DROP TABLE 让 audit INSERT 以稳定的 schema error 失败；SQLite 的
// RAISE(FAIL/ABORT) 触发器在显式事务+连接池场景下可能留下连接级 phantom，
// 不适合作为回滚验收注入。
func (e *p105Env) injectAuditFailure(t *testing.T) {
	t.Helper()
	if err := e.db.Exec("DROP TABLE audit_events").Error; err != nil {
		t.Fatal(err)
	}
}

func p105cEncryptedProviderKey(t *testing.T, clientID, plaintext string) string {
	t.Helper()
	masterKey := make([]byte, secrets.KeySize)
	copy(masterKey, []byte("p105c-test-master-key"))
	cipher, err := secrets.NewAESGCMCipher(masterKey)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := secrets.NewManager(cipher).EncryptClientBackendKey(clientID, []byte(plaintext))
	if err != nil {
		t.Fatal(err)
	}
	return envelope
}

// ---------------------------------------------------------------------------
// A. LifecycleState 三态推导（§1：RevokedAt 优先，无第四份状态真相）
// ---------------------------------------------------------------------------
func TestP105C_A_LifecycleStateDerivation(t *testing.T) {
	now := time.Now()
	cases := []struct {
		name   string
		client models.Client
		want   models.ClientLifecycleState
	}{
		{"active", models.Client{IsActive: true}, models.ClientStateActive},
		{"suspended", models.Client{IsActive: false}, models.ClientStateSuspended},
		{"revoked-inactive", models.Client{IsActive: false, RevokedAt: &now}, models.ClientStateRevoked},
		{"revoked-active", models.Client{IsActive: true, RevokedAt: &now}, models.ClientStateRevoked},
	}
	for _, tc := range cases {
		if got := tc.client.LifecycleState(); got != tc.want {
			t.Fatalf("[A] %s: LifecycleState()=%s want %s", tc.name, got, tc.want)
		}
	}
	t.Log("[A PASS] 三态推导：RevokedAt 优先，无持久化 Status 字段")
}

// ---------------------------------------------------------------------------
// B. Revoke ACTIVE 成功（字段 + audit 事件）
// ---------------------------------------------------------------------------
func TestP105C_B_RevokeActive_Success(t *testing.T) {
	env := newP105Env(t)
	c, key := env.createTestClient(t, "p105c-b")
	if resp := env.doAuth(t, key); resp.StatusCode != http.StatusOK {
		t.Fatalf("[B] revoke 前应 200，实际 %d", resp.StatusCode)
	}

	if err := env.clientSvc.RevokeClient(c.ID, p105cActor, p105cReasonRevoke); err != nil {
		t.Fatal(err)
	}
	got, err := env.clientSvc.GetClientByID(c.ID)
	if err != nil || got == nil {
		t.Fatal("client 不存在")
	}
	if got.RevokedAt == nil || got.RevokedBy != p105cActor || got.RevocationReason != p105cReasonRevoke {
		t.Fatalf("[B] revoked 元数据不符: at=%v by=%q reason=%q", got.RevokedAt, got.RevokedBy, got.RevocationReason)
	}
	if got.IsActive {
		t.Fatal("[B] revoke 后 IsActive 必须 false")
	}
	if !env.hashIsNull(t, c.ID) {
		t.Fatal("[B] revoke 后 api_key_hash 必须 IS NULL")
	}
	if got.LifecycleState() != models.ClientStateRevoked {
		t.Fatalf("[B] LifecycleState 应为 REVOKED，实际 %s", got.LifecycleState())
	}
	if n := env.auditCount(t, c.ID, "CLIENT_REVOKED"); n != 1 {
		t.Fatalf("[B] 应恰 1 条 CLIENT_REVOKED，实际 %d", n)
	}
	t.Log("[B PASS] Revoke ACTIVE：元数据/IsActive false/hash NULL/状态 REVOKED/恰 1 事件")
}

func TestP105C_AdminCreateFailure_RollsBackClientAndAudit(t *testing.T) {
	env := newP105Env(t)
	token := p105AdminSessionOf(t, env)
	w := env.adminPost(t, token, "/admin/clients", url.Values{
		"name":            {"p105c-create-fail"},
		"backend_api_key": {p105cProviderSec},
	})
	if w.Result().StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("[Create] missing master key should fail closed, actual %d", w.Result().StatusCode)
	}
	if clients, events := env.countAll(t, "clients"), env.countAll(t, "audit_events"); clients != 0 || events != 0 {
		t.Fatalf("[Create] failed create must rollback client and audit, clients=%d events=%d", clients, events)
	}
	t.Log("[Create PASS] provider-key encryption failure rolls back client/settings/audit atomically")
}

// ---------------------------------------------------------------------------
// C. Revoke SUSPENDED 成功
// ---------------------------------------------------------------------------
func TestP105C_C_RevokeSuspended_Success(t *testing.T) {
	env := newP105Env(t)
	c, _ := env.createTestClient(t, "p105c-c")
	if err := env.clientSvc.SuspendClient(c.ID, p105cActor, "P105C suspend reason"); err != nil {
		t.Fatal(err)
	}
	if err := env.clientSvc.RevokeClient(c.ID, p105cActor, p105cReasonRevoke); err != nil {
		t.Fatal(err)
	}
	got, _ := env.clientSvc.GetClientByID(c.ID)
	if got.RevokedAt == nil || got.LifecycleState() != models.ClientStateRevoked {
		t.Fatalf("[C] SUSPENDED→REVOKED 失败: state=%s at=%v", got.LifecycleState(), got.RevokedAt)
	}
	if n := env.auditCount(t, c.ID, "CLIENT_REVOKED"); n != 1 {
		t.Fatalf("[C] 应恰 1 条 CLIENT_REVOKED，实际 %d", n)
	}
	t.Log("[C PASS] Revoke SUSPENDED 成功（SUSPENDED→REVOKED 合法迁移）")
}

// ---------------------------------------------------------------------------
// D/E. revoke 后 api_key_hash = SQL NULL（unique index 下多行 revoked 不碰撞）
// ---------------------------------------------------------------------------
func TestP105C_D_E_RevokeClearsHashToNull_Multiple(t *testing.T) {
	env := newP105Env(t)
	c1, _ := env.createTestClient(t, "p105c-d1")
	c2, _ := env.createTestClient(t, "p105c-d2")

	if err := env.clientSvc.RevokeClient(c1.ID, p105cActor, p105cReasonRevoke); err != nil {
		t.Fatal(err)
	}
	if err := env.clientSvc.RevokeClient(c2.ID, p105cActor, p105cReasonRevoke); err != nil {
		t.Fatal(err)
	}
	if !env.hashIsNull(t, c1.ID) || !env.hashIsNull(t, c2.ID) {
		t.Fatalf("[D/E] 两个 revoked client 的 api_key_hash 均应 IS NULL（NULL 而非 empty blob）")
	}
	t.Log("[D/E PASS] revoke 清 hash 为 SQL NULL；双 revoked 行共存无 unique 碰撞")
}

// ---------------------------------------------------------------------------
// F. revoked key 公网 401（SUSPENDED/REVOKED/ROTATED-old/DELETED/random 统一 401）
// ---------------------------------------------------------------------------
func TestP105C_F_RevokedKey_401(t *testing.T) {
	env := newP105Env(t)
	c, key := env.createTestClient(t, "p105c-f")
	if err := env.clientSvc.RevokeClient(c.ID, p105cActor, p105cReasonRevoke); err != nil {
		t.Fatal(err)
	}
	resp := env.doAuth(t, key)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("[F] revoked key 应 401，实际 %d", resp.StatusCode)
	}
	b, _ := ioReadAll(resp.Body)
	resp.Body.Close()
	if !strings.Contains(string(b), "Invalid API key") {
		t.Fatalf("[F] 响应应为 invalid-key 语义，实际 %s", string(b))
	}
	t.Log("[F PASS] revoked key → 401 Invalid API key（无 403 credential-state oracle）")
}

// ---------------------------------------------------------------------------
// G/H. rotate/resume revoked → ErrClientRevoked + HTTP 409
// ---------------------------------------------------------------------------
func TestP105C_G_H_RevokedTransitions_409(t *testing.T) {
	env := newP105Env(t)
	c, key := env.createTestClient(t, "p105c-gh")
	if err := env.clientSvc.RevokeClient(c.ID, p105cActor, p105cReasonRevoke); err != nil {
		t.Fatal(err)
	}
	token := p105AdminSessionOf(t, env)

	// G service + HTTP：rotate revoked
	newKey, err := env.clientSvc.RegenerateAPIKey(c.ID, "openai", "sk-", p105cActor, p105cReasonRotate)
	if !errors.Is(err, services.ErrClientRevoked) {
		t.Fatalf("[G] rotate revoked 应 ErrClientRevoked，实际 %v", err)
	}
	if newKey != "" {
		t.Fatalf("[G] 失败路径不得返回新 key，实际 %q", newKey)
	}
	w := env.adminPost(t, token, "/admin/clients/"+c.ID+"/regenerate",
		url.Values{"key_type": {"openai"}, "reason": {p105cReasonRotate}})
	if w.Result().StatusCode != http.StatusConflict {
		t.Fatalf("[G] rotate revoked 应 409，实际 %d", w.Result().StatusCode)
	}

	// H service + HTTP：resume revoked
	if err := env.clientSvc.ResumeClient(c.ID, p105cActor, ""); !errors.Is(err, services.ErrClientRevoked) {
		t.Fatalf("[H] resume revoked 应 ErrClientRevoked，实际 %v", err)
	}
	w2 := env.adminPost(t, token, "/admin/clients/"+c.ID+"/toggle",
		url.Values{"active": {"true"}, "reason": {"P105C resume reason"}})
	if w2.Result().StatusCode != http.StatusConflict {
		t.Fatalf("[H] resume revoked 应 409，实际 %d", w2.Result().StatusCode)
	}
	// 再 revoke → 409
	w3 := env.adminPost(t, token, "/admin/clients/"+c.ID+"/revoke",
		url.Values{"reason": {p105cReasonRevoke}, "confirm_revoke": {"REVOKE"}})
	if w3.Result().StatusCode != http.StatusConflict {
		t.Fatalf("[G] 二次 revoke 应 409，实际 %d", w3.Result().StatusCode)
	}
	if env.auditCount(t, c.ID, "CLIENT_REVOKED") != 1 {
		t.Fatal("[G] 非法 transition 不得产生新 event（仍 1 条）")
	}
	if env.doAuth(t, key).StatusCode != http.StatusUnauthorized {
		t.Fatal("[G] revoked 后旧 key 必须永久 401")
	}
	t.Log("[G/H PASS] rotate/resume/再-revoke revoked → 409 + key==\"\" + 0 新事件 + 旧 key 永久 401")
}

// ---------------------------------------------------------------------------
// I. settings 更新无法复活 revoked（普通编辑不得触碰 lifecycle 真相）
// ---------------------------------------------------------------------------
func TestP105C_I_SettingsCannotResurrectRevoked(t *testing.T) {
	env := newP105Env(t)
	c, key := env.createTestClient(t, "p105c-i")
	if err := env.clientSvc.RevokeClient(c.ID, p105cActor, p105cReasonRevoke); err != nil {
		t.Fatal(err)
	}

	// 服务层：白名单外字段（is_active）被拒绝
	if err := env.clientSvc.UpdateClientSettings(c.ID, "test-admin", map[string]interface{}{"is_active": true}); !errors.Is(err, services.ErrInvalidSettingsField) {
		t.Fatalf("[I] settings 写入 is_active 应被拒绝（ErrInvalidSettingsField），实际 %v", err)
	}
	// 合法 settings 编辑允许（name 等），但不复活
	if err := env.clientSvc.UpdateClientSettings(c.ID, "test-admin", map[string]interface{}{"name": "p105c-i-renamed"}); err != nil {
		t.Fatal(err)
	}
	got, _ := env.clientSvc.GetClientByID(c.ID)
	if got.Name != "p105c-i-renamed" {
		t.Fatalf("[I] settings 编辑应生效，实际 %q", got.Name)
	}
	if got.RevokedAt == nil || got.IsActive || !env.hashIsNull(t, c.ID) || got.LifecycleState() != models.ClientStateRevoked {
		t.Fatalf("[I] settings 编辑不得复活 revoked：at=%v active=%v hashNull=%v state=%s",
			got.RevokedAt, got.IsActive, env.hashIsNull(t, c.ID), got.LifecycleState())
	}
	if env.doAuth(t, key).StatusCode != http.StatusUnauthorized {
		t.Fatal("[I] settings 编辑后 revoked key 仍必须 401")
	}

	// HTTP 层：/update 表单（不再含 is_active）→ 302 后状态不变
	token := p105AdminSessionOf(t, env)
	w := env.adminPost(t, token, "/admin/clients/"+c.ID+"/update",
		url.Values{"name": {"p105c-i-http"}, "backend": {"openai"}})
	if w.Result().StatusCode != http.StatusFound {
		t.Fatalf("[I] /update 应 302，实际 %d", w.Result().StatusCode)
	}
	got2, _ := env.clientSvc.GetClientByID(c.ID)
	if got2.RevokedAt == nil || got2.IsActive || !env.hashIsNull(t, c.ID) {
		t.Fatal("[I] HTTP settings 更新不得复活 revoked")
	}
	t.Log("[I PASS] settings 白名单：is_active 被拒；合法编辑生效但不触碰 lifecycle 真相")
}

// ---------------------------------------------------------------------------
// J. forged actor 表单字段完全忽略（actor 由服务端决定）
// ---------------------------------------------------------------------------
func TestP105C_J_ForgedActorIgnored(t *testing.T) {
	env := newP105Env(t)
	c, _ := env.createTestClient(t, "p105c-j")
	token := p105AdminSessionOf(t, env)

	w := env.adminPost(t, token, "/admin/clients/"+c.ID+"/revoke", url.Values{
		"reason":         {p105cReasonRevoke},
		"confirm_revoke": {"REVOKE"},
		"actor":          {"FORGED_ACTOR"},
		"revoked_by":     {"FORGED_REVOKED_BY"},
	})
	if w.Result().StatusCode != http.StatusFound {
		t.Fatalf("[J] revoke 应 302，实际 %d", w.Result().StatusCode)
	}
	got, _ := env.clientSvc.GetClientByID(c.ID)
	if got.RevokedBy != p105cActor {
		t.Fatalf("[J] RevokedBy 必须由服务端决定（%s），实际 %q", p105cActor, got.RevokedBy)
	}
	evs := env.auditEvents(t, c.ID)
	if len(evs) != 2 {
		t.Fatalf("[J] create + revoke 应有 2 条 audit event，实际 %+v", evs)
	}
	revokedEvent := evs[len(evs)-1]
	if revokedEvent.Action != "CLIENT_REVOKED" || revokedEvent.ActorID != p105cActor || revokedEvent.ActorType != "admin" {
		t.Fatalf("[J] audit ActorID 必须服务端取值，实际 %+v", evs)
	}
	t.Log("[J PASS] 表单 actor/revoked_by 被忽略；actor=服务端 admin identity")
}

// ---------------------------------------------------------------------------
// K. reason 缺失/过长/控制字符 → 400（错误响应不回显 reason 全文）
// ---------------------------------------------------------------------------
func TestP105C_K_ReasonPolicy_400(t *testing.T) {
	env := newP105Env(t)
	c, _ := env.createTestClient(t, "p105c-k")
	token := p105AdminSessionOf(t, env)

	longReason := strings.Repeat("r", 257)
	controlReason := "bad\nreason"
	rotForm := func(reason string) map[string][]string {
		m := map[string][]string{"key_type": {"openai"}}
		if reason != "" {
			m["reason"] = []string{reason}
		}
		return m
	}

	// rotate 缺 reason → 400
	w := env.adminPost(t, token, "/admin/clients/"+c.ID+"/regenerate", url.Values(rotForm("")))
	if w.Result().StatusCode != http.StatusBadRequest {
		t.Fatalf("[K] rotate 缺 reason 应 400，实际 %d", w.Result().StatusCode)
	}
	// 过长 → 400
	w = env.adminPost(t, token, "/admin/clients/"+c.ID+"/regenerate", url.Values(rotForm(longReason)))
	if w.Result().StatusCode != http.StatusBadRequest {
		t.Fatalf("[K] 过长 reason 应 400，实际 %d", w.Result().StatusCode)
	}
	// 控制字符 → 400
	w = env.adminPost(t, token, "/admin/clients/"+c.ID+"/regenerate", url.Values(rotForm(controlReason)))
	if w.Result().StatusCode != http.StatusBadRequest {
		t.Fatalf("[K] 控制字符 reason 应 400，实际 %d", w.Result().StatusCode)
	}
	// 错误响应不得回显 reason 全文
	body := w.Body.String()
	if strings.Contains(body, controlReason) || strings.Contains(body, longReason) {
		t.Fatalf("[K] 错误响应不得回显 reason，实际 %q", body)
	}
	// suspend 缺 reason → 400
	w = env.adminPost(t, token, "/admin/clients/"+c.ID+"/toggle", url.Values{"active": {"false"}})
	if w.Result().StatusCode != http.StatusBadRequest {
		t.Fatalf("[K] suspend 缺 reason 应 400，实际 %d", w.Result().StatusCode)
	}
	// delete 缺 reason → 400
	w = env.adminPost(t, token, "/admin/clients/"+c.ID+"/delete", url.Values{})
	if w.Result().StatusCode != http.StatusBadRequest {
		t.Fatalf("[K] delete 缺 reason 应 400，实际 %d", w.Result().StatusCode)
	}
	// revoke 缺准确确认 → 400（即使 reason 合法）
	w = env.adminPost(t, token, "/admin/clients/"+c.ID+"/revoke", url.Values{"reason": {p105cReasonRevoke}})
	if w.Result().StatusCode != http.StatusBadRequest {
		t.Fatalf("[K] revoke 缺 confirm_revoke=REVOKE 应 400，实际 %d", w.Result().StatusCode)
	}
	t.Log("[K PASS] reason 缺失/过长/控制字符 → 400；错误不回显 reason；revoke 需准确确认")
}

// ---------------------------------------------------------------------------
// L/M/N/O/P. 成功 action 恰 1 条 event；Delete 后 audit 保留
// ---------------------------------------------------------------------------
func TestP105C_L_M_N_O_P_EventsExactlyOnce(t *testing.T) {
	env := newP105Env(t)
	c, key := env.createTestClient(t, "p105c-lmop")

	// L: create 恰 1 条 CREATED
	if n := env.auditCount(t, c.ID, "CLIENT_CREATED"); n != 1 {
		t.Fatalf("[L] create 应恰 1 条 CLIENT_CREATED，实际 %d", n)
	}

	// M: rotate 恰 1 条 ROTATED
	newKey, err := env.clientSvc.RegenerateAPIKey(c.ID, "openai", "sk-", p105cActor, p105cReasonRotate)
	if err != nil {
		t.Fatal(err)
	}
	if env.auditCount(t, c.ID, "CLIENT_KEY_ROTATED") != 1 {
		t.Fatal("[M] rotate 应恰 1 条 CLIENT_KEY_ROTATED")
	}

	// N: suspend/resume → 两事件；RateLimiter 状态保留（不 reset）
	if err := env.db.Model(&models.Client{}).Where("id = ?", c.ID).Update("rate_limit_minute", 2).Error; err != nil {
		t.Fatal(err)
	}
	// 重新载入以新桶容量（bucket 首次创建时读 client 配置）
	key = newKey
	r1 := env.doAuth(t, key)
	if r1.StatusCode != http.StatusOK {
		t.Fatalf("[N] 消耗 1 应 200，实际 %d", r1.StatusCode)
	}
	if env.auditCount(t, c.ID, "CLIENT_SUSPENDED") != 0 {
		t.Fatal("[N] 前置状态错误：尚不应有 SUSPENDED 事件")
	}
	if err := env.clientSvc.SuspendClient(c.ID, p105cActor, "P105C suspend reason"); err != nil {
		t.Fatal(err)
	}
	if err := env.clientSvc.ResumeClient(c.ID, p105cActor, ""); err != nil {
		t.Fatal(err)
	}
	if env.auditCount(t, c.ID, "CLIENT_SUSPENDED") != 1 || env.auditCount(t, c.ID, "CLIENT_RESUMED") != 1 {
		t.Fatalf("[N] suspend/resume 应各恰 1 条：s=%d r=%d",
			env.auditCount(t, c.ID, "CLIENT_SUSPENDED"), env.auditCount(t, c.ID, "CLIENT_RESUMED"))
	}
	// 原 key 恢复；限流状态继承（剩余 1→消耗 →0；若 reset 过则剩 1）
	r2 := env.doAuth(t, key)
	if r2.StatusCode != http.StatusOK {
		t.Fatalf("[N] resume 后原 key 应 200，实际 %d", r2.StatusCode)
	}
	if got := r2.Header.Get("X-RateLimit-Remaining-Minute"); got != "0" {
		t.Fatalf("[N] suspend/resume 不得 reset 限流：remaining 应继承为 0，实际 %q", got)
	}

	// O: revoke → 1 条 REVOKED（bucket reset 布线由 StaticGate_ResetClientOnlyAfterCommit 证明）
	if err := env.clientSvc.RevokeClient(c.ID, p105cActor, p105cReasonRevoke); err != nil {
		t.Fatal(err)
	}
	if env.auditCount(t, c.ID, "CLIENT_REVOKED") != 1 {
		t.Fatal("[O] revoke 应恰 1 条 CLIENT_REVOKED")
	}

	// P: delete（reason 必填）→ CLIENT_DELETED 保留；三表清零
	if err := env.clientSvc.DeleteClient(c.ID, p105cActor, "P105C delete reason"); err != nil {
		t.Fatal(err)
	}
	if env.countAll(t, "clients") != 0 || env.countAll(t, "request_logs") != 0 || env.countAll(t, "daily_usages") != 0 {
		t.Fatal("[P] delete 后 clients/request_logs/daily_usages 应全 0")
	}
	evs := env.auditEvents(t, c.ID)
	if len(evs) != 6 {
		t.Fatalf("[P] 应有 6 条事件（C/R/S/RS/RV/D），实际 %d: %+v", len(evs), actionsOf(evs))
	}
	if evs[len(evs)-1].Action != "CLIENT_DELETED" {
		t.Fatalf("[P] 最后事件应为 CLIENT_DELETED，实际 %s", evs[len(evs)-1].Action)
	}
	// audit_events 与 clients 之间不得有 FK（client 删除后审计保留）
	rows, err := env.db.Raw("SELECT count(*) FROM pragma_foreign_key_list('audit_events')").Rows()
	if err != nil {
		t.Fatal(err)
	}
	var fkCount int
	for rows.Next() {
		_ = rows.Scan(&fkCount)
	}
	rows.Close()
	if fkCount != 0 {
		t.Fatalf("[P] audit_events 不得有 FK（禁止 cascade 删除），实际 %d", fkCount)
	}
	t.Log("[L/M/N/O/P PASS] 成功 action 恰 1 事件；SUSPEND/RESUME 不 reset 限流；DELETE 后审计保留、无 FK")
}

func actionsOf(evs []models.AuditEvent) []string {
	out := make([]string, len(evs))
	for i, e := range evs {
		out[i] = e.Action
	}
	return out
}

// ---------------------------------------------------------------------------
// Q–U. audit INSERT 失败 → 整个 lifecycle mutation rollback
// ---------------------------------------------------------------------------
func TestP105C_Q_AuditFail_CreateRollback(t *testing.T) {
	env := newP105Env(t)
	env.injectAuditFailure(t)

	before := env.countAll(t, "clients")
	c, key, err := env.clientSvc.CreateClient("p105c-q", "", "openai", "sk-", env.cfg, p105cActor)
	if err == nil {
		t.Fatalf("[Q] audit 失败 create 应 error，实际 key=%q client=%s", key, c.ID)
	}
	if env.countAll(t, "clients") != before {
		t.Fatalf("[Q] rollback 后 client 行应不变：before=%d after=%d", before, env.countAll(t, "clients"))
	}
	if key != "" || c != nil {
		t.Fatal("[Q] 失败路径不得返回 plaintext key / client")
	}
	var n int64
	_ = env.db.Raw("SELECT count(*) FROM audit_events").Scan(&n).Error
	if n != 0 {
		t.Fatalf("[Q] 失败路径 0 条 event，实际 %d", n)
	}
	t.Log("[Q PASS] audit 失败 → create 整体 rollback（无 client 行、无 key、0 event）")
}

func TestP105C_R_AuditFail_RotateRollback(t *testing.T) {
	env := newP105Env(t)
	c, key := env.createTestClient(t, "p105c-r")
	var beforeRow struct {
		APIKeyHash []byte `gorm:"column:api_key_hash"`
	}
	if err := env.db.Raw("SELECT api_key_hash FROM clients WHERE id = ?", c.ID).Scan(&beforeRow).Error; err != nil {
		t.Fatal(err)
	}
	env.injectAuditFailure(t)

	newKey, err := env.clientSvc.RegenerateAPIKey(c.ID, "openai", "sk-", p105cActor, p105cReasonRotate)
	if err == nil {
		t.Fatalf("[R] audit 失败 rotate 应 error，实际 newKey=%q", newKey)
	}
	if newKey != "" {
		t.Fatal("[R] 失败路径不得返回新 key")
	}
	var afterRow struct {
		APIKeyHash []byte `gorm:"column:api_key_hash"`
	}
	if err := env.db.Raw("SELECT api_key_hash FROM clients WHERE id = ?", c.ID).Scan(&afterRow).Error; err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(beforeRow.APIKeyHash, afterRow.APIKeyHash) {
		t.Fatal("[R] rollback 后旧 hash 必须原样（byte-for-byte）")
	}
	if resp := env.doAuth(t, key); resp.StatusCode != http.StatusOK {
		t.Fatalf("[R] 旧 key 应继续有效（200），实际 %d", resp.StatusCode)
	}
	t.Log("[R PASS] audit 失败 → rotate rollback（旧 hash 原样、old key 有效、new key 不返回）")
}

func TestP105C_S_AuditFail_SuspendRollback(t *testing.T) {
	env := newP105Env(t)
	c, key := env.createTestClient(t, "p105c-s")
	env.injectAuditFailure(t)

	if err := env.clientSvc.SuspendClient(c.ID, p105cActor, "P105C suspend reason"); err == nil {
		t.Fatal("[S] audit 失败 suspend 应 error")
	}
	if resp := env.doAuth(t, key); resp.StatusCode != http.StatusOK {
		t.Fatalf("[S] rollback 后仍应 ACTIVE（200），实际 %d", resp.StatusCode)
	}
	got, _ := env.clientSvc.GetClientByID(c.ID)
	if !got.IsActive {
		t.Fatal("[S] rollback 后 IsActive 应保持 true")
	}
	t.Log("[S PASS] audit 失败 → suspend rollback（仍 ACTIVE）")
}

func TestP105C_T_AuditFail_RevokeRollback(t *testing.T) {
	env := newP105Env(t)
	c, key := env.createTestClient(t, "p105c-t")
	env.injectAuditFailure(t)

	revokeErr := env.clientSvc.RevokeClient(c.ID, p105cActor, p105cReasonRevoke)
	if revokeErr == nil {
		t.Fatal("[T] audit 失败 revoke 应 error")
	}
	if env.hashIsNull(t, c.ID) {
		t.Fatal("[T] rollback 后 api_key_hash 应原样（非 NULL）")
	}
	got, _ := env.clientSvc.GetClientByID(c.ID)
	if got.RevokedAt != nil {
		t.Fatal("[T] rollback 后 RevokedAt 应保持 nil")
	}
	if resp := env.doAuth(t, key); resp.StatusCode != http.StatusOK {
		t.Fatalf("[T] rollback 后 key 应仍有效（200），实际 %d", resp.StatusCode)
	}
	t.Log("[T PASS] audit 失败 → revoke rollback（RevokedAt nil、hash 原样、key 有效）")
}

func TestP105C_U_AuditFail_DeleteRollback(t *testing.T) {
	env := newP105Env(t)
	c, _ := env.createTestClient(t, "p105c-u")
	if err := env.gemini.LogRequest(services.RequestRecord{
		RequestID: "p105c-u-1", ClientID: c.ID, Provider: "gemini",
		Model: "m", StatusCode: 200,
	}); err != nil {
		t.Fatal(err)
	}
	preClients, preLogs, preUsage := env.countAll(t, "clients"), env.countAll(t, "request_logs"), env.countAll(t, "daily_usages")
	env.injectAuditFailure(t)

	if err := env.clientSvc.DeleteClient(c.ID, p105cActor, "P105C delete reason"); err == nil {
		t.Fatal("[U] audit 失败 delete 应 error")
	}
	if env.countAll(t, "clients") != preClients || env.countAll(t, "request_logs") != preLogs || env.countAll(t, "daily_usages") != preUsage {
		t.Fatal("[U] rollback 后三表应原值保留")
	}
	t.Log("[U PASS] audit 失败 → delete rollback（client/logs/usage 全保留，动作未发生）")
}

// ---------------------------------------------------------------------------
// V. Rotate×Revoke race：最终 invariant——revoke 一旦提交则 hash 恒 NULL、状态 REVOKED
// ---------------------------------------------------------------------------
func TestP105C_V_RotateRevokeRace_Invariant(t *testing.T) {
	env := newP105Env(t)

	// 确定性 A：rotate 先提交 → revoke 随后 → rotate 返回的 key 随即永久失效
	cA, keyA := env.createTestClient(t, "p105c-va")
	rotatedA, err := env.clientSvc.RegenerateAPIKey(cA.ID, "openai", "sk-", p105cActor, p105cReasonRotate)
	if err != nil {
		t.Fatal(err)
	}
	if err := env.clientSvc.RevokeClient(cA.ID, p105cActor, p105cReasonRevoke); err != nil {
		t.Fatal(err)
	}
	if resp := env.doAuth(t, rotatedA); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("[V-A] revoke 后 rotate 返回过的 key 必须 401，实际 %d", resp.StatusCode)
	}
	if !env.hashIsNull(t, cA.ID) {
		t.Fatal("[V-A] revoke 提交后 hash 必须 NULL")
	}
	if resp := env.doAuth(t, keyA); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("[V-A] 原 key 必须 401，实际 %d", resp.StatusCode)
	}

	// 确定性 B：revoke 先提交 → rotate 返回 ErrClientRevoked + key==""
	cB, _ := env.createTestClient(t, "p105c-vb")
	if err := env.clientSvc.RevokeClient(cB.ID, p105cActor, p105cReasonRevoke); err != nil {
		t.Fatal(err)
	}
	rotatedB, err := env.clientSvc.RegenerateAPIKey(cB.ID, "openai", "sk-", p105cActor, p105cReasonRotate)
	if !errors.Is(err, services.ErrClientRevoked) || rotatedB != "" {
		t.Fatalf("[V-B] revoke 后 rotate 应 ErrClientRevoked+key==\"\"，实际 err=%v key=%q", err, rotatedB)
	}
	if !env.hashIsNull(t, cB.ID) {
		t.Fatal("[V-B] revoke 后 hash 必须 NULL（rotate 不得重写）")
	}

	// 并发：8 rotate × 1 revoke 同时竞争 → 终态恒为 REVOKED + hash NULL
	cC, _ := env.createTestClient(t, "p105c-vc")
	start := make(chan struct{})
	var wg sync.WaitGroup
	errs := make([]error, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			_, errs[i] = env.clientSvc.RegenerateAPIKey(cC.ID, "openai", "sk-", p105cActor, p105cReasonRotate)
		}(i)
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		<-start
		_ = env.clientSvc.RevokeClient(cC.ID, p105cActor, p105cReasonRevoke)
	}()
	close(start)
	wg.Wait()

	got, _ := env.clientSvc.GetClientByID(cC.ID)
	if got.RevokedAt == nil || got.IsActive || !env.hashIsNull(t, cC.ID) {
		t.Fatalf("[V-C] 并发终态必须是 REVOKED+NULL：at=%v active=%v", got.RevokedAt, got.IsActive)
	}
	// 任何 rotate 若在 revoke 前成功，其返回的 key 在 revoke 后同样 401（无法再验证个别 key——
	// 通过终态 NULL 保证任何 hash 都不存在）
	t.Log("[V PASS] rotate×revoke：A/B 两种合法竞态 + 并发终态恒 REVOKED+hash NULL（revoke 后无 key 可认证）")
}

// ---------------------------------------------------------------------------
// W. 审计事件 secret canary = 0（§20）
// ---------------------------------------------------------------------------
func TestP105C_W_AuditSecretCanaryZero(t *testing.T) {
	env := newP105Env(t)
	// client 网关 key 用 canary 注入（哈希落库）
	c := env.insertClientWithKey(t, "p105c-w", p105cClientKey, true)
	// provider secret canary：经真实 AES-GCM Manager 写入信封（明文不进库）
	if err := env.clientSvc.UpdateClientSettings(c.ID, "test-admin", map[string]interface{}{
		"backend_api_key_encrypted": p105cEncryptedProviderKey(t, c.ID, p105cProviderSec),
	}); err != nil {
		t.Fatal(err)
	}
	// 全生命周期
	key, err := env.clientSvc.RegenerateAPIKey(c.ID, "openai", "sk-", p105cActor, p105cReasonRotate)
	if err != nil {
		t.Fatal(err)
	}
	_ = key
	if err := env.clientSvc.SuspendClient(c.ID, p105cActor, "P105C suspend reason"); err != nil {
		t.Fatal(err)
	}
	if err := env.clientSvc.ResumeClient(c.ID, p105cActor, ""); err != nil {
		t.Fatal(err)
	}
	if err := env.clientSvc.RevokeClient(c.ID, p105cActor, p105cReasonRevoke); err != nil {
		t.Fatal(err)
	}
	if err := env.clientSvc.DeleteClient(c.ID, p105cActor, "P105C delete reason"); err != nil {
		t.Fatal(err)
	}

	// logical：audit_events 全列拼接不得含任何 secret 材料
	var evs []models.AuditEvent
	if err := env.db.Order("id ASC").Find(&evs).Error; err != nil {
		t.Fatal(err)
	}
	if len(evs) != 6 {
		t.Fatalf("[W] direct-insert client 的管理/生命周期应有 6 条事件，实际 %d", len(evs))
	}
	wantActions := []string{"CLIENT_PROVIDER_SECRET_CHANGED", "CLIENT_KEY_ROTATED", "CLIENT_SUSPENDED", "CLIENT_RESUMED", "CLIENT_REVOKED", "CLIENT_DELETED"}
	if gotActions := actionsOf(evs); strings.Join(gotActions, "|") != strings.Join(wantActions, "|") {
		t.Fatalf("[W] 生命周期事件顺序不符，实际 %v", gotActions)
	}
	var joined strings.Builder
	for _, e := range evs {
		joined.WriteString(e.EventID + "|" + e.Action + "|" + e.ActorType + "|" + e.ActorID + "|" + e.TargetType + "|" + e.TargetID + "|" + e.Reason + "|")
	}
	joinedS := joined.String()
	for _, banned := range []string{p105cClientKey, p105cProviderSec, "api_key_hash", "Authorization", "sk-"} {
		if strings.Contains(joinedS, banned) {
			t.Fatalf("[W] audit_events 含 banned 材料 %q", banned)
		}
	}

	// raw：DB 文件字节级也不得含 canary 明文（client 行已删除；审计行无 secret）
	sqlDB, err := env.db.DB()
	if err != nil {
		t.Fatal(err)
	}
	dbPath := env.dbPath
	_ = sqlDB
	raw, err := os.ReadFile(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte(p105cClientKey)) || bytes.Contains(raw, []byte(p105cProviderSec)) {
		t.Fatal("[W] DB 文件 raw 含 canary 明文")
	}
	t.Log("[W PASS] 全生命周期后 audit_events 逻辑与 DB raw 均 0 命中 canary/secret 材料")
}

// ---------------------------------------------------------------------------
// §19. Migration additive：P1-05B schema → AutoMigrate P1-05C 无破坏
// ---------------------------------------------------------------------------
func TestP105C_Migration_AdditiveFromP105BSchema(t *testing.T) {
	dir := t.TempDir()
	dbPath := dir + "/legacy.db"
	db, err := database.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatal(err)
	}
	// 构造 P1-05B 时点 schema（无 revoked 三列、无 audit_events）
	legacyDDL := []string{
		`CREATE TABLE clients (
			id varchar(36) PRIMARY KEY,
			name varchar(255) NOT NULL,
			description text,
			api_key_hash blob,
			is_active numeric DEFAULT true,
			key_prefix varchar(20),
			backend varchar(50) DEFAULT 'gemini',
			backend_api_key varchar(500),
			backend_api_key_encrypted text,
			backend_base_url varchar(500),
			backend_default_model varchar(200),
			backend_models text,
			fallback_models varchar(500),
			system_prompt text,
			tool_mode varchar(20) DEFAULT 'pass-through',
			server_tools numeric DEFAULT false,
			rate_limit_minute integer DEFAULT 60,
			rate_limit_hour integer DEFAULT 1000,
			rate_limit_day integer DEFAULT 10000,
			quota_input_tokens_day integer DEFAULT 1000000,
			quota_output_tokens_day integer DEFAULT 500000,
			quota_requests_day integer DEFAULT 1000,
			max_input_tokens integer DEFAULT 1000000,
			max_output_tokens integer DEFAULT 8192,
			last_seen datetime,
			created_at datetime,
			updated_at datetime
		)`,
		`CREATE TABLE request_logs (id integer PRIMARY KEY AUTOINCREMENT)`,
		`CREATE TABLE daily_usages (id integer PRIMARY KEY AUTOINCREMENT)`,
	}
	for _, ddl := range legacyDDL {
		// Match the compact DDL emitted by GORM. Its SQLite table-rebuild parser
		// treats indentation as part of a column name in hand-written multiline DDL.
		ddl = strings.Join(strings.Fields(ddl), " ")
		if _, err := sqlDB.Exec(ddl); err != nil {
			t.Fatal(err)
		}
	}
	// 插入旧 client 行（APIKeyHash 任意字节）
	hash := []byte("P105C-LEGACY-HASH-BYTES-0123456789abcdef")
	now := time.Now().UTC().Format("2006-01-02 15:04:05")
	if _, err := sqlDB.Exec(
		"INSERT INTO clients (id, name, api_key_hash, is_active, created_at, updated_at) VALUES (?, ?, ?, 1, ?, ?)",
		"legacy-client-1", "legacy", hash, now, now); err != nil {
		t.Fatal(err)
	}

	// Generic migration owns business tables; dedicated audit migration owns audit_events.
	if err := db.AutoMigrate(&models.Client{}, &models.RequestLog{}, &models.DailyUsage{}); err != nil {
		t.Fatalf("[Migration] P1-05C AutoMigrate 失败（禁止 destructive migration）: %v", err)
	}
	migrateHandlerAudit(t, db)

	// 旧行仍存在；hash byte-for-byte；RevokedAt == nil
	var got models.Client
	if err := db.First(&got, "id = ?", "legacy-client-1").Error; err != nil {
		t.Fatalf("[Migration] 旧 client 行丢失: %v", err)
	}
	if !bytes.Equal(got.APIKeyHash, hash) {
		t.Fatalf("[Migration] APIKeyHash 必须 byte-for-byte unchanged，实际 %x", got.APIKeyHash)
	}
	if got.RevokedAt != nil || got.RevokedBy != "" || got.RevocationReason != "" {
		t.Fatal("[Migration] 旧行 Revoked* 应保持零值")
	}
	// audit_events 表存在
	var n int64
	if err := db.Raw("SELECT count(*) FROM audit_events").Scan(&n).Error; err != nil {
		t.Fatalf("[Migration] audit_events 表应存在: %v", err)
	}
	sqlDB.Close()
	t.Log("[Migration PASS] P1-05B schema → P1-05C AutoMigrate：additive 无破坏（行保留/hash 原样/Revoked nil/audit 表存在）")
}
