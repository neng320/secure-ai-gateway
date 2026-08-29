package handlers

// P1-03C3 · Migration Simulation Security Gate（Admin UI 部分）
//
// 覆盖任务卡矩阵第 3/5 项中属于 Admin 创建流的部分：
//   - 有 Manager：表单明文即刻加密入库（legacy 空、信封可解密、响应不回显）
//   - 无 Manager + 非空 key：fail-closed（非 2xx、不留半创建 client、库内无明文）
//   - 无 Manager + 空 key：合法成功（Ollama/LM Studio 场景，无 key 需求）
//
// 更新语义矩阵（blank 保留/替换/显式清除）与 HTML 遮罩回归见
// p1_03a_key_flow_test.go 的 TestP103A_Fixed_UpdateClient_KeySemantics /
// TestP103A_ClientKey_ReDisplayedInEditFormHTML。
//
// Canary 约束：仅使用明显的测试标记串；禁止真实 API Key。

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"ai-gateway/internal/auth"
	"ai-gateway/internal/models"
	"ai-gateway/internal/secrets"

	"gorm.io/gorm"
)

const uiGateCanary = "P103C3GATE_CANARY_ADMIN_CREATE_SECRET"

func adminPostForm(t *testing.T, env *keyFlowEnv, token, path string, form url.Values) *http.Response {
	t.Helper()
	req := httptest.NewRequest("POST", path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: token})
	req.Header.Set("X-CSRF-Token", auth.CSRFToken(env.cfg.Admin.SessionSecret, token))
	w := httptest.NewRecorder()
	env.admin.ServeHTTP(w, req)
	return w.Result()
}

func countPlaintextAndEnvelopes(t *testing.T, db *gorm.DB) (legacy int64, encrypted int64) {
	t.Helper()
	if err := db.Raw("SELECT count(*) FROM clients WHERE backend_api_key != ''").Scan(&legacy).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Raw("SELECT count(*) FROM clients WHERE backend_api_key_encrypted != ''").Scan(&encrypted).Error; err != nil {
		t.Fatal(err)
	}
	return legacy, encrypted
}

// 有 Manager：Admin 创建流中表单明文即刻转为信封
func TestMigrationGate_AdminCreateClient_KeyEncrypted(t *testing.T) {
	env := newKeyFlowEnv(t, "")
	token := adminSessionToken(t, env)

	form := url.Values{
		"name":             {"ui-gate-client"},
		"backend":          {"openai"},
		"backend_api_key":  {uiGateCanary},
		"backend_base_url": {env.upstreamURL + "/v1"},
	}
	resp := adminPostForm(t, env, token, "/admin/clients", form)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("创建应成功，实际 %d", resp.StatusCode)
	}
	body := readBody(resp)
	if strings.Contains(body, uiGateCanary) || strings.Contains(body, "enc:v1:") {
		t.Fatal("[安全回归失败] 创建成功页回显了 key 材料")
	}

	var row struct {
		ID        string
		Legacy    string
		Encrypted string
	}
	if err := env.db.Raw("SELECT id, backend_api_key AS legacy, backend_api_key_encrypted AS encrypted FROM clients WHERE name = ?", "ui-gate-client").Scan(&row).Error; err != nil {
		t.Fatal(err)
	}
	if row.ID == "" {
		t.Fatal("client 未创建")
	}
	if row.Legacy != "" {
		t.Fatalf("[安全回归失败] legacy 字段应保持空，实际 %q", row.Legacy)
	}
	if !secrets.IsEncryptedEnvelope(row.Encrypted) {
		t.Fatalf("[安全回归失败] encrypted 应为信封，实际 %q", row.Encrypted)
	}
	pt, err := env.manager.DecryptClientBackendKey(row.ID, row.Encrypted)
	if err != nil || string(pt) != uiGateCanary {
		t.Fatalf("[安全回归失败] 信封应解密为表单 key，实际 %q err=%v", string(pt), err)
	}
}

// 无 Manager + 非空 key：fail-closed，不留半创建 client，库内无明文
func TestMigrationGate_AdminCreateClient_NoMasterKey_FailClosed(t *testing.T) {
	env := newKeyFlowEnvWithManager(t, "", nil)
	token := adminSessionToken(t, env)

	form := url.Values{
		"name":            {"orphan-client"},
		"backend":         {"openai"},
		"backend_api_key": {uiGateCanary},
	}
	resp := adminPostForm(t, env, token, "/admin/clients", form)
	if resp.StatusCode < 400 {
		t.Fatalf("[安全回归失败] 无 Master Key 保存 provider key 应被拒绝，实际 %d", resp.StatusCode)
	}

	var n int64
	if err := env.db.Raw("SELECT count(*) FROM clients WHERE name = ?", "orphan-client").Scan(&n).Error; err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatal("[安全回归失败] 加密失败后留下了半创建 client")
	}
	legacy, encrypted := countPlaintextAndEnvelopes(t, env.db)
	if legacy != 0 || encrypted != 0 {
		t.Fatalf("[安全回归失败] 库内出现 key 材料: legacy=%d encrypted=%d", legacy, encrypted)
	}
}

// 无 Manager + 空 key：合法成功（无 per-client key 需求的 backend 场景）
func TestMigrationGate_AdminCreateClient_BlankKey_NoManager_OK(t *testing.T) {
	env := newKeyFlowEnvWithManager(t, "", nil)
	token := adminSessionToken(t, env)

	form := url.Values{
		"name":    {"keyless-client"},
		"backend": {"ollama"},
	}
	resp := adminPostForm(t, env, token, "/admin/clients", form)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("[安全回归失败] 空 key + 无 Master Key 创建应成功，实际 %d", resp.StatusCode)
	}
	var n int64
	if err := env.db.Raw("SELECT count(*) FROM clients WHERE name = ?", "keyless-client").Scan(&n).Error; err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatal("client 未创建")
	}
}

// resolveProvider fail-closed：legacy 明文 invariant 破坏 → 请求失败而非明文外发
// （生产中启动 preflight 已阻止该状态；此处直接构造 DB 状态验证运行期防线）
func TestMigrationGate_ResolveProvider_LegacyPlaintext_FailClosed(t *testing.T) {
	env := newKeyFlowEnv(t, "")
	client := env.createClientWithKey(t, "")
	if err := env.db.Model(&models.Client{}).Where("id = ?", client.ID).
		Update("backend_api_key", canaryClient).Error; err != nil {
		t.Fatal(err)
	}
	gwKey, err := env.clientService.RegenerateAPIKey(client.ID, "openai", "sk-")
	if err != nil {
		t.Fatal(err)
	}

	body := `{"model":"test-model","messages":[{"role":"user","content":"ping"}]}`
	req := httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+gwKey)
	w := httptest.NewRecorder()
	env.openai.ServeHTTP(w, req)

	if w.Code < 400 {
		t.Fatalf("[安全回归失败] legacy 明文 invariant 破坏未被拒绝，实际 %d body=%s", w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), canaryClient) {
		t.Fatal("[安全回归失败] 错误响应泄露明文 key")
	}
	for _, a := range *env.upstreamAuths {
		if strings.Contains(a, canaryClient) {
			t.Fatal("[安全回归失败] 明文 key 被发往上游")
		}
	}
}
