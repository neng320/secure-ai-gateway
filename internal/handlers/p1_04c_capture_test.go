package handlers

// P1-04C · 诊断捕获端到端 Gate（SEC-003）
//
// 覆盖：显式启用后 authenticated 请求正文可经 Admin 端点按需读取；
// 全程 SQLite/磁盘 raw scan canary=0（正文只在内存）；捕获的是原始 inbound payload
//（cap 之前）；未认证访问拒绝；no-store 头；默认 OFF 行为。
// Dashboard HTML 无正文 / WS 无正文 已由 P1-04B 回归覆盖。

import (
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"ai-gateway/internal/capture"
)

const p104CGetCanary = "P104C_CANARY_DIAGNOSTIC_BODY"

// capture 开启：authenticated 请求 → Admin 端点按需读取；捕获为原始 payload（cap 之前）；
// 持久层逻辑为空 + DB 落盘文件 raw scan canary=0（正文只在内存）
func TestP104C_CaptureEnabled_E2E_MemoryOnly(t *testing.T) {
	env := newP104Env(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"candidates":[],"usageMetadata":{"promptTokenCount":1,"candidatesTokenCount":1}}`))
	})
	// 注入 live store：重建 env
	env = newP104EnvWithStore(t, env.behavior, capture.NewStore(true, time.Now().Add(time.Hour), 64*1024, 100))
	clientID, gwKey := env.newP104Client(t, "kf-cap", "", "")
	client, err := env.clientService.GetClientByID(clientID)
	if err != nil || client == nil {
		t.Fatal("client 不存在")
	}
	client.MaxOutputTokens = 100 // 触发 cap，验证捕获的是原始 payload
	if err := env.clientService.UpdateClient(client); err != nil {
		t.Fatal(err)
	}

	body := `{"contents":[{"parts":[{"text":"` + p104CGetCanary + `"}]}],"generationConfig":{"maxOutputTokens":5000}}`
	req := httptest.NewRequest("POST", "/v1/models/test-model:generateContent", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+gwKey)
	w := httptest.NewRecorder()
	env.api.ServeHTTP(w, req)
	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("chat 期望 200，实际 %d", resp.StatusCode)
	}
	requestID := resp.Header.Get("X-Request-ID")

	// Admin 端点按需读取（GET 免 CSRF，仅 session）
	token := p104AdminSession(t, env)
	adminReq := httptest.NewRequest("GET", "/admin/request-bodies/"+requestID, nil)
	adminReq.AddCookie(&http.Cookie{Name: sessionCookieName, Value: token})
	w2 := httptest.NewRecorder()
	env.admin.ServeHTTP(w2, adminReq)
	resp2 := w2.Result()
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("[功能回归失败] Admin 读取端点期望 200，实际 %d", resp2.StatusCode)
	}
	if got := w2.Body.String(); !strings.Contains(got, p104CGetCanary) {
		t.Fatalf("[功能回归失败] 读取内容应含 canary，实际 %q", got)
	}
	if got := w2.Body.String(); !strings.Contains(got, `"maxOutputTokens":5000`) {
		t.Fatalf("[安全回归失败] 捕获应为原始 inbound payload（cap 之前），实际 %q", got)
	}
	if v := resp2.Header.Get("Cache-Control"); v != "no-store" {
		t.Fatalf("[安全回归失败] Cache-Control 应为 no-store，实际 %q", v)
	}
	if v := resp2.Header.Get("Pragma"); v != "no-cache" {
		t.Fatalf("[安全回归失败] Pragma 应为 no-cache，实际 %q", v)
	}

	// 持久层逻辑断言（关闭 DB 之前）
	row := env.latestLog(t)
	if row.RequestBody != "" {
		t.Fatalf("[安全回归失败] request_body 应恒空，实际 %q", row.RequestBody)
	}

	// 关闭 DB → 落盘文件 raw scan：canary 命中必须为 0
	sqlDB, err := env.db.DB()
	if err != nil {
		t.Fatal(err)
	}
	_ = sqlDB.Close()
	raw, err := os.ReadFile(env.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), p104CGetCanary) {
		t.Fatal("[安全回归失败] 捕获启用下 DB 落盘文件含 canary——正文泄漏到磁盘")
	}
	t.Log("[SEC-003 FIXED] 诊断捕获：按需可读、原始 payload、no-store；持久层逻辑+磁盘均无正文")
}

// capture 关闭（nil store）：端点 404；请求正常处理
func TestP104C_CaptureDisabled_EndpointUnavailable(t *testing.T) {
	env := newP104Env(t, nil) // nil store
	_, gwKey := env.newP104Client(t, "kf-nocap", "", "")

	body := `{"contents":[{"parts":[{"text":"ping"}]}]}`
	req := httptest.NewRequest("POST", "/v1/models/test-model:generateContent", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+gwKey)
	w := httptest.NewRecorder()
	env.api.ServeHTTP(w, req)
	if w.Result().StatusCode != http.StatusOK {
		t.Fatalf("默认 OFF 下请求应正常处理，实际 %d", w.Result().StatusCode)
	}
	requestID := w.Result().Header.Get("X-Request-ID")

	token := p104AdminSession(t, env)
	adminReq := httptest.NewRequest("GET", "/admin/request-bodies/"+requestID, nil)
	adminReq.AddCookie(&http.Cookie{Name: sessionCookieName, Value: token})
	w2 := httptest.NewRecorder()
	env.admin.ServeHTTP(w2, adminReq)
	if w2.Result().StatusCode != http.StatusNotFound {
		t.Fatalf("[安全回归失败] capture 关闭时端点应 404，实际 %d", w2.Result().StatusCode)
	}
}

// 未认证访问 Admin 读取端点 → 拒绝（RequireAuth 重定向登录）
func TestP104C_CaptureEndpoint_Unauthenticated_Rejected(t *testing.T) {
	env := newP104EnvWithStore(t, nil, capture.NewStore(true, time.Now().Add(time.Hour), 64*1024, 100))
	req := httptest.NewRequest("GET", "/admin/request-bodies/reqsome1234567890123456789012", nil)
	w := httptest.NewRecorder()
	env.admin.ServeHTTP(w, req)
	if code := w.Result().StatusCode; code != http.StatusFound && code != http.StatusUnauthorized {
		t.Fatalf("[安全回归失败] 未认证应被拒（302 登录跳转），实际 %d", code)
	}
}

// 到期后：store 自动清空 + 端点不可用
func TestP104C_CaptureExpired_EndpointUnavailable(t *testing.T) {
	env := newP104EnvWithStore(t, nil, capture.NewStore(true, time.Now().Add(80*time.Millisecond), 64*1024, 100))
	_, gwKey := env.newP104Client(t, "kf-exp", "", "")
	body := `{"contents":[{"parts":[{"text":"x"}]}]}`
	req := httptest.NewRequest("POST", "/v1/models/test-model:generateContent", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+gwKey)
	w := httptest.NewRecorder()
	env.api.ServeHTTP(w, req)
	requestID := w.Result().Header.Get("X-Request-ID")

	time.Sleep(250 * time.Millisecond) // 到期

	token := p104AdminSession(t, env)
	adminReq := httptest.NewRequest("GET", "/admin/request-bodies/"+requestID, nil)
	adminReq.AddCookie(&http.Cookie{Name: sessionCookieName, Value: token})
	w2 := httptest.NewRecorder()
	env.admin.ServeHTTP(w2, adminReq)
	if w2.Result().StatusCode != http.StatusNotFound {
		t.Fatalf("[安全回归失败] 到期后端点应 404，实际 %d", w2.Result().StatusCode)
	}
}

// raw scan：启用捕获后的 DB 文件字节不含 canary（正文只在内存）
func TestP104C_CaptureEnabled_DiskRawScan_ZeroCanary(t *testing.T) {
	canaryDB := "P104C_CANARY_DISK_SCAN_PROMPT"
	env := newP104EnvWithStore(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"candidates":[],"usageMetadata":{"promptTokenCount":1,"candidatesTokenCount":1}}`))
	}, capture.NewStore(true, time.Now().Add(time.Hour), 64*1024, 100))
	_, gwKey := env.newP104Client(t, "kf-scan", "", "")

	body := `{"contents":[{"parts":[{"text":"` + canaryDB + `"}]}]}`
	req := httptest.NewRequest("POST", "/v1/models/test-model:generateContent", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+gwKey)
	w := httptest.NewRecorder()
	env.api.ServeHTTP(w, req)
	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("请求应成功，实际 %d", resp.StatusCode)
	}
	requestID := resp.Header.Get("X-Request-ID")

	// 内存侧：store 可读
	entry, ok := env.capture.Get(requestID)
	if !ok {
		t.Fatal("捕获 store 应含该请求")
	}
	if !strings.Contains(string(entry.Body), canaryDB) {
		t.Fatalf("[功能回归失败] 捕获内容应含 canary，实际 %q", string(entry.Body))
	}

	// 关闭 DB 后 raw scan 落盘文件：canary 命中必须为 0
	sqlDB, err := env.db.DB()
	if err != nil {
		t.Fatal(err)
	}
	_ = sqlDB.Close()
	raw, err := os.ReadFile(env.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), canaryDB) {
		t.Fatal("[安全回归失败] 捕获启用下 DB 落盘文件含 canary——正文泄漏到磁盘")
	}
	t.Log("[SEC-003 FIXED] 捕获启用：内存可读，磁盘 raw scan = 0")
}
