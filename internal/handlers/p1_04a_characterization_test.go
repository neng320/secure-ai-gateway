package handlers

// P1-04A · Request Logging Characterization Tests（SEC-003）
//
// 固化 tag secure-gateway-development-workflow-gate（develop 2a4a363）时点的
// Prompt/Request 正文数据流真实行为。生产行为 0 修改。
//
// 标记约定：
//   [CURRENT]                 —— 当时行为，P1-04B 后按设计决定保留或调整
//   [KNOWN-VULN: SEC-003]     —— 正文/错误文本暴露事实，P1-04B 必须翻红并改写
//
// Canary 约束：仅使用明显的测试标记串，绝不使用疑似真实 prompt/凭证的字符串。

import (
	"bytes"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"ai-gateway/internal/auth"
	"ai-gateway/internal/config"
	"ai-gateway/internal/models"
	"ai-gateway/internal/providers"
	"ai-gateway/internal/services"

	mw "ai-gateway/internal/middleware"
	"github.com/go-chi/chi/v5"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

const (
	p104CanaryPrompt       = "P104_CANARY_PROMPT_DO_NOT_PERSIST"
	p104CanaryUpstreamErr  = "P104_CANARY_UPSTREAM_ERROR_DO_NOT_LOG"
	p104CanaryErrInDBField = "P104_CANARY_DB_ERRORTEXT_RENDER_CHECK"
)

// p104Env: 正文数据流测试环境（proxy + openai + admin 三路由同构 buildAPIRouter/buildAdminRouter）
type p104Env struct {
	db            *gorm.DB
	cfg           *config.Config
	clientService *services.ClientService
	api           http.Handler
	admin         http.Handler
	upstreamURL   string

	mu       sync.Mutex
	behavior http.HandlerFunc
}

func newP104Env(t *testing.T, initial http.HandlerFunc) *p104Env {
	t.Helper()
	var auths []string
	_ = auths

	env := &p104Env{behavior: initial}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		env.mu.Lock()
		h := env.behavior
		env.mu.Unlock()
		if h != nil {
			h(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"choices": []map[string]interface{}{{"message": map[string]string{"role": "assistant", "content": "pong"}}},
			"usage":   map[string]int{"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
		})
	}))
	t.Cleanup(upstream.Close)
	env.upstreamURL = upstream.URL

	db, err := gorm.Open(sqlite.Open(filepath.Join(t.TempDir(), "p104.db")), &gorm.Config{})
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
	env.db = db

	cfg := &config.Config{
		Server: config.ServerConfig{Host: "127.0.0.1", Port: 8090},
		Admin:  config.AdminConfig{Username: "admin", SessionSecret: "p104-secret", CookieSecure: false},
		Providers: map[string]config.ProviderConfig{
			"openai": {Type: "openai", BaseURL: upstream.URL + "/v1"},
			"gemini": {Type: "gemini", BaseURL: upstream.URL},
		},
	}
	cfg.Admin.PasswordHash = testPasswordHash
	env.cfg = cfg

	clientService := services.NewClientService(db)
	geminiService := services.NewGeminiService(db, cfg)
	statsService := services.NewStatsService(db)
	registry := providers.BuildRegistry(cfg)
	toolService := services.NewToolService(nil)

	// Public API（与 buildAPIRouter 同构：proxy + openai，含 client 认证）
	proxyHandler := NewProxyHandler(geminiService, statsService)
	openaiHandler := NewOpenAIHandler(geminiService, clientService, statsService, registry, toolService, nil)
	apiMux := chi.NewRouter()
	apiMux.Use(mw.NewAuthMiddleware(clientService).Handler)
	proxyHandler.RegisterRoutes(apiMux)
	openaiHandler.RegisterRoutes(apiMux)
	env.api = apiMux
	env.clientService = clientService

	// Admin（与 buildAdminRouter 同构）
	store := auth.NewSQLiteStore(db)
	limiter := auth.NewLoginRateLimiter()
	limiter.Configure(5, 15*time.Minute, cfg.Admin.Username)
	adminHandler, err := NewAdminHandler(cfg, clientService, statsService, geminiService, services.NewDashboardHub(statsService), toolService, store, limiter, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	adminMux := chi.NewRouter()
	adminHandler.RegisterRoutes(adminMux)
	env.admin = adminMux

	return env
}

func (e *p104Env) setBehavior(h http.HandlerFunc) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.behavior = h
}

// newP104Client: 建网关 client 并返回网关 API key
func (e *p104Env) newP104Client(t *testing.T, name, backend, baseURLOverride string) (string, string) {
	t.Helper()
	client, gwKey, err := e.clientService.CreateClient(name, "", "openai", "sk-", e.cfg)
	if err != nil {
		t.Fatal(err)
	}
	if backend != "" {
		client.Backend = backend
	}
	if baseURLOverride != "" {
		client.BackendBaseURL = baseURLOverride
	}
	if err := e.clientService.UpdateClient(client); err != nil {
		t.Fatal(err)
	}
	return client.ID, gwKey
}

func (e *p104Env) latestRequestBody(t *testing.T) string {
	t.Helper()
	var row struct {
		RequestBody string
	}
	if err := e.db.Raw("SELECT request_body FROM request_logs ORDER BY id DESC LIMIT 1").Scan(&row).Error; err != nil {
		t.Fatal(err)
	}
	return row.RequestBody
}

func (e *p104Env) requestLogCount(t *testing.T) int64 {
	t.Helper()
	var n int64
	if err := e.db.Raw("SELECT count(*) FROM request_logs").Scan(&n).Error; err != nil {
		t.Fatal(err)
	}
	return n
}

// ---------------------------------------------------------------------------
// 1) [KNOWN-VULN: SEC-003] OpenAI non-stream：完整 inbound JSON 持久化
// ---------------------------------------------------------------------------
func TestP104A_OpenAI_NonStream_PersistsFullBody(t *testing.T) {
	env := newP104Env(t, nil)
	_, gwKey := env.newP104Client(t, "kf-nons", "openai", env.upstreamURL+"/v1")

	body := `{"model":"test-model","messages":[{"role":"user","content":"` + p104CanaryPrompt + `"}]}`
	req := httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+gwKey)
	w := httptest.NewRecorder()
	env.api.ServeHTTP(w, req)
	if w.Result().StatusCode != http.StatusOK {
		t.Fatalf("chat 期望 200，实际 %d body=%s", w.Result().StatusCode, w.Body.String())
	}

	if got := env.latestRequestBody(t); !strings.Contains(got, p104CanaryPrompt) {
		t.Fatalf("[CURRENT BEHAVIOR CHANGED] request_body 不再含完整 prompt——若 metadata-only 已落地，请改写为安全断言；实际 %q", got)
	}
	t.Log("[KNOWN-VULN: SEC-003] 确认：OpenAI 非流式完整 inbound JSON 持久化到 SQLite request_body")
}

// ---------------------------------------------------------------------------
// 2) [KNOWN-VULN: SEC-003] OpenAI stream：完整 inbound JSON 持久化
// ---------------------------------------------------------------------------
func TestP104A_OpenAI_Stream_PersistsFullBody(t *testing.T) {
	env := newP104Env(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte("data: {\"choices\":[{\"delta\":{\"content\":\"hi\"}}]}\n\ndata: [DONE]\n\n"))
	})
	_, gwKey := env.newP104Client(t, "kf-str", "openai", env.upstreamURL+"/v1")

	body := `{"model":"test-model","stream":true,"messages":[{"role":"user","content":"` + p104CanaryPrompt + `"}]}`
	req := httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+gwKey)
	w := httptest.NewRecorder()
	env.api.ServeHTTP(w, req)
	if w.Result().StatusCode != http.StatusOK {
		t.Fatalf("stream chat 期望 200，实际 %d", w.Result().StatusCode)
	}

	if got := env.latestRequestBody(t); !strings.Contains(got, p104CanaryPrompt) {
		t.Fatalf("[CURRENT BEHAVIOR CHANGED] stream request_body 不再含 prompt；实际 %q", got)
	}
	t.Log("[KNOWN-VULN: SEC-003] 确认：OpenAI 流式完整 inbound JSON 持久化")
}

// ---------------------------------------------------------------------------
//  3. [KNOWN-VULN: SEC-003] Gemini native non-stream：正文持久化
//     并精确固化：记录的是 capOutputTokens 之后的 body（非原始 body）
//
// ---------------------------------------------------------------------------
func TestP104A_Gemini_Native_PersistsCappedBody(t *testing.T) {
	env := newP104Env(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"candidates":[],"usageMetadata":{"promptTokenCount":1,"candidatesTokenCount":1}}`))
	})
	clientID, gwKey := env.newP104Client(t, "kf-gem", "", "") // gemini 默认 backend
	// 触发 capOutputTokens：client.MaxOutputTokens=100 < 请求的 5000
	client, _ := env.clientService.GetClientByID(clientID)
	client.MaxOutputTokens = 100
	if err := env.clientService.UpdateClient(client); err != nil {
		t.Fatal(err)
	}

	body := `{"contents":[{"parts":[{"text":"` + p104CanaryPrompt + `"}]}],"generationConfig":{"maxOutputTokens":5000}}`
	req := httptest.NewRequest("POST", "/v1/models/test-model:generateContent", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+gwKey)
	w := httptest.NewRecorder()
	env.api.ServeHTTP(w, req)
	if w.Result().StatusCode != http.StatusOK {
		t.Fatalf("gemini proxy 期望 200，实际 %d body=%s", w.Result().StatusCode, w.Body.String())
	}

	got := env.latestRequestBody(t)
	if !strings.Contains(got, p104CanaryPrompt) {
		t.Fatalf("[CURRENT BEHAVIOR CHANGED] gemini request_body 不再含 prompt；实际 %q", got)
	}
	if !strings.Contains(got, `"maxOutputTokens":100`) {
		t.Fatalf("[固化失败] 应持久化 cap 后的 body（maxOutputTokens=100），实际 %q", got)
	}
	if strings.Contains(got, `"maxOutputTokens":5000`) {
		t.Fatal("[固化失败] 不应持久化原始未 cap 的 body")
	}
	t.Log("[KNOWN-VULN: SEC-003] 确认：Gemini native 持久化的是 capOutputTokens 之后的 body（含完整 prompt）")
}

// ---------------------------------------------------------------------------
// 4) [CURRENT] Gemini StreamGenerateContent：当前【没有】RequestLog 行（元数据缺口）
//
//	证据分两层：
//	  a) proxy.StreamGenerateContent 处理器中不存在任何 LogRequest 调用（代码事实，见审计文档）
//	  b) services.ForwardStreamRequest（BaseURL 可注入）完成流式转发后同样不产生 RequestLog
//	本测试以 (b) 驱动——proxy 的 GetBaseURL() 硬编码 googleapis（C3 已知遗留），
//	为遵守"禁止出外网"纪律不能对其 e2e。
//
// ---------------------------------------------------------------------------
func TestP104A_Gemini_Stream_NoRequestLogAtAll(t *testing.T) {
	env := newP104Env(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("data: {\"candidates\":[{\"content\":{\"parts\":[{\"text\":\"x\"}]}}]}\n\n"))
	})
	geminiService := services.NewGeminiService(env.db, env.cfg)

	streamBody := []byte(`{"contents":[{"parts":[{"text":"` + p104CanaryPrompt + `"}]}]}`)
	resp, _, err := geminiService.ForwardStreamRequest("test-model", streamBody)
	if err != nil {
		t.Fatalf("ForwardStreamRequest 失败: %v", err)
	}
	_, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("gemini stream 期望 200，实际 %d", resp.StatusCode)
	}

	if n := env.requestLogCount(t); n != 0 {
		t.Fatalf("[CURRENT BEHAVIOR CHANGED] Gemini stream 开始产生 RequestLog（%d 行）——P1-04B 若为其补 metadata-only 记录，请更新本固化", n)
	}
	t.Log("[CURRENT] 确认：Gemini StreamGenerateContent 当前完全无 RequestLog（元数据缺口，B 阶段将以 metadata-only 补齐）")
}

// ---------------------------------------------------------------------------
// 5) [KNOWN-VULN: SEC-003] RequestLog JSON 序列化：正文/错误文本可序列化
// ---------------------------------------------------------------------------
func TestP104A_RequestLog_JSON_SerializesBodyAndError(t *testing.T) {
	b, _ := json.Marshal(models.RequestLog{
		RequestBody:  p104CanaryPrompt,
		ErrorMessage: p104CanaryUpstreamErr,
	})
	out := string(b)
	if !strings.Contains(out, p104CanaryPrompt) || !strings.Contains(out, p104CanaryUpstreamErr) {
		t.Fatalf("[CURRENT BEHAVIOR CHANGED] RequestLog JSON 不再输出正文/错误——若 json:\"-\" 已落地请改写")
	}
	if !strings.Contains(out, "request_body") || !strings.Contains(out, "error_message") {
		t.Fatalf("[固化失败] 应含 request_body/error_message 键名，实际 %s", out)
	}
	t.Log("[KNOWN-VULN: SEC-003] 确认：RequestLog JSON 序列化输出 request_body/error_message")
}

// ---------------------------------------------------------------------------
// 6) [KNOWN-VULN: SEC-003] Dashboard server-render：完整正文进 HTML/JS
// ---------------------------------------------------------------------------
func TestP104A_DashboardHTML_RendersFullBody(t *testing.T) {
	env := newP104Env(t, nil)
	clientID, _ := env.newP104Client(t, "kf-dash", "openai", env.upstreamURL+"/v1")
	if err := env.db.Create(&models.RequestLog{
		ClientID:    clientID,
		Model:       "test-model",
		StatusCode:  200,
		RequestBody: p104CanaryPrompt,
	}).Error; err != nil {
		t.Fatal(err)
	}

	token := p104AdminSession(t, env)
	req := httptest.NewRequest("GET", "/admin/dashboard", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: token})
	w := httptest.NewRecorder()
	env.admin.ServeHTTP(w, req)
	if w.Result().StatusCode != http.StatusOK {
		t.Fatalf("dashboard 期望 200，实际 %d", w.Result().StatusCode)
	}
	body := w.Body.String()
	if !strings.Contains(body, p104CanaryPrompt) {
		t.Fatal("[CURRENT BEHAVIOR CHANGED] Dashboard HTML 不再包含正文——若已移除请改写")
	}
	if !strings.Contains(body, "showRequestBody(") {
		t.Fatal("[固化失败] 应存在 showRequestBody 正文 modal 注入点")
	}
	t.Log("[KNOWN-VULN: SEC-003] 确认：Dashboard 将完整 RequestBody 渲染进 HTML/JS（showRequestBody modal）")
}

// ---------------------------------------------------------------------------
// 7) [KNOWN-VULN: SEC-003] Client Detail：legacy ErrorMessage 原样渲染进 HTML
// ---------------------------------------------------------------------------
func TestP104A_ClientDetail_RendersRawErrorMessage(t *testing.T) {
	env := newP104Env(t, nil)
	clientID, _ := env.newP104Client(t, "kf-detail", "openai", env.upstreamURL+"/v1")
	if err := env.db.Create(&models.RequestLog{
		ClientID:     clientID,
		Model:        "test-model",
		StatusCode:   502,
		ErrorMessage: p104CanaryErrInDBField,
	}).Error; err != nil {
		t.Fatal(err)
	}

	token := p104AdminSession(t, env)
	req := httptest.NewRequest("GET", "/admin/clients/"+clientID, nil)
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: token})
	w := httptest.NewRecorder()
	env.admin.ServeHTTP(w, req)
	if w.Result().StatusCode != http.StatusOK {
		t.Fatalf("client detail 期望 200，实际 %d", w.Result().StatusCode)
	}
	if body := w.Body.String(); !strings.Contains(body, p104CanaryErrInDBField) {
		t.Fatal("[CURRENT BEHAVIOR CHANGED] Client Detail 不再渲染 ErrorMessage——若已改为 ErrorCode 请改写")
	}
	t.Log("[KNOWN-VULN: SEC-003] 确认：Client Detail 将 DB ErrorMessage 原样渲染进 HTML")
}

// ---------------------------------------------------------------------------
// 8) [KNOWN-VULN: SEC-003] runtime log：不可信 upstream error body 原样进 stderr
// ---------------------------------------------------------------------------
func TestP104A_RuntimeLog_UpstreamErrorEchoed(t *testing.T) {
	env := newP104Env(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte(`{"error":{"message":"` + p104CanaryUpstreamErr + `"}}`))
	})
	_, gwKey := env.newP104Client(t, "kf-fb", "openai", env.upstreamURL+"/v1")
	client, err := env.clientService.GetClientByAPIKey(gwKey)
	if err != nil || client == nil {
		t.Fatal("client 不存在")
	}
	client.FallbackModels = "fallback-x"
	if err := env.clientService.UpdateClient(client); err != nil {
		t.Fatal(err)
	}

	var logBuf bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&logBuf)
	defer log.SetOutput(prev)

	body := `{"model":"test-model","messages":[{"role":"user","content":"ping"}]}`
	req := httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+gwKey)
	w := httptest.NewRecorder()
	env.api.ServeHTTP(w, req)
	_, _ = io.ReadAll(w.Body)

	if !strings.Contains(logBuf.String(), p104CanaryUpstreamErr) {
		t.Fatalf("[CURRENT BEHAVIOR CHANGED] runtime log 不再回显 upstream error body——若已改为 ErrorCode 请改写；log=%q", logBuf.String())
	}
	// 同时固化：openai 错误路径当前【不】持久化 error_message（DB ErrorMessage 无该 canary）
	var n int64
	_ = env.db.Raw("SELECT count(*) FROM request_logs WHERE error_message LIKE ?", "%"+p104CanaryUpstreamErr+"%").Scan(&n).Error
	if n != 0 {
		t.Fatal("[固化失败] openai 错误路径不应持久化 error_message")
	}
	t.Log("[KNOWN-VULN: SEC-003] 确认：fallback runtime log 回显不可信 upstream error body；DB error_message 在 openai 错误路径为空（仅 Gemini proxy 传输错误路径写 ErrorMessage）")
}

// ---------------------------------------------------------------------------
// 辅助
// ---------------------------------------------------------------------------
func p104AdminSession(t *testing.T, env *p104Env) string {
	t.Helper()
	resp := login(t, env.admin, env.cfg.Admin.Username, testAdminPassword)
	c := getSessionCookie(resp)
	if c == nil {
		t.Fatal("admin login did not set session cookie")
	}
	return c.Value
}
