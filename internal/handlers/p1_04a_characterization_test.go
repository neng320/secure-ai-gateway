package handlers

// P1-04A/B · Request Logging Privacy Tests（SEC-003）
//
// P1-04A 阶段：固化 KNOWN-VULN（正文全量持久化等 6 项）。
// P1-04B 阶段：全部发生红→绿转换，改写为 [SEC-003 FIXED] 安全回归（本文件现状）。
// 反转前的 KNOWN-VULN 原文见 git 历史（P1-04A commit）与
// docs/p1-04-request-log-characterization.md §6。
//
// Canary 约束：仅使用明显的测试标记串，绝不使用疑似真实 prompt/凭证的字符串。

import (
	"encoding/json"
	"log"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"ai-gateway/internal/auth"
	"ai-gateway/internal/capture"
	"ai-gateway/internal/config"
	mw "ai-gateway/internal/middleware"
	"ai-gateway/internal/models"
	"ai-gateway/internal/providers"
	"ai-gateway/internal/services"

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
	dbPath        string
	cfg           *config.Config
	capture       *capture.Store
	clientService *services.ClientService
	api           http.Handler
	admin         http.Handler
	upstreamURL   string

	mu       sync.Mutex
	behavior http.HandlerFunc
}

func newP104Env(t *testing.T, initial http.HandlerFunc) *p104Env {
	t.Helper()
	return newP104EnvWithStore(t, initial, nil)
}

// newP104EnvWithStore: 允许注入诊断捕获 store（P1-04C；nil = 捕获关闭）
func newP104EnvWithStore(t *testing.T, initial http.HandlerFunc, envCapture *capture.Store) *p104Env {
	t.Helper()
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

	dbPath := filepath.Join(t.TempDir(), "p104.db")
	db, err := gorm.Open(sqlite.Open(dbPath), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	env.dbPath = dbPath
	env.capture = envCapture
	if err := db.AutoMigrate(&models.Client{}, &models.RequestLog{}, &models.DailyUsage{}, &models.AdminSession{}); err != nil {
		t.Fatal(err)
	}
	migrateHandlerAudit(t, db)
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

	// Public API（与 buildAPIRouter 同构：RequestID + proxy + openai，含 client 认证）
	proxyHandler := NewProxyHandler(geminiService, statsService, envCapture)
	openaiHandler := NewOpenAIHandler(geminiService, clientService, statsService, registry, toolService, nil, envCapture)
	apiMux := chi.NewRouter()
	apiMux.Use(mw.RequestID())
	apiMux.Use(mw.NewAuthMiddleware(clientService).Handler)
	proxyHandler.RegisterRoutes(apiMux)
	openaiHandler.RegisterRoutes(apiMux)
	env.api = apiMux
	env.clientService = clientService

	// Admin（与 buildAdminRouter 同构）
	store := auth.NewSQLiteStore(db)
	limiter := auth.NewLoginRateLimiter()
	limiter.Configure(5, 15*time.Minute, cfg.Admin.Username)
	adminHandler, err := NewAdminHandler(cfg, clientService, statsService, geminiService, services.NewDashboardHub(statsService), toolService, store, limiter, nil, "", envCapture, mw.NewRateLimiter())
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

// newP104Client: 建网关 client 并返回 (clientID, 网关 API key)
func (e *p104Env) newP104Client(t *testing.T, name, backend, baseURLOverride string) (string, string) {
	t.Helper()
	client, gwKey, err := e.clientService.CreateClient(name, "", "openai", "sk-", e.cfg, "test-admin")
	if err != nil {
		t.Fatal(err)
	}
	updates := map[string]interface{}{}
	if backend != "" {
		updates["backend"] = backend
	}
	if baseURLOverride != "" {
		updates["backend_base_url"] = baseURLOverride
	}
	if err := e.clientService.UpdateClientSettings(client.ID, updates); err != nil {
		t.Fatal(err)
	}
	return client.ID, gwKey
}

// latestLog: 最近一条 RequestLog 行
func (e *p104Env) latestLog(t *testing.T) models.RequestLog {
	t.Helper()
	var row models.RequestLog
	if err := e.db.Raw("SELECT * FROM request_logs ORDER BY id DESC LIMIT 1").Scan(&row).Error; err != nil {
		t.Fatal(err)
	}
	return row
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
// 1) [SEC-003 FIXED]（反转自 KNOWN-VULN "OpenAI 非流式完整 body 持久化"）
// ---------------------------------------------------------------------------
func TestP104B_Fixed_OpenAI_NonStream_MetadataOnly(t *testing.T) {
	env := newP104Env(t, nil)
	_, gwKey := env.newP104Client(t, "kf-nons", "openai", env.upstreamURL+"/v1")

	body := `{"model":"test-model","messages":[{"role":"user","content":"` + p104CanaryPrompt + `"}]}`
	req := httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+gwKey)
	w := httptest.NewRecorder()
	env.api.ServeHTTP(w, req)
	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("chat 期望 200，实际 %d body=%s", resp.StatusCode, w.Body.String())
	}
	respHeaderID := resp.Header.Get("X-Request-ID")
	if len(respHeaderID) != 32 {
		t.Fatalf("[安全回归失败] X-Request-ID 应为 32 hex（128-bit），实际 %q", respHeaderID)
	}

	row := env.latestLog(t)
	if row.RequestBody != "" {
		t.Fatalf("[安全回归失败] request_body 应恒为空，实际 %q", row.RequestBody)
	}
	if row.ErrorMessage != "" {
		t.Fatalf("[安全回归失败] error_message 应恒为空，实际 %q", row.ErrorMessage)
	}
	if row.RequestID != respHeaderID {
		t.Fatalf("[安全回归失败] DB RequestID %q 应与响应头 %q 一致", row.RequestID, respHeaderID)
	}
	if row.Provider != "openai" {
		t.Fatalf("[安全回归失败] Provider 元数据缺失: %q", row.Provider)
	}
	if row.ErrorCode != "" {
		t.Fatalf("成功请求 ErrorCode 应为空，实际 %q", row.ErrorCode)
	}
	t.Log("[SEC-003 FIXED] OpenAI 非流式：metadata-only 持久化 + RequestID 全链一致")
}

// ---------------------------------------------------------------------------
// 2) [SEC-003 FIXED]（反转自 KNOWN-VULN "OpenAI 流式完整 body 持久化"）
// ---------------------------------------------------------------------------
func TestP104B_Fixed_OpenAI_Stream_MetadataOnly(t *testing.T) {
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
	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("stream chat 期望 200，实际 %d", resp.StatusCode)
	}
	respHeaderID := resp.Header.Get("X-Request-ID")

	row := env.latestLog(t)
	if row.RequestBody != "" || row.ErrorMessage != "" {
		t.Fatalf("[安全回归失败] 流式持久化应 metadata-only，实际 body=%q err=%q", row.RequestBody, row.ErrorMessage)
	}
	if !row.IsStreaming {
		t.Fatal("[安全回归失败] IsStreaming 元数据应为 true")
	}
	if row.RequestID != respHeaderID || row.RequestID == "" {
		t.Fatalf("[安全回归失败] RequestID 与响应头不一致: db=%q header=%q", row.RequestID, respHeaderID)
	}
	t.Log("[SEC-003 FIXED] OpenAI 流式：metadata-only 持久化")
}

// ---------------------------------------------------------------------------
// 3) [SEC-003 FIXED]（反转自 KNOWN-VULN "Gemini native 持久化 cap 后 body"）
// ---------------------------------------------------------------------------
func TestP104B_Fixed_Gemini_Native_MetadataOnly(t *testing.T) {
	env := newP104Env(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"candidates":[],"usageMetadata":{"promptTokenCount":1,"candidatesTokenCount":1}}`))
	})
	_, gwKey := env.newP104Client(t, "kf-gem", "", "")

	body := `{"contents":[{"parts":[{"text":"` + p104CanaryPrompt + `"}]}],"generationConfig":{"maxOutputTokens":5000}}`
	req := httptest.NewRequest("POST", "/v1/models/test-model:generateContent", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+gwKey)
	w := httptest.NewRecorder()
	env.api.ServeHTTP(w, req)
	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("gemini proxy 期望 200，实际 %d body=%s", resp.StatusCode, w.Body.String())
	}
	respHeaderID := resp.Header.Get("X-Request-ID")

	row := env.latestLog(t)
	if row.RequestBody != "" {
		t.Fatalf("[安全回归失败] request_body 应恒为空（cap 语义随正文一并消失），实际 %q", row.RequestBody)
	}
	if row.ErrorMessage != "" {
		t.Fatalf("[安全回归失败] error_message 应恒为空，实际 %q", row.ErrorMessage)
	}
	if row.Provider != "gemini" || row.RequestID != respHeaderID {
		t.Fatalf("[安全回归失败] 元数据不符: provider=%q requestID=%q header=%q", row.Provider, row.RequestID, respHeaderID)
	}
	t.Log("[SEC-003 FIXED] Gemini native：metadata-only 持久化")
}

// ---------------------------------------------------------------------------
//  4. [SEC-003 FIXED]（反转自 CURRENT "Gemini stream 完全无 RequestLog"）
//     元数据缺口补齐：流式路径产生 metadata-only 行；正文照旧不落盘。
//
// ---------------------------------------------------------------------------
func TestP104B_Fixed_Gemini_Stream_MetadataOnly(t *testing.T) {
	env := newP104Env(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("data: {\"candidates\":[{\"content\":{\"parts\":[{\"text\":\"x\"}]}}]}\n\n"))
	})
	_, gwKey := env.newP104Client(t, "kf-gems", "", "")

	body := `{"contents":[{"parts":[{"text":"` + p104CanaryPrompt + `"}]}]}`
	req := httptest.NewRequest("POST", "/v1/models/test-model:streamGenerateContent", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+gwKey)
	w := httptest.NewRecorder()
	env.api.ServeHTTP(w, req)
	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("gemini stream 期望 200，实际 %d", resp.StatusCode)
	}
	respHeaderID := resp.Header.Get("X-Request-ID")

	if n := env.requestLogCount(t); n != 1 {
		t.Fatalf("[安全回归失败] gemini stream 应产生 1 条 metadata-only 行，实际 %d", n)
	}
	row := env.latestLog(t)
	if row.RequestBody != "" || !row.IsStreaming || row.Provider != "gemini" {
		t.Fatalf("[安全回归失败] 流式元数据行不符: body=%q streaming=%v provider=%q", row.RequestBody, row.IsStreaming, row.Provider)
	}
	if row.RequestID != respHeaderID {
		t.Fatalf("[安全回归失败] RequestID 与响应头不一致: db=%q header=%q", row.RequestID, respHeaderID)
	}
	t.Log("[SEC-003 FIXED] Gemini 流式：元数据缺口补齐且无正文")
}

// ---------------------------------------------------------------------------
// 5) [SEC-003 FIXED]（反转自 KNOWN-VULN "RequestLog JSON 序列化正文/错误"）
// ---------------------------------------------------------------------------
func TestP104B_Fixed_RequestLog_JSON_OmitsBodyAndError(t *testing.T) {
	// 即便 legacy 列被人工填入（旧库读出），JSON 序列化也不得输出
	b, err := json.Marshal(models.RequestLog{
		RequestBody:  p104CanaryPrompt,
		ErrorMessage: p104CanaryUpstreamErr,
		RequestID:    "reqmeta1234567890123456789012345",
		Provider:     "gemini",
		ErrorCode:    services.ErrCodeUpstreamRate,
	})
	if err != nil {
		t.Fatal(err)
	}
	out := string(b)
	if strings.Contains(out, p104CanaryPrompt) || strings.Contains(out, p104CanaryUpstreamErr) {
		t.Fatal("[安全回归失败] RequestLog JSON 输出了正文/错误文本")
	}
	if strings.Contains(out, "request_body") || strings.Contains(out, "error_message") {
		t.Fatalf("[安全回归失败] JSON 键名 request_body/error_message 应消失，实际 %s", out)
	}
	for _, want := range []string{"request_id", "provider", "error_code"} {
		if !strings.Contains(out, want) {
			t.Fatalf("[安全回归失败] JSON 应含 %s，实际 %s", want, out)
		}
	}
	t.Log("[SEC-003 FIXED] RequestLog JSON：legacy 字段不可序列化，元数据键齐全")
}

// ---------------------------------------------------------------------------
// 6) [SEC-003 FIXED]（反转自 KNOWN-VULN "Dashboard 渲染全量正文"）
// ---------------------------------------------------------------------------
func TestP104B_Fixed_DashboardHTML_NoBody_ExposesMetadata(t *testing.T) {
	env := newP104Env(t, nil)
	clientID, _ := env.newP104Client(t, "kf-dash", "openai", env.upstreamURL+"/v1")
	if err := env.db.Create(&models.RequestLog{
		ClientID:     clientID,
		Model:        "test-model",
		StatusCode:   429,
		RequestID:    "reqdash12345678901234567890123",
		Provider:     "openai",
		ErrorCode:    services.ErrCodeUpstreamRate,
		RequestBody:  p104CanaryPrompt, // 模拟 legacy 存量行：仍不得渲染
		ErrorMessage: p104CanaryUpstreamErr,
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
	for _, banned := range []string{p104CanaryPrompt, p104CanaryUpstreamErr, "showRequestBody(", "requestModal", "requestBodyContent"} {
		if strings.Contains(body, banned) {
			t.Fatalf("[安全回归失败] Dashboard HTML 含 %q", banned)
		}
	}
	// Dashboard 服务器渲染要求：bounded ErrorCode 可见（RequestID 展示属 Client Detail 要求）
	if !strings.Contains(body, services.ErrCodeUpstreamRate) {
		t.Fatalf("[安全回归失败] Dashboard 应展示 ErrorCode %q", services.ErrCodeUpstreamRate)
	}
	t.Log("[SEC-003 FIXED] Dashboard：无正文/无 modal 注入点，展示 RequestID/ErrorCode")
}

// ---------------------------------------------------------------------------
// 7) [SEC-003 FIXED]（反转自 KNOWN-VULN "Client Detail 原样渲染 ErrorMessage"）
// ---------------------------------------------------------------------------
func TestP104B_Fixed_ClientDetail_NoRawError_ExposesMetadata(t *testing.T) {
	env := newP104Env(t, nil)
	clientID, _ := env.newP104Client(t, "kf-detail", "openai", env.upstreamURL+"/v1")
	if err := env.db.Create(&models.RequestLog{
		ClientID:     clientID,
		Model:        "test-model",
		StatusCode:   502,
		RequestID:    "reqdetail1234567890123456789012",
		Provider:     "gemini",
		ErrorCode:    services.ErrCodeUpstreamNetwork,
		ErrorMessage: p104CanaryErrInDBField, // 模拟 legacy 存量行：仍不得渲染
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
	body := w.Body.String()
	if strings.Contains(body, p104CanaryErrInDBField) {
		t.Fatal("[安全回归失败] Client Detail 渲染了 raw ErrorMessage")
	}
	for _, want := range []string{"reqdetail1234567890123456789012", "gemini", services.ErrCodeUpstreamNetwork} {
		if !strings.Contains(body, want) {
			t.Fatalf("[安全回归失败] Client Detail 应展示元数据 %q", want)
		}
	}
	t.Log("[SEC-003 FIXED] Client Detail：不渲染 raw ErrorMessage，展示 RequestID/Provider/ErrorCode")
}

// ---------------------------------------------------------------------------
// 8) [SEC-003 FIXED]（反转自 KNOWN-VULN "runtime log 回显 upstream error body"）
// ---------------------------------------------------------------------------
func TestP104B_Fixed_RuntimeLog_BoundedErrorCodeOnly(t *testing.T) {
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
	if err := env.clientService.UpdateClientSettings(client.ID, map[string]interface{}{"fallback_models": "fallback-x"}); err != nil {
		t.Fatal(err)
	}

	var logBuf syncBuffer
	prev := log.Writer()
	log.SetOutput(&logBuf)
	defer log.SetOutput(prev)

	body := `{"model":"test-model","messages":[{"role":"user","content":"ping"}]}`
	req := httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+gwKey)
	w := httptest.NewRecorder()
	env.api.ServeHTTP(w, req)

	logs := logBuf.String()
	if strings.Contains(logs, p104CanaryUpstreamErr) {
		t.Fatalf("[安全回归失败] runtime log 回显 upstream error body: %q", logs)
	}
	if !strings.Contains(logs, "upstream_error_code="+services.ErrCodeUpstreamRate) {
		t.Fatalf("[安全回归失败] runtime log 应只含 bounded 错误码 %s，实际 %q", services.ErrCodeUpstreamRate, logs)
	}
	// 错误路径不产生 RequestLog 行（与 P1-04A 固化的现状一致）
	if n := env.requestLogCount(t); n != 0 {
		t.Fatalf("[安全回归失败] 错误路径不应产生 RequestLog，实际 %d", n)
	}
	t.Log("[SEC-003 FIXED] fallback runtime log：仅 bounded 错误码，无不可信 upstream body")
}

// ---------------------------------------------------------------------------
// 9) [SEC-003 FIXED 新增] RequestID：服务器生成、逐请求唯一、与 DB 一致
// ---------------------------------------------------------------------------
func TestP104B_RequestID_ServerGenerated_UniquePerRequest(t *testing.T) {
	env := newP104Env(t, nil)
	_, gwKey := env.newP104Client(t, "kf-rid", "openai", env.upstreamURL+"/v1")

	doChat := func() string {
		body := `{"model":"test-model","messages":[{"role":"user","content":"ping"}]}`
		req := httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+gwKey)
		w := httptest.NewRecorder()
		env.api.ServeHTTP(w, req)
		if w.Result().StatusCode != http.StatusOK {
			t.Fatalf("chat 期望 200，实际 %d", w.Result().StatusCode)
		}
		return w.Result().Header.Get("X-Request-ID")
	}

	id1 := doChat()
	id2 := doChat()
	if id1 == "" || id2 == "" || id1 == id2 {
		t.Fatalf("[安全回归失败] 请求 ID 应逐请求唯一: %q vs %q", id1, id2)
	}

	row := env.latestLog(t)
	if row.RequestID != id2 {
		t.Fatalf("[安全回归失败] 最新行 RequestID 应为第二次请求的 id: db=%q header=%q", row.RequestID, id2)
	}

	// 客户端伪造的 X-Request-ID 不得被采纳
	spoofed := httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(`{"model":"m","messages":[{"role":"user","content":"x"}]}`))
	spoofed.Header.Set("X-Request-ID", "attacker-controlled-id")
	spoofed.Header.Set("Authorization", "Bearer "+gwKey)
	w := httptest.NewRecorder()
	env.api.ServeHTTP(w, spoofed)
	if got := w.Result().Header.Get("X-Request-ID"); got == "attacker-controlled-id" || len(got) != 32 {
		t.Fatalf("[安全回归失败] 服务器不应信任客户端 X-Request-ID，实际 %q", got)
	}
	t.Log("[SEC-003 FIXED] RequestID：服务器生成、唯一、DB/响应一致、不信任客户端值")
}

// ---------------------------------------------------------------------------
// 10) [SEC-003 FIXED 新增] gemini 传输错误 → bounded ErrorCode 入库，raw 错误文本不入库
// ---------------------------------------------------------------------------
func TestP104B_ErrorCode_TransportFailure_BoundedOnly(t *testing.T) {
	env := newP104Env(t, nil)
	_, gwKey := env.newP104Client(t, "kf-tf", "", "")
	// 指向必然连接失败的端口
	geminiProvider := env.cfg.Providers["gemini"]
	geminiProvider.BaseURL = "http://127.0.0.1:1"
	env.cfg.Providers["gemini"] = geminiProvider

	body := `{"contents":[{"parts":[{"text":"` + p104CanaryPrompt + `"}]}]}`
	req := httptest.NewRequest("POST", "/v1/models/test-model:generateContent", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+gwKey)
	w := httptest.NewRecorder()
	env.api.ServeHTTP(w, req)

	if n := env.requestLogCount(t); n != 1 {
		t.Fatalf("传输失败应产生 1 条元数据行，实际 %d", n)
	}
	row := env.latestLog(t)
	if row.ErrorCode != services.ErrCodeUpstreamNetwork {
		t.Fatalf("[安全回归失败] ErrorCode 应为 %s，实际 %q", services.ErrCodeUpstreamNetwork, row.ErrorCode)
	}
	if row.ErrorMessage != "" || row.RequestBody != "" {
		t.Fatalf("[安全回归失败] legacy 字段应恒空: body=%q err=%q", row.RequestBody, row.ErrorMessage)
	}
	t.Log("[SEC-003 FIXED] 传输失败：bounded ErrorCode 入库，raw 错误文本/正文不落盘")
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

// syncBuffer: 并发安全 bytes.Buffer（log 输出捕获用）
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
