package handlers

import (
	"context"
	"crypto/subtle"
	"encoding/gob"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"ai-gateway/internal/auth"
	"ai-gateway/internal/capture"
	"ai-gateway/internal/config"
	"ai-gateway/internal/models"
	"ai-gateway/internal/providers"
	"ai-gateway/internal/secrets"
	"ai-gateway/internal/services"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/gorilla/websocket"
	"golang.org/x/crypto/bcrypt"
)

// wsOriginAllowed: 严格同源校验——scheme + hostname + effective port 全部一致。
// effective port：显式端口优先，否则 scheme 默认端口（http=80 / https=443）。
// Host 头按期望 scheme 解析（Admin 面浏览器访问的 scheme 即该值）。
// 缺失 Origin 拒绝；不做子串/后缀判断；不信任 X-Forwarded-*。
func wsOriginAllowed(r *http.Request, expectedScheme string) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return false
	}
	u, err := url.Parse(origin)
	if err != nil || u.Host == "" {
		return false
	}
	if !strings.EqualFold(u.Scheme, expectedScheme) {
		return false
	}
	oh := u.Hostname()
	if oh == "" {
		return false
	}
	ru, err := url.Parse(expectedScheme + "://" + r.Host)
	if err != nil {
		return false
	}
	rh := ru.Hostname()
	if rh == "" || !strings.EqualFold(oh, rh) {
		return false
	}
	return effectivePort(u.Scheme, u.Port()) == effectivePort(expectedScheme, ru.Port())
}

// effectivePort: 显式端口优先，否则 scheme 默认端口
func effectivePort(scheme, port string) string {
	if port != "" {
		return port
	}
	switch strings.ToLower(scheme) {
	case "https":
		return "443"
	default:
		return "80"
	}
}

func KnownProviderTypes() []string {
	return []string{
		"gemini",
		"openai",
		"anthropic",
		"mistral",
		"perplexity",
		"xai",
		"cohere",
		"azure-openai",
		"ollama",
		"lmstudio",
		"vllm",
		"openrouter",
	}
}

// adminCSRFKey: request context 中携带的会话绑定 CSRF token
type adminCSRFKey struct{}

func csrfFromContext(ctx context.Context) string {
	if v, ok := ctx.Value(adminCSRFKey{}).(string); ok {
		return v
	}
	return ""
}

type AdminHandler struct {
	cfg           *config.Config
	clientService *services.ClientService
	statsService  *services.StatsService
	geminiService *services.GeminiService
	dashboardHub  *services.DashboardHub
	toolService   *services.ToolService
	templates     *template.Template
	sessionStore  auth.Store
	loginLimiter  *auth.LoginRateLimiter
	secretMgr     *secrets.Manager
	configPath    string
	capture       *capture.Store // MEMORY-ONLY 诊断正文读取（SEC-003/P1-04C）；nil = 永不可用
	wsUpgrader    *websocket.Upgrader
}

type PageData struct {
	Title     string
	User      string
	Data      interface{}
	CSRFToken string
}

// NewAdminHandler: secretMgr 为 Provider Secret 加密/解密的唯一入口（可为 nil——
// 未配置 Master Key 且无密文存在的部署）；configPath 是运行配置的真实来源路径，
// 供持久化使用（禁止回到硬编码 "config.yaml"）。
func NewAdminHandler(cfg *config.Config, clientService *services.ClientService, statsService *services.StatsService, geminiService *services.GeminiService, dashboardHub *services.DashboardHub, toolService *services.ToolService, sessionStore auth.Store, loginLimiter *auth.LoginRateLimiter, secretMgr *secrets.Manager, configPath string, captureStore *capture.Store) (*AdminHandler, error) {
	tmpl := template.New("admin").Funcs(template.FuncMap{
		"formatDate":     formatDate,
		"formatInt":      formatInt,
		"formatDuration": formatDuration,
		"percentUsed":    percentUsed,
		"splitToolNames": splitToolNames,
		"add":            func(a, b int) int { return a + b },
		"toJson":         func(v interface{}) (string, error) { b, err := json.Marshal(v); return string(b), err },
	})

	tmpl, err := tmpl.Parse(string(adminTemplates))
	if err != nil {
		return nil, err
	}

	gob.Register(time.Time{})

	// SEC-004（P1-02.1）：WS 期望 scheme 由 admin.cookie_secure 权威决定
	expectedScheme := "http"
	if cfg.Admin.CookieSecure {
		expectedScheme = "https"
	}

	return &AdminHandler{
		cfg:           cfg,
		clientService: clientService,
		statsService:  statsService,
		geminiService: geminiService,
		dashboardHub:  dashboardHub,
		toolService:   toolService,
		templates:     tmpl,
		sessionStore:  sessionStore,
		loginLimiter:  loginLimiter,
		secretMgr:     secretMgr,
		configPath:    configPath,
		capture:       captureStore,
		wsUpgrader: &websocket.Upgrader{
			ReadBufferSize:  1024,
			WriteBufferSize: 1024,
			// SEC-004（P1-02.1）：严格同源——scheme + hostname + effective port 全比较
			CheckOrigin: func(r *http.Request) bool {
				return wsOriginAllowed(r, expectedScheme)
			},
		},
	}, nil
}

func (h *AdminHandler) RegisterRoutes(r *chi.Mux) {
	r.Group(func(r chi.Router) {
		// SEC-004（P1-02B）：login/logout POST 必须携带有效 CSRF（pre-auth double-submit
		// 或会话绑定 token）；GET 只读不受限
		r.Use(h.requireCSRFPublic)
		r.Get("/admin", func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "/admin/dashboard", http.StatusFound)
		})
		r.Get("/admin/login", h.ShowLogin)
		r.Post("/admin/login", h.HandleLogin)
		r.Post("/admin/logout", h.HandleLogout)
	})

	r.Group(func(r chi.Router) {
		r.Use(middleware.Timeout(60 * time.Second))
		r.Use(h.RequireAuth)
		// SEC-004（P1-02B）：受保护组所有 POST 必须携带会话绑定 CSRF token
		r.Use(h.requireCSRFSession)

		r.Get("/admin/dashboard", h.Dashboard)
		r.Get("/admin/clients", h.ListClients)
		r.Post("/admin/clients", h.CreateClient)
		r.Get("/admin/clients/{id}", h.ShowClient)
		r.Post("/admin/clients/{id}/update", h.UpdateClient)
		r.Post("/admin/clients/{id}/delete", h.DeleteClient)
		r.Post("/admin/clients/{id}/regenerate", h.RegenerateKey)
		r.Post("/admin/clients/{id}/toggle", h.ToggleClient)
		r.Get("/admin/clients/{id}/test", h.TestClientConnection)
		r.Get("/admin/clients/{id}/fetch-models", h.FetchClientModels)
		// SEC-003（P1-04C）：诊断正文按需读取——仅 Admin 监听面 + RequireAuth；
		// 禁止 server-render 进 Dashboard/正文 modal
		r.Get("/admin/request-bodies/{requestID}", h.GetCapturedRequestBody)
		r.Post("/admin/clients/{id}/update-models", h.UpdateClientModels)
		r.Get("/admin/stats", h.ShowStats)
		r.Get("/admin/stats/api", h.GetAPISTats)
		r.Get("/admin/server-tools", h.ShowServerTools)
		r.Post("/admin/server-tools", h.UpdateServerTools)
		r.Get("/admin/ws", h.HandleDashboardWS)
	})
}

func (h *AdminHandler) RequireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie(auth.SessionCookieName)
		if err != nil || cookie.Value == "" {
			http.Redirect(w, r, "/admin/login", http.StatusFound)
			return
		}

		// SEC-001 修复（P1-01D）：服务端权威校验——存在 / 未撤销 / 未过期。
		// Cookie 内容本身不再是权限；任何无法通过服务端会话校验的值一律拒绝。
		if _, err := h.sessionStore.Validate(r.Context(), cookie.Value); err != nil {
			log.Printf("[ADMIN] session rejected (%s): %v", r.URL.Path, err)
			http.Redirect(w, r, "/admin/login", http.StatusFound)
			return
		}

		// SEC-004 修复（P1-02B）：派生会话绑定 CSRF token 注入 context，供模板渲染
		ctx := context.WithValue(r.Context(), adminCSRFKey{}, auth.CSRFToken(h.cfg.Admin.SessionSecret, cookie.Value))
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// ---------------------------------------------------------------------------
// CSRF（SEC-004 修复，P1-02B）
//
// 两种模式：
//   会话绑定（受保护组 POST）：token = HMAC-SHA256(SessionSecret, "csrf:"+rawToken)，
//     constant-time 比对；token 随会话轮换，跨会话/跨实例不可复用。
//   Pre-auth（login/setup POST）：double-submit Cookie——GET 时 Set-Cookie(preauth_csrf)
//     并渲染同值 token，POST 比对两者；攻击者跨站既读不到也设不了该 Cookie。
// 缺 token / 不匹配 / 无 Cookie → 一律 403，不泄露期望值。
// ---------------------------------------------------------------------------

func (h *AdminHandler) csrfTokenFromRequest(r *http.Request) string {
	if r.Form == nil || r.Form.Get("csrf_token") == "" {
		r.ParseForm()
	}
	if t := r.Form.Get("csrf_token"); t != "" {
		return t
	}
	return r.Header.Get("X-CSRF-Token")
}

// verifySessionCSRF: 会话绑定模式校验
func (h *AdminHandler) verifySessionCSRF(r *http.Request) bool {
	cookie, err := r.Cookie(auth.SessionCookieName)
	if err != nil || cookie.Value == "" {
		return false
	}
	expected := auth.CSRFToken(h.cfg.Admin.SessionSecret, cookie.Value)
	token := h.csrfTokenFromRequest(r)
	return token != "" && subtle.ConstantTimeCompare([]byte(token), []byte(expected)) == 1
}

// verifyPreAuthCSRF: double-submit 模式校验（Cookie 值 vs 表单 token，均为服务端签发）
func (h *AdminHandler) verifyPreAuthCSRF(r *http.Request) bool {
	return auth.PreAuthCSRFValid(r)
}

// requireCSRFPublic: 公开组（login/logout）——先试会话绑定，再退 pre-auth double-submit。
func (h *AdminHandler) requireCSRFPublic(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			next.ServeHTTP(w, r)
			return
		}
		if h.verifySessionCSRF(r) || h.verifyPreAuthCSRF(r) {
			next.ServeHTTP(w, r)
			return
		}
		log.Printf("[ADMIN] CSRF rejected %s", r.URL.Path)
		http.Error(w, "Forbidden", http.StatusForbidden)
	})
}

// requireCSRFSession: 受保护组——POST 必须携带会话绑定 token（GET 只读跳过）。
func (h *AdminHandler) requireCSRFSession(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			next.ServeHTTP(w, r)
			return
		}
		if !h.verifySessionCSRF(r) {
			log.Printf("[ADMIN] CSRF rejected %s (session-bound)", r.URL.Path)
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// issuePreAuthCSRF: 为 login/setup 页面签发 pre-auth token（渲染值 + 同值 Cookie）
func (h *AdminHandler) issuePreAuthCSRF(w http.ResponseWriter) (string, error) {
	token, err := auth.NewPreAuthCSRF()
	if err != nil {
		return "", err
	}
	http.SetCookie(w, &http.Cookie{
		Name:     auth.PreAuthCSRFCookie,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   h.cfg.Admin.CookieSecure,
		SameSite: http.SameSiteStrictMode,
		Expires:  time.Now().Add(15 * time.Minute),
	})
	return token, nil
}

func (h *AdminHandler) ShowLogin(w http.ResponseWriter, r *http.Request) {
	token, err := h.issuePreAuthCSRF(w)
	if err != nil {
		log.Printf("[ADMIN] pre-auth csrf issue failed: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	h.render(r, w, "login.html", PageData{
		Title:     "Admin Login",
		CSRFToken: token,
	})
}

func (h *AdminHandler) HandleLogin(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	username := r.Form.Get("username")
	password := r.Form.Get("password")

	// SEC（P1-02D）：防爆破短路。username 维度，不信任 X-Forwarded-*。
	if !h.loginLimiter.Allow(username) {
		w.Header().Set("Retry-After", strconv.Itoa(h.loginLimiter.RetryAfter(username)))
		http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
		return
	}

	// P1-02.1：无论 username 是否存在都执行等价 bcrypt 校验，消除响应时间差异
	// （不存在用户名提前返回会让攻击者枚举出真实管理员名）
	usernameOK := username == h.cfg.Admin.Username
	passwordOK := bcrypt.CompareHashAndPassword([]byte(h.cfg.Admin.PasswordHash), []byte(password)) == nil
	if !usernameOK || !passwordOK {
		h.loginLimiter.RecordFailure(username)
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	h.loginLimiter.RecordSuccess(username)

	// SEC-001 修复（P1-01C）：凭据验证通过后签发真实服务端会话。
	// 原始 256-bit 随机 token 仅此一次可见并放入 Cookie；库中只存 SHA-256。
	expiresAt := time.Now().Add(auth.SessionDuration)
	rawToken, err := h.sessionStore.Create(r.Context(), username, expiresAt)
	if err != nil {
		// 会话创建失败时绝不能让登录"静默成功"（否则会退回无法验证的状态）
		log.Printf("[ADMIN] session create failed: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	cookie := &http.Cookie{
		Name:     auth.SessionCookieName,
		Value:    rawToken,
		Path:     "/",
		HttpOnly: true,
		Secure:   h.cfg.Admin.CookieSecure, // P1-02A：显式配置，与已废弃的 server.https 解耦
		SameSite: http.SameSiteStrictMode,
		Expires:  expiresAt, // 与服务端 expires_at 一致（权威在服务端）
	}

	http.SetCookie(w, cookie)
	http.Redirect(w, r, "/admin/dashboard", http.StatusFound)
}

func (h *AdminHandler) HandleLogout(w http.ResponseWriter, r *http.Request) {
	// SEC-001 修复（P1-01E）：登出必须在服务端吊销会话，仅清浏览器 Cookie 不够。
	// 未知/伪造 token 静默忽略（幂等），不让登出端点成为探测/500 源。
	if cookie, err := r.Cookie(auth.SessionCookieName); err == nil && cookie.Value != "" {
		if err := h.sessionStore.Revoke(r.Context(), cookie.Value); err != nil && !errors.Is(err, auth.ErrSessionNotFound) {
			log.Printf("[ADMIN] session revoke failed: %v", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
	}

	// 清理 Cookie 的属性必须与登录时一致（P1-02A），并明确置为过去时间
	clearCookie := &http.Cookie{
		Name:     auth.SessionCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   h.cfg.Admin.CookieSecure,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   -1,
		Expires:  time.Now().Add(-time.Hour),
	}
	http.SetCookie(w, clearCookie)
	http.Redirect(w, r, "/admin/login", http.StatusFound)
}

func (h *AdminHandler) Dashboard(w http.ResponseWriter, r *http.Request) {
	stats, _ := h.statsService.GetGlobalStats()
	recentLogs, _ := h.statsService.GetRecentRequests("", 20)
	modelUsage, _ := h.statsService.GetModelUsage()
	recentStats, _ := h.statsService.GetRecentStats(5)

	h.render(r, w, "dashboard.html", PageData{
		Title: "Dashboard",
		User:  h.cfg.Admin.Username,
		Data: map[string]interface{}{
			"Stats":       stats,
			"RecentLogs":  recentLogs,
			"ModelUsage":  modelUsage,
			"RecentStats": recentStats,
		},
	})
}

func (h *AdminHandler) ListClients(w http.ResponseWriter, r *http.Request) {
	clients, _ := h.clientService.GetAllClients()
	clientStats, _ := h.statsService.GetAllClientStats()

	statsMap := make(map[string]models.ClientStats)
	for _, cs := range clientStats {
		statsMap[cs.ClientID] = cs
	}

	h.render(r, w, "clients.html", PageData{
		Title: "Clients",
		User:  h.cfg.Admin.Username,
		Data: map[string]interface{}{
			"Clients":     clients,
			"ClientStats": statsMap,
			"Providers":   KnownProviderTypes(),
		},
	})
}

// keyOpError: Admin key 操作失败的受限错误——消息面向运维，绝不携带 key 材料。
type keyOpError struct {
	message string
	status  int
}

// encryptClientKey: 把表单明文 key 转为该 client 的 AEAD 信封（P1-03C3）。
// Master Key 未配置 → 明确拒绝（明文保存被禁止，无明文 fallback）；加密失败 → 通用错误。
func (h *AdminHandler) encryptClientKey(clientID, plaintext string) (string, *keyOpError) {
	if h.secretMgr == nil {
		return "", &keyOpError{
			message: "master key not configured: refusing to store provider key in plaintext (set AIGATEWAY_MASTER_KEY or AIGATEWAY_MASTER_KEY_FILE)",
			status:  http.StatusServiceUnavailable,
		}
	}
	env, err := h.secretMgr.EncryptClientBackendKey(clientID, []byte(plaintext))
	if err != nil {
		log.Printf("[ADMIN] encrypt client provider key failed: %v", err)
		return "", &keyOpError{message: "failed to encrypt provider key", status: http.StatusInternalServerError}
	}
	return env, nil
}

// buildClientRuntimeProviderConfig: 组装 Admin 侧连接测试/模型拉取用的运行时
// provider 配置（P1-03C3.1）。key 优先级与 OpenAI resolveProvider 完全一致，单一实现防漂移：
//
//	runtime 全局 provider（h.geminiService.GetConfig()，明文已解密）
//	  → client BaseURL / DefaultModel override
//	  → client 密文 override（point-of-use 解密，覆盖全局 key）
//
// 硬性约束：必须使用运行时视图；禁止解密全局 key 写回 h.cfg（持久化视图恒 envelope-only）。
// client 无 key 时保留 runtime 全局 key（修复此前 Test/Fetch 丢 global fallback 的功能回归）。
func (h *AdminHandler) buildClientRuntimeProviderConfig(client *models.Client, timeoutSeconds int) (config.ProviderConfig, *keyOpError) {
	backend := client.Backend
	if backend == "" {
		backend = "gemini"
	}
	var cfg config.ProviderConfig
	if gp := h.geminiService.GetConfig().GetProvider(backend); gp != nil {
		cfg = *gp // 运行时视图副本：只读，修改不回流
	}
	cfg.Type = backend
	if client.BackendBaseURL != "" {
		cfg.BaseURL = client.BackendBaseURL
	}
	if client.BackendDefaultModel != "" {
		cfg.DefaultModel = client.BackendDefaultModel
	}
	switch {
	case client.BackendAPIKeyEncrypted != "":
		if h.secretMgr == nil {
			return config.ProviderConfig{}, &keyOpError{message: "client provider key is encrypted but no master key is configured", status: http.StatusServiceUnavailable}
		}
		pt, err := h.secretMgr.DecryptClientBackendKey(client.ID, client.BackendAPIKeyEncrypted)
		if err != nil {
			log.Printf("[ADMIN] decrypt client %s provider key failed: %v", client.ID, err)
			return config.ProviderConfig{}, &keyOpError{message: "client provider key could not be decrypted", status: http.StatusInternalServerError}
		}
		cfg.APIKey = string(pt)
	case client.BackendAPIKey != "":
		return config.ProviderConfig{}, &keyOpError{message: "client has a legacy plaintext provider key; run -migrate-provider-secrets", status: http.StatusConflict}
	}
	cfg.TimeoutSeconds = timeoutSeconds
	return cfg, nil
}

func (h *AdminHandler) CreateClient(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	name := r.Form.Get("name")
	description := r.Form.Get("description")
	keyType := r.Form.Get("key_type")
	if keyType == "" {
		keyType = "gemini"
	}
	keyPrefix := r.Form.Get("key_prefix")
	backend := r.Form.Get("backend")
	if backend == "" {
		backend = "gemini"
	}
	backendAPIKey := r.Form.Get("backend_api_key")
	backendBaseURL := r.Form.Get("backend_base_url")
	backendDefaultModel := r.Form.Get("backend_default_model")
	systemPrompt := r.Form.Get("system_prompt")
	toolMode := r.Form.Get("tool_mode")
	fallbackModels := r.Form.Get("fallback_models")
	serverTools := r.Form.Get("server_tools") == "on"

	if name == "" {
		http.Error(w, "Name is required", http.StatusBadRequest)
		return
	}

	client, apiKey, err := h.clientService.CreateClient(name, description, keyType, keyPrefix, h.cfg)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	client.Backend = backend
	client.BackendBaseURL = backendBaseURL
	client.BackendDefaultModel = backendDefaultModel
	client.SystemPrompt = systemPrompt
	client.ToolMode = toolMode
	client.FallbackModels = fallbackModels
	client.ServerTools = serverTools

	// SEC-002（P1-03C3）：client Provider Key 只存密文。表单明文即刻消费为信封，
	// legacy 字段保持空——绝不写 client.BackendAPIKey。
	if backendAPIKey != "" {
		env, encErr := h.encryptClientKey(client.ID, backendAPIKey)
		if encErr != nil {
			_ = h.clientService.DeleteClient(client.ID) // 补偿：不留半创建 client
			http.Error(w, encErr.message, encErr.status)
			return
		}
		client.BackendAPIKeyEncrypted = env
	}
	if err := h.clientService.UpdateClient(client); err != nil {
		_ = h.clientService.DeleteClient(client.ID) // 补偿：不留半创建 client
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	h.render(r, w, "client_created.html", PageData{
		Title: "Client Created",
		User:  h.cfg.Admin.Username,
		Data: map[string]interface{}{
			"Client": client,
			"APIKey": apiKey,
		},
	})
}

func (h *AdminHandler) ShowClient(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	client, err := h.clientService.GetClientByID(id)
	if err != nil || client == nil {
		http.Error(w, "Client not found", http.StatusNotFound)
		return
	}

	clientStats, _ := h.statsService.GetClientStats(id)
	recentLogs, _ := h.statsService.GetRecentRequests(id, 50)

	h.render(r, w, "client_detail.html", PageData{
		Title: client.Name,
		User:  h.cfg.Admin.Username,
		Data: map[string]interface{}{
			"Client":     client,
			"Stats":      clientStats,
			"RecentLogs": recentLogs,
			"Providers":  KnownProviderTypes(),
		},
	})
}

func (h *AdminHandler) UpdateClient(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	r.ParseForm()
	name := r.Form.Get("name")
	description := r.Form.Get("description")
	isActive := r.Form.Get("is_active") == "on"
	backend := r.Form.Get("backend")
	backendAPIKey := r.Form.Get("backend_api_key")
	clearBackendKey := r.Form.Get("clear_backend_api_key") == "on"
	backendBaseURL := r.Form.Get("backend_base_url")
	backendDefaultModel := r.Form.Get("backend_default_model")
	systemPrompt := r.Form.Get("system_prompt")
	toolMode := r.Form.Get("tool_mode")
	fallbackModels := r.Form.Get("fallback_models")
	serverTools := r.Form.Get("server_tools") == "on"
	rateLimitMinute := parseInt(r.Form.Get("rate_limit_minute"), 60)
	rateLimitHour := parseInt(r.Form.Get("rate_limit_hour"), 1000)
	rateLimitDay := parseInt(r.Form.Get("rate_limit_day"), 10000)
	quotaInputTokens := parseInt(r.Form.Get("quota_input_tokens"), 1000000)
	quotaOutputTokens := parseInt(r.Form.Get("quota_output_tokens"), 500000)
	quotaRequests := parseInt(r.Form.Get("quota_requests"), 1000)
	maxInputTokens := parseInt(r.Form.Get("max_input_tokens"), 1000000)
	maxOutputTokens := parseInt(r.Form.Get("max_output_tokens"), 8192)
	modelsList := r.Form.Get("models_list")

	client, err := h.clientService.GetClientByID(id)
	if err != nil || client == nil {
		http.Error(w, "Client not found", http.StatusNotFound)
		return
	}

	client.Name = name
	client.Description = description
	client.IsActive = isActive
	client.Backend = backend
	client.BackendBaseURL = backendBaseURL
	client.BackendDefaultModel = backendDefaultModel
	client.SystemPrompt = systemPrompt
	client.ToolMode = toolMode
	client.FallbackModels = fallbackModels
	client.ServerTools = serverTools
	client.RateLimitMinute = rateLimitMinute
	client.RateLimitHour = rateLimitHour
	client.RateLimitDay = rateLimitDay
	client.QuotaInputTokensDay = quotaInputTokens
	client.QuotaOutputTokensDay = quotaOutputTokens
	client.QuotaRequestsDay = quotaRequests
	client.MaxInputTokens = maxInputTokens
	client.MaxOutputTokens = maxOutputTokens
	if modelsList != "" {
		client.BackendModels = modelsList
	}

	// SEC-002（P1-03C3）key 更新语义（取代旧 "blank=清空" 的危险默认）：
	//   填入新 key            → 加密替换 BackendAPIKeyEncrypted（legacy 字段保持空）
	//   blank 且未勾选清除    → 保留现有 key（密文/legacy 都不动——编辑表单不再回填明文，
	//                            旧行为会在此把用户想保留的 key 静默清掉）
	//   clear_backend_api_key → 显式清除
	switch {
	case clearBackendKey:
		client.BackendAPIKey = ""
		client.BackendAPIKeyEncrypted = ""
	case backendAPIKey != "":
		env, kerr := h.encryptClientKey(client.ID, backendAPIKey)
		if kerr != nil {
			http.Error(w, kerr.message, kerr.status)
			return
		}
		client.BackendAPIKeyEncrypted = env
		client.BackendAPIKey = ""
	}

	err = h.clientService.UpdateClient(client)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/admin/clients/"+id, http.StatusFound)
}

func (h *AdminHandler) ToggleClient(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	client, err := h.clientService.GetClientByID(id)
	if err != nil || client == nil {
		http.Error(w, "Client not found", http.StatusNotFound)
		return
	}

	client.IsActive = !client.IsActive
	h.clientService.UpdateClient(client)

	http.Redirect(w, r, "/admin/clients/"+id, http.StatusFound)
}

func (h *AdminHandler) DeleteClient(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	err := h.clientService.DeleteClient(id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/admin/clients", http.StatusFound)
}

func (h *AdminHandler) RegenerateKey(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	r.ParseForm()
	keyType := r.Form.Get("key_type")
	if keyType == "" {
		keyType = "gemini"
	}
	keyPrefix := r.Form.Get("key_prefix")

	apiKey, err := h.clientService.RegenerateAPIKey(id, keyType, keyPrefix)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	client, _ := h.clientService.GetClientByID(id)

	h.render(r, w, "client_created.html", PageData{
		Title: "API Key Regenerated",
		User:  h.cfg.Admin.Username,
		Data: map[string]interface{}{
			"Client": client,
			"APIKey": apiKey,
			"Regen":  true,
		},
	})
}

func (h *AdminHandler) ShowServerTools(w http.ResponseWriter, r *http.Request) {
	allTools := h.toolService.GetToolDefinitions()

	enabledTools := make(map[string]bool)
	for _, name := range h.cfg.ServerTools.Tools {
		enabledTools[name] = true
	}

	h.render(r, w, "server_tools.html", PageData{
		Title: "Server Tools",
		User:  h.cfg.Admin.Username,
		Data: map[string]interface{}{
			"Tools":        allTools,
			"EnabledTools": enabledTools,
		},
	})
}

func (h *AdminHandler) UpdateServerTools(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()

	enabledTools := r.Form["tool"]

	h.cfg.ServerTools.Tools = enabledTools
	h.cfg.ServerTools.Enabled = len(enabledTools) > 0

	// P1-03C3：持久化必须写真实配置来源路径（废除硬编码 "config.yaml"——
	// 那会在配置不在 CWD 时分裂出第二份配置，并把运行态 cfg 落到错误位置）。
	// h.cfg 为持久化视图：Provider 密钥只含信封，不含运行态明文。
	if h.configPath == "" {
		http.Error(w, "config source path unknown; refusing to persist", http.StatusInternalServerError)
		return
	}
	if err := config.SaveConfig(h.cfg, h.configPath); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Update tool service
	for _, name := range h.toolService.ToolNames() {
		enabled := false
		for _, t := range enabledTools {
			if t == name {
				enabled = true
				break
			}
		}
		_ = enabled // The tool service will be rebuilt on restart
	}

	http.Redirect(w, r, "/admin/server-tools", http.StatusFound)
}

func (h *AdminHandler) ShowStats(w http.ResponseWriter, r *http.Request) {
	historical7, _ := h.statsService.GetHistoricalStats(7)
	historical30, _ := h.statsService.GetHistoricalStats(30)
	hourly24, _ := h.statsService.GetHourlyStats(24)
	modelStats, _ := h.statsService.GetModelStats(7)
	clientStats, _ := h.statsService.GetClientStats2(7)
	stats, _ := h.statsService.GetGlobalStats()

	h.render(r, w, "stats.html", PageData{
		Title: "Statistics",
		User:  h.cfg.Admin.Username,
		Data: map[string]interface{}{
			"Historical7":  historical7,
			"Historical30": historical30,
			"Hourly24":     hourly24,
			"ModelStats":   modelStats,
			"ClientStats":  clientStats,
			"Stats":        stats,
		},
	})
}

func (h *AdminHandler) GetAPISTats(w http.ResponseWriter, r *http.Request) {
	stats, err := h.statsService.GetGlobalStats()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"total_requests":%d,"total_input_tokens":%d,"total_output_tokens":%d,"active_clients":%d,"total_clients":%d,"error_rate":%.2f}`,
		stats.TotalRequestsToday, stats.TotalInputTokensToday, stats.TotalOutputTokensToday, stats.ActiveClients, stats.TotalClients, stats.ErrorRate)
}

func (h *AdminHandler) TestConnection(w http.ResponseWriter, r *http.Request) {
	msg, ok, err := h.geminiService.TestConnection()
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"success":false,"message":"%s"}`, msg)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"success":%v,"message":"%s"}`, ok, msg)
}

func (h *AdminHandler) GetModels(w http.ResponseWriter, r *http.Request) {
	var models []string
	if p := h.cfg.GetProvider("gemini"); p != nil {
		models = p.AllowedModels
	}

	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"models":[%s]}`, formatStringArray(models))
}

func (h *AdminHandler) FetchModels(w http.ResponseWriter, r *http.Request) {
	models, err := h.geminiService.FetchAvailableModels()
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"success":false,"error":"%s"}`, err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"success":true,"models":[%s]}`, formatStringArray(models))
}

func (h *AdminHandler) TestClientConnection(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	client, err := h.clientService.GetClientByID(id)
	if err != nil || client == nil {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"success":false,"message":"Client not found"}`)
		return
	}

	pcfg, kerr := h.buildClientRuntimeProviderConfig(client, 30)
	if kerr != nil {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"success":false,"message":"%s"}`, kerr.message)
		return
	}

	provider, err := providers.BuildSingleProvider(pcfg.Type, pcfg)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"success":false,"message":"Failed to build provider: %s"}`, err.Error())
		return
	}

	msg, ok, testErr := provider.TestConnection()
	if testErr != nil {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"success":false,"message":"Error: %s"}`, testErr.Error())
		return
	}

	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"success":%v,"message":"%s"}`, ok, msg)
}

func (h *AdminHandler) FetchClientModels(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	client, err := h.clientService.GetClientByID(id)
	if err != nil || client == nil {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"success":false,"error":"Client not found"}`)
		return
	}

	pcfg, kerr := h.buildClientRuntimeProviderConfig(client, 30)
	if kerr != nil {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"success":false,"error":"%s"}`, kerr.message)
		return
	}

	provider, err := providers.BuildSingleProvider(pcfg.Type, pcfg)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"success":false,"error":"Failed to build provider: %s"}`, err.Error())
		return
	}

	models, err := provider.FetchModels()
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"success":false,"error":"%s"}`, err.Error())
		return
	}

	client.BackendModels = formatModelArray(models)
	h.clientService.UpdateClient(client)

	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"success":true,"models":[%s]}`, formatStringArray(models))
}

func (h *AdminHandler) UpdateClientModels(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	r.ParseForm()

	models := r.Form["models"]

	client, err := h.clientService.GetClientByID(id)
	if err != nil || client == nil {
		http.Error(w, "Client not found", http.StatusNotFound)
		return
	}

	client.BackendModels = formatModelArray(models)
	h.clientService.UpdateClient(client)

	http.Redirect(w, r, "/admin/clients/"+id, http.StatusFound)
}

func formatModelArray(models []string) string {
	if len(models) == 0 {
		return "[]"
	}
	result := "["
	for i, m := range models {
		if i > 0 {
			result += ","
		}
		result += fmt.Sprintf(`"%s"`, m)
	}
	result += "]"
	return result
}

// GetCapturedRequestBody: MEMORY-ONLY 诊断正文的按需读取端点（SEC-003/P1-04C）。
// 纪律：RequireAuth 保护（路由注册在受保护组）；no-store/no-cache 防缓存落盘；
// capture 关闭/过期/不存在 → 404；正文仅按需返回，绝不 server-render 进列表 HTML。
func (h *AdminHandler) GetCapturedRequestBody(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "requestID")
	entry, ok := h.capture.Get(id)
	if !ok {
		http.Error(w, "captured request body not available", http.StatusNotFound)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	if entry.Truncated {
		w.Header().Set("X-Body-Truncated", "true")
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write(entry.Body)
}

// HandleDashboardWS upgrades an HTTP connection to WebSocket for real-time dashboard updates.
func (h *AdminHandler) HandleDashboardWS(w http.ResponseWriter, r *http.Request) {
	conn, err := h.wsUpgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("[WS] Upgrade failed: %v", err)
		return
	}
	h.dashboardHub.Register(conn)
}

func formatStringArray(arr []string) string {
	result := ""
	for i, s := range arr {
		if i > 0 {
			result += ","
		}
		result += fmt.Sprintf(`"%s"`, s)
	}
	return result
}

func (h *AdminHandler) render(r *http.Request, w http.ResponseWriter, name string, data PageData) {
	if data.CSRFToken == "" && r != nil {
		// 受保护页面：从 context 取会话绑定 CSRF token（RequireAuth 注入）
		data.CSRFToken = csrfFromContext(r.Context())
	}
	err := h.templates.ExecuteTemplate(w, name, data)
	if err != nil {
		log.Printf("Template error for %s: %v", name, err)
		http.Error(w, "Template error: "+err.Error(), http.StatusInternalServerError)
	}
}

func formatDate(t time.Time) string {
	return t.Format("Jan 02, 2006 15:04")
}

func formatDuration(ms interface{}) string {
	var m int
	switch v := ms.(type) {
	case int:
		m = v
	case float64:
		m = int(v)
	default:
		return "0ms"
	}
	if m < 1000 {
		return fmt.Sprintf("%dms", m)
	}
	if m < 60000 {
		return fmt.Sprintf("%.1fs", float64(m)/1000)
	}
	mins := m / 60000
	secs := (m % 60000) / 1000
	return fmt.Sprintf("%dm %ds", mins, secs)
}

func formatInt(n interface{}) string {
	switch v := n.(type) {
	case int:
		if v == 0 {
			return "0"
		}
		return fmt.Sprintf("%d", v)
	case int64:
		if v == 0 {
			return "0"
		}
		return fmt.Sprintf("%d", v)
	case float64:
		if v == 0 {
			return "0"
		}
		return fmt.Sprintf("%.0f", v)
	default:
		return "0"
	}
}

func splitToolNames(names string) []string {
	if names == "" {
		return nil
	}
	return strings.Split(names, ",")
}

func percentUsed(used, limit interface{}) int {
	var usedVal, limitVal int64
	switch v := used.(type) {
	case int:
		usedVal = int64(v)
	case int64:
		usedVal = v
	default:
		usedVal = 0
	}
	switch v := limit.(type) {
	case int:
		limitVal = int64(v)
	case int64:
		limitVal = v
	default:
		limitVal = 0
	}
	if limitVal == 0 {
		return 0
	}
	return int((usedVal * 100) / limitVal)
}

func parseInt(s string, def int) int {
	if s == "" {
		return def
	}
	var n int
	fmt.Sscanf(s, "%d", &n)
	if n == 0 {
		return def
	}
	return n
}

var adminTemplates = []byte(`
{{define "login.html"}}
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Login - AI Gateway</title>
    <link rel="stylesheet" href="/static/style.css">
    <style>
        body { font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif; }
        .hidden { display: none; }
    </style>
    <script>
        document.addEventListener('DOMContentLoaded', function() {
            window.showModal = function(id) { var el = document.getElementById(id); if(el) el.classList.remove('hidden'); };
            window.hideModal = function(id) { var el = document.getElementById(id); if(el) el.classList.add('hidden'); };
        });
    </script>
</head>
<body class="bg-gradient-to-br from-gray-900 via-gray-800 to-gray-900 min-h-screen flex items-center justify-center">
    <div class="w-full max-w-md">
        <div class="text-center mb-8">
            <div class="inline-flex items-center justify-center w-16 h-16 rounded-2xl bg-blue-600 mb-4">
                <svg class="w-8 h-8 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"/>
                </svg>
            </div>
            <h1 class="text-3xl font-bold text-white">AI Gateway</h1>
            <p class="text-gray-400 mt-2">Sign in to your admin account</p>
        </div>
        
        <div class="bg-gray-800/50 backdrop-blur-sm border border-gray-700 rounded-2xl p-8">
            <form method="POST" action="/admin/login">
                <input type="hidden" name="csrf_token" value="{{.CSRFToken}}">
                
                <div class="mb-6">
                    <label class="block text-gray-300 text-sm font-medium mb-2">Username</label>
                    <input type="text" name="username" 
                        class="w-full px-4 py-3 bg-gray-900/50 border border-gray-600 text-white rounded-xl focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent transition-all">
                </div>
                
                <div class="mb-8">
                    <label class="block text-gray-300 text-sm font-medium mb-2">Password</label>
                    <input type="password" name="password" 
                        class="w-full px-4 py-3 bg-gray-900/50 border border-gray-600 text-white rounded-xl focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent transition-all">
                </div>
                
                <button type="submit" 
                    class="w-full bg-gradient-to-r from-blue-600 to-blue-700 text-white font-semibold py-3 px-4 rounded-xl hover:from-blue-700 hover:to-blue-800 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2 focus:ring-offset-gray-900 transition-all">
                    Sign In
                </button>
            </form>
        </div>
        
        <p class="text-center text-gray-500 text-sm mt-6">
            AI Gateway Gateway
        </p>
    </div>
</body>
</html>
{{end}}

{{define "dashboard.html"}}
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Dashboard - AI Gateway</title>
    <link rel="stylesheet" href="/static/style.css">
    <script src="/static/chart.js"></script>
    <style>body { font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif; }</style>
    <script>window.chartColors = ['#3B82F6','#10B981','#8B5CF6','#F59E0B','#EF4444','#EC4899','#06B6D4','#F97316','#84CC16','#E879F9'];</script>
</head>
<body class="bg-gray-900 min-h-screen">
    <!-- Top Navigation -->
    <nav class="bg-gray-800/80 backdrop-blur-md border-b border-gray-700 sticky top-0 z-50">
        <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
            <div class="flex items-center justify-between h-16">
                <div class="flex items-center space-x-3">
                    <div class="w-8 h-8 bg-gradient-to-br from-blue-500 to-blue-700 rounded-lg flex items-center justify-center">
                        <svg class="w-5 h-5 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 10V3L4 14h7v7l9-11h-7z"/>
                        </svg>
                    </div>
                    <span class="text-xl font-bold text-white">AI Gateway</span>
                </div>
                
                <div class="flex items-center space-x-1">
                    <a href="/admin/dashboard" class="px-3 py-2 rounded-lg text-sm font-medium text-white bg-gray-700">Dashboard</a>
                    <a href="/admin/clients" class="px-3 py-2 rounded-lg text-sm font-medium text-gray-300 hover:text-white hover:bg-gray-700">Clients</a>
                    <a href="/admin/stats" class="px-3 py-2 rounded-lg text-sm font-medium text-gray-300 hover:text-white hover:bg-gray-700">Stats</a>
                    <a href="/admin/server-tools" class="px-3 py-2 rounded-lg text-sm font-medium text-gray-300 hover:text-white hover:bg-gray-700">Server Tools</a>
                    <a href="https://github.com/DatanoiseTV/aigateway" target="_blank" class="px-3 py-2 rounded-lg text-gray-300 hover:text-white hover:bg-gray-700">
                        <svg class="w-5 h-5" fill="currentColor" viewBox="0 0 24 24">
                            <path fill-rule="evenodd" clip-rule="evenodd" d="M12 2C6.477 2 2 6.477 2 12c0 4.42 2.865 8.17 6.839 9.49.5.092.682-.217.682-.482 0-.237-.008-.866-.013-1.7-2.782.604-3.369-1.34-3.369-1.34-.454-1.156-1.11-1.464-1.11-1.464-.908-.62.069-.608.069-.608 1.003.07 1.531 1.03 1.531 1.03.892 1.529 2.341 1.087 2.91.831.092-.646.35-1.086.636-1.336-2.22-.253-4.555-1.11-4.555-4.943 0-1.091.39-1.984 1.029-2.683-.103-.253-.446-1.27.098-2.647 0 0 .84-.269 2.75 1.025A9.578 9.578 0 0112 6.836c.85.004 1.705.114 2.504.336 1.909-1.294 2.747-1.025 2.747-1.025.546 1.377.203 2.394.1 2.647.64.699 1.028 1.592 1.028 2.683 0 3.842-2.339 4.687-4.566 4.935.359.309.678.919.678 1.852 0 1.336-.012 2.415-.012 2.743 0 .267.18.578.688.48C19.138 20.167 22 16.418 22 12c0-5.523-4.477-10-10-10z"/>
                        </svg>
                    </a>
                    <form method="POST" action="/admin/logout" class="ml-2">
                        <input type="hidden" name="csrf_token" value="{{.CSRFToken}}">
                        <button type="submit" class="px-3 py-2 rounded-lg text-sm font-medium text-gray-300 hover:text-white hover:bg-gray-700">
                            <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M17 16l4-4m0 0l-4-4m4 4H7m6 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h4a3 3 0 013 3v1"/>
                            </svg>
                        </button>
                    </form>
                </div>
            </div>
        </div>
    </nav>

    <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        <!-- Stats Grid -->
        <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-5 gap-6 mb-8">
            <div class="bg-gray-800 rounded-2xl p-6 border border-gray-700">
                <div class="flex items-center justify-between">
                    <div>
                        <p class="text-gray-400 text-sm font-medium">In Progress</p>
                        <p id="stat-in-progress" class="text-3xl font-bold text-white mt-1">0</p>
                    </div>
                    <div class="w-12 h-12 bg-yellow-500/20 rounded-xl flex items-center justify-center">
                        <svg class="w-6 h-6 text-yellow-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z"/>
                        </svg>
                    </div>
                </div>
            </div>
            <div class="bg-gray-800 rounded-2xl p-6 border border-gray-700">
                <div class="flex items-center justify-between">
                    <div>
                        <p class="text-gray-400 text-sm font-medium">Total Requests</p>
                        <p id="stat-requests" class="text-3xl font-bold text-white mt-1">{{(index .Data "Stats").TotalRequestsToday}}</p>
                    </div>
                    <div class="w-12 h-12 bg-blue-500/20 rounded-xl flex items-center justify-center">
                        <svg class="w-6 h-6 text-blue-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"/>
                        </svg>
                    </div>
                </div>
            </div>
            
            <div class="bg-gray-800 rounded-2xl p-6 border border-gray-700">
                <div class="flex items-center justify-between">
                    <div>
                        <p class="text-gray-400 text-sm font-medium">Input Tokens</p>
                        <p id="stat-input-tokens" class="text-3xl font-bold text-white mt-1">{{formatInt (index .Data "Stats").TotalInputTokensToday}}</p>
                    </div>
                    <div class="w-12 h-12 bg-green-500/20 rounded-xl flex items-center justify-center">
                        <svg class="w-6 h-6 text-green-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M11 5H6a2 2 0 00-2 2v11a2 2 0 002 2h11a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z"/>
                        </svg>
                    </div>
                </div>
            </div>
            
            <div class="bg-gray-800 rounded-2xl p-6 border border-gray-700">
                <div class="flex items-center justify-between">
                    <div>
                        <p class="text-gray-400 text-sm font-medium">Output Tokens</p>
                        <p id="stat-output-tokens" class="text-3xl font-bold text-white mt-1">{{formatInt (index .Data "Stats").TotalOutputTokensToday}}</p>
                    </div>
                    <div class="w-12 h-12 bg-purple-500/20 rounded-xl flex items-center justify-center">
                        <svg class="w-6 h-6 text-purple-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"/>
                        </svg>
                    </div>
                </div>
            </div>
            
            <div class="bg-gray-800 rounded-2xl p-6 border border-gray-700">
                <div class="flex items-center justify-between">
                    <div>
                        <p class="text-gray-400 text-sm font-medium">Active Clients</p>
                        <p class="text-3xl font-bold text-white mt-1"><span id="stat-active-clients">{{(index .Data "Stats").ActiveClients}}</span> <span class="text-lg text-gray-500">/ <span id="stat-total-clients">{{(index .Data "Stats").TotalClients}}</span></span></p>
                    </div>
                    <div class="w-12 h-12 bg-emerald-500/20 rounded-xl flex items-center justify-center">
                        <svg class="w-6 h-6 text-emerald-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M17 20h5v-2a3 3 0 00-5.356-1.857M17 20H7m10 0v-2c0-.656-.126-1.283-.356-1.857M7 20H2v-2a3 3 0 015.356-1.857M7 20v-2c0-.656.126-1.283.356-1.857m0 0a5.002 5.002 0 019.288 0M15 7a3 3 0 11-6 0 3 3 0 016 0z"/>
                        </svg>
                    </div>
                </div>
            </div>
        </div>
        
        <!-- Charts Row - Compact Model Usage -->
        <div class="grid grid-cols-1 lg:grid-cols-3 gap-6 mb-6">
            <div class="bg-gray-800 rounded-2xl p-4 border border-gray-700 lg:col-span-2">
                <h3 class="text-sm font-semibold text-white mb-3">Top Models (Today)</h3>
                <div class="overflow-x-auto">
                    <table class="w-full text-sm">
                        <thead>
                            <tr class="text-left text-xs text-gray-400 border-b border-gray-700">
                                <th class="pb-2">Model</th>
                                <th class="pb-2 text-right">Requests</th>
                                <th class="pb-2 text-right">%</th>
                            </tr>
                        </thead>
                        <tbody id="modelUsageList" class="divide-y divide-gray-700">
                            <tr><td colspan="3" class="py-4 text-gray-500">Loading...</td></tr>
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
        
        <!-- Recent Requests -->
        <div class="bg-gray-800 rounded-2xl border border-gray-700 overflow-hidden">
            <div class="px-6 py-4 border-b border-gray-700 flex justify-between items-center">
                <h3 class="text-lg font-semibold text-white">Recent Requests</h3>
                <a href="/admin/stats" class="text-sm text-blue-400 hover:text-blue-300">View All</a>
            </div>
            <div class="overflow-x-auto">
                <table class="w-full">
                    <thead class="bg-gray-900/50">
                        <tr>
                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">Time</th>
                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">Client</th>
                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">Model</th>
                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">Status</th>
                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">Tokens</th>
                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">Runtime</th>
                        </tr>
                    </thead>
                    <tbody id="recent-logs" class="divide-y divide-gray-700">
                        {{range (index .Data "RecentLogs")}}
                        <tr class="hover:bg-gray-700/50 transition-colors">
                            <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-400">{{formatDate .CreatedAt}}</td>
                            <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-300 font-mono">{{.ClientID}}</td>
                            <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-300">{{.Model}}</td>
                            <td class="px-6 py-4 whitespace-nowrap">
                                <span class="px-2 py-1 text-xs font-medium rounded-full {{if ge .StatusCode 400}}bg-red-500/20 text-red-400{{else}}bg-green-500/20 text-green-400{{end}}">
                                    {{.StatusCode}}
                                </span>
                            </td>
                            <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-400">{{.InputTokens}} / {{.OutputTokens}}</td>
                            <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-400">{{formatDuration .LatencyMs}}</td>
                            <td class="px-6 py-4 whitespace-nowrap">
                                <div class="flex flex-wrap gap-1">
                                    {{if .IsStreaming}}<span class="text-xs px-2 py-0.5 bg-purple-500/20 text-purple-400 rounded-full">stream</span>{{end}}
                                    {{if .HasTools}}{{range splitToolNames .ToolNames}}<span class="text-xs px-2 py-0.5 bg-orange-500/20 text-orange-400 rounded-full">{{.}}</span>{{end}}{{end}}
                                    {{if .ErrorCode}}<span class="text-xs px-2 py-0.5 bg-red-500/20 text-red-400 rounded-full" title="bounded error code">{{.ErrorCode}}</span>{{end}}
                                </div>
                        </tr>
                        {{else}}
                        <tr>
                            <td colspan="6" class="px-6 py-8 text-center text-gray-500">No requests yet</td>
                        </tr>
                        {{end}}
                    </tbody>
                </table>
            </div>
        </div>

        <script>
        var chartColors = ['#3B82F6','#10B981','#8B5CF6','#F59E0B','#EF4444','#EC4899','#06B6D4','#F97316','#84CC16','#E879F9'];

        function formatDuration(ms) {
            if (ms < 1000) return ms + 'ms';
            if (ms < 60000) return (ms / 1000).toFixed(1) + 's';
            var mins = Math.floor(ms / 60000);
            var secs = Math.floor((ms % 60000) / 1000);
            return mins + 'm ' + secs + 's';
        }

        function initChart(usage) {
            var container = document.getElementById('modelUsageList');
            var labels = Object.keys(usage);
            var data = Object.values(usage);
            if (labels.length === 0) {
                container.innerHTML = '<tr><td colspan="3" class="py-4 text-gray-500">No usage data yet</td></tr>';
                return;
            }
            var total = data.reduce(function(a, b) { return a + b; }, 0);
            var html = '';
            var sorted = labels.map(function(label, i) {
                return { label: label, count: data[i] };
            }).sort(function(a, b) { return b.count - a.count; }).slice(0, 5);
            sorted.forEach(function(item) {
                var pct = total > 0 ? Math.round(item.count / total * 100) : 0;
                html += '<tr class="border-b border-gray-700 last:border-0">' +
                    '<td class="py-2 text-gray-300 font-mono text-xs truncate max-w-xs" title="' + item.label + '">' + item.label + '</td>' +
                    '<td class="py-2 text-gray-300 text-right font-mono">' + item.count + '</td>' +
                    '<td class="py-2 text-gray-400 text-right font-mono">' + pct + '%</td>' +
                '</tr>';
            });
            container.innerHTML = html;
        }

        function updateChart(usage) {
            initChart(usage);
        }

        function updateStats(stats) {
            document.getElementById('stat-requests').textContent = stats.total_requests_today.toLocaleString();
            document.getElementById('stat-input-tokens').textContent = (stats.total_input_tokens_today / 1000).toFixed(1) + 'k';
            document.getElementById('stat-output-tokens').textContent = (stats.total_output_tokens_today / 1000).toFixed(1) + 'k';
            document.getElementById('stat-active-clients').textContent = stats.active_clients;
            if (stats.requests_in_progress !== undefined) {
                document.getElementById('stat-in-progress').textContent = stats.requests_in_progress;
            }
        }

        function updateRecentLogs(logs) {
            var tbody = document.getElementById('recent-logs');
            if (!logs || logs.length === 0) {
                tbody.innerHTML = '<tr><td colspan="6" class="px-6 py-8 text-center text-gray-500">No requests yet</td></tr>';
                return;
            }
            var html = '';
            logs.forEach(function(l) {
                var statusClass = l.status_code >= 400 ? 'bg-red-500/20 text-red-400' : 'bg-green-500/20 text-green-400';
                html += '<tr class="hover:bg-gray-700/50 transition-colors">';
                html += '<td class="px-6 py-4 whitespace-nowrap text-sm text-gray-400">' + l.created_at + '</td>';
                html += '<td class="px-6 py-4 whitespace-nowrap text-sm text-gray-300 font-mono">' + l.client_id + '</td>';
                html += '<td class="px-6 py-4 whitespace-nowrap text-sm text-gray-300">' + l.model + '</td>';
                html += '<td class="px-6 py-4 whitespace-nowrap"><span class="px-2 py-1 text-xs font-medium rounded-full ' + statusClass + '">' + l.status_code + '</span></td>';
                html += '<td class="px-6 py-4 whitespace-nowrap text-sm text-gray-400">' + l.input_tokens + ' / ' + l.output_tokens + '</td>';
                html += '<td class="px-6 py-4 whitespace-nowrap text-sm text-gray-400">' + formatDuration(l.latency_ms) + '</td>';
                html += '<td class="px-6 py-4 whitespace-nowrap text-sm text-gray-400">';
                if (l.is_streaming) html += '<span class="text-xs px-2 py-0.5 bg-purple-500/20 text-purple-400 rounded-full">stream</span> ';
                if (l.has_tools && l.tool_names) {
                    var toolNames = l.tool_names.split(',');
                    toolNames.forEach(function(t) {
                        html += '<span class="text-xs px-2 py-0.5 bg-orange-500/20 text-orange-400 rounded-full">' + t + '</span> ';
                    });
                }
                if (l.error_code) html += '<span class="text-xs px-2 py-0.5 bg-red-500/20 text-red-400 rounded-full">' + l.error_code + '</span> ';
                html += '</td>';
                html += '</tr>';
            });
            tbody.innerHTML = html;
        }

        // WebSocket connection for real-time updates
        function connectWS() {
            console.log('[WS] Connecting to dashboard WebSocket...');
            var proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
            var wsUrl = proto + '//' + location.host + '/admin/ws';
            console.log('[WS] URL:', wsUrl);
            var ws = new WebSocket(wsUrl);

            ws.onopen = function() {
                console.log('[WS] Connected successfully');
            };
            ws.onerror = function(err) {
                console.error('[WS] Error:', err);
            };
            ws.onclose = function(e) {
                console.log('[WS] Closed:', e.code, e.reason);
            };
            ws.onmessage = function(event) {
                console.log('[WS] Received message');
                try {
                    var msg = JSON.parse(event.data);
                    if (msg.type === 'stats_update') {
                        console.log('[WS] Stats update:', msg.stats);
                        updateStats(msg.stats);
                        updateRecentLogs(msg.recent_logs);
                        updateChart(msg.model_usage);
                    }
                } catch (e) {
                    console.error('WS parse error:', e);
                }
            };

            ws.onclose = function() {
                // Reconnect after 3 seconds
                setTimeout(connectWS, 3000);
            };

            ws.onerror = function() {
                ws.close();
            };
        }

        // Initialize chart with server-rendered data, then connect WS
        document.addEventListener('DOMContentLoaded', function() {
            initChart({{toJson (index .Data "ModelUsage")}});
            connectWS();
        });
    </script>
</body>
</html>
{{end}}

{{define "clients.html"}}
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Clients - AI Gateway</title>
    <link rel="stylesheet" href="/static/style.css">
    <style>body { font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif; } .hidden { display: none; }</style>
    <script>
        document.addEventListener('DOMContentLoaded', function() {
            window.showModal = function(id) { var el = document.getElementById(id); if(el) el.classList.remove('hidden'); };
            window.hideModal = function(id) { var el = document.getElementById(id); if(el) el.classList.add('hidden'); };
        });
    </script>
</head>
<body class="bg-gray-900 min-h-screen">
    <nav class="bg-gray-800/80 backdrop-blur-md border-b border-gray-700 sticky top-0 z-50">
        <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
            <div class="flex items-center justify-between h-16">
                <div class="flex items-center space-x-3">
                    <div class="w-8 h-8 bg-gradient-to-br from-blue-500 to-blue-700 rounded-lg flex items-center justify-center">
                        <svg class="w-5 h-5 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 10V3L4 14h7v7l9-11h-7z"/>
                        </svg>
                    </div>
                    <span class="text-xl font-bold text-white">AI Gateway</span>
                </div>
                <div class="flex items-center space-x-1">
                    <a href="/admin/dashboard" class="px-3 py-2 rounded-lg text-sm font-medium text-gray-300 hover:text-white hover:bg-gray-700">Dashboard</a>
                    <a href="/admin/clients" class="px-3 py-2 rounded-lg text-sm font-medium text-white bg-gray-700">Clients</a>
                    <a href="/admin/stats" class="px-3 py-2 rounded-lg text-sm font-medium text-gray-300 hover:text-white hover:bg-gray-700">Stats</a>
                    <a href="/admin/server-tools" class="px-3 py-2 rounded-lg text-sm font-medium text-gray-300 hover:text-white hover:bg-gray-700">Server Tools</a>
                    <a href="https://github.com/DatanoiseTV/aigateway" target="_blank" class="px-3 py-2 rounded-lg text-gray-300 hover:text-white hover:bg-gray-700">
                        <svg class="w-5 h-5" fill="currentColor" viewBox="0 0 24 24">
                            <path fill-rule="evenodd" clip-rule="evenodd" d="M12 2C6.477 2 2 6.477 2 12c0 4.42 2.865 8.17 6.839 9.49.5.092.682-.217.682-.482 0-.237-.008-.866-.013-1.7-2.782.604-3.369-1.34-3.369-1.34-.454-1.156-1.11-1.464-1.11-1.464-.908-.62.069-.608.069-.608 1.003.07 1.531 1.03 1.531 1.03.892 1.529 2.341 1.087 2.91.831.092-.646.35-1.086.636-1.336-2.22-.253-4.555-1.11-4.555-4.943 0-1.091.39-1.984 1.029-2.683-.103-.253-.446-1.27.098-2.647 0 0 .84-.269 2.75 1.025A9.578 9.578 0 0112 6.836c.85.004 1.705.114 2.504.336 1.909-1.294 2.747-1.025 2.747-1.025.546 1.377.203 2.394.1 2.647.64.699 1.028 1.592 1.028 2.683 0 3.842-2.339 4.687-4.566 4.935.359.309.678.919.678 1.852 0 1.336-.012 2.415-.012 2.743 0 .267.18.578.688.48C19.138 20.167 22 16.418 22 12c0-5.523-4.477-10-10-10z"/>
                        </svg>
                    </a>
                    <form method="POST" action="/admin/logout" class="ml-2">
                        <input type="hidden" name="csrf_token" value="{{.CSRFToken}}">
                        <button type="submit" class="px-3 py-2 rounded-lg text-sm font-medium text-gray-300 hover:text-white hover:bg-gray-700">
                            <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M17 16l4-4m0 0l-4-4m4 4H7m6 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h4a3 3 0 013 3v1"/>
                            </svg>
                        </button>
                    </form>
                </div>
            </div>
        </div>
    </nav>

    <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        <div class="flex justify-between items-center mb-8">
            <div>
                <h1 class="text-3xl font-bold text-white">Clients</h1>
                <p class="text-gray-400 mt-1">Manage API clients and their quotas</p>
            </div>
            <button onclick="showModal('createModal')" 
                class="bg-gradient-to-r from-blue-600 to-blue-700 text-white px-5 py-2.5 rounded-xl font-medium hover:from-blue-700 hover:to-blue-800 transition-all flex items-center space-x-2">
                <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4v16m8-8H4"/>
                </svg>
                <span>New Client</span>
            </button>
        </div>

        <div class="bg-gray-800 rounded-2xl border border-gray-700 overflow-hidden">
            <table class="w-full">
                <thead class="bg-gray-900/50">
                    <tr>
                        <th class="px-6 py-4 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">Client</th>
                        <th class="px-6 py-4 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">Status</th>
                        <th class="px-6 py-4 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">Requests</th>
                        <th class="px-6 py-4 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">Input Tokens</th>
                        <th class="px-6 py-4 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">Output Tokens</th>
                        <th class="px-6 py-4 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">Created</th>
                        <th class="px-6 py-4 text-right text-xs font-medium text-gray-400 uppercase tracking-wider">Actions</th>
                    </tr>
                </thead>
                <tbody class="divide-y divide-gray-700">
                    {{$root := .}}
                    {{range .Data.Clients}}
                    <tr class="hover:bg-gray-700/50 transition-colors">
                        <td class="px-6 py-4">
                            <a href="/admin/clients/{{.ID}}" class="flex items-center space-x-3">
                                <div class="w-10 h-10 bg-gradient-to-br from-blue-500/20 to-purple-500/20 rounded-xl flex items-center justify-center">
                                    <span class="text-blue-400 font-semibold">{{slice .Name 0 1}}</span>
                                </div>
                                <div>
                                    <div class="text-white font-medium">{{.Name}}</div>
                                    <div class="text-gray-500 text-sm">{{.Description}}</div>
                                </div>
                            </a>
                        </td>
                        <td class="px-6 py-4">
                            <form method="POST" action="/admin/clients/{{.ID}}/toggle">
                                <input type="hidden" name="csrf_token" value="{{.CSRFToken}}">
                                <button type="submit" class="px-3 py-1 text-xs font-medium rounded-full {{if .IsActive}}bg-green-500/20 text-green-400{{else}}bg-red-500/20 text-red-400{{end}} hover:opacity-80 transition-opacity">
                                    {{if .IsActive}}Active{{else}}Disabled{{end}}
                                </button>
                            </form>
                        </td>
                        <td class="px-6 py-4">
                            <div class="flex items-center space-x-2">
                                <div class="w-24 bg-gray-700 rounded-full h-2">
                                    <div class="bg-blue-500 h-2 rounded-full" style="width: {{with (index $root.Data.ClientStats .ID)}}{{percentUsed .RequestsToday .RequestsLimit}}{{else}}0{{end}}%"></div>
                                </div>
                                <span class="text-gray-400 text-sm">
                                    {{with (index $root.Data.ClientStats .ID)}}{{.RequestsToday}}{{else}}0{{end}} / {{.QuotaRequestsDay}}
                                </span>
                            </div>
                        </td>
                        <td class="px-6 py-4">
                            <div class="flex items-center space-x-2">
                                <div class="w-24 bg-gray-700 rounded-full h-2">
                                    <div class="bg-green-500 h-2 rounded-full" style="width: {{with (index $root.Data.ClientStats .ID)}}{{percentUsed .InputTokensToday .InputTokensLimit}}{{else}}0{{end}}%"></div>
                                </div>
                                <span class="text-gray-400 text-sm">
                                    {{with (index $root.Data.ClientStats .ID)}}{{.InputTokensToday}}{{else}}0{{end}} / {{.QuotaInputTokensDay}}
                                </span>
                            </div>
                        </td>
                        <td class="px-6 py-4">
                            <div class="flex items-center space-x-2">
                                <div class="w-24 bg-gray-700 rounded-full h-2">
                                    <div class="bg-purple-500 h-2 rounded-full" style="width: {{with (index $root.Data.ClientStats .ID)}}{{percentUsed .OutputTokensToday .OutputTokensLimit}}{{else}}0{{end}}%"></div>
                                </div>
                                <span class="text-gray-400 text-sm">
                                    {{with (index $root.Data.ClientStats .ID)}}{{.OutputTokensToday}}{{else}}0{{end}} / {{.QuotaOutputTokensDay}}
                                </span>
                            </div>
                        </td>
                        <td class="px-6 py-4 text-gray-400 text-sm">{{formatDate .CreatedAt}}</td>
                        <td class="px-6 py-4 text-right">
                            <a href="/admin/clients/{{.ID}}" class="text-blue-400 hover:text-blue-300 font-medium">Manage</a>
                        </td>
                    </tr>
                    {{else}}
                    <tr>
                        <td colspan="7" class="px-6 py-12 text-center">
                            <div class="flex flex-col items-center">
                                <svg class="w-12 h-12 text-gray-600 mb-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M17 20h5v-2a3 3 0 00-5.356-1.857M17 20H7m10 0v-2c0-.656-.126-1.283-.356-1.857M7 20H2v-2a3 3 0 015.356-1.857M7 20v-2c0-.656.126-1.283.356-1.857m0 0a5.002 5.002 0 019.288 0M15 7a3 3 0 11-6 0 3 3 0 016 0z"/>
                                </svg>
                                <p class="text-gray-500">No clients yet</p>
                                <button onclick="showModal('createModal')" class="mt-2 text-blue-400 hover:text-blue-300 font-medium">Create your first client</button>
                            </div>
                        </td>
                    </tr>
                    {{end}}
                </tbody>
            </table>
        </div>
    </div>
    
    <!-- Create Modal -->
    <div id="createModal" class="hidden fixed inset-0 bg-black/70 backdrop-blur-sm flex items-start justify-center z-50 p-4 overflow-y-auto">
        <div class="bg-gray-800 border border-gray-700 rounded-2xl w-full max-w-md p-4 my-4">
            <div class="flex justify-between items-center mb-4">
                <h2 class="text-lg font-bold text-white">New Client</h2>
                <button onclick="hideModal('createModal')" class="text-gray-400 hover:text-white">
                    <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"/>
                    </svg>
                </button>
            </div>
            <form method="POST" action="/admin/clients">
                <input type="hidden" name="csrf_token" value="{{.CSRFToken}}">
                <div class="space-y-3">
                    <div>
                        <label class="block text-gray-400 text-xs font-medium my-2">Name</label>
                        <input type="text" name="name" required placeholder="My App" class="w-full px-3 py-2 bg-gray-900 border border-gray-600 text-white text-sm rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500">
                    </div>
                    <div class="grid grid-cols-2 gap-2">
                        <div>
                            <label class="block text-gray-400 text-xs font-medium my-2">API Key</label>
                            <select name="key_type" onchange="toggleCustomPrefix(this)" class="w-full px-3 py-2 bg-gray-900 border border-gray-600 text-white text-sm rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500">
                                <option value="gemini">gm_</option>
                                <option value="openai">sk-</option>
                                <option value="anthropic">sk-ant-</option>
                                <option value="custom">Custom</option>
                            </select>
                        </div>
                        <div id="customPrefixDiv" class="hidden">
                            <label class="block text-gray-400 text-xs font-medium my-2">Prefix</label>
                            <input type="text" name="key_prefix" placeholder="myapp_" class="w-full px-3 py-2 bg-gray-900 border border-gray-600 text-white text-sm rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500">
                        </div>
                    </div>
                    <script>function toggleCustomPrefix(el) { var div = document.getElementById('customPrefixDiv'); div.className = el.value === 'custom' ? '' : 'hidden'; }</script>
                    <div class="grid grid-cols-2 gap-2">
                        <div>
                            <label class="block text-gray-400 text-xs font-medium my-2">Backend</label>
                            <select name="backend" class="w-full px-3 py-2 bg-gray-900 border border-gray-600 text-white text-sm rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500">
                                {{range (index .Data "Providers")}}<option value="{{.}}" {{if eq . "gemini"}}selected{{end}}>{{.}}</option>{{end}}
                            </select>
                        </div>
                        <div>
                            <label class="block text-gray-400 text-xs font-medium my-2">Model</label>
                            <input type="text" name="backend_default_model" placeholder="optional" class="w-full px-3 py-2 bg-gray-900 border border-gray-600 text-white text-sm rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500">
                        </div>
                    </div>
                    <div>
                        <label class="block text-gray-400 text-xs font-medium my-2">API Key <span class="text-gray-500">(optional)</span></label>
                        <input type="password" name="backend_api_key" placeholder="Per-client upstream key" class="w-full px-3 py-2 bg-gray-900 border border-gray-600 text-white text-sm rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500">
                    </div>
                    <details class="text-xs">
                        <summary class="text-gray-400 cursor-pointer hover:text-white py-1">Advanced options</summary>
                        <div class="space-y-2 pt-2">
                            <div>
                                <label class="block text-gray-500 text-xs my-2">Base URL</label>
                                <input type="text" name="backend_base_url" placeholder="http://localhost:11434" class="w-full px-3 py-2 bg-gray-900 border border-gray-600 text-white text-sm rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500">
                            </div>
                            <div>
                                <label class="block text-gray-500 text-xs my-2">Description</label>
                                <textarea name="description" rows="1" placeholder="Optional" class="w-full px-3 py-2 bg-gray-900 border border-gray-600 text-white text-sm rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"></textarea>
                            </div>
                            <div>
                                <label class="block text-gray-500 text-xs my-2">System Prompt</label>
                                <textarea name="system_prompt" rows="2" placeholder="Optional" class="w-full px-3 py-2 bg-gray-900 border border-gray-600 text-white text-sm rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"></textarea>
                            </div>
                            <div class="flex items-center">
                                <input type="checkbox" name="server_tools" id="server_tools_create" class="w-4 h-4 rounded bg-gray-900 border-gray-600 text-blue-600 focus:ring-blue-500">
                                <label for="server_tools_create" class="ml-2 text-gray-400 text-sm">Enable server tools (http_get, tcp_connect, etc.)</label>
                            </div>
                        </div>
                    </details>
                </div>
                <div class="flex space-x-2 mt-4">
                    <button type="button" onclick="hideModal('createModal')" class="flex-1 px-3 py-2 bg-gray-700 text-white text-sm rounded-lg hover:bg-gray-600">Cancel</button>
                    <button type="submit" class="flex-1 px-3 py-2 bg-blue-600 text-white text-sm rounded-lg hover:bg-blue-700">Create</button>
                </div>
            </form>
        </div>
    </div>
</body>
</html>
{{end}}

{{define "client_detail.html"}}
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>{{.Title}} - AI Gateway</title>
    <link rel="stylesheet" href="/static/style.css">
    <script src="/static/chart.js"></script>
    <style>body { font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif; }</style>
</head>
<body class="bg-gray-900 min-h-screen">
    <nav class="bg-gray-800/80 backdrop-blur-md border-b border-gray-700 sticky top-0 z-50">
        <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
            <div class="flex items-center justify-between h-16">
                <div class="flex items-center space-x-3">
                    <a href="/admin/clients" class="text-gray-400 hover:text-white">
                        <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 19l-7-7 7-7"/>
                        </svg>
                    </a>
                    <div class="w-8 h-8 bg-gradient-to-br from-blue-500 to-blue-700 rounded-lg flex items-center justify-center">
                        <span class="text-white font-semibold text-sm">{{slice (index .Data "Client").Name 0 1}}</span>
                    </div>
                    <span class="text-xl font-bold text-white">{{(index .Data "Client").Name}}</span>
                    {{if (index .Data "Client").IsActive}}
                    <span class="px-2 py-0.5 text-xs font-medium bg-green-500/20 text-green-400 rounded-full">Active</span>
                    {{else}}
                    <span class="px-2 py-0.5 text-xs font-medium bg-red-500/20 text-red-400 rounded-full">Disabled</span>
                    {{end}}
                </div>
                <div class="flex items-center space-x-1">
                    <a href="/admin/dashboard" class="px-3 py-2 rounded-lg text-sm font-medium text-gray-300 hover:text-white hover:bg-gray-700">Dashboard</a>
                    <a href="/admin/clients" class="px-3 py-2 rounded-lg text-sm font-medium text-gray-300 hover:text-white hover:bg-gray-700">Clients</a>
                    <a href="/admin/stats" class="px-3 py-2 rounded-lg text-sm font-medium text-gray-300 hover:text-white hover:bg-gray-700">Stats</a>
                    <a href="https://github.com/DatanoiseTV/aigateway" target="_blank" class="px-3 py-2 rounded-lg text-gray-300 hover:text-white hover:bg-gray-700">
                        <svg class="w-5 h-5" fill="currentColor" viewBox="0 0 24 24">
                            <path fill-rule="evenodd" clip-rule="evenodd" d="M12 2C6.477 2 2 6.477 2 12c0 4.42 2.865 8.17 6.839 9.49.5.092.682-.217.682-.482 0-.237-.008-.866-.013-1.7-2.782.604-3.369-1.34-3.369-1.34-.454-1.156-1.11-1.464-1.11-1.464-.908-.62.069-.608.069-.608 1.003.07 1.531 1.03 1.531 1.03.892 1.529 2.341 1.087 2.91.831.092-.646.35-1.086.636-1.336-2.22-.253-4.555-1.11-4.555-4.943 0-1.091.39-1.984 1.029-2.683-.103-.253-.446-1.27.098-2.647 0 0 .84-.269 2.75 1.025A9.578 9.578 0 0112 6.836c.85.004 1.705.114 2.504.336 1.909-1.294 2.747-1.025 2.747-1.025.546 1.377.203 2.394.1 2.647.64.699 1.028 1.592 1.028 2.683 0 3.842-2.339 4.687-4.566 4.935.359.309.678.919.678 1.852 0 1.336-.012 2.415-.012 2.743 0 .267.18.578.688.48C19.138 20.167 22 16.418 22 12c0-5.523-4.477-10-10-10z"/>
                        </svg>
                    </a>
                    <form method="POST" action="/admin/logout" class="ml-2">
                        <input type="hidden" name="csrf_token" value="{{.CSRFToken}}">
                        <button type="submit" class="px-3 py-2 rounded-lg text-sm font-medium text-gray-300 hover:text-white hover:bg-gray-700">
                            <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M17 16l4-4m0 0l-4-4m4 4H7m6 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h4a3 3 0 013 3v1"/>
                            </svg>
                        </button>
                    </form>
                </div>
            </div>
        </div>
    </nav>

    <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        <script>
        var clientID = "{{(index .Data "Client").ID}}";
        
        function connectWS() {
            var proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
            var ws = new WebSocket(proto + '//' + location.host + '/admin/ws');

            ws.onmessage = function(event) {
                try {
                    var msg = JSON.parse(event.data);
                    if (msg.type === 'stats_update') {
                        // Check if this update is for our client
                        if (msg.client_stats && msg.client_stats[clientID]) {
                            var s = msg.client_stats[clientID];
                            var reqEl = document.getElementById('client-requests');
                            var inEl = document.getElementById('client-input');
                            var outEl = document.getElementById('client-output');
                            if (reqEl) reqEl.textContent = s.requests_today;
                            if (inEl) inEl.textContent = s.input_tokens.toLocaleString();
                            if (outEl) outEl.textContent = s.output_tokens.toLocaleString();
                        }
                    }
                } catch (e) {
                    console.error('WS parse error:', e);
                }
            };

            ws.onclose = function() {
                setTimeout(connectWS, 3000);
            };

            ws.onerror = function() {
                ws.close();
            };
        }
        
        // Also poll as fallback
        (function pollClientStats() {
            fetch('/admin/stats/api')
                .then(function(res) { return res.json(); })
                .then(function(data) {
                    // Could add client-specific stats here if available
                })
                .catch(function() {});
            setTimeout(pollClientStats, 3000);
        })();
        
        connectWS();
        </script>
        
        <!-- Stats Cards -->
        <div class="grid grid-cols-2 lg:grid-cols-4 gap-4 mb-6">
            <div class="bg-gray-800 rounded-xl p-4 border border-gray-700">
                <p class="text-gray-400 text-xs font-medium">Requests Today</p>
                <p class="text-2xl font-bold text-white mt-1">{{(index .Data "Stats").RequestsToday}}</p>
            </div>
            <div class="bg-gray-800 rounded-xl p-4 border border-gray-700">
                <p class="text-gray-400 text-xs font-medium">Input Tokens</p>
                <p class="text-2xl font-bold text-white mt-1">{{formatInt (index .Data "Stats").InputTokensToday}}</p>
            </div>
            <div class="bg-gray-800 rounded-xl p-4 border border-gray-700">
                <p class="text-gray-400 text-xs font-medium">Output Tokens</p>
                <p class="text-2xl font-bold text-white mt-1">{{formatInt (index .Data "Stats").OutputTokensToday}}</p>
            </div>
            <div class="bg-gray-800 rounded-xl p-4 border border-gray-700">
                <p class="text-gray-400 text-xs font-medium">Error Rate</p>
                <p class="text-2xl font-bold text-white mt-1">{{printf "%.1f" (index .Data "Stats").ErrorRate}}%</p>
            </div>
        </div>

        <!-- Charts Row -->
        <div class="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-8">
            <!-- Settings Form -->
            <div class="bg-gray-800 rounded-2xl p-6 border border-gray-700">
                <h3 class="text-lg font-semibold text-white mb-6">Client Settings</h3>
                <form method="POST" action="/admin/clients/{{(index .Data "Client").ID}}/update">
                    <input type="hidden" name="csrf_token" value="{{.CSRFToken}}">
                    <div class="grid grid-cols-2 gap-4 mb-4">
                        <div>
                            <label class="block text-gray-400 text-sm font-medium mb-2">Rate (req/min)</label>
                            <input type="number" name="rate_limit_minute" value="{{(index .Data "Client").RateLimitMinute}}" class="w-full px-4 py-2 bg-gray-900 border border-gray-600 text-white rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500">
                        </div>
                        <div>
                            <label class="block text-gray-400 text-sm font-medium mb-2">Rate (req/hour)</label>
                            <input type="number" name="rate_limit_hour" value="{{(index .Data "Client").RateLimitHour}}" class="w-full px-4 py-2 bg-gray-900 border border-gray-600 text-white rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500">
                        </div>
                        <div>
                            <label class="block text-gray-400 text-sm font-medium mb-2">Rate (req/day)</label>
                            <input type="number" name="rate_limit_day" value="{{(index .Data "Client").RateLimitDay}}" class="w-full px-4 py-2 bg-gray-900 border border-gray-600 text-white rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500">
                        </div>
                        <div>
                            <label class="block text-gray-400 text-sm font-medium mb-2">Quota (requests/day)</label>
                            <input type="number" name="quota_requests" value="{{(index .Data "Client").QuotaRequestsDay}}" class="w-full px-4 py-2 bg-gray-900 border border-gray-600 text-white rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500">
                        </div>
                        <div>
                            <label class="block text-gray-400 text-sm font-medium mb-2">Quota (input tokens)</label>
                            <input type="number" name="quota_input_tokens" value="{{(index .Data "Client").QuotaInputTokensDay}}" class="w-full px-4 py-2 bg-gray-900 border border-gray-600 text-white rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500">
                        </div>
                        <div>
                            <label class="block text-gray-400 text-sm font-medium mb-2">Quota (output tokens/day)</label>
                            <input type="number" name="quota_output_tokens" value="{{(index .Data "Client").QuotaOutputTokensDay}}" class="w-full px-4 py-2 bg-gray-900 border border-gray-600 text-white rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500">
                        </div>
                        <div>
                            <label class="block text-gray-400 text-sm font-medium mb-2">Max input tokens/request</label>
                            <input type="number" name="max_input_tokens" value="{{(index .Data "Client").MaxInputTokens}}" class="w-full px-4 py-2 bg-gray-900 border border-gray-600 text-white rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500">
                            <p class="text-gray-500 text-xs mt-1">0 = unlimited</p>
                        </div>
                        <div>
                            <label class="block text-gray-400 text-sm font-medium mb-2">Max output tokens/request</label>
                            <input type="number" name="max_output_tokens" value="{{(index .Data "Client").MaxOutputTokens}}" class="w-full px-4 py-2 bg-gray-900 border border-gray-600 text-white rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500">
                            <p class="text-gray-500 text-xs mt-1">0 = unlimited</p>
                        </div>
                    </div>
                    <div class="mb-6">
                        <label class="block text-gray-400 text-sm font-medium mb-2">Client Name</label>
                        <input type="text" name="name" value="{{(index .Data "Client").Name}}" class="w-full px-4 py-2 bg-gray-900 border border-gray-600 text-white rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500">
                    </div>
                    <div class="mb-6">
                        <label class="block text-gray-400 text-sm font-medium mb-2">Description</label>
                        <textarea name="description" rows="2" class="w-full px-4 py-2 bg-gray-900 border border-gray-600 text-white rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500">{{(index .Data "Client").Description}}</textarea>
                    </div>
                    <div class="grid grid-cols-2 gap-4 mb-6">
                        <div>
                            <label class="block text-gray-400 text-sm font-medium mb-2">Backend Provider</label>
                            <select name="backend" id="backendSelect" class="w-full px-4 py-2 bg-gray-900 border border-gray-600 text-white rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500">
                                {{range (index .Data "Providers")}}<option value="{{.}}" {{if eq . (index $.Data "Client").Backend}}selected{{end}}>{{.}}</option>{{end}}
                            </select>
                        </div>
                        <div>
                            <label class="block text-gray-400 text-sm font-medium mb-2">Default Model</label>
                            <div class="flex space-x-2">
                                <input type="text" name="backend_default_model" value="{{(index .Data "Client").BackendDefaultModel}}" placeholder="e.g. gemini-2.0-flash-lite-001" class="w-full px-4 py-2 bg-gray-900 border border-gray-600 text-white rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500">
                                <button type="button" onclick="fetchModels()" class="px-3 py-2 bg-purple-600 hover:bg-purple-700 text-white rounded-lg text-sm" title="Fetch available models from backend">
                                    <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"/>
                                    </svg>
                                </button>
                            </div>
                        </div>
                    </div>
                    <div class="mb-6">
                        <label class="block text-gray-400 text-sm font-medium mb-2">Backend API Key</label>
                        {{if (index .Data "Client").HasBackendKey}}<p class="text-green-400 text-xs mb-1">Provider key configured</p>{{else}}<p class="text-gray-500 text-xs mb-1">No per-client key — using global provider config.</p>{{end}}
                        <input type="password" name="backend_api_key" value="" placeholder="Enter a new key to replace (leave empty to keep current)" class="w-full px-4 py-2 bg-gray-900 border border-gray-600 text-white rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500">
                        <label class="flex items-center text-gray-300 mt-2">
                            <input type="checkbox" name="clear_backend_api_key" class="w-4 h-4 rounded bg-gray-900 border-gray-600 text-red-600 focus:ring-red-500">
                            <span class="ml-2">Clear stored provider key (revert to global config)</span>
                        </label>
                        <p class="text-gray-500 text-xs mt-1">Stored keys are encrypted at rest and never re-displayed. Leave empty to keep the current key.</p>
                    </div>
                    <div class="mb-6">
                        <label class="block text-gray-400 text-sm font-medium mb-2">Base URL Override</label>
                        <div class="flex space-x-2">
                            <input type="text" name="backend_base_url" value="{{(index .Data "Client").BackendBaseURL}}" placeholder="Leave empty for default" class="w-full px-4 py-2 bg-gray-900 border border-gray-600 text-white rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500">
                            <button type="button" onclick="testConnection()" class="px-4 py-2 bg-green-600 hover:bg-green-700 text-white rounded-lg text-sm flex items-center space-x-1" title="Test connection to backend">
                                <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 10V3L4 14h7v7l9-11h-7z"/>
                                </svg>
                                <span>Test</span>
                            </button>
                        </div>
                        <p class="text-gray-500 text-xs mt-1">For Ollama, LM Studio, Azure, or custom endpoints</p>
                    </div>
                    <div class="mb-6">
                        <label class="block text-gray-400 text-sm font-medium mb-2">System Prompt</label>
                        <textarea name="system_prompt" rows="3" placeholder="Injected as system message on every request from this client" class="w-full px-4 py-2 bg-gray-900 border border-gray-600 text-white rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500">{{(index .Data "Client").SystemPrompt}}</textarea>
                        <p class="text-gray-500 text-xs mt-1">Prepended before the user's messages. Leave empty to disable.</p>
                    </div>
                    <div class="mb-6">
                        <label class="block text-gray-400 text-sm font-medium mb-2">Tool Mode</label>
                        <select name="tool_mode" class="w-full px-4 py-2 bg-gray-900 border border-gray-600 text-white rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500">
                            <option value="pass-through" {{if or (eq (index .Data "Client").ToolMode "pass-through" (index .Data "Client").ToolMode "")}}selected{{end}}>Pass-through (forward to client)</option>
                            <option value="gateway" {{if eq (index .Data "Client").ToolMode "gateway"}}selected{{end}}>Gateway (execute tools internally)</option>
                        </select>
                        <p class="text-gray-500 text-xs mt-1">Pass-through forwards tool_calls to the client (opencode) for execution.</p>
                    </div>
                    <div class="mb-6">
                        <label class="block text-gray-400 text-sm font-medium mb-2">Fallback Models</label>
                        <input type="text" name="fallback_models" placeholder="claude-3-haiku,claude-3-sonnet" value="{{(index .Data "Client").FallbackModels}}" class="w-full px-4 py-2 bg-gray-900 border border-gray-600 text-white rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500">
                        <p class="text-gray-500 text-xs mt-1">Comma-separated list of models to try if the primary model fails (rate limit, quota, server errors). Tried in order.</p>
                    </div>
                    <div class="mb-6">
                        <label class="flex items-center text-gray-300">
                            <input type="checkbox" name="server_tools" {{if (index .Data "Client").ServerTools}}checked{{end}} class="w-5 h-5 rounded bg-gray-900 border-gray-600 text-blue-600 focus:ring-blue-500">
                            <span class="ml-2">Enable Server Tools</span>
                        </label>
                        <p class="text-gray-500 text-xs mt-1">Enable server-provided tools: http_get, tcp_connect, udp_connect, ssh_to_host, get_time, get_date, get_last_commits_from_url, ripgrep_style_grep, sed, send_http_request_json</p>
                    </div>

                    <!-- Model Whitelist -->
                    <div class="mb-6">
                        <label class="block text-gray-400 text-sm font-medium mb-2">Allowed Models (Whitelist)</label>
                        <div id="modelsList" class="bg-gray-900 border border-gray-600 rounded-lg p-3 max-h-48 overflow-y-auto">
                            <p class="text-gray-500 text-sm">Click "Fetch Models" to load available models from your backend, then select which models this client can use.</p>
                        </div>
                        <div id="selectedModels" class="mt-2 flex flex-wrap gap-2"></div>
                        <input type="hidden" name="models_list" id="modelsInput">
                        <p class="text-gray-500 text-xs mt-1">Leave empty to allow all models. Click "Fetch Models" button above to discover available models.</p>
                    </div>

                    <div class="flex items-center justify-between">
                        <label class="flex items-center text-gray-300">
                            <input type="checkbox" name="is_active" {{if (index .Data "Client").IsActive}}checked{{end}} class="w-5 h-5 rounded bg-gray-900 border-gray-600 text-blue-600 focus:ring-blue-500">
                            <span class="ml-2">Active</span>
                        </label>
                        <button type="submit" class="bg-blue-600 text-white px-6 py-2 rounded-lg hover:bg-blue-700 transition-colors">Save Changes</button>
                    </div>
                </form>
            </div>

            <!-- Danger Zone -->
            <div class="bg-gray-800 rounded-2xl p-6 border border-gray-700">
                <h3 class="text-lg font-semibold text-white mb-6">Danger Zone</h3>
                
                <div class="space-y-4">
                    <div class="p-4 bg-gray-900/50 rounded-xl">
                        <div class="flex items-center justify-between">
                            <div>
                                <p class="text-white font-medium">Regenerate API Key</p>
                                <p class="text-gray-500 text-sm">Invalidates the current key and generates a new one</p>
                            </div>
                            <form method="POST" action="/admin/clients/{{(index .Data "Client").ID}}/regenerate" class="flex items-center space-x-2">
                                <input type="hidden" name="csrf_token" value="{{.CSRFToken}}">
                                <select name="key_type" onchange="toggleRegenPrefix(this)" class="px-3 py-2 bg-gray-800 border border-gray-600 text-white text-sm rounded-lg focus:outline-none focus:ring-2 focus:ring-yellow-500">
                                    <option value="gemini">gm_</option>
                                    <option value="openai">sk-</option>
                                    <option value="anthropic">sk-ant-</option>
                                    <option value="custom">Custom</option>
                                </select>
                                <input type="text" name="key_prefix" placeholder="prefix_" class="hidden px-2 py-2 bg-gray-800 border border-gray-600 text-white text-sm rounded-lg focus:outline-none focus:ring-2 focus:ring-yellow-500 w-24">
                                <button type="submit" class="px-4 py-2 bg-yellow-600/20 text-yellow-400 border border-yellow-600/50 rounded-lg hover:bg-yellow-600/30 transition-colors">Regenerate</button>
                            </form>
                        </div>
                    </div>
                    <script>function toggleRegenPrefix(el) { var input = el.nextElementSibling; input.className = el.value === 'custom' ? 'px-2 py-2 bg-gray-800 border border-gray-600 text-white text-sm rounded-lg focus:outline-none focus:ring-2 focus:ring-yellow-500 w-24' : 'hidden px-2 py-2 bg-gray-800 border border-gray-600 text-white text-sm rounded-lg focus:outline-none focus:ring-2 focus:ring-yellow-500 w-24'; }</script>
                    
                    <div class="p-4 bg-red-500/10 rounded-xl border border-red-500/30">
                        <div class="flex items-center justify-between">
                            <div>
                                <p class="text-white font-medium">Delete Client</p>
                                <p class="text-gray-500 text-sm">Permanently delete this client and all associated data</p>
                            </div>
                            <form method="POST" action="/admin/clients/{{(index .Data "Client").ID}}/delete" onsubmit="return confirm('Are you sure? This cannot be undone.')">
                                <input type="hidden" name="csrf_token" value="{{.CSRFToken}}">
                                <button type="submit" class="px-4 py-2 bg-red-600/20 text-red-400 border border-red-600/50 rounded-lg hover:bg-red-600/30 transition-colors">Delete</button>
                            </form>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <!-- Request Logs -->
        <div class="bg-gray-800 rounded-2xl border border-gray-700 overflow-hidden">
            <div class="px-6 py-4 border-b border-gray-700">
                <h3 class="text-lg font-semibold text-white">Request History</h3>
            </div>
            <div class="overflow-x-auto">
                <table class="w-full">
                    <thead class="bg-gray-900/50">
                        <tr>
                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase">Time</th>
                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase">Request</th>
                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase">Provider</th>
                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase">Model</th>
                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase">Status</th>
                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase">Runtime</th>
                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase">In / Out</th>
                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase">Flags</th>
                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase">Error</th>
                        </tr>
                    </thead>
                    <tbody class="divide-y divide-gray-700">
                        {{range (index .Data "RecentLogs")}}
                        <tr class="hover:bg-gray-700/50">
                            <td class="px-6 py-4 text-sm text-gray-400">{{formatDate .CreatedAt}}</td>
                            <td class="px-6 py-4 text-sm text-white">{{.Model}}</td>
                            <td class="px-6 py-4">
                                <span class="px-2 py-1 text-xs font-medium rounded-full {{if ge .StatusCode 400}}bg-red-500/20 text-red-400{{else}}bg-green-500/20 text-green-400{{end}}">
                                    {{.StatusCode}}
                                </span>
                            </td>
                            <td class="px-6 py-4 text-sm text-gray-400">{{formatDuration .LatencyMs}}</td>
                            <td class="px-6 py-4 text-sm text-gray-400">{{.InputTokens}} / {{.OutputTokens}}</td>
                            <td class="px-6 py-4">
                                <div class="flex items-center gap-1">
                                    {{if .IsStreaming}}<span class="inline-flex items-center gap-1 text-xs px-1.5 py-0.5 bg-purple-500/20 text-purple-400 rounded">stream</span>{{end}}
                                    {{if .HasTools}}<span class="inline-flex items-center gap-1 text-xs px-1.5 py-0.5 bg-orange-500/20 text-orange-400 rounded">tools</span>{{end}}
                                    {{if .ErrorCode}}<span class="inline-flex items-center gap-1 text-xs px-1.5 py-0.5 bg-red-500/20 text-red-400 rounded" title="bounded error code">{{.ErrorCode}}</span>{{end}}
                                </div>
                            </td>
                            <td class="px-6 py-4 text-sm text-gray-500 font-mono max-w-xs truncate">{{.RequestID}}</td>
                            <td class="px-6 py-4 text-sm text-gray-300">{{.Provider}}</td>
                            <td class="px-6 py-4 text-sm text-red-400 max-w-xs truncate">{{.ErrorCode}}</td>
                        </tr>
                        {{else}}
                        <tr>
                            <td colspan="9" class="px-6 py-8 text-center text-gray-500">No requests yet</td>
                        </tr>
                        {{end}}
                    </tbody>
                </table>
            </div>
        </div>
    </div>

    <!-- Toast Notification -->
    <div id="toast" class="fixed bottom-4 right-4 px-6 py-3 rounded-lg text-white font-medium hidden transition-opacity duration-300"></div>

    <script>
        var clientID = "{{(index .Data "Client").ID}}";
        var currentModels = {{toJson (index .Data "Client").BackendModels}};
        if (!Array.isArray(currentModels)) currentModels = [];

        function showToast(message, isSuccess) {
            var toast = document.getElementById('toast');
            toast.textContent = message;
            toast.className = 'fixed bottom-4 right-4 px-6 py-3 rounded-lg text-white font-medium transition-opacity duration-300 ' + (isSuccess ? 'bg-green-600' : 'bg-red-600');
            toast.classList.remove('hidden');
            setTimeout(function() {
                toast.classList.add('hidden');
            }, 3000);
        }

        function testConnection() {
            var btn = event.target.closest('button');
            btn.disabled = true;
            btn.innerHTML = '<svg class="w-4 h-4 animate-spin" fill="none" stroke="currentColor" viewBox="0 0 24 24"><circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle><path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path></svg>';

            fetch('/admin/clients/' + clientID + '/test')
                .then(function(res) { return res.json(); })
                .then(function(data) {
                    showToast(data.message, data.success);
                })
                .catch(function(err) {
                    showToast('Error: ' + err.message, false);
                })
                .finally(function() {
                    btn.disabled = false;
                    btn.innerHTML = '<svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 10V3L4 14h7v7l9-11h-7z"/></svg><span class="ml-1">Test</span>';
                });
        }

        function fetchModels() {
            var btn = event.target.closest('button');
            btn.disabled = true;
            btn.innerHTML = '<svg class="w-5 h-5 animate-spin" fill="none" stroke="currentColor" viewBox="0 0 24 24"><circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle><path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm291A7.962 7.2 5.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path></svg>';

            fetch('/admin/clients/' + clientID + '/fetch-models')
                .then(function(res) { return res.json(); })
                .then(function(data) {
                    if (data.success) {
                        showToast('Loaded ' + data.models.length + ' models', true);
                        renderModelsList(data.models);
                        currentModels = data.models;
                    } else {
                        showToast(data.error || 'Failed to fetch models', false);
                    }
                })
                .catch(function(err) {
                    showToast('Error: ' + err.message, false);
                })
                .finally(function() {
                    btn.disabled = false;
                    btn.innerHTML = '<svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"/></svg>';
                });
        }

        function renderModelsList(models) {
            var container = document.getElementById('modelsList');
            if (!models || models.length === 0) {
                container.innerHTML = '<p class="text-gray-500 text-sm">No models found</p>';
                return;
            }
            var selected = currentModels || [];
            var html = '<div class="grid grid-cols-2 gap-2">';
            models.forEach(function(m) {
                var isChecked = selected.indexOf(m) !== -1 ? 'checked' : '';
                html += '<label class="flex items-center space-x-2 cursor-pointer hover:bg-gray-800 p-1 rounded">';
                html += '<input type="checkbox" value="' + m + '" ' + isChecked + ' onchange="updateSelectedModels()" class="rounded bg-gray-700 border-gray-600 text-blue-600">';
                html += '<span class="text-gray-300 text-sm truncate">' + m + '</span>';
                html += '</label>';
            });
            html += '</div>';
            container.innerHTML = html;
            updateSelectedModels();
        }

        function updateSelectedModels() {
            var checkboxes = document.querySelectorAll('#modelsList input[type="checkbox"]:checked');
            var selected = Array.from(checkboxes).map(function(cb) { return cb.value; });
            document.getElementById('modelsInput').value = JSON.stringify(selected);
            
            var container = document.getElementById('selectedModels');
            if (selected.length === 0) {
                container.innerHTML = '<span class="text-gray-500 text-xs">All models allowed</span>';
            } else {
                container.innerHTML = selected.map(function(m) {
                    return '<span class="px-2 py-1 bg-blue-600/20 text-blue-400 text-xs rounded-full">' + m + '</span>';
                }).join('');
            }
        }

        if (currentModels && currentModels.length > 0) {
            renderModelsList(currentModels);
        }
    </script>
</body>
</html>
{{end}}

{{define "client_created.html"}}
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>{{.Title}} - AI Gateway</title>
    <link rel="stylesheet" href="/static/style.css">
    <style>body { font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif; }</style>
</head>
<body class="bg-gray-900 min-h-screen flex items-center justify-center p-4">
    <div class="w-full max-w-lg">
        <div class="bg-gray-800 border border-gray-700 rounded-2xl p-8 text-center">
            <div class="w-16 h-16 bg-green-500/20 rounded-full flex items-center justify-center mx-auto mb-6">
                <svg class="w-8 h-8 text-green-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"/>
                </svg>
            </div>
            
            <h1 class="text-2xl font-bold text-white mb-2">
                {{if (index .Data "Regen")}}API Key Regenerated{{else}}Client Created{{end}}
            </h1>
            <p class="text-gray-400 mb-6">{{(index .Data "Client").Name}}</p>
            
            <div class="bg-amber-500/10 border border-amber-500/50 rounded-xl p-4 mb-6">
                <div class="flex items-start space-x-3">
                    <svg class="w-5 h-5 text-amber-500 flex-shrink-0 mt-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/>
                    </svg>
                    <div class="text-left">
                        <p class="text-amber-400 font-medium text-sm">Save this API key now!</p>
                        <p class="text-amber-300/70 text-xs">It will not be shown again</p>
                    </div>
                </div>
            </div>
            
            <div class="bg-gray-900 rounded-xl p-4 mb-6">
                <code class="text-green-400 break-all text-sm font-mono">{{(index .Data "APIKey")}}</code>
            </div>
            
            <button onclick="navigator.clipboard.writeText('{{(index .Data "APIKey")}}')" class="mb-6 text-blue-400 hover:text-blue-300 text-sm font-medium">
                Copy to clipboard
            </button>
            
            <div class="flex space-x-3">
                <a href="/admin/clients/{{(index .Data "Client").ID}}" class="flex-1 px-4 py-3 bg-gray-700 text-white rounded-xl hover:bg-gray-600 transition-colors">
                    View Client
                </a>
                <a href="/admin/clients" class="flex-1 px-4 py-3 bg-blue-600 text-white rounded-xl hover:bg-blue-700 transition-colors">
                    All Clients
                </a>
            </div>
        </div>
    </div>
</body>
</html>
{{end}}


{{define "stats.html"}}
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Statistics - AI Gateway</title>
    <link rel="stylesheet" href="/static/style.css">
    <script src="/static/chart.js"></script>
    <style>body { font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif; }</style>
    <script>window.chartColors = ['#3B82F6','#10B981','#8B5CF6','#F59E0B','#EF4444','#EC4899','#06B6D4','#F97316','#84CC16','#E879F9'];</script>
</head>
<body class="bg-gray-900 min-h-screen">
    <nav class="bg-gray-800/80 backdrop-blur-md border-b border-gray-700 sticky top-0 z-50">
        <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
            <div class="flex items-center justify-between h-16">
                <div class="flex items-center space-x-3">
                    <div class="w-8 h-8 bg-gradient-to-br from-blue-500 to-blue-700 rounded-lg flex items-center justify-center">
                        <svg class="w-5 h-5 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 10V3L4 14h7v7l9-11h-7z"/>
                        </svg>
                    </div>
                    <span class="text-xl font-bold text-white">AI Gateway</span>
                </div>
                <div class="flex items-center space-x-1">
                    <a href="/admin/dashboard" class="px-3 py-2 rounded-lg text-sm font-medium text-gray-300 hover:text-white hover:bg-gray-700">Dashboard</a>
                    <a href="/admin/clients" class="px-3 py-2 rounded-lg text-sm font-medium text-gray-300 hover:text-white hover:bg-gray-700">Clients</a>
                    <a href="/admin/stats" class="px-3 py-2 rounded-lg text-sm font-medium text-gray-300 hover:text-white hover:bg-gray-700">Stats</a>
                    <a href="https://github.com/DatanoiseTV/aigateway" target="_blank" class="px-3 py-2 rounded-lg text-gray-300 hover:text-white hover:bg-gray-700">
                        <svg class="w-5 h-5" fill="currentColor" viewBox="0 0 24 24">
                            <path fill-rule="evenodd" clip-rule="evenodd" d="M12 2C6.477 2 2 6.477 2 12c0 4.42 2.865 8.17 6.839 9.49.5.092.682-.217.682-.482 0-.237-.008-.866-.013-1.7-2.782.604-3.369-1.34-3.369-1.34-.454-1.156-1.11-1.464-1.11-1.464-.908-.62.069-.608.069-.608 1.003.07 1.531 1.03 1.531 1.03.892 1.529 2.341 1.087 2.91.831.092-.646.35-1.086.636-1.336-2.22-.253-4.555-1.11-4.555-4.943 0-1.091.39-1.984 1.029-2.683-.103-.253-.446-1.27.098-2.647 0 0 .84-.269 2.75 1.025A9.578 9.578 0 0112 6.836c.85.004 1.705.114 2.504.336 1.909-1.294 2.747-1.025 2.747-1.025.546 1.377.203 2.394.1 2.647.64.699 1.028 1.592 1.028 2.683 0 3.842-2.339 4.687-4.566 4.935.359.309.678.919.678 1.852 0 1.336-.012 2.415-.012 2.743 0 .267.18.578.688.48C19.138 20.167 22 16.418 22 12c0-5.523-4.477-10-10-10z"/>
                        </svg>
                    </a>
                    <form method="POST" action="/admin/logout" class="ml-2">
                        <input type="hidden" name="csrf_token" value="{{.CSRFToken}}">
                        <button type="submit" class="px-3 py-2 rounded-lg text-sm font-medium text-gray-300 hover:text-white hover:bg-gray-700">
                            <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M17 16l4-4m0 0l-4-4m4 4H7m6 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h4a3 3 0 013 3v1"/>
                            </svg>
                        </button>
                            </svg>
                        </button>
                    </form>
                </div>
            </div>
        </div>
    </nav>

    <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        <h1 class="text-2xl font-bold text-white mb-8">Statistics</h1>

        <!-- Overview Cards -->
        <div class="grid grid-cols-1 md:grid-cols-4 gap-6 mb-8">
            <div class="bg-gray-800 rounded-2xl p-6 border border-gray-700">
                <p class="text-gray-400 text-sm font-medium">Requests Today</p>
                <p class="text-3xl font-bold text-white mt-2">{{(index .Data "Stats").TotalRequestsToday}}</p>
            </div>
            <div class="bg-gray-800 rounded-2xl p-6 border border-gray-700">
                <p class="text-gray-400 text-sm font-medium">Input Tokens Today</p>
                <p class="text-3xl font-bold text-white mt-2">{{formatInt (index .Data "Stats").TotalInputTokensToday}}</p>
            </div>
            <div class="bg-gray-800 rounded-2xl p-6 border border-gray-700">
                <p class="text-gray-400 text-sm font-medium">Output Tokens Today</p>
                <p class="text-3xl font-bold text-white mt-2">{{formatInt (index .Data "Stats").TotalOutputTokensToday}}</p>
            </div>
            <div class="bg-gray-800 rounded-2xl p-6 border border-gray-700">
                <p class="text-gray-400 text-sm font-medium">Error Rate</p>
                <p class="text-3xl font-bold text-white mt-2">{{printf "%.1f" (index .Data "Stats").ErrorRate}}%</p>
            </div>
        </div>

        <!-- Charts Row -->
        <div class="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-8">
            <div class="bg-gray-800 rounded-2xl p-6 border border-gray-700">
                <h3 class="text-lg font-semibold text-white mb-4">Requests (Last 7 Days)</h3>
                <canvas id="requestsChart" height="200"></canvas>
            </div>
            <div class="bg-gray-800 rounded-2xl p-6 border border-gray-700">
                <h3 class="text-lg font-semibold text-white mb-4">Tokens (Last 7 Days)</h3>
                <canvas id="tokensChart" height="200"></canvas>
            </div>
        </div>

        <!-- Model Usage Bars -->
        <div class="bg-gray-800 rounded-2xl p-6 border border-gray-700 mb-8">
            <h3 class="text-lg font-semibold text-white mb-4">Model Usage (7 days)</h3>
            <div id="modelUsageBars" class="space-y-2">
                <p class="text-gray-500 text-sm">Loading...</p>
            </div>
        </div>

        <!-- Hourly Chart -->
        <div class="bg-gray-800 rounded-2xl p-6 border border-gray-700 mb-8">
            <h3 class="text-lg font-semibold text-white mb-4">Last 24 Hours</h3>
            <canvas id="hourlyChart" height="100"></canvas>
        </div>

        <!-- Model Stats -->
        <div class="bg-gray-800 rounded-2xl border border-gray-700 overflow-hidden mb-8">
            <div class="px-6 py-4 border-b border-gray-700">
                <h3 class="text-lg font-semibold text-white">Model Statistics (7 days)</h3>
            </div>
            <div class="overflow-x-auto">
                <table class="w-full">
                    <thead class="bg-gray-900/50">
                        <tr>
                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase">Model</th>
                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase">Requests</th>
                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase">Tokens</th>
                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase">Avg Runtime</th>
                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase">Success Rate</th>
                        </tr>
                    </thead>
                    <tbody class="divide-y divide-gray-700">
                        {{range (index .Data "ModelStats")}}
                        <tr class="hover:bg-gray-700/50">
                            <td class="px-6 py-4 text-sm text-white">{{.Model}}</td>
                            <td class="px-6 py-4 text-sm text-gray-300">{{formatInt .TotalRequests}}</td>
                            <td class="px-6 py-4 text-sm text-gray-300">{{formatInt .TotalTokens}}</td>
                            <td class="px-6 py-4 text-sm text-gray-300">{{formatDuration .AvgLatencyMs}}</td>
                            <td class="px-6 py-4 text-sm">
                                <span class="px-2 py-1 text-xs font-medium rounded-full {{if ge .SuccessRate 95.0}}bg-green-500/20 text-green-400{{else if ge .SuccessRate 80.0}}bg-yellow-500/20 text-yellow-400{{else}}bg-red-500/20 text-red-400{{end}}">
                                    {{printf "%.1f" .SuccessRate}}%
                                </span>
                            </td>
                        </tr>
                        {{else}}
                        <tr>
                            <td colspan="5" class="px-6 py-8 text-center text-gray-500">No model data yet</td>
                        </tr>
                        {{end}}
                    </tbody>
                </table>
            </div>
        </div>

        <!-- Client Stats -->
        <div class="bg-gray-800 rounded-2xl border border-gray-700 overflow-hidden">
            <div class="px-6 py-4 border-b border-gray-700">
                <h3 class="text-lg font-semibold text-white">Client Statistics (7 days)</h3>
            </div>
            <div class="overflow-x-auto">
                <table class="w-full">
                    <thead class="bg-gray-900/50">
                        <tr>
                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase">Client</th>
                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase">Requests</th>
                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase">Tokens</th>
                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase">Success Rate</th>
                        </tr>
                    </thead>
                    <tbody class="divide-y divide-gray-700">
                        {{range (index .Data "ClientStats")}}
                        <tr class="hover:bg-gray-700/50">
                            <td class="px-6 py-4 text-sm text-white">{{.ClientName}}</td>
                            <td class="px-6 py-4 text-sm text-gray-300">{{formatInt .TotalRequests}}</td>
                            <td class="px-6 py-4 text-sm text-gray-300">{{formatInt .TotalTokens}}</td>
                            <td class="px-6 py-4 text-sm">
                                <span class="px-2 py-1 text-xs font-medium rounded-full {{if ge .SuccessRate 95.0}}bg-green-500/20 text-green-400{{else if ge .SuccessRate 80.0}}bg-yellow-500/20 text-yellow-400{{else}}bg-red-500/20 text-red-400{{end}}">
                                    {{printf "%.1f" .SuccessRate}}%
                                </span>
                            </td>
                        </tr>
                        {{else}}
                        <tr>
                            <td colspan="4" class="px-6 py-8 text-center text-gray-500">No client data yet</td>
                        </tr>
                        {{end}}
                    </tbody>
                </table>
            </div>
        </div>
    </div>

    <script>
        document.addEventListener('DOMContentLoaded', function() {
        // Model usage bars
        var modelStats = {{toJson (index .Data "ModelStats")}};
        var modelUsageContainer = document.getElementById('modelUsageBars');
        if (!Array.isArray(modelStats) || modelStats.length === 0) {
            modelUsageContainer.innerHTML = '<p class="text-gray-500 text-sm">No model data yet</p>';
        } else {
            var total = modelStats.reduce(function(sum, m) { return sum + m.total_requests; }, 0);
            var colors = ['#3B82F6','#10B981','#8B5CF6','#F59E0B','#EF4444','#EC4899','#06B6D4'];
            var html = '';
            modelStats.slice(0, 5).forEach(function(m, i) {
                var pct = total > 0 ? Math.round(m.total_requests / total * 100) : 0;
                html += '<div class="flex items-center gap-3">' +
                    '<div class="w-32 text-xs text-gray-400 truncate font-mono" title="' + m.model + '">' + m.model + '</div>' +
                    '<div class="flex-1 h-2 bg-gray-700 rounded-full overflow-hidden">' +
                        '<div class="h-full rounded-full" style="width: ' + pct + '%; background-color: ' + colors[i % colors.length] + '"></div>' +
                    '</div>' +
                    '<div class="w-20 text-xs text-gray-300 text-right font-mono">' + m.total_requests + ' (' + pct + '%)</div>' +
                '</div>';
            });
            modelUsageContainer.innerHTML = html;
        }

        // Historical 7 days chart
        var histData = {{toJson (index .Data "Historical7")}};
        if (!Array.isArray(histData)) histData = [];
        const requestsCtx = document.getElementById('requestsChart').getContext('2d');
        if (histData && histData.length > 0) {
            new Chart(requestsCtx, {
                type: 'line',
                data: {
                    labels: histData.map(d => new Date(d.date).toLocaleDateString()),
                    datasets: [{
                        label: 'Requests',
                        data: histData.map(d => d.total_requests),
                        borderColor: '#3B82F6',
                        backgroundColor: 'rgba(59, 130, 246, 0.1)',
                        fill: true,
                        tension: 0.4
                    }]
                },
                options: { responsive: true, plugins: { legend: { display: false } }, scales: { x: { ticks: { color: '#9CA3AF' }, grid: { color: '#374151' } }, y: { ticks: { color: '#9CA3AF' }, grid: { color: '#374151' } } } }
            });
        } else {
            requestsCtx.font = '14px Inter';
            requestsCtx.fillStyle = '#6B7280';
            requestsCtx.fillText('No data yet', requestsCtx.canvas.width / 2 - 40, requestsCtx.canvas.height / 2);
        }

        const tokensCtx = document.getElementById('tokensChart').getContext('2d');
        if (histData && histData.length > 0) {
            new Chart(tokensCtx, {
                type: 'line',
                data: {
                    labels: histData.map(d => new Date(d.date).toLocaleDateString()),
                    datasets: [
                        { label: 'Input', data: histData.map(d => d.total_input_tokens), borderColor: '#10B981', tension: 0.4 },
                        { label: 'Output', data: histData.map(d => d.total_output_tokens), borderColor: '#8B5CF6', tension: 0.4 }
                    ]
                },
                options: { responsive: true, plugins: { legend: { labels: { color: '#9CA3AF' } } }, scales: { x: { ticks: { color: '#9CA3AF' }, grid: { color: '#374151' } }, y: { ticks: { color: '#9CA3AF' }, grid: { color: '#374151' } } } }
            });
        } else {
            tokensCtx.font = '14px Inter';
            tokensCtx.fillStyle = '#6B7280';
            tokensCtx.fillText('No data yet', tokensCtx.canvas.width / 2 - 40, tokensCtx.canvas.height / 2);
        }

        // Hourly chart
        var hourlyData = {{toJson (index .Data "Hourly24")}};
        if (!Array.isArray(hourlyData)) hourlyData = [];
        const hourlyCtx = document.getElementById('hourlyChart').getContext('2d');
        if (hourlyData && hourlyData.length > 0) {
            new Chart(hourlyCtx, {
                type: 'bar',
                data: {
                    labels: hourlyData.map(d => new Date(d.hour).toLocaleTimeString([], {hour: '2-digit', minute: '2-digit'})),
                    datasets: [
                        { label: 'Requests', data: hourlyData.map(d => d.total_requests), backgroundColor: '#3B82F6' },
                        { label: 'Errors', data: hourlyData.map(d => d.error_count), backgroundColor: '#EF4444' }
                    ]
                },
                options: { responsive: true, plugins: { legend: { labels: { color: '#9CA3AF' } } }, scales: { x: { stacked: true, ticks: { color: '#9CA3AF' }, grid: { color: '#374151' } }, y: { stacked: true, ticks: { color: '#9CA3AF' }, grid: { color: '#374151' } } } }
            });
        } else {
            hourlyCtx.font = '14px Inter';
            hourlyCtx.fillStyle = '#6B7280';
            hourlyCtx.fillText('No data yet', hourlyCtx.canvas.width / 2 - 40, hourlyCtx.canvas.height / 2);
        }
        });
    </script>
</body>
</html>
{{end}}

{{define "server_tools.html"}}
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Server Tools - AI Gateway</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link rel="stylesheet" href="/static/style.css">
</head>
<body class="bg-gray-900 text-white">
    {{template "sidebar" .}}

    <div class="ml-64 p-8">
        <div class="max-w-4xl">
            <div class="flex justify-between items-center mb-8">
                <h1 class="text-3xl font-bold">Server Tools</h1>
            </div>

            <div class="bg-gray-800 rounded-2xl p-6 border border-gray-700">
                <p class="text-gray-400 mb-6">Enable or disable server-provided tools. These tools are available to clients that have "Enable Server Tools" checked in their settings.</p>

                <form method="POST" action="/admin/server-tools">
                    <input type="hidden" name="csrf_token" value="{{.CSRFToken}}">
                    <div class="space-y-4">
                        {{range .Data.Tools}}
                        <div class="flex items-center p-4 bg-gray-900 rounded-lg border border-gray-700">
                            <input type="checkbox" 
                                   name="tool" 
                                   value="{{.Name}}" 
                                   {{if index (index .Data "EnabledTools") .Name}}checked{{end}}
                                   class="w-5 h-5 rounded bg-gray-800 border-gray-600 text-blue-600 focus:ring-blue-500">
                            <div class="ml-4 flex-1">
                                <h3 class="font-medium text-white">{{.Name}}</h3>
                                <p class="text-sm text-gray-400">{{.Description}}</p>
                            </div>
                        </div>
                        {{end}}
                    </div>

                    <div class="mt-6 flex justify-end">
                        <button type="submit" class="bg-blue-600 text-white px-6 py-2 rounded-lg hover:bg-blue-700 transition-colors">
                            Save Changes
                        </button>
                    </div>
                </form>
            </div>

            <div class="mt-6 bg-gray-800 rounded-2xl p-6 border border-gray-700">
                <h2 class="text-xl font-semibold mb-4">Restart Required</h2>
                <p class="text-gray-400">After changing tool settings, restart the server for changes to take effect.</p>
            </div>
        </div>
    </div>
</body>
</html>
{{end}}
`)
