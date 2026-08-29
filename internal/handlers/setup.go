package handlers

import (
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"strconv"
	"strings"
	"time"

	"ai-gateway/internal/auth"
	"ai-gateway/internal/config"

	"github.com/go-chi/chi/v5"
	"golang.org/x/crypto/bcrypt"
)

type SetupHandler struct {
	cfg          *config.Config
	setupMode    bool
	loginLimiter *auth.LoginRateLimiter
}

// NewSetupHandler: loginLimiter 必须与 AdminHandler 共享同一实例（P1-02.2），
// 以便 Setup 修改管理员用户名后同步 limiter 的受保护身份。
func NewSetupHandler(cfg *config.Config, setupMode bool, loginLimiter *auth.LoginRateLimiter) *SetupHandler {
	return &SetupHandler{cfg: cfg, setupMode: setupMode, loginLimiter: loginLimiter}
}

func (h *SetupHandler) IsSetupRequired() bool {
	return h.cfg.Admin.PasswordHash == "__SETUP_REQUIRED__" || h.setupMode
}

func (h *SetupHandler) RegisterRoutes(r chi.Router) {
	r.Get("/setup", h.ShowSetup)
	r.Post("/setup", h.setupCSRF(http.HandlerFunc(h.HandleSetup)).ServeHTTP)
}

// setupCSRF: Setup 无会话，使用 pre-auth double-submit（SEC-004，P1-02B）。
func (h *SetupHandler) setupCSRF(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !auth.PreAuthCSRFValid(r) {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// renderSetupPage: 渲染 setup 页面。
// 注意：页面 CSS 含裸百分号（linear-gradient 0%/100%），绝不能用 fmt.Fprintf——
// 裸 % 会被当作格式化 verb 吞掉参数（上游曾因此 Port 行渲染成 %!d(MISSING)）。
// 改用显式占位符替换。
func (h *SetupHandler) renderSetupPage(csrfToken string) []byte {
	page := strings.NewReplacer(
		"{{CSRF}}", csrfToken,
		"{{PORT}}", strconv.Itoa(h.cfg.Server.Port),
	).Replace(setupHTML)
	return []byte(page)
}

// issuePreAuthCSRF: 签发 pre-auth token（渲染值 + 同值 Cookie）
func (h *SetupHandler) issuePreAuthCSRF(w http.ResponseWriter) (string, error) {
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

func (h *SetupHandler) ShowSetup(w http.ResponseWriter, r *http.Request) {
	if !h.IsSetupRequired() {
		http.Redirect(w, r, "/admin/login", http.StatusFound)
		return
	}

	token, err := h.issuePreAuthCSRF(w)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(h.renderSetupPage(token)))
}

func (h *SetupHandler) HandleSetup(w http.ResponseWriter, r *http.Request) {
	if !h.IsSetupRequired() {
		http.Redirect(w, r, "/admin/login", http.StatusFound)
		return
	}

	r.ParseForm()
	username := r.Form.Get("username")
	password := r.Form.Get("password")
	confirmPassword := r.Form.Get("confirm_password")

	if username == "" || password == "" {
		h.showError(w, "Username and password are required")
		return
	}

	if password != confirmPassword {
		h.showError(w, "Passwords do not match")
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		h.showError(w, "Failed to hash password")
		return
	}

	h.cfg.Admin.Username = username
	h.cfg.Admin.PasswordHash = string(hash)

	if h.cfg.Admin.SessionSecret == "" {
		h.cfg.Admin.SessionSecret = generateRandomString(32)
	}

	h.cfg.Prometheus.Enabled = true
	h.cfg.Prometheus.Username = "prometheus"
	h.cfg.Prometheus.Password = generateRandomString(20)

	if err := config.SaveConfig(h.cfg, "config.yaml"); err != nil {
		h.showError(w, "Failed to save config: "+err.Error())
		return
	}

	// P1-02.2：配置成功保存后才同步 limiter 的受保护身份（避免保存失败但内存已变）。
	// 同时清除新用户名的失败记录，让成功的 Setup 从干净登录状态开始。
	if h.loginLimiter != nil {
		h.loginLimiter.SetProtectedUser(username)
	}

	http.Redirect(w, r, "/admin/login", http.StatusFound)
}

func (h *SetupHandler) showError(w http.ResponseWriter, msg string) {
	// 重签 pre-auth token，保证用户修正输入后可重新提交
	token, err := h.issuePreAuthCSRF(w)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(h.renderSetupPage(token)))
}

func generateRandomString(length int) string {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return ""
	}
	return hex.EncodeToString(bytes)[:length]
}

var setupHTML = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AI Gateway - Setup</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <style>
        body { background: linear-gradient(135deg, #1e293b 0%, #0f172a 100%); min-height: 100vh; }
    </style>
</head>
<body class="flex items-center justify-center">
    <div class="w-full max-w-md">
        <div class="bg-gray-800 rounded-2xl p-8 shadow-2xl border border-gray-700">
            <div class="text-center mb-8">
                <h1 class="text-3xl font-bold text-white mb-2">AI Gateway</h1>
                <p class="text-gray-400">Setup Wizard</p>
            </div>

            <form method="POST" class="space-y-6">
                <input type="hidden" name="csrf_token" value="{{CSRF}}">
                <div>
                    <label class="block text-gray-400 text-sm font-medium mb-2">Admin Username</label>
                    <input type="text" name="username" value="admin" required
                        class="w-full px-4 py-3 bg-gray-900 border border-gray-600 text-white rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500">
                </div>

                <div>
                    <label class="block text-gray-400 text-sm font-medium mb-2">Password</label>
                    <input type="password" name="password" required
                        class="w-full px-4 py-3 bg-gray-900 border border-gray-600 text-white rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500">
                </div>

                <div>
                    <label class="block text-gray-400 text-sm font-medium mb-2">Confirm Password</label>
                    <input type="password" name="confirm_password" required
                        class="w-full px-4 py-3 bg-gray-900 border border-gray-600 text-white rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500">
                </div>

                <div class="p-4 bg-gray-900/50 rounded-lg border border-gray-700">
                    <h3 class="text-white font-medium mb-2">Default Configuration</h3>
                    <ul class="text-gray-400 text-sm space-y-1">
                        <li>Prometheus metrics enabled</li>
                        <li>Username: prometheus</li>
                        <li>Password: auto-generated</li>
                        <li>Port: {{PORT}}</li>
                    </ul>
                </div>

                <button type="submit"
                    class="w-full bg-blue-600 text-white py-3 rounded-lg hover:bg-blue-700 transition-colors font-medium">
                    Complete Setup
                </button>
            </form>
        </div>
    </div>
</body>
</html>`
