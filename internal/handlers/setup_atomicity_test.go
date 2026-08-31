package handlers

// P1-02.3 · Setup Configuration Commit Atomicity 回归测试
//
// 语义：先持久化 candidate 配置，成功后才切换运行态。
//   A. 自定义 config path —— 只写指定文件，绝不偷偷生成 cwd/config.yaml
//   B. 持久化失败 —— 运行态 Admin/Prometheus 与 limiter 受保护身份全部保持原值
//   C. 成功 —— 磁盘与内存一致，limiter 同步新用户名

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"ai-gateway/internal/audit"
	"ai-gateway/internal/auth"
	"ai-gateway/internal/config"
	"ai-gateway/internal/database"
	"ai-gateway/internal/models"

	"github.com/go-chi/chi/v5"
)

// setupCSRFDance: GET 页面取 pre-auth token/Cookie，再 POST 表单
func setupCSRFDance(t *testing.T, r http.Handler, form url.Values) *http.Response {
	t.Helper()
	pre := httptest.NewRequest("GET", "/setup", nil)
	w1 := httptest.NewRecorder()
	r.ServeHTTP(w1, pre)
	resp1 := w1.Result()
	token := extractPreAuthCSRF(t, readBody(resp1))
	pc := findCookie(resp1, auth.PreAuthCSRFCookie)
	if pc == nil {
		t.Fatal("setup page did not set preauth_csrf cookie")
	}
	form.Set("csrf_token", token)
	req := httptest.NewRequest("POST", "/setup", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(pc)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w.Result()
}

func minimalSetupCfg() *config.Config {
	return &config.Config{
		Server: config.ServerConfig{
			Host:    "127.0.0.1",
			Port:    8090,
			Admin:   config.ListenerConfig{Host: "127.0.0.1", Port: 8091},
			Metrics: config.ListenerConfig{Host: "127.0.0.1", Port: 9090},
		},
		Admin: config.AdminConfig{
			Username:      "admin",
			PasswordHash:  "__SETUP_REQUIRED__",
			SessionSecret: "setup-atomicity-test-secret",
			CookieSecure:  false,
		},
		Providers: map[string]config.ProviderConfig{},
	}
}

// newSetupHandlerForTest: 构造 SetupHandler 并为 limiter 配置受保护账号
func newSetupHandlerForTest(t *testing.T, cfg *config.Config, configPath string) (*SetupHandler, *auth.LoginRateLimiter) {
	t.Helper()
	if cfg.Database.Path == "" {
		cfg.Database.Path = filepath.Join(t.TempDir(), "setup.db")
	}
	db, err := database.Open(cfg.Database.Path)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.AutoMigrate(&models.AdminSession{}); err != nil {
		t.Fatal(err)
	}
	if err := audit.MigrateIntegrity(db); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if sqlDB, err := db.DB(); err == nil {
			_ = sqlDB.Close()
		}
	})
	if parent, statErr := os.Stat(filepath.Dir(configPath)); statErr == nil && parent.IsDir() {
		raw, readErr := os.ReadFile(configPath)
		if readErr == nil {
			diskCfg, parseErr := config.ParseExistingForMigration(raw)
			if parseErr != nil {
				t.Fatal(parseErr)
			}
			diskCfg.Database.Path = cfg.Database.Path
			data, marshalErr := config.MarshalYAML(diskCfg)
			if marshalErr != nil {
				t.Fatal(marshalErr)
			}
			if writeErr := os.WriteFile(configPath, data, 0600); writeErr != nil {
				t.Fatal(writeErr)
			}
		} else if os.IsNotExist(readErr) {
			data, marshalErr := config.MarshalYAML(cfg)
			if marshalErr != nil {
				t.Fatal(marshalErr)
			}
			if writeErr := os.WriteFile(configPath, data, 0600); writeErr != nil {
				t.Fatal(writeErr)
			}
		} else {
			t.Fatal(readErr)
		}
	}
	limiter := auth.NewLoginRateLimiter()
	limiter.Configure(5, 15, cfg.Admin.Username)
	return NewSetupHandler(cfg, false, limiter, configPath, db), limiter
}

func newSetupTestRouter(t *testing.T, setupH *SetupHandler) http.Handler {
	t.Helper()
	r := chi.NewRouter()
	setupH.RegisterRoutes(r)
	return r
}

// [P1-02.3 A] 自定义 config path：只修改指定文件；cwd/config.yaml 不得意外产生。
func TestP1_023_Setup_CustomConfigPath_OnlyWritesThatFile(t *testing.T) {
	dir := t.TempDir()
	orig, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Chdir(orig) }()

	custom := filepath.Join(dir, "custom-gateway.yaml")
	if err := os.WriteFile(custom, []byte("server:\n  host: 127.0.0.1\n  port: 8090\nadmin:\n  username: admin\n  cookie_secure: false\n"), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(custom) // SourcePath = custom
	if err != nil {
		t.Fatal(err)
	}
	setupH, limiter := newSetupHandlerForTest(t, cfg, config.SourcePath())
	r := newSetupTestRouter(t, setupH)

	resp := setupCSRFDance(t, r, url.Values{
		"username":         {"newadmin"},
		"password":         {"SetupPass-77"},
		"confirm_password": {"SetupPass-77"},
	})
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("setup 期望 302，实际 %d", resp.StatusCode)
	}

	// 指定文件已更新
	data, err := os.ReadFile(custom)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "newadmin") {
		t.Fatal("自定义配置文件应包含新用户名")
	}
	// cwd/config.yaml 不得存在
	if _, err := os.Stat(filepath.Join(dir, "config.yaml")); !os.IsNotExist(err) {
		t.Fatal("[安全回归失败] Setup 偷偷生成了 cwd/config.yaml")
	}
	if limiter.ProtectedUser() != "newadmin" {
		t.Fatalf("limiter 受保护身份应同步为 newadmin，实际 %q", limiter.ProtectedUser())
	}
}

// [P1-02.3 B] 持久化失败：运行态与 limiter 全部保持原值，HTTP 不得报告成功。
func TestP1_023_Setup_SaveFailure_RuntimeUnchanged(t *testing.T) {
	dir := t.TempDir()
	cfg := minimalSetupCfg()
	limiter := auth.NewLoginRateLimiter()
	limiter.Configure(5, 15, cfg.Admin.Username)
	// 确定性失败注入：父路径是一个已存在的【文件】→ saveConfig 的 MkdirAll 必失败。
	// （不能用"不存在目录"——saveConfig 会 MkdirAll 自动建目录导致保存意外成功）
	blocked := filepath.Join(dir, "blocked")
	if err := os.WriteFile(blocked, []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	failingPath := filepath.Join(blocked, "gateway.yaml")
	setupH, _ := newSetupHandlerForTest(t, cfg, failingPath)
	r := newSetupTestRouter(t, setupH)

	resp := setupCSRFDance(t, r, url.Values{
		"username":         {"newadmin"},
		"password":         {"SetupPass-77"},
		"confirm_password": {"SetupPass-77"},
	})
	if resp.StatusCode == http.StatusFound {
		t.Fatal("[安全回归失败] 保存失败时 Setup 不得报告成功（302）")
	}

	if cfg.Admin.Username != "admin" {
		t.Fatalf("[安全回归失败] 保存失败后运行态用户名应为 admin，实际 %q", cfg.Admin.Username)
	}
	if cfg.Admin.PasswordHash != "__SETUP_REQUIRED__" {
		t.Fatalf("[安全回归失败] 保存失败后运行态密码哈希应保持原值，实际 %q", cfg.Admin.PasswordHash)
	}
	if limiter.ProtectedUser() != "admin" {
		t.Fatalf("[安全回归失败] 保存失败后 limiter 受保护身份应为 admin，实际 %q", limiter.ProtectedUser())
	}
	if cfg.Prometheus.Enabled {
		t.Fatal("[安全回归失败] 保存失败后 Prometheus.Enabled 应保持 false")
	}
}

// [P1-02.3 C] 成功路径：磁盘与内存一致，limiter 同步。
func TestP1_023_Setup_Success_FileAndMemoryConsistent(t *testing.T) {
	dir := t.TempDir()
	cfg := minimalSetupCfg()
	path := filepath.Join(dir, "gateway.yaml")
	setupH, limiter := newSetupHandlerForTest(t, cfg, path)
	r := newSetupTestRouter(t, setupH)

	resp := setupCSRFDance(t, r, url.Values{
		"username":         {"newadmin"},
		"password":         {"SetupPass-77"},
		"confirm_password": {"SetupPass-77"},
	})
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("setup 期望 302，实际 %d", resp.StatusCode)
	}

	if cfg.Admin.Username != "newadmin" {
		t.Fatalf("内存用户名应切换为 newadmin，实际 %q", cfg.Admin.Username)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "newadmin") {
		t.Fatal("磁盘配置应包含 newadmin")
	}
	if limiter.ProtectedUser() != "newadmin" {
		t.Fatalf("limiter 受保护身份应为 newadmin，实际 %q", limiter.ProtectedUser())
	}
}
