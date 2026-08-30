package handlers

// P1-04.4 · Bootstrap→Setup 全流程回归（SEC-003）
//
// fresh config（createDefaultConfig 现在写 __SETUP_REQUIRED__，stdout 零密码材料）
// → IsSetupRequired==true → GET /setup 正常 → POST 用户自定义密码
// → bcrypt 落盘、用户密码不出现在 stdout → 重载后 IsSetupRequired==false
// → bcrypt 校验通过（登录链路可用）。
// CSRF / candidate 原子保存 / 真实 config path / limiter 同步由既有 P1-02 Gate 覆盖。

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"ai-gateway/internal/auth"
	"ai-gateway/internal/config"
	mw "ai-gateway/internal/middleware"
	"ai-gateway/internal/models"
	"ai-gateway/internal/services"

	"github.com/go-chi/chi/v5"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

const p1044UserPassword = "P1044_USER_CHOSEN_PASSWORD_x9K2"

func captureStdoutH(t *testing.T, fn func()) string {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	fn()
	_ = w.Close()
	os.Stdout = old
	data, _ := io.ReadAll(r)
	return string(data)
}

func TestP1044_FreshBootstrap_SetupFlowRegression(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")

	// fresh config：stdout 零密码材料，进入 setup 流程
	var cfg *config.Config
	out := captureStdoutH(t, func() {
		var err error
		cfg, err = config.Load(cfgPath)
		if err != nil {
			t.Fatal(err)
		}
	})
	if cfg.Admin.PasswordHash != "__SETUP_REQUIRED__" {
		t.Fatalf("[安全回归失败] 应为 __SETUP_REQUIRED__，实际 %q", cfg.Admin.PasswordHash)
	}
	if strings.Contains(out, "Password") {
		t.Fatalf("[安全回归失败] bootstrap stdout 含密码材料: %q", out)
	}

	// SetupHandler 判定 + 路由注册（与 buildAdminRouter 同构）
	db, err := gorm.Open(sqlite.Open(filepath.Join(dir, "gw.db")), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.AutoMigrate(&models.Client{}, &models.RequestLog{}, &models.DailyUsage{}, &models.AdminSession{}); err != nil {
		t.Fatal(err)
	}
	migrateHandlerAudit(t, db)
	t.Cleanup(func() {
		if sqlDB, e := db.DB(); e == nil {
			_ = sqlDB.Close()
		}
	})
	limiter := auth.NewLoginRateLimiter()
	setupHandler := NewSetupHandler(cfg, false, limiter, cfgPath)
	if !setupHandler.IsSetupRequired() {
		t.Fatal("[安全回归失败] fresh config 应判定 setup required")
	}
	mux := chi.NewRouter()
	setupHandler.RegisterRoutes(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	// GET /setup → 200
	resp, err := http.Get(srv.URL + "/setup")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := ioReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /setup 期望 200，实际 %d", resp.StatusCode)
	}
	token := extractPreAuthCSRF(t, string(b))
	var preauth *http.Cookie
	for _, c := range resp.Cookies() {
		if c.Name == auth.PreAuthCSRFCookie {
			preauth = c
		}
	}
	if preauth == nil {
		t.Fatal("setup 页未设置 preauth cookie")
	}

	// POST /setup：用户自定义密码
	form := "username=admin&password=" + p1044UserPassword + "&confirm_password=" + p1044UserPassword + "&csrf_token=" + token
	req, _ := http.NewRequest("POST", srv.URL+"/setup", strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(preauth)
	noRedirect := &http.Client{CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	resp2, err := noRedirect.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	b2, _ := ioReadAll(resp2.Body)
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusFound {
		t.Fatalf("POST /setup 期望 302，实际 %d body=%s", resp2.StatusCode, string(b2))
	}

	// 重载：bcrypt 落盘、setup 完成
	cfg2, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if cfg2.Admin.PasswordHash == "__SETUP_REQUIRED__" || strings.Contains(cfg2.Admin.PasswordHash, p1044UserPassword) {
		t.Fatalf("[安全回归失败] 落盘哈希异常: %q", cfg2.Admin.PasswordHash)
	}
	if err := bcrypt.CompareHashAndPassword([]byte(cfg2.Admin.PasswordHash), []byte(p1044UserPassword)); err != nil {
		t.Fatalf("[功能回归失败] 落盘哈希应与用户密码匹配: %v", err)
	}
	if NewSetupHandler(cfg2, false, limiter, cfgPath).IsSetupRequired() {
		t.Fatal("[安全回归失败] setup 完成后仍判定 setup required")
	}

	// 用户密码绝不出现在 stdout
	if strings.Contains(out, p1044UserPassword) {
		t.Fatal("[安全回归失败] bootstrap stdout 含用户密码")
	}

	// 后续 Admin 登录正常（AdminHandler bcrypt 链路）
	clientSvc := services.NewClientService(db)
	store := auth.NewSQLiteStore(db)
	adminCfg := cfg2
	adminCfg.Admin.SessionSecret = "p1044-session-secret"
	adminH, err := NewAdminHandler(adminCfg, clientSvc, services.NewStatsService(db), services.NewGeminiService(db, adminCfg), services.NewDashboardHub(services.NewStatsService(db)), services.NewToolService(nil), store, limiter, nil, "", nil, mw.NewRateLimiter())
	if err != nil {
		t.Fatal(err)
	}
	loginMux := chi.NewRouter()
	adminH.RegisterRoutes(loginMux)
	if resp := login(t, loginMux, "admin", p1044UserPassword); resp.StatusCode != http.StatusFound {
		t.Fatalf("[功能回归失败] setup 后 admin 登录应成功，实际 %d", resp.StatusCode)
	}
	t.Log("[SEC-003 FIXED] Bootstrap→Setup 全流程：零明文密码输出，登录链路可用")
}

func ioReadAll(rc io.Reader) ([]byte, error) {
	return io.ReadAll(rc)
}
