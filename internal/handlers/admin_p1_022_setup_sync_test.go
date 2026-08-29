package handlers

// P1-02.2 · Setup → LoginLimiter 受保护身份同步回归测试
//
// 场景：容量被刷满 → Setup 修改管理员用户名（不重启）→ 新用户名必须立即获得
// 容量硬保障（fail-open 缺口回归）。

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"ai-gateway/internal/auth"
)

func TestP1_022_Setup_SyncsLimiterProtectedUser(t *testing.T) {
	env := newAuthEnvWithHash(t, "__SETUP_REQUIRED__")
	setupH := NewSetupHandler(env.cfg, false, env.limiter)
	r := setupEnvRouter(env)
	setupH.RegisterRoutes(r)

	// 1) 刷满容量（protectedUser 此刻仍是 "admin"，随机用户名受容量约束）
	for i := 0; i < 10000; i++ {
		env.limiter.RecordFailure(fmt.Sprintf("user%06d", i))
	}

	// 2) 完成 Setup：管理员改为 newadmin（带 pre-auth CSRF 流程），不重启服务
	preReq := httptest.NewRequest("GET", "/setup", nil)
	preW := httptest.NewRecorder()
	r.ServeHTTP(preW, preReq)
	preResp := preW.Result()
	token := extractPreAuthCSRF(t, readBody(preResp))
	pc := findCookie(preResp, auth.PreAuthCSRFCookie)
	if pc == nil {
		t.Fatal("setup page did not set preauth_csrf cookie")
	}
	form := url.Values{
		"username":         {"newadmin"},
		"password":         {"SetupPass-77"},
		"confirm_password": {"SetupPass-77"},
		"csrf_token":       {token},
	}
	req := httptest.NewRequest("POST", "/setup", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(pc)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Result().StatusCode != http.StatusFound {
		t.Fatalf("setup 期望 302，实际 %d", w.Result().StatusCode)
	}

	// 3) 容量仍满，攻击 newadmin：必须正常累计失败并锁定（fail-open 缺口回归）
	for i := 0; i < 5; i++ {
		resp := login(t, env.router, "newadmin", "totally-wrong")
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("newadmin 第 %d 次错误登录期望 401，实际 %d", i+1, resp.StatusCode)
		}
	}
	resp := login(t, env.router, "newadmin", "totally-wrong")
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("[安全回归失败] Setup 后 newadmin 防爆破 fail-open：期望 429，实际 %d", resp.StatusCode)
	}
	if resp.Header.Get("Retry-After") == "" {
		t.Fatal("[安全回归失败] 429 缺少 Retry-After")
	}
	if env.limiter.Allow("newadmin") {
		t.Fatal("[安全回归失败] limiter.Allow(newadmin) 应为 false")
	}
}
