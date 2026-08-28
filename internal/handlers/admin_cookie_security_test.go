package handlers

// P1-02A · Cookie Security 回归测试
// admin.cookie_secure 显式配置取代已废弃的 server.https.enabled 耦合。

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"ai-gateway/internal/auth"
)

func loginAndGetCookies(t *testing.T, env *authEnv) (session *http.Cookie, logoutClear *http.Cookie) {
	t.Helper()
	resp := login(t, env.router, testAdminUser, testAdminPassword)
	session = getSessionCookie(resp)
	if session == nil {
		t.Fatal("登录未获得 Cookie")
	}

	logoutReq := httptest.NewRequest("POST", "/admin/logout", nil)
	logoutReq.AddCookie(session)
	w := httptest.NewRecorder()
	env.router.ServeHTTP(w, logoutReq)
	logoutClear = getSessionCookie(w.Result())
	return session, logoutClear
}

// [P1-02A 回归] cookie_secure=false（默认）：支持 loopback/SSH 隧道 HTTP 开发。
func TestP1_02A_CookieSecure_False_AllowsHTTPDev(t *testing.T) {
	env := newAuthEnv(t)
	session, clear := loginAndGetCookies(t, env)

	if session.Secure {
		t.Fatal("cookie_secure=false 时登录 Cookie 不应带 Secure")
	}
	if !session.HttpOnly || session.SameSite != http.SameSiteStrictMode || session.Path != "/" {
		t.Fatalf("登录 Cookie 属性不符: HttpOnly=%v SameSite=%v Path=%q", session.HttpOnly, session.SameSite, session.Path)
	}

	if clear == nil || clear.Secure {
		t.Fatalf("登出清理 Cookie 的 Secure 应与登录一致（false），实际 %+v", clear)
	}
	if clear.HttpOnly != session.HttpOnly || clear.SameSite != session.SameSite || clear.Path != session.Path {
		t.Fatalf("登出清理 Cookie 属性与登录不一致: %+v vs %+v", clear, session)
	}
	if !(clear.MaxAge < 0) || clear.Expires.After(time.Now()) {
		t.Fatalf("登出清理 Cookie 应 MaxAge=-1 且 Expires 为过去时间，实际 MaxAge=%d Expires=%v", clear.MaxAge, clear.Expires)
	}
}

// [P1-02A 回归] cookie_secure=true：生产 HTTPS 访问 Admin 面时必须带 Secure。
func TestP1_02A_CookieSecure_True_SetsSecureAttribute(t *testing.T) {
	env := newAuthEnv(t)
	env.cfg.Admin.CookieSecure = true // 请求时读取，运行时可翻转
	session, clear := loginAndGetCookies(t, env)

	if !session.Secure {
		t.Fatal("cookie_secure=true 时登录 Cookie 必须带 Secure")
	}
	if clear == nil || !clear.Secure {
		t.Fatalf("登出清理 Cookie 的 Secure 应与登录一致（true），实际 %+v", clear)
	}

	// 与已废弃的 server.https 彻底解耦：无论其值如何都以 admin.cookie_secure 为准
	env.cfg.Server.HTTPS.Enabled = false
	resp := login(t, env.router, testAdminUser, testAdminPassword)
	if c := getSessionCookie(resp); c == nil || !c.Secure {
		t.Fatal("cookie_secure=true 不应受 server.https 影响")
	}
	_ = auth.SessionCookieName // 保持 import 稳定
}
