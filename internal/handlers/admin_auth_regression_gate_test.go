package handlers

// P1-01B~E · Auth Security Regression Gate（认证子系统验收 Gate）
//
// 本文件是 P1-01B(Session Store) → P1-01C(Login 签发) → P1-01D(RequireAuth 校验)
// → P1-01E(Logout 吊销) 完成后的整体红绿底线。
// 全部通过 ⇒ 输出 "P1-01B~E Auth Core Complete"，SEC-001 核心绕过确认关闭。
// 任何用例失败 = 不满足验收，不得进入 P1-01F/P1-02。

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// gateLogin 便捷登录，返回会话 token
func gateLogin(t *testing.T, env *authEnv) string {
	t.Helper()
	resp := login(t, env.router, testAdminUser, testAdminPassword)
	c := getSessionCookie(resp)
	if c == nil {
		t.Fatal("登录未获得 Cookie")
	}
	return c.Value
}

// TestGate_ValidSession_AccessesAllAdminSurfaces：合法会话在全部资源面畅通
func TestGate_ValidSession_AccessesAllAdminSurfaces(t *testing.T) {
	env := newAuthEnv(t)
	token := gateLogin(t, env)

	// HTML 面
	resp := doReq(env.router, "GET", "/admin/clients",
		[]*http.Cookie{{Name: sessionCookieName, Value: token}})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("/admin/clients 期望 200，实际 %d", resp.StatusCode)
	}

	// JSON 面（含结构特征，证明真正进入受保护资源）
	resp2 := doReq(env.router, "GET", "/admin/stats/api",
		[]*http.Cookie{{Name: sessionCookieName, Value: token}})
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("/admin/stats/api 期望 200，实际 %d", resp2.StatusCode)
	}
	if ct := resp2.Header.Get("Content-Type"); !strings.Contains(ct, "application/json") {
		t.Fatalf("stats api Content-Type 期望 application/json，实际 %q", ct)
	}

	// WebSocket 面（合法会话应能完成升级）
	srv := httptest.NewServer(env.router)
	defer srv.Close()
	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http") + "/admin/ws"
	d := websocket.Dialer{HandshakeTimeout: 3 * time.Second}
	hdr := http.Header{"Cookie": {sessionCookieName + "=" + token}}
	conn, _, err := d.Dial(wsURL, hdr)
	if err != nil {
		t.Fatalf("[安全回归失败] 合法会话的 WS 升级被拒绝: %v", err)
	}
	_ = conn.Close()
}

// TestGate_AttackMatrix_AllDenied：攻击矩阵——所有非法会话形态在所有资源面一律拒绝
func TestGate_AttackMatrix_AllDenied(t *testing.T) {
	env := newAuthEnv(t)
	ctx := context.Background()

	valid, err := env.store.Create(ctx, "admin", time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	expired, err := env.store.Create(ctx, "admin", time.Now().Add(-time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	revoked, err := env.store.Create(ctx, "admin", time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if err := env.store.Revoke(ctx, revoked); err != nil {
		t.Fatal(err)
	}

	// 有效 token 改动一位字符
	mutated := []byte(valid)
	last := mutated[len(mutated)-1]
	if last == '0' {
		mutated[len(mutated)-1] = '1'
	} else {
		mutated[len(mutated)-1] = '0'
	}

	cases := []struct {
		name  string
		value string
		use   bool
	}{
		{"no-cookie", "", false},
		{"empty-cookie", "", true},
		{"admin_session=x", "x", true},
		{"static-authenticated", "authenticated", true},
		{"random-256bit", strings.Repeat("de", 32), true},
		{"valid-token-modified-1-char", string(mutated), true},
		{"server-side-expired", expired, true},
		{"server-side-revoked", revoked, true},
	}

	for _, tc := range cases {
		var cookies []*http.Cookie
		if tc.use {
			cookies = []*http.Cookie{{Name: sessionCookieName, Value: tc.value}}
		}
		resp := doReq(env.router, "GET", "/admin/clients", cookies)
		if resp.StatusCode != http.StatusFound || resp.Header.Get("Location") != "/admin/login" {
			t.Fatalf("[安全回归失败] 攻击矩阵 %q: /admin/clients 期望 302→login，实际 %d %q", tc.name, resp.StatusCode, resp.Header.Get("Location"))
		}
		resp2 := doReq(env.router, "GET", "/admin/stats/api", cookies)
		if resp2.StatusCode != http.StatusFound {
			t.Fatalf("[安全回归失败] 攻击矩阵 %q: /admin/stats/api 期望 302，实际 %d", tc.name, resp2.StatusCode)
		}
	}

	// 对照组：同一环境下合法 token 放行，证明矩阵断言有效而非全 302
	control := doReq(env.router, "GET", "/admin/clients",
		[]*http.Cookie{{Name: sessionCookieName, Value: valid}})
	if control.StatusCode != http.StatusOK {
		t.Fatalf("[矩阵校验失败] 对照组合法 token 应 200，实际 %d", control.StatusCode)
	}
}

// TestGate_LoginRotatesSession_EveryLoginNewToken：同环境连续登录必须每次换发新 token
func TestGate_LoginRotatesSession_EveryLoginNewToken(t *testing.T) {
	env := newAuthEnv(t)
	t1 := gateLogin(t, env)
	t2 := gateLogin(t, env)
	t3 := gateLogin(t, env)
	if t1 == t2 || t2 == t3 || t1 == t3 {
		t.Fatal("[安全回归失败] 连续登录出现重复会话 token")
	}
	// 三个 token 均应有效（未吊销的会话互相独立）
	ctx := context.Background()
	for i, tok := range []string{t1, t2, t3} {
		if user, err := env.store.Validate(ctx, tok); err != nil || user != testAdminUser {
			t.Fatalf("第 %d 个 token 应仍有效，err=%v", i+1, err)
		}
	}
}

// TestGate_LoginFlow_EndToEnd：端到端——表单登录 → Cookie → 访问 → 登出 → 拒绝
func TestGate_LoginFlow_EndToEnd(t *testing.T) {
	env := newAuthEnv(t)

	token := gateLogin(t, env)

	ok := doReq(env.router, "GET", "/admin/dashboard",
		[]*http.Cookie{{Name: sessionCookieName, Value: token}})
	if ok.StatusCode != http.StatusOK {
		t.Fatalf("登录后 dashboard 期望 200，实际 %d", ok.StatusCode)
	}

	logoutReq := httptest.NewRequest("POST", "/admin/logout", nil)
	logoutReq.AddCookie(&http.Cookie{Name: sessionCookieName, Value: token})
	logoutReq.Header.Set("X-CSRF-Token", csrfFor(env, token))
	w2 := httptest.NewRecorder()
	env.router.ServeHTTP(w2, logoutReq)

	denied := doReq(env.router, "GET", "/admin/dashboard",
		[]*http.Cookie{{Name: sessionCookieName, Value: token}})
	if denied.StatusCode != http.StatusFound {
		t.Fatalf("[安全回归失败] 登出后 dashboard 期望 302，实际 %d", denied.StatusCode)
	}
}
