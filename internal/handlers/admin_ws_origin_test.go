package handlers

// P1-02C · WebSocket Origin Security 回归测试
//
// Admin WS 仅接受同源：严格解析、拒绝缺失 Origin、拒绝跨源/后缀伪装/端口不匹配。

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

func dialWS(t *testing.T, srv *httptest.Server, path, sessionToken, origin string) error {
	t.Helper()
	url := "ws" + strings.TrimPrefix(srv.URL, "http") + path
	d := websocket.Dialer{HandshakeTimeout: 3 * time.Second}
	hdr := http.Header{}
	if sessionToken != "" {
		hdr.Set("Cookie", sessionCookieName+"="+sessionToken)
	}
	if origin != "" {
		hdr.Set("Origin", origin)
	}
	conn, _, err := d.Dial(url, hdr)
	if conn != nil {
		_ = conn.Close()
	}
	return err
}

// [P1-02C 回归] 合法会话 + 同源 Origin → 升级成功。
func TestGate_WS_SameOrigin_ValidSession_Allowed(t *testing.T) {
	env := newAuthEnv(t)
	srv := httptest.NewServer(env.router)
	defer srv.Close()
	token := gateLogin(t, env)

	if err := dialWS(t, srv, "/admin/ws", token, srv.URL); err != nil {
		t.Fatalf("[安全回归失败] 同源合法会话 WS 升级应成功: %v", err)
	}
}

// [P1-02C 回归] 恶意 Origin / 后缀伪装 / 缺 Origin / 伪造或缺失会话 → 全部拒绝。
func TestGate_WS_OriginMatrix_AllDenied(t *testing.T) {
	env := newAuthEnv(t)
	srv := httptest.NewServer(env.router)
	defer srv.Close()
	token := gateLogin(t, env)
	host := strings.TrimPrefix(srv.URL, "http://") // 127.0.0.1:port

	cases := []struct {
		name    string
		session string
		origin  string
	}{
		{"evil-origin", token, "https://evil.example"},
		{"suffix-spoof-origin", token, "http://" + host + ".evil.example"},
		{"missing-origin", token, ""},
		{"fake-session-valid-origin", "forged-token-value", srv.URL},
		{"no-session-valid-origin", "", srv.URL},
		{"explicit-different-port", token, "http://" + host + ":9"},
	}

	for _, tc := range cases {
		if err := dialWS(t, srv, "/admin/ws", tc.session, tc.origin); err == nil {
			t.Fatalf("[安全回归失败] WS Origin 矩阵 %q 应被拒绝", tc.name)
		}
	}
}

// [P1-02C 回归] 同 host 不同显式端口 → 拒绝；省略端口的同源写法 → 允许。
func TestGate_WS_PortSemantics(t *testing.T) {
	env := newAuthEnv(t)
	srv := httptest.NewServer(env.router)
	defer srv.Close()
	token := gateLogin(t, env)

	host := strings.TrimPrefix(srv.URL, "http://") // 127.0.0.1:port

	// 显式不同端口 → 拒绝
	if err := dialWS(t, srv, "/admin/ws", token, "http://"+host+":9"); err == nil {
		t.Fatal("[安全回归失败] 同 host 不同显式端口应拒绝")
	}

	// 隐式端口同源写法（省略端口）→ 允许
	if err := dialWS(t, srv, "/admin/ws", token, "http://"+host); err != nil {
		t.Fatalf("[安全回归失败] 同 host 隐式端口应视为同源: %v", err)
	}
}
