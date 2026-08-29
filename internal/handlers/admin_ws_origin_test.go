package handlers

// P1-02.1 · WebSocket Origin 严格同源回归测试
//
// 矩阵覆盖：scheme + hostname + effective port（http=80 / https=443）三要素，
// 期望 scheme 由 admin.cookie_secure 推导（false→http / true→https）。

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

func originAllowed(host, origin, expectedScheme string) bool {
	r := httptest.NewRequest("GET", "/admin/ws", nil)
	r.Host = host
	if origin != "" {
		r.Header.Set("Origin", origin)
	}
	return wsOriginAllowed(r, expectedScheme)
}

// [P1-02.1 安全回归] 严格同源矩阵（用户验收用例逐条覆盖）。
func TestWSOrigin_StrictMatrix(t *testing.T) {
	cases := []struct {
		name   string
		host   string
		origin string
		scheme string
		want   bool
	}{
		// cookie_secure=false → http
		{"same origin explicit port", "localhost:8091", "http://localhost:8091", "http", true},
		{"implicit port mismatch (80 != 8091)", "localhost:8091", "http://localhost", "http", false},
		{"explicit port mismatch", "localhost:8091", "http://localhost:8092", "http", false},
		{"scheme mismatch https vs http", "localhost:8091", "https://localhost:8091", "http", false},
		{"missing origin", "localhost:8091", "", "http", false},
		{"ipv6 same", "[::1]:8091", "http://[::1]:8091", "http", true},
		{"ipv6 port mismatch", "[::1]:8091", "http://[::1]:8092", "http", false},
		// cookie_secure=true → https
		{"https same origin", "admin.example.com", "https://admin.example.com", "https", true},
		{"https explicit 443 equals default", "admin.example.com", "https://admin.example.com:443", "https", true},
		{"https wrong port 8443", "admin.example.com", "https://admin.example.com:8443", "https", false},
		{"http origin vs https expected", "admin.example.com", "http://admin.example.com", "https", false},
		// 通用
		{"suffix spoof", "admin.example.com", "https://admin.example.com.evil.example", "https", false},
		{"evil origin", "admin.example.com", "https://evil.example", "https", false},
		{"case-insensitive host", "Admin.Example.com", "https://admin.example.com", "https", true},
	}
	for _, tc := range cases {
		if got := originAllowed(tc.host, tc.origin, tc.scheme); got != tc.want {
			t.Fatalf("[安全回归失败] %q: host=%q origin=%q scheme=%q 期望 %v 实际 %v",
				tc.name, tc.host, tc.origin, tc.scheme, tc.want, got)
		}
	}
}

func dialWS(t *testing.T, srv *httptest.Server, path, sessionToken, origin string) error {
	t.Helper()
	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http") + path
	d := websocket.Dialer{HandshakeTimeout: 3 * time.Second}
	hdr := http.Header{}
	if sessionToken != "" {
		hdr.Set("Cookie", sessionCookieName+"="+sessionToken)
	}
	if origin != "" {
		hdr.Set("Origin", origin)
	}
	conn, _, err := d.Dial(wsURL, hdr)
	if conn != nil {
		_ = conn.Close()
	}
	return err
}

// [P1-02.1 集成回归] 真实服务器：合法会话 + 同源 → 升级成功；
// 恶意 Origin / 缺 Origin → 升级失败（即使会话合法）。
func TestGate_WS_Integration(t *testing.T) {
	env := newAuthEnv(t) // CookieSecure=false → 期望 http
	srv := httptest.NewServer(env.router)
	defer srv.Close()
	token := gateLogin(t, env)

	if err := dialWS(t, srv, "/admin/ws", token, srv.URL); err != nil {
		t.Fatalf("[安全回归失败] 同源合法会话 WS 升级应成功: %v", err)
	}
	if err := dialWS(t, srv, "/admin/ws", token, "https://evil.example"); err == nil {
		t.Fatal("[安全回归失败] 恶意 Origin 应拒绝")
	}
	if err := dialWS(t, srv, "/admin/ws", token, ""); err == nil {
		t.Fatal("[安全回归失败] 缺失 Origin 应拒绝")
	}
}
