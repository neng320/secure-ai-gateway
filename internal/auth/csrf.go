package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"net/http"
)

// PreAuthCSRFCookie: 登录/Setup 等无会话页面的 pre-auth CSRF double-submit Cookie 名。
const PreAuthCSRFCookie = "preauth_csrf"

// PreAuthCSRFValid: double-submit 校验——服务端签发的 Cookie 值与表单/header token
// 必须同时存在且 constant-time 相等。GET 页面时同时签发两者，跨站攻击者既读不到
// Cookie 也无法把受害者的 Cookie 设置为已知值。
func PreAuthCSRFValid(r *http.Request) bool {
	c, err := r.Cookie(PreAuthCSRFCookie)
	if err != nil || c.Value == "" {
		return false
	}
	_ = r.ParseForm()
	token := r.Form.Get("csrf_token")
	if token == "" {
		token = r.Header.Get("X-CSRF-Token")
	}
	if token == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(token), []byte(c.Value)) == 1
}

// CSRFToken 由管理员会话派生其专属 CSRF token：
//
//	HMAC-SHA256(SessionSecret, "csrf:" + rawSessionToken)
//
// - 与会话一一绑定（换会话即换 token）
// - 单向：页面/JS 拿到 CSRF token 推不出原始会话 token
// - 无需入库：服务端用同一输入即时重算并 constant-time 比对
// - SessionSecret 参与签名，仅凭库泄漏不可伪造
func CSRFToken(secret, rawSessionToken string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte("csrf:" + rawSessionToken))
	return hex.EncodeToString(mac.Sum(nil))
}

// NewPreAuthCSRF 生成 pre-auth 场景（登录/Setup）的一次性随机 token
// （配合 double-submit Cookie：页面渲染 token + Set-Cookie 同值，POST 比对两者）。
func NewPreAuthCSRF() (string, error) {
	return GenerateToken()
}
