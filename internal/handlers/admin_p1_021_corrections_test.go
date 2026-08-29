package handlers

// P1-02.1 · Admin Security Gate Corrections 回归测试
// 覆盖：username 存在性 timing 侧信道消除（status/body 一致）。

import (
	"net/http"
	"testing"
)

// [P1-02.1 回归] 未知用户名与错误密码的响应 status/body 完全一致（无存在性侧信道）。
func TestP1_021_Login_NoUserExistenceSideChannel(t *testing.T) {
	env := newAuthEnv(t)

	respUnknown := login(t, env.router, "ghost-user", testAdminPassword)
	respWrongPass := login(t, env.router, testAdminUser, "definitely-wrong")

	if respUnknown.StatusCode != http.StatusUnauthorized || respWrongPass.StatusCode != http.StatusUnauthorized {
		t.Fatalf("两者均应 401，实际 unknown=%d wrongpass=%d", respUnknown.StatusCode, respWrongPass.StatusCode)
	}
	b1 := readBody(respUnknown)
	b2 := readBody(respWrongPass)
	if b1 != b2 {
		t.Fatalf("[安全回归失败] 未知用户名与错误密码响应体不一致（存在性侧信道）: %q vs %q", b1, b2)
	}
}
