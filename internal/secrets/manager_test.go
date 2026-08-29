package secrets

// P1-03C0 · Domain Secret Manager 测试
//
// 核心保证：AAD 绑定正确（跨上下文密文不可复用）、空引用 fail-closed、
// 规范化两侧一致、原始 Cipher 不经 Manager 不可达业务语义。

import (
	"strings"
	"testing"
)

func newTestManager(t *testing.T) *Manager {
	t.Helper()
	c, err := NewAESGCMCipher(testKey32(t))
	if err != nil {
		t.Fatal(err)
	}
	return NewManager(c)
}

// [C0 回归] Global round-trip + AAD 固定格式
func TestManager_GlobalProvider_RoundTrip(t *testing.T) {
	m := newTestManager(t)
	env, err := m.EncryptGlobalProviderKey("openai", []byte("P103C0_CANARY"))
	if err != nil {
		t.Fatal(err)
	}
	pt, err := m.DecryptGlobalProviderKey("openai", env)
	if err != nil {
		t.Fatal(err)
	}
	if string(pt) != "P103C0_CANARY" {
		t.Fatal("round-trip 不符")
	}
}

// [C0 回归] Client round-trip + AAD 固定格式
func TestManager_ClientBackend_RoundTrip(t *testing.T) {
	m := newTestManager(t)
	id := "3f2b1a9c-0000-0000-0000-000000000001"
	env, err := m.EncryptClientBackendKey(id, []byte("P103C0_CANARY"))
	if err != nil {
		t.Fatal(err)
	}
	pt, err := m.DecryptClientBackendKey(id, env)
	if err != nil {
		t.Fatal(err)
	}
	if string(pt) != "P103C0_CANARY" {
		t.Fatal("round-trip 不符")
	}
}

// [C0 安全回归] provider A 密文 → provider B 解密必须失败
func TestManager_CrossProvider_Rejected(t *testing.T) {
	m := newTestManager(t)
	env, _ := m.EncryptGlobalProviderKey("provider-A", []byte("secret"))
	if _, err := m.DecryptGlobalProviderKey("provider-B", env); err == nil {
		t.Fatal("[安全回归失败] provider A 的密文在 provider B 上下文解密成功")
	}
}

// [C0 安全回归] client A 密文 → client B 解密必须失败
func TestManager_CrossClient_Rejected(t *testing.T) {
	m := newTestManager(t)
	env, _ := m.EncryptClientBackendKey("client-A-id", []byte("secret"))
	if _, err := m.DecryptClientBackendKey("client-B-id", env); err == nil {
		t.Fatal("[安全回归失败] client A 的密文在 client B 上下文解密成功")
	}
}

// [C0 安全回归] 全局密文 → client 上下文解密必须失败（领域隔离）
func TestManager_GlobalCiphertext_InClientContext_Rejected(t *testing.T) {
	m := newTestManager(t)
	env, _ := m.EncryptGlobalProviderKey("openai", []byte("secret"))
	if _, err := m.DecryptClientBackendKey("some-client-id", env); err == nil {
		t.Fatal("[安全回归失败] 全局密文在 client 上下文解密成功")
	}
	// 反向同样
	env2, _ := m.EncryptClientBackendKey("some-client-id", []byte("secret"))
	if _, err := m.DecryptGlobalProviderKey("openai", env2); err == nil {
		t.Fatal("[安全回归失败] client 密文在全局上下文解密成功")
	}
}

// [C0 安全回归] 空 context → fail-closed
func TestManager_EmptyContext_Fails(t *testing.T) {
	m := newTestManager(t)
	if _, err := m.EncryptGlobalProviderKey("", []byte("x")); err != ErrEmptyProviderName {
		t.Fatalf("空 provider name 期望 ErrEmptyProviderName，实际 %v", err)
	}
	if _, err := m.EncryptGlobalProviderKey("   ", []byte("x")); err != ErrEmptyProviderName {
		t.Fatalf("空白 provider name 期望 ErrEmptyProviderName，实际 %v", err)
	}
	if _, err := m.DecryptGlobalProviderKey("", "enc:v1:x:y"); err != ErrEmptyProviderName {
		t.Fatalf("空 provider name 解密期望 ErrEmptyProviderName，实际 %v", err)
	}
	if _, err := m.EncryptClientBackendKey("", []byte("x")); err != ErrEmptyClientID {
		t.Fatalf("空 client id 期望 ErrEmptyClientID，实际 %v", err)
	}
	if _, err := m.DecryptClientBackendKey("  ", "enc:v1:x:y"); err != ErrEmptyClientID {
		t.Fatalf("空白 client id 解密期望 ErrEmptyClientID，实际 %v", err)
	}
}

// [C0 回归] 规范化两侧一致：Encrypt 带 TrimSpace 前后空白，Decrypt 同值可解；
// 且 AAD 恰为 TrimSpace 后的 canonical 名称（无隐式改名）。
func TestManager_Normalization_ConsistentBothSides(t *testing.T) {
	m := newTestManager(t)
	env, err := m.EncryptGlobalProviderKey("  openai  ", []byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	// canonical 名称（TrimSpace 后）必须可解
	if _, err := m.DecryptGlobalProviderKey("openai", env); err != nil {
		t.Fatalf("canonical 名称解密失败: %v", err)
	}
	// 带空白的原始名称也必须可解（同一 canonical AAD）
	if _, err := m.DecryptGlobalProviderKey("  openai  ", env); err != nil {
		t.Fatalf("原始带空白名称解密失败: %v", err)
	}
	// AAD 值断言
	aad, _ := globalProviderAAD("  openai  ")
	if aad != GlobalProviderAADPrefix+"openai" {
		t.Fatalf("AAD 应为规范化形式，实际 %q", aad)
	}
}

// [C0 防回归] Manager 拒绝任意 AAD 直通：AAD 前缀由 Manager 固定，
// 调用方无法通过 provider name 注入别的领域前缀（如把全局密文伪装成 client 上下文）。
func TestManager_NoAADPrefixInjection(t *testing.T) {
	m := newTestManager(t)
	// 尝试用名称注入 client 前缀：provider name 不能改变 AAD 领域
	env, _ := m.EncryptGlobalProviderKey(ClientBackendAADPrefix+"evil", []byte("secret"))
	// 该密文的 AAD = provider-config:v1:client-backend:v1:evil —— 不等于任何合法 client AAD
	if _, err := m.DecryptClientBackendKey(ClientBackendAADPrefix+"evil", env); err == nil {
		t.Fatal("[安全回归失败] 全局领域密文通过名称注入跨越到 client 领域")
	}
	_ = strings.Contains // strings 保留给后续断言
}
