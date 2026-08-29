package secrets

// P1-03C1 · Secret 状态机与 Preflight 测试

import (
	"errors"
	"strings"
	"testing"
)

func TestClassifySecret_Matrix(t *testing.T) {
	cases := []struct {
		name              string
		legacy, encrypted string
		want              SecretState
	}{
		{"empty", "", "", SecretEmpty},
		{"legacy only", "sk-legacy-plaintext", "", SecretLegacyOnly},
		{"encrypted only", "", "enc:v1:abc:def", SecretEncryptedOnly},
		{"mixed", "sk-legacy-plaintext", "enc:v1:abc:def", SecretMixed},
		{"invalid encrypted form", "", "base64-not-envelope", SecretInvalidEncrypted},
		{"invalid with legacy", "sk-legacy", "garbage", SecretInvalidEncrypted},
	}
	for _, tc := range cases {
		if got := ClassifySecret(tc.legacy, tc.encrypted); got != tc.want {
			t.Fatalf("%s: 期望 %s，实际 %s", tc.name, tc.want, got)
		}
	}
}

func TestScanPreflight_Empty_AllowNoMasterKey(t *testing.T) {
	res := ScanPreflight([]SecretItem{
		{Kind: KindGlobal, Ref: "ollama"},
		{Kind: KindClient, Ref: "client-1"},
	})
	if res.MigrationRequired || res.NeedMasterKey || len(res.Offenders) != 0 {
		t.Fatalf("全空不应阻断: %+v", res)
	}
	if res.EmptyCount != 2 {
		t.Fatalf("EmptyCount 期望 2，实际 %d", res.EmptyCount)
	}
}

func TestScanPreflight_LegacyOnly_MigrationRequired(t *testing.T) {
	res := ScanPreflight([]SecretItem{
		{Kind: KindGlobal, Ref: "openai", Legacy: "sk-legacy-plaintext"},
	})
	if !res.MigrationRequired {
		t.Fatal("[安全回归失败] LEGACY_ONLY 未触发 MigrationRequired")
	}
	if !strings.Contains(strings.Join(res.Offenders, ","), "global:openai=LEGACY_ONLY") {
		t.Fatalf("Offenders 应含位置标注，实际 %v", res.Offenders)
	}
	// Offenders 不得包含 secret 明文
	for _, o := range res.Offenders {
		if strings.Contains(o, "sk-legacy-plaintext") {
			t.Fatal("[安全回归失败] Offenders 泄露明文 secret")
		}
	}
}

func TestScanPreflight_Mixed_MigrationRequiredAndNeedsKey(t *testing.T) {
	res := ScanPreflight([]SecretItem{
		{Kind: KindClient, Ref: "client-1", Legacy: "sk-legacy", Encrypted: "enc:v1:abc:def"},
	})
	if !res.MigrationRequired {
		t.Fatal("MIXED 应触发 MigrationRequired")
	}
	if !res.NeedMasterKey {
		t.Fatal("MIXED 需要解密比对，应 NeedMasterKey")
	}
	if len(res.EncryptedItems) != 1 {
		t.Fatalf("EncryptedItems 期望 1，实际 %d", len(res.EncryptedItems))
	}
}

func TestScanPreflight_EncryptedOnly_NeedsMasterKey(t *testing.T) {
	res := ScanPreflight([]SecretItem{
		{Kind: KindGlobal, Ref: "openai", Encrypted: "enc:v1:abc:def"},
		{Kind: KindClient, Ref: "client-1", Encrypted: "enc:v1:abc:ghi"},
	})
	if res.MigrationRequired {
		t.Fatal("ENCRYPTED_ONLY 不应触发迁移要求")
	}
	if !res.NeedMasterKey || len(res.EncryptedItems) != 2 {
		t.Fatalf("ENCRYPTED_ONLY 应 NeedMasterKey 且列出 2 项，实际 %+v", res)
	}
}

func TestScanPreflight_InvalidEncrypted_MigrationRequired(t *testing.T) {
	res := ScanPreflight([]SecretItem{
		{Kind: KindClient, Ref: "client-1", Encrypted: "not-an-envelope"},
	})
	if !res.MigrationRequired || len(res.InvalidRefs) != 1 {
		t.Fatalf("INVALID_ENCRYPTED 应阻断并列出位置，实际 %+v", res)
	}
}

func TestVerifyEncryptedItems_OKAndWrongKey(t *testing.T) {
	m := newTestManager(t)
	env, err := m.EncryptClientBackendKey("client-1", []byte("live-key"))
	if err != nil {
		t.Fatal(err)
	}
	items := []SecretItem{{Kind: KindClient, Ref: "client-1", Encrypted: env}}

	// 正确 Manager → 通过
	if err := VerifyEncryptedItems(m, items); err != nil {
		t.Fatalf("[安全回归失败] 正确 key 校验失败: %v", err)
	}

	// 错误 key 的 Manager → 失败
	wrongCipher, err := NewAESGCMCipher(testKey32Alt(t))
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyEncryptedItems(NewManager(wrongCipher), items); err == nil {
		t.Fatal("[安全回归失败] 错误 key 校验应失败")
	}

	// 空项跳过
	if err := VerifyEncryptedItems(m, []SecretItem{{Kind: KindGlobal, Ref: "ollama"}}); err != nil {
		t.Fatalf("空项应跳过，实际 %v", err)
	}
}

// [P1-03C1 防御] MigrationRequired 错误为哨兵错误，主程序 %w 包装后可 errors.Is 判定
func TestMigrationRequired_Sentinel(t *testing.T) {
	wrapped := func() error {
		return ErrProviderSecretMigrationRequired
	}
	if !errors.Is(wrapped(), ErrProviderSecretMigrationRequired) {
		t.Fatal("哨兵错误语义失效")
	}
	if !strings.Contains(ErrProviderSecretMigrationRequired.Error(), "PROVIDER_SECRET_MIGRATION_REQUIRED") {
		t.Fatal("错误信息应含机器可识别标记")
	}
}
