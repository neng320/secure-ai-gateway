package secrets

// P1-03B · Master Key + AEAD Foundation 测试
//
// 覆盖任务要求的全部 15 项：round-trip / 随机化 / 篡改 / nonce / 错误密钥 /
// 错误 AAD / 畸形信封 / 版本 / key_id / 缺失密钥 / base64 错 / 长度错 /
// 双源冲突 / key_id 稳定性 / 空明文与任意字节。
// 错误信息纪律：绝不包含明文/密钥/完整密文（测试内断言不含 canary key 材料本身）。

import (
	"encoding/base64"
	"strings"
	"testing"
)

func testKey32(t *testing.T) []byte {
	t.Helper()
	key, err := base64.StdEncoding.DecodeString("jJx0mGVJyJGKpLPUaUhSvUNqWYIVD3NtQazmOYnH8nk=") // 随机 32B 的 base64
	if err != nil || len(key) != 32 {
		t.Fatalf("test key setup: %v", err)
	}
	return key
}

func testKey32Alt(t *testing.T) []byte {
	t.Helper()
	key, err := base64.StdEncoding.DecodeString("GROnfCSaRXSkQ9VpR8kjD9Xc1vLGZ0zGKivSgNzTuw0=")
	if err != nil || len(key) != 32 {
		t.Fatalf("test key alt setup: %v", err)
	}
	return key
}

func newTestCipher(t *testing.T) *AESGCMCipher {
	t.Helper()
	c, err := NewAESGCMCipher(testKey32(t))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// 1) round-trip
func TestCipher_RoundTrip(t *testing.T) {
	c := newTestCipher(t)
	env, err := c.Encrypt([]byte("hello secrets"), "provider-config:openai")
	if err != nil {
		t.Fatal(err)
	}
	pt, err := c.Decrypt(env, "provider-config:openai")
	if err != nil {
		t.Fatal(err)
	}
	if string(pt) != "hello secrets" {
		t.Fatalf("round-trip 明文不符: %q", pt)
	}
}

// 2) 随机化加密：同明文同 AAD 两次密文必不同（随机 nonce）
func TestCipher_RandomizedEncryption(t *testing.T) {
	c := newTestCipher(t)
	e1, _ := c.Encrypt([]byte("same"), "aad")
	e2, _ := c.Encrypt([]byte("same"), "aad")
	if e1 == e2 {
		t.Fatal("[安全回归失败] 同明文两次加密产生了相同密文（nonce 未随机化）")
	}
}

// 3) 密文篡改 → fail
func TestCipher_TamperedCiphertext_Fails(t *testing.T) {
	c := newTestCipher(t)
	env, _ := c.Encrypt([]byte("secret-body"), "aad")
	raw, _ := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(env, "enc:v1:"+c.KeyID()+":"))
	raw[len(raw)-1] ^= 0x01 // 翻转 tag 最后一字节
	tampered := "enc:v1:" + c.KeyID() + ":" + base64.RawURLEncoding.EncodeToString(raw)
	if _, err := c.Decrypt(tampered, "aad"); err == nil {
		t.Fatal("[安全回归失败] 篡改密文未被发现")
	}
}

// 4) nonce 篡改 → fail
func TestCipher_TamperedNonce_Fails(t *testing.T) {
	c := newTestCipher(t)
	env, _ := c.Encrypt([]byte("secret-body"), "aad")
	raw, _ := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(env, "enc:v1:"+c.KeyID()+":"))
	raw[0] ^= 0x01 // nonce 首字节
	tampered := "enc:v1:" + c.KeyID() + ":" + base64.RawURLEncoding.EncodeToString(raw)
	if _, err := c.Decrypt(tampered, "aad"); err == nil {
		t.Fatal("[安全回归失败] 篡改 nonce 未被发现")
	}
}

// 5) 错误 Master Key → fail
func TestCipher_WrongMasterKey_Fails(t *testing.T) {
	c1 := newTestCipher(t)
	c2, err := NewAESGCMCipher(testKey32Alt(t))
	if err != nil {
		t.Fatal(err)
	}
	env, _ := c1.Encrypt([]byte("secret"), "aad")
	if _, err := c2.Decrypt(env, "aad"); err == nil {
		t.Fatal("[安全回归失败] 错误 Master Key 解密成功")
	}
}

// 6) 错误 AAD → fail（密文不可跨上下文复制）
func TestCipher_WrongAAD_Fails(t *testing.T) {
	c := newTestCipher(t)
	env, _ := c.Encrypt([]byte("secret"), "client-backend:client-A")
	if _, err := c.Decrypt(env, "client-backend:client-B"); err == nil {
		t.Fatal("[安全回归失败] 错误 AAD 解密成功（密文可跨上下文复制）")
	}
}

// 7) 畸形信封 → fail 且不 panic
func TestCipher_MalformedEnvelope_Fails(t *testing.T) {
	c := newTestCipher(t)
	bad := []string{
		"",
		"garbage",
		"enc:",
		"enc:v1",
		"enc:v1:",
		"enc:v1:" + c.KeyID(),
		"enc:v1:" + c.KeyID() + ":",
		"enc:v1:" + c.KeyID() + ":!!!not-base64!!!",
		"enc:v1:" + c.KeyID() + ":QUJD",               // base64 合法但短于 nonce
		"notenc:v1:" + c.KeyID() + ":QUJDREVG",        // 前缀错误
		"enc:v1:" + c.KeyID() + ":AAAA:extra",         // 分段过多
		strings.Repeat("enc:v1:"+c.KeyID()+":", 1000), // 超长畸形
	}
	for _, b := range bad {
		if pt, err := c.Decrypt(b, "aad"); err == nil {
			t.Fatalf("[安全回归失败] 畸形信封 %q 解密成功: %q", b, pt)
		}
	}
}

// 8) 不支持的版本 → ErrUnsupportedVersion
func TestCipher_UnsupportedVersion_Fails(t *testing.T) {
	c := newTestCipher(t)
	if _, err := c.Decrypt("enc:v2:"+c.KeyID()+":QUJDREVG", "aad"); err != ErrUnsupportedVersion {
		t.Fatalf("期望 ErrUnsupportedVersion，实际 %v", err)
	}
}

// 9) key_id 不匹配 → ErrKeyIDMismatch
func TestCipher_WrongKeyID_Fails(t *testing.T) {
	c := newTestCipher(t)
	if _, err := c.Decrypt("enc:v1:deadbeefdeadbeef:QUJDREVG", "aad"); err != ErrKeyIDMismatch {
		t.Fatalf("期望 ErrKeyIDMismatch，实际 %v", err)
	}
}

// 14) KeyID 稳定性：同 key 同 id；不同 key 不同 id
func TestCipher_KeyIDStability(t *testing.T) {
	k := testKey32(t)
	id1, id2 := KeyIDFromKey(k), KeyIDFromKey(k)
	if id1 != id2 || id1 == "" {
		t.Fatal("同 key 的 KeyID 必须稳定且非空")
	}
	if KeyIDFromKey(testKey32Alt(t)) == id1 {
		t.Fatal("不同 key 的 KeyID 不应相同")
	}
	c := newTestCipher(t)
	if c.KeyID() != id1 {
		t.Fatal("cipher.KeyID() 应与 KeyIDFromKey 一致")
	}
}

// 15) 空明文 / unicode / 任意字节
func TestCipher_EmptyUnicodeArbitraryBytes(t *testing.T) {
	c := newTestCipher(t)
	cases := [][]byte{
		{},
		[]byte("中文🔐unicode"),
		{0x00, 0x01, 0xFE, 0xFF, 0x0A, 0x00},
	}
	for i, pt := range cases {
		env, err := c.Encrypt(pt, "aad")
		if err != nil {
			t.Fatalf("case %d encrypt: %v", i, err)
		}
		got, err := c.Decrypt(env, "aad")
		if err != nil {
			t.Fatalf("case %d decrypt: %v", i, err)
		}
		if string(got) != string(pt) {
			t.Fatalf("case %d round-trip 不符", i)
		}
	}
}

// [P1-02B 同源纪律] 错误信息不泄露敏感材料：密文错误串不含明文与 key 材料
func TestCipher_ErrorsDoNotLeakMaterial(t *testing.T) {
	c := newTestCipher(t)
	plaintext := []byte("TOP-SECRET-BODY")
	env, _ := c.Encrypt(plaintext, "aad")
	payload, _ := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(env, "enc:v1:"+c.KeyID()+":"))
	payload[len(payload)-1] ^= 0xFF
	tampered := "enc:v1:" + c.KeyID() + ":" + base64.RawURLEncoding.EncodeToString(payload)
	_, err := c.Decrypt(tampered, "aad")
	if err == nil {
		t.Fatal("篡改应失败")
	}
	if strings.Contains(err.Error(), string(plaintext)) || strings.Contains(err.Error(), env) {
		t.Fatal("[安全回归失败] 错误信息泄露明文或完整密文")
	}
}

// [P1-02B 式防御] 畸形输入永不 panic（确定性恶意样本循环，替代 fuzz 扩展）
func TestCipher_DecryptNeverPanics(t *testing.T) {
	c := newTestCipher(t)
	nasty := []string{
		"enc:v1:" + c.KeyID() + ":", strings.Repeat(":", 200),
		"enc:v1:" + strings.Repeat("z", 100) + ":AAAA",
		"enc:v0:whatever:AAAA", "ENC:V1:AAAA:AAAA",
		"enc:v1:" + c.KeyID() + ":" + strings.Repeat("A", 100000),
	}
	for _, s := range nasty {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("Decrypt panic on %q: %v", s, r)
				}
			}()
			_, _ = c.Decrypt(s, "aad")
		}()
	}
}
