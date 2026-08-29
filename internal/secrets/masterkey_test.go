package secrets

// P1-03B · Master Key 加载测试（fail-closed 全矩阵）

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"encoding/base64"
)

const (
	validKeyB64    = "jJx0mGVJyJGKpLPUaUhSvUNqWYIVD3NtQazmOYnH8nk="
	validKeyB64Alt = "GROnfCSaRXSkQ9VpR8kjD9Xc1vLGZ0zGKivSgNzTuw0="
)

func getenvFrom(mapEnv map[string]string) func(string) string {
	return func(k string) string { return mapEnv[k] }
}

// 10) 都不存在 → ErrMasterKeyUnavailable
func TestLoadMasterKey_Missing_Fails(t *testing.T) {
	_, err := LoadMasterKey(getenvFrom(map[string]string{}))
	if !errors.Is(err, ErrMasterKeyUnavailable) {
		t.Fatalf("期望 ErrMasterKeyUnavailable，实际 %v", err)
	}
}

// 13) ENV + FILE 同时设置 → ErrMasterKeyConflict
func TestLoadMasterKey_BothSources_Conflict(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "mk")
	if err := os.WriteFile(file, []byte(validKeyB64), 0600); err != nil {
		t.Fatal(err)
	}
	_, err := LoadMasterKey(getenvFrom(map[string]string{
		EnvMasterKey:     validKeyB64,
		EnvMasterKeyFile: file,
	}))
	if !errors.Is(err, ErrMasterKeyConflict) {
		t.Fatalf("期望 ErrMasterKeyConflict，实际 %v", err)
	}
}

// ENV 正常加载 → 32 字节
func TestLoadMasterKey_Env_OK(t *testing.T) {
	key, err := LoadMasterKey(getenvFrom(map[string]string{EnvMasterKey: validKeyB64}))
	if err != nil {
		t.Fatal(err)
	}
	if len(key) != 32 {
		t.Fatalf("期望 32 字节，实际 %d", len(key))
	}
}

// FILE 正常加载（含换行空白 → TrimSpace）
func TestLoadMasterKey_File_OK(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "mk")
	if err := os.WriteFile(file, []byte(validKeyB64+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	key, err := LoadMasterKey(getenvFrom(map[string]string{EnvMasterKeyFile: file}))
	if err != nil {
		t.Fatal(err)
	}
	if len(key) != 32 {
		t.Fatalf("期望 32 字节，实际 %d", len(key))
	}
}

// FILE 不存在 → 明确错误（不含文件内容）
func TestLoadMasterKey_FileMissing_Fails(t *testing.T) {
	_, err := LoadMasterKey(getenvFrom(map[string]string{
		EnvMasterKeyFile: filepath.Join(t.TempDir(), "nope"),
	}))
	if err == nil || !strings.Contains(err.Error(), "master key file unreadable") {
		t.Fatalf("期望文件不可读错误，实际 %v", err)
	}
}

// 11) base64 非法 → fail
func TestLoadMasterKey_MalformedBase64_Fails(t *testing.T) {
	_, err := LoadMasterKey(getenvFrom(map[string]string{EnvMasterKey: "!!!not-base64!!!"}))
	if err == nil || !strings.Contains(err.Error(), "base64") {
		t.Fatalf("期望 base64 错误，实际 %v", err)
	}
}

// 12) 长度不是 32 字节 → fail（31 / 33 / 空）
func TestLoadMasterKey_WrongLength_Fails(t *testing.T) {
	for name, b64 := range map[string]string{
		"31 bytes": base64.StdEncoding.EncodeToString(make([]byte, 31)),
		"33 bytes": base64.StdEncoding.EncodeToString(make([]byte, 33)),
	} {
		if _, err := LoadMasterKey(getenvFrom(map[string]string{EnvMasterKey: b64})); err == nil || !strings.Contains(err.Error(), "32 bytes") {
			t.Fatalf("%s 期望长度错误，实际 %v", name, err)
		}
	}
	// 空 base64（解码后 0 字节）→ 与"未配置"同等 fail-closed，绝不静默通过
	if _, err := LoadMasterKey(getenvFrom(map[string]string{EnvMasterKey: ""})); err == nil {
		t.Fatal("[安全回归失败] 空 Master Key 来源被静默接受")
	}
}

// 端到端：加载的 key 可直接构造可用 Cipher 且 key_id 稳定
func TestLoadMasterKey_ThenCipher_EndToEnd(t *testing.T) {
	key, err := LoadMasterKey(getenvFrom(map[string]string{EnvMasterKey: validKeyB64}))
	if err != nil {
		t.Fatal(err)
	}
	c, err := NewAESGCMCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	env, err := c.Encrypt([]byte("e2e"), "e2e-aad")
	if err != nil {
		t.Fatal(err)
	}
	// 用另一个正确来源（FILE）加载同 key → 解密一致
	dir := t.TempDir()
	file := filepath.Join(dir, "mk")
	_ = os.WriteFile(file, []byte(validKeyB64), 0600)
	key2, err := LoadMasterKey(getenvFrom(map[string]string{EnvMasterKeyFile: file}))
	if err != nil {
		t.Fatal(err)
	}
	c2, _ := NewAESGCMCipher(key2)
	pt, err := c2.Decrypt(env, "e2e-aad")
	if err != nil || string(pt) != "e2e" {
		t.Fatalf("同 key 双来源解密失败: %v %q", err, pt)
	}
	// 不同 key → 不应解密
	key3, _ := LoadMasterKey(getenvFrom(map[string]string{EnvMasterKey: validKeyB64Alt}))
	c3, _ := NewAESGCMCipher(key3)
	if _, err := c3.Decrypt(env, "e2e-aad"); err == nil {
		t.Fatal("不同 key 不应解密成功")
	}
}

// [P1-03B 纪律] GenerateMasterKey：显式生成可用且每次不同（不静默保存）
func TestGenerateMasterKey_UniqueAndValid(t *testing.T) {
	g1, err := GenerateMasterKey()
	if err != nil {
		t.Fatal(err)
	}
	g2, err := GenerateMasterKey()
	if err != nil {
		t.Fatal(err)
	}
	if g1 == g2 {
		t.Fatal("两次生成的 Master Key 不应相同")
	}
	key, err := base64.StdEncoding.DecodeString(g1)
	if err != nil || len(key) != 32 {
		t.Fatalf("生成结果应为 base64(32B)，实际 len=%d err=%v", len(key), err)
	}
}
