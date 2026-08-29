package config

// P1-03C2.1 · Secret JSON 暴露回归 + 迁移纯读加载器
//
// 覆盖（任务卡修正 4 + 修正 1 的 loader 部分）：
//   - ProviderConfig.APIKey / APIKeyEncrypted 均为 json:"-"：
//     任何 json.Marshal(cfg) 路径都不得出现 legacy 明文、信封、或 "api_key" 键名
//   - LoadExistingForMigration：缺失/解析失败 → 错误且不创建/不修改文件；
//     不生成 default password / session secret；legacy gemini 段仅内存合并

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const jsonCanary = "P103C21_CANARY_JSON_PROVIDER_SECRET"
const jsonEnvelope = "enc:v1:deadbeef:QUJDREVGR0hJSktMTU5PUA"

// [安全回归]（反转自"legacy 明文可进 JSON"）：
// ProviderConfig 单体与整个 Config 的 JSON 序列化都不得包含任何 secret 材料。
func TestProviderConfig_JSON_OmitsSecretFields(t *testing.T) {
	p := ProviderConfig{Type: "openai", APIKey: jsonCanary, APIKeyEncrypted: jsonEnvelope}
	out := marshalJSON(t, p)
	assertNoSecret(t, out)

	cfg := &Config{Providers: map[string]ProviderConfig{
		"openai": {Type: "openai", APIKey: jsonCanary, APIKeyEncrypted: jsonEnvelope, BaseURL: "https://api.example.internal/v1"},
	}}
	out = marshalJSON(t, cfg)
	assertNoSecret(t, out)

	// 非对称确认：序列化仍在工作（非 secret 字段可见）
	if !strings.Contains(out, `"base_url":"https://api.example.internal/v1"`) {
		t.Fatalf("JSON 序列化应保留非 secret 字段，实际: %s", out)
	}
}

func marshalJSON(t *testing.T, v interface{}) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func assertNoSecret(t *testing.T, out string) {
	t.Helper()
	if strings.Contains(out, jsonCanary) {
		t.Fatal("[安全回归失败] legacy 明文 API Key 出现在 JSON 序列化中")
	}
	if strings.Contains(out, jsonEnvelope) {
		t.Fatal("[安全回归失败] 密文信封出现在 JSON 序列化中")
	}
	if strings.Contains(out, "api_key") {
		t.Fatal("[安全回归失败] 'api_key' 键名出现在 JSON 序列化中")
	}
}

func writeMigrationCfg(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

// LoadExistingForMigration：文件不存在 → 错误，且绝不创建文件
func TestLoadExistingForMigration_MissingFile_ErrorNoCreate(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "absent.yaml")
	if _, err := LoadExistingForMigration(path); err == nil {
		t.Fatal("文件不存在应返回错误")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("[安全回归失败] 纯读 loader 创建了缺失的配置文件")
	}
}

// LoadExistingForMigration：解析失败 → 错误，且文件字节不变
func TestLoadExistingForMigration_ParseError_NoWrite(t *testing.T) {
	path := writeMigrationCfg(t, "[unclosed\n")
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := LoadExistingForMigration(path); err == nil {
		t.Fatal("解析失败应返回错误")
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatal("[安全回归失败] 解析失败后配置文件被修改")
	}
}

// LoadExistingForMigration：绝不生成 default password / session secret（ensureDefaults 不参与）
func TestLoadExistingForMigration_NoDefaultsGenerated(t *testing.T) {
	path := writeMigrationCfg(t, "server:\n  host: 127.0.0.1\nadmin:\n  username: admin\nproviders: {}\n")
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadExistingForMigration(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Admin.PasswordHash != "" {
		t.Fatalf("[安全回归失败] 迁移 loader 生成了 password_hash（含 __SETUP_REQUIRED__）: %q", cfg.Admin.PasswordHash)
	}
	if cfg.Admin.SessionSecret != "" {
		t.Fatal("[安全回归失败] 迁移 loader 生成了 session secret")
	}
	after, _ := os.ReadFile(path)
	if string(before) != string(after) {
		t.Fatal("[安全回归失败] 纯读 loader 修改了配置文件")
	}
}

// LoadExistingForMigration：legacy 顶层 gemini 段仅内存合并，文件保持原样
func TestLoadExistingForMigration_LegacyGeminiSection_InMemoryOnly(t *testing.T) {
	path := writeMigrationCfg(t, "gemini:\n  api_key: "+jsonCanary+"\n  default_model: gemini-2.0-flash\n")
	cfg, err := LoadExistingForMigration(path)
	if err != nil {
		t.Fatal(err)
	}
	gp, ok := cfg.Providers["gemini"]
	if !ok || gp.APIKey != jsonCanary {
		t.Fatalf("legacy gemini 段应内存并入 Providers，实际 %+v", cfg.Providers)
	}
	raw, _ := os.ReadFile(path)
	if !strings.Contains(string(raw), "gemini:") {
		t.Fatal("[安全回归失败] 迁移 loader 把内存合并结果写回了文件")
	}
}
