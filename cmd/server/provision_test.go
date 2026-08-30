package main

// P1-03D1A · Secure Global Provider Key Provisioning Gate
//
// 覆盖：安全 provisioning 全语义矩阵 + 纪律（无 argv/明文/信封泄漏、无临时残留、
// 失败路径零写入、LEGACY_ONLY/MIXED/INVALID/已加密均 fail-closed）。
// 全部在 t.TempDir() fixture 上执行，Master Key 走测试 ENV，绝无真实凭证。

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"ai-gateway/internal/audit"
	"ai-gateway/internal/config"
	"ai-gateway/internal/database"
	"ai-gateway/internal/models"
	"ai-gateway/internal/secrets"
)

const provCanary = "P103D1A_CANARY_GLOBAL_PROVISION_SECRET"
const provCanaryRotated = "P103D1A_CANARY_GLOBAL_PROVISION_SECRET_ROTATED"

func mustProvCipher(t *testing.T) *secrets.AESGCMCipher {
	t.Helper()
	c, err := secrets.NewAESGCMCipher(mustDecodeB64(t, testMasterKeyB64))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func writeProvConfig(t *testing.T, providerLines string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	dbPath := filepath.Join(dir, "gateway.db")
	db, err := database.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := audit.MigrateIntegrity(db); err != nil {
		t.Fatal(err)
	}
	if sqlDB, err := db.DB(); err == nil {
		_ = sqlDB.Close()
	}
	content := "server:\n  host: 127.0.0.1\n  port: 8090\nadmin:\n  username: admin\ndatabase:\n  path: \"" + filepath.ToSlash(dbPath) + "\"\nproviders:\n  openai:\n" + providerLines
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func runProv(t *testing.T, configPath, provider string, allowReplace bool, secret string) (string, error) {
	t.Helper()
	t.Setenv("AIGATEWAY_MASTER_KEY", testMasterKeyB64)
	var out bytes.Buffer
	reader := newProviderKeyReader(strings.NewReader(secret+"\n"), true)
	_, err := runSetProviderKey(configPath, provider, allowReplace, reader, &out)
	return out.String(), err
}

func provisionAuditEvents(t *testing.T, configPath string) []models.AuditEvent {
	t.Helper()
	cfg, err := config.LoadExistingForMigration(configPath)
	if err != nil {
		t.Fatal(err)
	}
	db, err := database.Open(cfg.Database.Path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if sqlDB, err := db.DB(); err == nil {
			_ = sqlDB.Close()
		}
	}()
	var events []models.AuditEvent
	if err := db.Order("id ASC").Find(&events).Error; err != nil {
		t.Fatal(err)
	}
	return events
}

// Happy path：EMPTY provider → 表单 canary 经隐藏输入加密落盘；明文/信封绝不进 stdout
func TestProvision_SetProviderKey_HappyPath(t *testing.T) {
	path := writeProvConfig(t, "    type: openai\n    base_url: https://api.example.internal/v1\n")

	out, err := runProv(t, path, "openai", false, provCanary)
	if err != nil {
		t.Fatalf("provisioning 失败: %v", err)
	}
	if strings.Contains(out, provCanary) || strings.Contains(out, "enc:v1:") {
		t.Fatal("[安全回归失败] stdout 泄露 secret 材料")
	}
	if !strings.Contains(out, "encrypted at rest") || !strings.Contains(out, "key_id=") {
		t.Fatalf("输出应含状态摘要: %q", out)
	}

	cfg, err := config.LoadExistingForMigration(path)
	if err != nil {
		t.Fatal(err)
	}
	p := cfg.Providers["openai"]
	if p.APIKey != "" {
		t.Fatalf("[安全回归失败] 持久化 api_key 应为空，实际 %q", p.APIKey)
	}
	if !secrets.IsEncryptedEnvelope(p.APIKeyEncrypted) {
		t.Fatalf("[安全回归失败] api_key_encrypted 应为信封，实际 %q", p.APIKeyEncrypted)
	}
	events := provisionAuditEvents(t, path)
	if len(events) != 1 || events[0].Action != audit.ActionGlobalProviderSecretChanged || events[0].ActorType != "cli" || events[0].ActorID != "set-provider-key" || events[0].TargetType != "provider" || events[0].TargetID != "openai" || events[0].Reason != "" {
		t.Fatalf("provisioning audit event mismatch: %+v", events)
	}
	mgr := secrets.NewManager(mustProvCipher(t))
	pt, err := mgr.DecryptGlobalProviderKey("openai", p.APIKeyEncrypted)
	if err != nil || string(pt) != provCanary {
		t.Fatalf("[功能回归失败] 解密应还原 canary，实际 %q err=%v", string(pt), err)
	}
	// 非 secret 字段保持
	if p.BaseURL != "https://api.example.internal/v1" || p.Type != "openai" {
		t.Fatalf("provisioning 不得破坏 provider 其他字段: %+v", p)
	}
	// 无临时残留
	if _, err := os.Stat(path + ".provisioning"); !os.IsNotExist(err) {
		t.Fatal("[安全回归失败] 残留 .provisioning 临时文件")
	}
	// YAML 不含明文键名 api_key
	raw, _ := os.ReadFile(path)
	if strings.Contains(string(raw), "\n    api_key: "+provCanary) {
		t.Fatal("[安全回归失败] YAML 出现明文 api_key")
	}
}

// config 缺失 → 拒绝且不创建（绝不代替 setup wizard）
func TestProvision_MissingConfig_RefusedNoCreate(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "absent.yaml")
	if _, err := runProv(t, path, "openai", false, provCanary); err == nil {
		t.Fatal("[安全回归失败] config 缺失应拒绝")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("[安全回归失败] provisioning 创建了缺失的 config")
	}
}

// provider 不存在 → 拒绝（typo 防护，不静默创建陌生 provider）
func TestProvision_UnknownProvider_Refused(t *testing.T) {
	path := writeProvConfig(t, "    type: openai\n")
	before, _ := os.ReadFile(path)
	if _, err := runProv(t, path, "oepnai", false, provCanary); err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("[安全回归失败] 未知 provider 应拒绝，实际 err=%v", err)
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(before, after) {
		t.Fatal("[安全回归失败] 拒绝路径修改了 config")
	}
}

func TestProvision_InvalidProviderName_RefusedWithoutMutation(t *testing.T) {
	for _, name := range []string{"", "bad\nname", strings.Repeat("p", 65)} {
		t.Run("invalid", func(t *testing.T) {
			path := writeProvConfig(t, "    type: openai\n")
			before, _ := os.ReadFile(path)
			if _, err := runProv(t, path, name, false, provCanary); err == nil {
				t.Fatal("invalid provider name must be rejected")
			}
			after, _ := os.ReadFile(path)
			if !bytes.Equal(before, after) {
				t.Fatal("invalid provider name changed config")
			}
		})
	}
}

// LEGACY_ONLY / MIXED / INVALID → 拒绝并指向迁移 CLI；文件零改动
func TestProvision_PlaintextAndCorruptStates_Refused(t *testing.T) {
	mgr := secrets.NewManager(mustProvCipher(t))
	env, _ := mgr.EncryptGlobalProviderKey("openai", []byte("already-encrypted"))

	cases := []struct {
		name    string
		lines   string
		wantErr string
	}{
		{"legacy_only", "    type: openai\n    api_key: P103D1A_LEGACY_PLACEHOLDER\n", "-migrate-provider-secrets"},
		{"mixed", "    type: openai\n    api_key: P103D1A_LEGACY_PLACEHOLDER\n    api_key_encrypted: " + env + "\n", "-migrate-provider-secrets"},
		{"invalid", "    type: openai\n    api_key_encrypted: not-an-envelope\n", "invalid/corrupt"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := writeProvConfig(t, tc.lines)
			before, _ := os.ReadFile(path)
			_, err := runProv(t, path, "openai", false, provCanary)
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("[安全回归失败] %s 应拒绝并提示 %q，实际 err=%v", tc.name, tc.wantErr, err)
			}
			after, _ := os.ReadFile(path)
			if !bytes.Equal(before, after) {
				t.Fatalf("[安全回归失败] %s 拒绝路径修改了 config", tc.name)
			}
		})
	}
}

// 既有 ENCRYPTED_ONLY：默认拒绝；显式 -replace-provider-key 才覆盖
func TestProvision_EncryptedExists_ReplaceSemantics(t *testing.T) {
	mgr := secrets.NewManager(mustProvCipher(t))
	oldEnv, _ := mgr.EncryptGlobalProviderKey("openai", []byte("old-secret"))
	path := writeProvConfig(t, "    type: openai\n    api_key_encrypted: "+oldEnv+"\n")

	// 默认拒绝
	if _, err := runProv(t, path, "openai", false, provCanary); err == nil || !strings.Contains(err.Error(), "-replace-provider-key") {
		t.Fatalf("[安全回归失败] 已加密 key 默认应拒绝，实际 err=%v", err)
	}

	// 显式 replace → 覆盖为新信封
	out, err := runProv(t, path, "openai", true, provCanaryRotated)
	if err != nil {
		t.Fatalf("显式替换失败: %v", err)
	}
	if strings.Contains(out, provCanaryRotated) {
		t.Fatal("[安全回归失败] stdout 泄露 secret 材料")
	}
	cfg, err := config.LoadExistingForMigration(path)
	if err != nil {
		t.Fatal(err)
	}
	newEnv := cfg.Providers["openai"].APIKeyEncrypted
	if newEnv == "" || newEnv == oldEnv {
		t.Fatalf("[安全回归失败] 应产生新信封，实际 %q", newEnv)
	}
	if events := provisionAuditEvents(t, path); len(events) != 1 || events[0].Action != audit.ActionGlobalProviderSecretChanged {
		t.Fatalf("replacement should append exactly one global provider audit event: %+v", events)
	}
	pt, err := mgr.DecryptGlobalProviderKey("openai", newEnv)
	if err != nil || string(pt) != provCanaryRotated {
		t.Fatalf("新信封应解密为新 key，实际 %q err=%v", string(pt), err)
	}
}

// Master Key 缺失 → fail-closed，config 零改动（绝不出现明文 fallback）
func TestProvision_MasterKeyMissing_FailClosed(t *testing.T) {
	path := writeProvConfig(t, "    type: openai\n")
	t.Setenv("AIGATEWAY_MASTER_KEY", "")
	os.Unsetenv("AIGATEWAY_MASTER_KEY")
	os.Unsetenv("AIGATEWAY_MASTER_KEY_FILE")

	before, _ := os.ReadFile(path)
	var out bytes.Buffer
	reader := newProviderKeyReader(strings.NewReader(provCanary+"\n"), true)
	if _, err := runSetProviderKey(path, "openai", false, reader, &out); err == nil {
		t.Fatal("[安全回归失败] 无 Master Key 应拒绝 provisioning")
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(before, after) {
		t.Fatal("[安全回归失败] 失败路径修改了 config")
	}
}

func TestProvision_AuditPreflightFailureLeavesConfigUnchanged(t *testing.T) {
	path := writeProvConfig(t, "    type: openai\n")
	cfg, err := config.LoadExistingForMigration(path)
	if err != nil {
		t.Fatal(err)
	}
	db, err := database.Open(cfg.Database.Path)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Exec("DROP TRIGGER audit_events_no_update").Error; err != nil {
		t.Fatal(err)
	}
	if sqlDB, err := db.DB(); err == nil {
		_ = sqlDB.Close()
	}
	before, _ := os.ReadFile(path)
	if _, err := runProv(t, path, "openai", false, provCanary); err == nil {
		t.Fatal("corrupt audit preflight must reject provider provisioning")
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(before, after) {
		t.Fatal("audit preflight failure changed config")
	}
}

// 空 key 输入 → 拒绝
func TestProvision_EmptyInput_Refused(t *testing.T) {
	path := writeProvConfig(t, "    type: openai\n")
	before, _ := os.ReadFile(path)
	if _, err := runProv(t, path, "openai", false, "   "); err == nil {
		t.Fatal("[安全回归失败] 空 key 应拒绝")
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(before, after) {
		t.Fatal("[安全回归失败] 失败路径修改了 config")
	}
}

// 非 TTY 且未显式 stdin 模式 → fail-closed（绝不回显/读取）
func TestProvision_NonTTY_DefaultRefused(t *testing.T) {
	r := newProviderKeyReader(bytes.NewBufferString("anything"), false)
	if _, err := r(); err == nil || !strings.Contains(err.Error(), "-provider-key-stdin") {
		t.Fatalf("[安全回归失败] 非 TTY 默认应拒绝，实际 err=%v", err)
	}
}

// stdin 模式：显式非交互路径读取并 trim
func TestProvision_StdinMode_ReadsTrimmed(t *testing.T) {
	r := newProviderKeyReader(strings.NewReader("  "+provCanary+"  \n"), true)
	got, err := r()
	if err != nil || string(got) != provCanary {
		t.Fatalf("stdin 模式应读取并 trim，实际 %q err=%v", string(got), err)
	}
}
