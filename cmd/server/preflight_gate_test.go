package main

// P1-03C1 · 启动 preflight（Provider Secrets fail-closed）回归测试
//
// 覆盖：
//   legacy plaintext   → REFUSE（PROVIDER_SECRET_MIGRATION_REQUIRED）
//   mixed              → REFUSE
//   encrypted 无 key    → REFUSE
//   encrypted 错 key    → REFUSE
//   encrypted 对 key    → PASS（返回已验证 Manager）
//   全空无 key          → PASS（Ollama/LM Studio 场景）
//   client 侧密文       → PASS/REFUSE 同规则

import (
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"ai-gateway/internal/config"
	"ai-gateway/internal/models"
	"ai-gateway/internal/secrets"

	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

const (
	testMasterKeyB64    = "jJx0mGVJyJGKpLPUaUhSvUNqWYIVD3NtQazmOYnH8nk="
	testMasterKeyB64Alt = "GROnfCSaRXSkQ9VpR8kjD9Xc1vLGZ0zGKivSgNzTuw0="
)

func mustCipherForTest(t *testing.T) *secrets.AESGCMCipher {
	t.Helper()
	c, err := secrets.NewAESGCMCipher(mustDecodeB64(t, testMasterKeyB64))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func mustDecodeB64(t *testing.T, s string) []byte {
	t.Helper()
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// newPreflightFixture: 临时配置（Load 设定 SourcePath）+ 已迁移表结构的临时 DB
func newPreflightFixture(t *testing.T) (*config.Config, *gorm.DB) {
	t.Helper()
	cfgPath := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(cfgPath, []byte("server:\n  host: 127.0.0.1\n  port: 8090\nadmin:\n  username: admin\n  cookie_secure: false\n"), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	hash, _ := bcrypt.GenerateFromPassword([]byte("preflight-test-password"), bcrypt.DefaultCost)
	cfg.Admin.Username = "admin"
	cfg.Admin.PasswordHash = string(hash)
	cfg.Providers = map[string]config.ProviderConfig{}

	db, err := gorm.Open(sqlite.Open(filepath.Join(t.TempDir(), "gw.db")), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.AutoMigrate(&models.Client{}, &models.RequestLog{}, &models.DailyUsage{}, &models.AdminSession{}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if sqlDB, e := db.DB(); e == nil {
			_ = sqlDB.Close()
		}
	})
	return cfg, db
}

// clearMasterKeyEnv: 清空两个来源（模拟未配置）
func clearMasterKeyEnv(t *testing.T) {
	t.Helper()
	t.Setenv("AIGATEWAY_MASTER_KEY", "")
	t.Setenv("AIGATEWAY_MASTER_KEY_FILE", "")
	os.Unsetenv("AIGATEWAY_MASTER_KEY")
	os.Unsetenv("AIGATEWAY_MASTER_KEY_FILE")
}

func TestPreflightGate_LegacyPlaintext_Refused(t *testing.T) {
	cfg, db := newPreflightFixture(t)
	cfg.Providers["openai"] = config.ProviderConfig{
		Type:    "openai",
		APIKey:  "sk-legacy-plaintext-live-key",
		BaseURL: "https://api.openai.example/v1",
	}
	_, err := ensureProviderSecretsRunnable(cfg, db)
	if err == nil {
		t.Fatal("[安全回归失败] legacy 明文 Provider Secret 未被拒绝启动")
	}
	if !errors.Is(err, secrets.ErrProviderSecretMigrationRequired) {
		t.Fatalf("错误应含 PROVIDER_SECRET_MIGRATION_REQUIRED 哨兵，实际 %v", err)
	}
	if strings.Contains(err.Error(), "sk-legacy-plaintext-live-key") {
		t.Fatal("[安全回归失败] 启动错误信息泄露明文 secret")
	}
	t.Logf("拒绝信息: %v", err)
}

func TestPreflightGate_Mixed_Refused(t *testing.T) {
	cfg, db := newPreflightFixture(t)
	mgr := secrets.NewManager(mustCipherForTest(t))
	env, _ := mgr.EncryptGlobalProviderKey("openai", []byte("encrypted-part"))
	cfg.Providers["openai"] = config.ProviderConfig{
		Type:            "openai",
		APIKey:          "sk-legacy-still-here",
		APIKeyEncrypted: env,
		BaseURL:         "https://api.openai.example/v1",
	}
	if _, err := ensureProviderSecretsRunnable(cfg, db); !errors.Is(err, secrets.ErrProviderSecretMigrationRequired) {
		t.Fatalf("[安全回归失败] MIXED 未被拒绝启动，实际 %v", err)
	}
}

func TestPreflightGate_Encrypted_NoMasterKey_Refused(t *testing.T) {
	cfg, db := newPreflightFixture(t)
	mgr := secrets.NewManager(mustCipherForTest(t))
	env, _ := mgr.EncryptGlobalProviderKey("openai", []byte("live-key"))
	cfg.Providers["openai"] = config.ProviderConfig{
		Type:            "openai",
		APIKeyEncrypted: env,
		BaseURL:         "https://api.openai.example/v1",
	}
	clearMasterKeyEnv(t)
	if _, err := ensureProviderSecretsRunnable(cfg, db); err == nil {
		t.Fatal("[安全回归失败] 密文存在但无 Master Key 未被拒绝")
	}
}

func TestPreflightGate_Encrypted_WrongMasterKey_Refused(t *testing.T) {
	cfg, db := newPreflightFixture(t)
	mgr := secrets.NewManager(mustCipherForTest(t))
	env, _ := mgr.EncryptGlobalProviderKey("openai", []byte("live-key"))
	cfg.Providers["openai"] = config.ProviderConfig{
		Type:            "openai",
		APIKeyEncrypted: env,
		BaseURL:         "https://api.openai.example/v1",
	}
	t.Setenv("AIGATEWAY_MASTER_KEY", testMasterKeyB64Alt)
	if _, err := ensureProviderSecretsRunnable(cfg, db); err == nil {
		t.Fatal("[安全回归失败] 错误 Master Key 未被拒绝")
	}
}

func TestPreflightGate_Encrypted_CorrectKey_Passes(t *testing.T) {
	cfg, db := newPreflightFixture(t)
	mgr := secrets.NewManager(mustCipherForTest(t))
	env, _ := mgr.EncryptGlobalProviderKey("openai", []byte("live-key"))
	cfg.Providers["openai"] = config.ProviderConfig{
		Type:            "openai",
		APIKeyEncrypted: env,
		BaseURL:         "https://api.openai.example/v1",
	}
	t.Setenv("AIGATEWAY_MASTER_KEY", testMasterKeyB64)
	got, err := ensureProviderSecretsRunnable(cfg, db)
	if err != nil {
		t.Fatalf("[安全回归失败] 正确 Master Key 应通过，实际 %v", err)
	}
	if got == nil {
		t.Fatal("应返回已验证的 Manager")
	}
}

func TestPreflightGate_AllEmpty_NoMasterKey_Passes(t *testing.T) {
	cfg, db := newPreflightFixture(t)
	clearMasterKeyEnv(t)
	mgr, err := ensureProviderSecretsRunnable(cfg, db)
	if err != nil {
		t.Fatalf("[安全回归失败] 全空场景应允许无 Master Key 启动，实际 %v", err)
	}
	if mgr != nil {
		t.Fatal("全空场景 Manager 应为 nil")
	}
}

// P1-03C3 · Manager availability：空系统 + 恰好配置一个合法 Master Key →
// 返回非 nil Manager（Admin 才能在空系统上安全新增第一个 Provider Secret）
func TestPreflightGate_AllEmpty_ValidMasterKey_ManagerAvailable(t *testing.T) {
	cfg, db := newPreflightFixture(t)
	t.Setenv("AIGATEWAY_MASTER_KEY", testMasterKeyB64)
	mgr, err := ensureProviderSecretsRunnable(cfg, db)
	if err != nil {
		t.Fatalf("[安全回归失败] 全空 + 合法 Master Key 应构造 Manager，实际 %v", err)
	}
	if mgr == nil {
		t.Fatal("[安全回归失败] 空系统 + Master Key 已配置时 Manager 不应为 nil——否则第一个 secret 无法加密新增")
	}
}

// P1-03C3 · 空系统 + 双源冲突 → fail-closed（运营者配置了 Secret 基础设施但配置错误）
func TestPreflightGate_AllEmpty_ConflictingSources_Refused(t *testing.T) {
	cfg, db := newPreflightFixture(t)
	t.Setenv("AIGATEWAY_MASTER_KEY", testMasterKeyB64)
	t.Setenv("AIGATEWAY_MASTER_KEY_FILE", "C:\\nonexistent\\master.key")
	if _, err := ensureProviderSecretsRunnable(cfg, db); err == nil {
		t.Fatal("[安全回归失败] 空系统 + 双源冲突应拒绝启动")
	}
}

// P1-03C3 · 空系统 + Master Key 格式非法 → fail-closed
func TestPreflightGate_AllEmpty_InvalidMasterKey_Refused(t *testing.T) {
	cfg, db := newPreflightFixture(t)
	t.Setenv("AIGATEWAY_MASTER_KEY", "not-valid-base64-!!!")
	if _, err := ensureProviderSecretsRunnable(cfg, db); err == nil {
		t.Fatal("[安全回归失败] 空系统 + 非法 Master Key 应拒绝启动")
	}
}

// Client 侧密文同样受 preflight 保护（正确 key 通过）
func TestPreflightGate_ClientEncrypted_CorrectKey_Passes(t *testing.T) {
	cfg, db := newPreflightFixture(t)
	t.Setenv("AIGATEWAY_MASTER_KEY", testMasterKeyB64)
	mgr := secrets.NewManager(mustCipherForTest(t))

	client := &models.Client{ID: "client-preflight-1", Name: "kf", Backend: "openai"}
	if err := db.Create(client).Error; err != nil {
		t.Fatal(err)
	}
	env, err := mgr.EncryptClientBackendKey(client.ID, []byte("live-key"))
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Model(&models.Client{}).Where("id = ?", client.ID).
		Update("backend_api_key_encrypted", env).Error; err != nil {
		t.Fatal(err)
	}

	if _, err := ensureProviderSecretsRunnable(cfg, db); err != nil {
		t.Fatalf("[安全回归失败] client 密文 + 正确 key 应通过，实际 %v", err)
	}
}
