package main

// P1-03D1A · Secure Global Provider Key Provisioning
//
// 为全新部署提供"第一天就不产生明文 api_key"的安全入口：
//
//	ai-gateway -config /etc/ai-gateway/config.yaml -set-provider-key openai
//
// 硬性纪律：
//   - Provider Key 绝不允许作为 CLI 参数（防 shell history / argv 泄露）
//   - 默认 TTY no-echo 输入（x/term.ReadPassword）+ 二次确认；非 TTY 默认拒绝，
//     仅显式 -provider-key-stdin 允许非交互（stdin 内容同样绝不回显）
//   - 不写任何临时明文文件；config 走 candidate + 临时文件 + rename 原子替换
//   - stdout/log/error 永不包含 secret 或 envelope
//   - 既有 LEGACY_ONLY/MIXED → 拒绝并指向 migration CLI；INVALID → 拒绝
//   - 既有 ENCRYPTED_ONLY → 默认拒绝，须显式 -replace-provider-key 才覆盖
//   - provider 不存在 → 拒绝（防 typo 制造陌生 provider）
//   - Master Key 仍为 ENV/FILE 恰好其一，fail-closed

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"unicode"
	"unicode/utf8"

	"ai-gateway/internal/audit"
	"ai-gateway/internal/config"
	"ai-gateway/internal/configaudit"
	"ai-gateway/internal/configstore"
	"ai-gateway/internal/database"
	"ai-gateway/internal/models"
	"ai-gateway/internal/secrets"

	"golang.org/x/term"
	"gorm.io/gorm"
)

// provisionResult: 仅供输出摘要使用（不含任何 secret 材料）。
type provisionResult struct {
	Provider   string
	KeyID      string
	ConfigPath string
	Replaced   bool
}

// runSetProviderKey: -set-provider-key 主流程。readSecret 由调用方注入
// （生产：TTY no-echo / stdin 模式；测试：注入固定值）。任何失败路径都不得
// 修改磁盘上的 config。
func runSetProviderKey(configPath, providerName string, allowReplace bool, readSecret func() ([]byte, error), stdout io.Writer) (*provisionResult, error) {
	return runSetProviderKeyWithAuditDBOpener(configPath, providerName, allowReplace, readSecret, openProviderAuditDB, stdout)
}

// runSetProviderKeyWithAuditDBOpener keeps the production flow testable at the
// audit-write boundary without adding a production fault-injection switch.
// Production callers always pass openProviderAuditDB.
func runSetProviderKeyWithAuditDBOpener(configPath, providerName string, allowReplace bool, readSecret func() ([]byte, error), openAuditDB func(string) (*gorm.DB, error), stdout io.Writer) (*provisionResult, error) {
	providerName = strings.TrimSpace(providerName)
	if providerName == "" || !utf8.ValidString(providerName) || len([]rune(providerName)) > 64 {
		return nil, errors.New("invalid provider name")
	}
	for _, r := range providerName {
		if unicode.IsControl(r) {
			return nil, errors.New("invalid provider name")
		}
	}
	if configPath == "" {
		return nil, errors.New("config path is required")
	}

	// config 必须已存在（绝不代替 setup wizard 创建默认配置）
	if st, err := os.Stat(configPath); err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("config %s not found — start the gateway once (setup wizard) to create it first", configPath)
		}
		return nil, fmt.Errorf("config %s: %w", configPath, err)
	} else if !st.Mode().IsRegular() {
		return nil, fmt.Errorf("config %s is not a regular file", configPath)
	}

	// Cheap pre-lock validation avoids prompting for an obviously unknown or
	// already-provisioned provider. The authoritative copy is re-read below
	// under the cross-process mutation lock.
	cfg, err := config.LoadExistingForMigration(configPath)
	if err != nil {
		return nil, fmt.Errorf("load config: %w", err)
	}

	// provider 必须已声明（typo 防护：不静默创建陌生 provider）
	p, ok := cfg.Providers[providerName]
	if !ok {
		return nil, fmt.Errorf("provider %q not found in config — declare the provider section (type/base_url) first; refusing to create an unknown provider", providerName)
	}

	// 状态机判定（与 preflight/迁移引擎同一分类器）
	switch state := secrets.ClassifySecret(p.APIKey, p.APIKeyEncrypted); state {
	case secrets.SecretLegacyOnly, secrets.SecretMixed:
		return nil, fmt.Errorf("provider %q holds a legacy plaintext key — run -migrate-provider-secrets instead (plaintext provisioning is not allowed)", providerName)
	case secrets.SecretInvalidEncrypted:
		return nil, fmt.Errorf("provider %q holds an invalid/corrupt encrypted key — manual intervention required", providerName)
	case secrets.SecretEncryptedOnly:
		if !allowReplace {
			return nil, fmt.Errorf("provider %q already has an encrypted key — pass -replace-provider-key to overwrite it deliberately", providerName)
		}
	}

	secret, err := readSecret()
	if err != nil {
		return nil, err
	}
	if len(secret) == 0 {
		return nil, errors.New("empty provider key — nothing to provision")
	}

	key, err := secrets.LoadMasterKey(os.Getenv)
	if err != nil {
		return nil, err
	}
	cipher, err := secrets.NewAESGCMCipher(key)
	if err != nil {
		return nil, err
	}
	mgr := secrets.NewManager(cipher)
	var replaced bool
	if openAuditDB == nil {
		return nil, errors.New("audit database opener is required")
	}
	if err := configaudit.New(nil).RunLocked(configaudit.Mutation{
		ConfigPath: configPath,
		Build: func(snapshot configstore.Snapshot) (configaudit.BuildResult, error) {
			authoritative, err := config.ParseExistingForMigration(snapshot.Bytes)
			if err != nil {
				return configaudit.BuildResult{}, fmt.Errorf("parse authoritative config: %w", err)
			}
			provider, ok := authoritative.Providers[providerName]
			if !ok {
				return configaudit.BuildResult{}, fmt.Errorf("provider %q not found in config", providerName)
			}
			switch state := secrets.ClassifySecret(provider.APIKey, provider.APIKeyEncrypted); state {
			case secrets.SecretLegacyOnly, secrets.SecretMixed:
				return configaudit.BuildResult{}, fmt.Errorf("provider %q holds a legacy plaintext key — run -migrate-provider-secrets instead (plaintext provisioning is not allowed)", providerName)
			case secrets.SecretInvalidEncrypted:
				return configaudit.BuildResult{}, fmt.Errorf("provider %q holds an invalid/corrupt encrypted key — manual intervention required", providerName)
			case secrets.SecretEncryptedOnly:
				if !allowReplace {
					return configaudit.BuildResult{}, fmt.Errorf("provider %q already has an encrypted key — pass -replace-provider-key to overwrite it deliberately", providerName)
				}
			}
			auditDB, err := openAuditDB(authoritative.Database.Path)
			if err != nil {
				return configaudit.BuildResult{}, fmt.Errorf("audit preflight: %w", err)
			}
			cleanup := func() {
				if sqlDB, dbErr := auditDB.DB(); dbErr == nil {
					_ = sqlDB.Close()
				}
			}
			envelope, err := mgr.EncryptGlobalProviderKey(providerName, secret)
			if err != nil {
				cleanup()
				return configaudit.BuildResult{}, fmt.Errorf("encrypt provider key: %w", err)
			}
			candidate := *authoritative
			candidate.Providers = make(map[string]config.ProviderConfig, len(authoritative.Providers))
			for name, configuredProvider := range authoritative.Providers {
				candidate.Providers[name] = configuredProvider
			}
			candidateProvider := candidate.Providers[providerName]
			candidateProvider.APIKey = "" // 持久化视图绝不持有明文
			candidateProvider.APIKeyEncrypted = envelope
			candidate.Providers[providerName] = candidateProvider
			candidateBytes, err := config.MarshalYAML(&candidate)
			if err != nil {
				cleanup()
				return configaudit.BuildResult{}, fmt.Errorf("marshal config: %w", err)
			}
			replaced = provider.APIKeyEncrypted != ""
			return configaudit.BuildResult{
				Candidate: candidateBytes,
				Audit:     audit.NewService(auditDB),
				Cleanup:   cleanup,
				Event: models.AuditEvent{
					Action: audit.ActionGlobalProviderSecretChanged, ActorType: "cli", ActorID: "set-provider-key",
					TargetType: "provider", TargetID: providerName,
				},
			}, nil
		},
	}); err != nil {
		return nil, err
	}

	res := &provisionResult{
		Provider:   providerName,
		KeyID:      mgr.KeyID(),
		ConfigPath: configPath,
		Replaced:   replaced,
	}
	fmt.Fprintf(stdout, "provider %q key provisioned (encrypted at rest, key_id=%s, config=%s)\n",
		res.Provider, res.KeyID, res.ConfigPath)
	return res, nil
}

func openProviderAuditDB(path string) (*gorm.DB, error) {
	if path == "" {
		return nil, errors.New("database path is required for audited provisioning")
	}
	st, err := os.Stat(path)
	if err != nil {
		if !os.IsNotExist(err) {
			return nil, fmt.Errorf("database %s: %w (refusing to create)", path, err)
		}
		// Fresh-install provisioning may be the first database operation. It
		// bootstraps the audit schema before the config candidate is persisted;
		// this is never an unaudited config-write exception.
		if dir := filepath.Dir(path); dir != "." {
			if err := os.MkdirAll(dir, 0700); err != nil {
				return nil, fmt.Errorf("create database directory: %w", err)
			}
		}
	} else if !st.Mode().IsRegular() {
		return nil, fmt.Errorf("database %s is not a regular file", path)
	}
	db, err := database.Open(path)
	if err != nil {
		return nil, err
	}
	if err := audit.MigrateIntegrity(db); err != nil {
		if sqlDB, dbErr := db.DB(); dbErr == nil {
			_ = sqlDB.Close()
		}
		return nil, err
	}
	return db, nil
}

// newProviderKeyReader: 构造默认的 secret 读取器。
//   - stdin 模式（显式 -provider-key-stdin）：从 r 读取一行；不回显（管道场景天然不回显）
//   - 默认：r 必须是 TTY（char device）；no-echo 读取 + 二次确认
//
// 两个分支都绝不把输入写进任何 log/stdout。
func newProviderKeyReader(r io.Reader, stdinMode bool) func() ([]byte, error) {
	if stdinMode {
		return func() ([]byte, error) {
			data, err := io.ReadAll(r)
			if err != nil {
				return nil, fmt.Errorf("read provider key from stdin: %w", err)
			}
			s := strings.TrimSpace(string(data))
			if s == "" {
				return nil, errors.New("empty provider key from stdin")
			}
			return []byte(s), nil
		}
	}

	f, isFile := r.(*os.File)
	if !isFile {
		return func() ([]byte, error) {
			return nil, errors.New("provider key input must be a TTY (interactive) or use -provider-key-stdin")
		}
	}
	return func() ([]byte, error) {
		if !term.IsTerminal(int(f.Fd())) {
			return nil, errors.New("stdin is not a TTY — use -provider-key-stdin for explicit non-interactive provisioning (input is never echoed)")
		}
		fmt.Fprintln(os.Stderr, "Enter provider key (input hidden):")
		first, err := term.ReadPassword(int(f.Fd()))
		if err != nil {
			return nil, fmt.Errorf("read provider key: %w", err)
		}
		fmt.Fprintln(os.Stderr)
		if len(strings.TrimSpace(string(first))) == 0 {
			return nil, errors.New("empty provider key")
		}
		fmt.Fprintln(os.Stderr, "Re-enter provider key to confirm:")
		second, err := term.ReadPassword(int(f.Fd()))
		if err != nil {
			return nil, fmt.Errorf("read provider key confirmation: %w", err)
		}
		fmt.Fprintln(os.Stderr)
		if string(first) != string(second) {
			return nil, errors.New("provider key confirmation does not match — nothing was written")
		}
		return []byte(strings.TrimSpace(string(first))), nil
	}
}
