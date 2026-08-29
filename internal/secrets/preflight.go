package secrets

// P1-03C1 · Secret 状态机与启动 Preflight
//
// 每个 Provider Secret 位置（全局 api_key / client backend_api_key）有且仅有五种状态：
//
//	EMPTY                legacy 与 encrypted 均空（无 Key 场景：Ollama/LM Studio）
//	LEGACY_ONLY          仅明文 → 正常服务拒绝启动，需执行迁移
//	ENCRYPTED_ONLY       仅密文 → 正常形态，需要 Master Key 才能运行
//	MIXED                两者并存 → 迁移中间态（PREPARE 后 FINALIZE 前），正常服务拒绝启动，
//	                     由迁移引擎 verify 后 finalize
//	INVALID_ENCRYPTED    encrypted 存在但不是 enc: 信封形态 → 数据损坏，拒绝启动
//
// 禁止在业务代码里散落 if string != "" 判断——统一走 ClassifySecret。

import (
	"errors"
	"fmt"
	"strings"
)

type SecretState int

const (
	SecretEmpty SecretState = iota
	SecretLegacyOnly
	SecretEncryptedOnly
	SecretMixed
	SecretInvalidEncrypted
)

func (s SecretState) String() string {
	switch s {
	case SecretEmpty:
		return "EMPTY"
	case SecretLegacyOnly:
		return "LEGACY_ONLY"
	case SecretEncryptedOnly:
		return "ENCRYPTED_ONLY"
	case SecretMixed:
		return "MIXED"
	case SecretInvalidEncrypted:
		return "INVALID_ENCRYPTED"
	}
	return "UNKNOWN"
}

// IsEncryptedEnvelope: 粗判是否为 AEAD 信封形态（深度校验由 Decrypt 完成）
func IsEncryptedEnvelope(encrypted string) bool {
	return strings.HasPrefix(encrypted, EnvelopePrefix+":"+EnvelopeVersion+":")
}

// ClassifySecret: 依据 legacy/encrypted 两个存储位判定状态。
func ClassifySecret(legacy, encrypted string) SecretState {
	hasLegacy := legacy != ""
	hasEnc := encrypted != "" && IsEncryptedEnvelope(encrypted)
	corruptEnc := encrypted != "" && !IsEncryptedEnvelope(encrypted)

	switch {
	case !hasLegacy && !hasEnc && !corruptEnc:
		return SecretEmpty
	case hasLegacy && !hasEnc && !corruptEnc:
		return SecretLegacyOnly
	case !hasLegacy && hasEnc:
		return SecretEncryptedOnly
	case hasLegacy && hasEnc:
		return SecretMixed
	default: // corruptEnc
		return SecretInvalidEncrypted
	}
}

// ---------------------------------------------------------------------------
// 启动 Preflight
// ---------------------------------------------------------------------------

// SecretItem: 一个待检 Provider Secret 位置
type SecretItem struct {
	Kind      string // "global"（Ref=provider name）或 "client"（Ref=client ID）
	Ref       string
	Legacy    string
	Encrypted string
}

const (
	KindGlobal = "global"
	KindClient = "client"
)

// ErrProviderSecretMigrationRequired: 检测到明文 Provider Secret，正常服务拒绝启动。
// main 层必须以此错误退出（fail-closed），并提示执行迁移命令。
var ErrProviderSecretMigrationRequired = errors.New(
	"PROVIDER_SECRET_MIGRATION_REQUIRED: plaintext provider secrets present; " +
		"run: gateway --migrate-provider-secrets -config <config-path> --migration-backup-dir <dir>")

// PreflightResult: 启动 preflight 结果
type PreflightResult struct {
	// MigrationRequired: 存在 LEGACY_ONLY / MIXED / INVALID 明文或损坏 → 正常服务必须拒绝启动
	MigrationRequired bool
	// Offenders: 触发阻断的位置（只含 kind:ref=STATE，不含 secret）
	Offenders []string
	// InvalidRefs: encrypted 字段非 enc: 信封形态的位置
	InvalidRefs []string
	// NeedMasterKey: 存在需要解密的内容（ENCRYPTED_ONLY / MIXED）
	NeedMasterKey bool
	// EncryptedItems: 需要解密才能运行/校验的位置（ENCRYPTED_ONLY / MIXED 均含密文）
	EncryptedItems []SecretItem
	// EmptyCount: 空 secret 位置数
	EmptyCount int
}

// ScanPreflight: 汇总所有位置的启动前判定。
// 返回错误仅用于数据损坏（INVALID）之外的编程性失败；明文存在通过 MigrationRequired 表达。
func ScanPreflight(items []SecretItem) PreflightResult {
	res := PreflightResult{}
	for _, it := range items {
		st := ClassifySecret(it.Legacy, it.Encrypted)
		switch st {
		case SecretEmpty:
			res.EmptyCount++
		case SecretLegacyOnly:
			res.MigrationRequired = true
			res.Offenders = append(res.Offenders, it.Kind+":"+it.Ref+"=LEGACY_ONLY")
		case SecretMixed:
			res.MigrationRequired = true
			res.Offenders = append(res.Offenders, it.Kind+":"+it.Ref+"=MIXED")
			res.EncryptedItems = append(res.EncryptedItems, it)
		case SecretEncryptedOnly:
			res.NeedMasterKey = true
			res.EncryptedItems = append(res.EncryptedItems, it)
		case SecretInvalidEncrypted:
			res.MigrationRequired = true // 数据损坏同样阻断启动（先修数据再迁移）
			res.InvalidRefs = append(res.InvalidRefs, it.Kind+":"+it.Ref)
			res.Offenders = append(res.Offenders, it.Kind+":"+it.Ref+"=INVALID_ENCRYPTED")
		}
	}
	return res
}

// VerifyEncryptedItems: 用 Manager 逐项试解密（启动 preflight 的
// "Master Key 错误 / key_id 不符 / decrypt fail → fail closed" 落点）。
// 返回第一个失败的错误（错误不含 secret 材料）。
func VerifyEncryptedItems(m *Manager, items []SecretItem) error {
	for _, it := range items {
		if it.Encrypted == "" {
			continue
		}
		var err error
		switch it.Kind {
		case KindGlobal:
			_, err = m.DecryptGlobalProviderKey(it.Ref, it.Encrypted)
		case KindClient:
			_, err = m.DecryptClientBackendKey(it.Ref, it.Encrypted)
		default:
			return fmt.Errorf("secrets: unknown secret item kind %q", it.Kind)
		}
		if err != nil {
			return fmt.Errorf("secrets: encrypted secret at %s:%s failed verification: %w", it.Kind, it.Ref, err)
		}
	}
	return nil
}
