// Package secrets 提供静态加密（encryption at rest）的密码学基础设施。
//
// P1-03B 范围：仅本包 + 测试。不接入 ProviderConfig.APIKey、Client.BackendAPIKey、
// Admin Handler、Provider 运行时、数据库 migration——业务接入属 P1-03C（需人工验收）。
//
// 设计要点（ADR-006）：
//   - AES-256-GCM（Go 标准库 crypto/aes + cipher.NewGCM），随机 96-bit nonce
//   - 版本化信封：enc:v1:<key_id>:<base64url(nonce|ciphertext+GCM tag)>
//   - AAD 参与认证（密文不可跨上下文复制，如 client-backend:<client-id>）
//   - Master Key 只来自外部（ENV 或 FILE），fail-closed：缺失/冲突/格式错误一律拒绝
//   - 本包不做任何日志输出，错误信息不含明文/密钥/完整密文
package secrets

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

const (
	// EnvelopePrefix: 密文信封固定前缀
	EnvelopePrefix = "enc"
	// EnvelopeVersion: 信封版本（当前唯一支持 v1）
	EnvelopeVersion = "v1"
	// nonceSize: GCM 标准 nonce 长度
	nonceSize = 12
	// KeySize: AES-256 主密钥字节数
	KeySize = 32
)

var (
	// ErrMasterKeyUnavailable: 未配置任何 Master Key 来源
	ErrMasterKeyUnavailable = errors.New("secrets: master key unavailable (set AIGATEWAY_MASTER_KEY or AIGATEWAY_MASTER_KEY_FILE)")
	// ErrMasterKeyConflict: 同时配置了两个来源，拒绝启动语义（fail-closed）
	ErrMasterKeyConflict = errors.New("secrets: both AIGATEWAY_MASTER_KEY and AIGATEWAY_MASTER_KEY_FILE are set; configure exactly one")
	// ErrInvalidEnvelope: 信封格式非法（前缀/分段/base64/长度）
	ErrInvalidEnvelope = errors.New("secrets: malformed ciphertext envelope")
	// ErrUnsupportedVersion: 信封版本不被当前实现支持
	ErrUnsupportedVersion = errors.New("secrets: unsupported envelope version")
	// ErrKeyIDMismatch: 信封 key_id 与当前 Master Key 不符
	ErrKeyIDMismatch = errors.New("secrets: envelope key_id does not match this master key")
)

// Cipher: 业务层使用的最小加密接口。业务层不得直接操作 AES/GCM。
type Cipher interface {
	// Encrypt: 加密并返回版本化信封字符串。aad 参与认证但不加密。
	Encrypt(plaintext []byte, aad string) (string, error)
	// Decrypt: 校验并解密信封。aad 必须与加密时完全一致。
	Decrypt(envelope string, aad string) ([]byte, error)
	// KeyID: 当前 Master Key 的稳定标识（用于信封与未来轮换）。
	KeyID() string
}

// AESGCMCipher: Cipher 的 AES-256-GCM 实现。
type AESGCMCipher struct {
	gcm   cipher.AEAD
	keyID string
}

var _ Cipher = (*AESGCMCipher)(nil)

// NewAESGCMCipher: 用 32 字节 Master Key 构造。
func NewAESGCMCipher(masterKey []byte) (*AESGCMCipher, error) {
	if len(masterKey) != KeySize {
		return nil, fmt.Errorf("secrets: master key must be %d bytes, got %d", KeySize, len(masterKey))
	}
	block, err := aes.NewCipher(masterKey)
	if err != nil {
		return nil, fmt.Errorf("secrets: aes init failed: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("secrets: gcm init failed: %w", err)
	}
	return &AESGCMCipher{gcm: gcm, keyID: KeyIDFromKey(masterKey)}, nil
}

// KeyIDFromKey: Master Key 的稳定标识 = SHA-256(key) 前 8 字节 hex。
// 仅作标识用途，不是加密密钥的替代品。
func KeyIDFromKey(masterKey []byte) string {
	sum := sha256.Sum256(masterKey)
	return hex.EncodeToString(sum[:8])
}

// KeyID 实现 Cipher.KeyID。
func (c *AESGCMCipher) KeyID() string { return c.keyID }

// Encrypt 实现 Cipher.Encrypt。每次调用生成新的随机 nonce（同一明文两次加密产生不同密文）。
func (c *AESGCMCipher) Encrypt(plaintext []byte, aad string) (string, error) {
	nonce := make([]byte, nonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("secrets: nonce generation failed: %w", err)
	}
	sealed := c.gcm.Seal(nonce, nonce, plaintext, []byte(aad))
	return EnvelopePrefix + ":" + EnvelopeVersion + ":" + c.keyID + ":" +
		base64.RawURLEncoding.EncodeToString(sealed), nil
}

// Decrypt 实现 Cipher.Decrypt。任何篡改（密文/nonce/tag/AAD/key_id/版本）都返回错误。
// 错误信息不包含明文、密钥或完整密文。
func (c *AESGCMCipher) Decrypt(envelope string, aad string) ([]byte, error) {
	if !strings.HasPrefix(envelope, EnvelopePrefix+":") {
		return nil, ErrInvalidEnvelope
	}
	parts := strings.Split(envelope, ":")
	if len(parts) != 4 {
		return nil, ErrInvalidEnvelope
	}
	if parts[1] != EnvelopeVersion {
		return nil, ErrUnsupportedVersion
	}
	if parts[2] != c.keyID {
		return nil, ErrKeyIDMismatch
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[3])
	if err != nil {
		return nil, ErrInvalidEnvelope
	}
	if len(raw) < nonceSize {
		return nil, ErrInvalidEnvelope
	}
	nonce, ciphertext := raw[:nonceSize], raw[nonceSize:]
	plaintext, err := c.gcm.Open(nil, nonce, ciphertext, []byte(aad))
	if err != nil {
		return nil, fmt.Errorf("secrets: decrypt failed (tampered or wrong key/aad): %w", err)
	}
	return plaintext, nil
}
