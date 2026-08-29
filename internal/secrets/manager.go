package secrets

// P1-03C0 · Domain Secret Manager
//
// 业务层（Provider Registry / handlers / migration）不得自行拼 AAD 或直接操作
// AES/GCM。所有 Provider Secret 的加解密必须经过本 Manager：
//
//	Global Provider Key → AAD "provider-config:v1:<provider-name>"
//	Client Backend Key  → AAD "client-backend:v1:<client-id>"
//
// 规则：
//   - provider name / client ID 为空（或纯空白）→ fail-closed
//   - 名称规范化仅 TrimSpace（使用配置 map 中的 canonical 名称，不隐式改名）；
//     Encrypt 与 Decrypt 使用完全相同的规范化，杜绝两侧不一致
//   - Client 使用稳定 Client.ID，不使用 Name

import (
	"errors"
	"strings"
)

const (
	// GlobalProviderAADPrefix / ClientBackendAADPrefix: 领域 AAD 前缀（版本化）
	GlobalProviderAADPrefix = "provider-config:v1:"
	ClientBackendAADPrefix  = "client-backend:v1:"
)

var (
	// ErrEmptyProviderName: provider 名称为空（fail-closed）
	ErrEmptyProviderName = errors.New("secrets: provider name is empty")
	// ErrEmptyClientID: client ID 为空（fail-closed）
	ErrEmptyClientID = errors.New("secrets: client id is empty")
)

// Manager: 领域级 Secret Manager——业务层唯一入口。
type Manager struct {
	cipher Cipher
}

func NewManager(c Cipher) *Manager {
	return &Manager{cipher: c}
}

func globalProviderAAD(providerName string) (string, error) {
	name := strings.TrimSpace(providerName)
	if name == "" {
		return "", ErrEmptyProviderName
	}
	return GlobalProviderAADPrefix + name, nil
}

func clientBackendAAD(clientID string) (string, error) {
	id := strings.TrimSpace(clientID)
	if id == "" {
		return "", ErrEmptyClientID
	}
	return ClientBackendAADPrefix + id, nil
}

// EncryptGlobalProviderKey: 加密全局 Provider Key（AAD 绑定 canonical provider name）。
func (m *Manager) EncryptGlobalProviderKey(providerName string, plaintext []byte) (string, error) {
	aad, err := globalProviderAAD(providerName)
	if err != nil {
		return "", err
	}
	return m.cipher.Encrypt(plaintext, aad)
}

// DecryptGlobalProviderKey: 解密全局 Provider Key。
func (m *Manager) DecryptGlobalProviderKey(providerName string, envelope string) ([]byte, error) {
	aad, err := globalProviderAAD(providerName)
	if err != nil {
		return nil, err
	}
	return m.cipher.Decrypt(envelope, aad)
}

// EncryptClientBackendKey: 加密 Client Backend Key（AAD 绑定稳定 Client.ID）。
func (m *Manager) EncryptClientBackendKey(clientID string, plaintext []byte) (string, error) {
	aad, err := clientBackendAAD(clientID)
	if err != nil {
		return "", err
	}
	return m.cipher.Encrypt(plaintext, aad)
}

// DecryptClientBackendKey: 解密 Client Backend Key。
func (m *Manager) DecryptClientBackendKey(clientID string, envelope string) ([]byte, error) {
	aad, err := clientBackendAAD(clientID)
	if err != nil {
		return nil, err
	}
	return m.cipher.Decrypt(envelope, aad)
}

// KeyID: 透传当前 Master Key 标识（迁移/审计用）。
func (m *Manager) KeyID() string { return m.cipher.KeyID() }
