package secrets

// Master Key 加载（fail-closed）
//
// 来源（恰好其一，禁止同时配置）：
//   AIGATEWAY_MASTER_KEY      —— base64 编码的 32 字节随机密钥
//   AIGATEWAY_MASTER_KEY_FILE —— 含 base64 密钥的文件路径
//
// 硬性规则：
//   - 两者同时设置 → ErrMasterKeyConflict
//   - 都不存在     → ErrMasterKeyUnavailable
//   - base64/长度非法 → 明确错误
//   - 禁止自动生成并静默保存 Master Key
//   - 错误信息绝不包含密钥内容或文件内容

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"strings"
)

const (
	// EnvMasterKey: base64 编码的 256-bit Master Key
	EnvMasterKey = "AIGATEWAY_MASTER_KEY"
	// EnvMasterKeyFile: 含 base64 Master Key 的文件路径
	EnvMasterKeyFile = "AIGATEWAY_MASTER_KEY_FILE"
)

// LoadMasterKey 从环境（或密钥文件）加载 32 字节 Master Key。
// getenv 可注入（测试用）；生产传 os.Getenv。
func LoadMasterKey(getenv func(string) string) ([]byte, error) {
	envVal := strings.TrimSpace(getenv(EnvMasterKey))
	fileVal := strings.TrimSpace(getenv(EnvMasterKeyFile))

	if envVal != "" && fileVal != "" {
		return nil, ErrMasterKeyConflict
	}
	if envVal == "" && fileVal == "" {
		return nil, ErrMasterKeyUnavailable
	}

	raw := envVal
	if envVal == "" {
		data, err := os.ReadFile(fileVal)
		if err != nil {
			return nil, fmt.Errorf("secrets: master key file unreadable: %w", err)
		}
		raw = strings.TrimSpace(string(data))
	}
	if raw == "" {
		return nil, fmt.Errorf("secrets: master key source is empty")
	}

	key, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		return nil, fmt.Errorf("secrets: master key must be base64-encoded 32 bytes: %w", err)
	}
	if len(key) != KeySize {
		return nil, fmt.Errorf("secrets: master key must decode to %d bytes, got %d", KeySize, len(key))
	}
	return key, nil
}

// GenerateMasterKey: 生成新的随机 Master Key（显式调用，绝不静默保存）。
// 返回 base64 编码形式，供运维配置 ENV/FILE 使用。
func GenerateMasterKey() (string, error) {
	key := make([]byte, KeySize)
	if _, err := rand.Read(key); err != nil {
		return "", fmt.Errorf("secrets: master key generation failed: %w", err)
	}
	return base64.StdEncoding.EncodeToString(key), nil
}
