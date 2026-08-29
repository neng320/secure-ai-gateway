package services

import (
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"log"
	"time"

	"ai-gateway/internal/config"
	"ai-gateway/internal/models"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type ClientService struct {
	db *gorm.DB
}

// ErrClientNotFound: 稳定 sentinel（P1-05B）。RowsAffected==0 时返回——
// handler 一律 errors.Is 判断，禁止按字符串匹配错误。
var ErrClientNotFound = errors.New("client not found")

func NewClientService(db *gorm.DB) *ClientService {
	return &ClientService{db: db}
}

func (s *ClientService) CreateClient(name, description, keyType, keyPrefix string, cfg *config.Config) (*models.Client, string, error) {
	apiKey := GenerateAPIKeyWithPrefix(keyType, keyPrefix)
	apiKeyHash := hashAPIKey(apiKey)

	client := &models.Client{
		ID:                   uuid.New().String(),
		Name:                 name,
		Description:          description,
		APIKeyHash:           apiKeyHash,
		KeyPrefix:            keyPrefix,
		IsActive:             true,
		RateLimitMinute:      cfg.Defaults.RateLimit.RequestsPerMinute,
		RateLimitHour:        cfg.Defaults.RateLimit.RequestsPerHour,
		RateLimitDay:         cfg.Defaults.RateLimit.RequestsPerDay,
		QuotaInputTokensDay:  cfg.Defaults.Quota.MaxInputTokensPerDay,
		QuotaOutputTokensDay: cfg.Defaults.Quota.MaxOutputTokensPerDay,
		QuotaRequestsDay:     cfg.Defaults.Quota.MaxRequestsPerDay,
		MaxInputTokens:       cfg.Defaults.Quota.MaxInputTokens,
		MaxOutputTokens:      cfg.Defaults.Quota.MaxOutputTokens,
		CreatedAt:            time.Now(),
		UpdatedAt:            time.Now(),
	}

	if err := s.db.Create(client).Error; err != nil {
		return nil, "", fmt.Errorf("failed to create client: %w", err)
	}

	return client, apiKey, nil
}

func (s *ClientService) GetClientByAPIKey(apiKey string) (*models.Client, error) {
	apiKeyHash := hashAPIKey(apiKey)
	// P1-04.2：key 前缀也是凭证材料——日志只允许哈希片段
	log.Printf("[CLIENT] Looking up API key (hash: %x)", apiKeyHash[:8])

	var client models.Client
	err := s.db.Where("api_key_hash = ? AND is_active = ?", apiKeyHash, true).First(&client).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			log.Printf("[CLIENT] No client found for key (hash: %x)", apiKeyHash[:8])
			return nil, nil
		}
		return nil, err
	}

	log.Printf("[CLIENT] Found client: %s (%s)", client.Name, client.ID)
	return &client, nil
}

func (s *ClientService) GetClientByID(id string) (*models.Client, error) {
	var client models.Client
	err := s.db.Where("id = ?", id).First(&client).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return &client, nil
}

func (s *ClientService) GetAllClients() ([]models.Client, error) {
	var clients []models.Client
	err := s.db.Order("created_at DESC").Find(&clients).Error
	return clients, err
}

func (s *ClientService) UpdateClient(client *models.Client) error {
	client.UpdatedAt = time.Now()
	return s.db.Save(client).Error
}

func (s *ClientService) UpdateLastSeen(clientID string) error {
	return s.db.Model(&models.Client{}).Where("id = ?", clientID).Update("last_seen", time.Now()).Error
}

// DeleteClient: ALL OR NOTHING（P1-05B）。client 删除与 operational data
// （request_logs / daily_usages）清理在同一事务内；任一步 DB error → 整体
// rollback。RowsAffected==0（id 不存在）→ ErrClientNotFound。
// 顺序：先清 children 再删 client——即使 SQLite FK CASCADE 未生效（旧库），
// 事务内显式清理仍保证无孤儿；FK 生效时行列删除为幂等 no-op。
func (s *ClientService) DeleteClient(id string) error {
	return s.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("client_id = ?", id).Delete(&models.DailyUsage{}).Error; err != nil {
			return fmt.Errorf("delete daily usage: %w", err)
		}
		if err := tx.Where("client_id = ?", id).Delete(&models.RequestLog{}).Error; err != nil {
			return fmt.Errorf("delete request logs: %w", err)
		}
		res := tx.Where("id = ?", id).Delete(&models.Client{})
		if res.Error != nil {
			return res.Error
		}
		if res.RowsAffected == 0 {
			return ErrClientNotFound
		}
		return nil
	})
}

// SetClientActive: Suspend/Resume（P1-05B）。显式目标状态优于盲 toggle；
// UpdatedAt 同步更新。RowsAffected==0 → ErrClientNotFound。
func (s *ClientService) SetClientActive(id string, active bool) error {
	res := s.db.Model(&models.Client{}).Where("id = ?", id).Updates(map[string]interface{}{
		"is_active":  active,
		"updated_at": time.Now(),
	})
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return ErrClientNotFound
	}
	return nil
}

func (s *ClientService) RegenerateAPIKey(clientID, keyType, keyPrefix string) (string, error) {
	apiKey := GenerateAPIKeyWithPrefix(keyType, keyPrefix)
	apiKeyHash := hashAPIKey(apiKey)

	res := s.db.Model(&models.Client{}).Where("id = ?", clientID).Updates(map[string]interface{}{
		"api_key_hash": apiKeyHash,
		"key_prefix":   keyPrefix,
		"updated_at":   time.Now(),
	})

	if res.Error != nil {
		// 失败路径绝不让调用方拿到未入库的新明文 key
		return "", res.Error
	}
	if res.RowsAffected == 0 {
		return "", ErrClientNotFound
	}

	return apiKey, nil
}

func (s *ClientService) ValidateAPIKey(apiKey string, storedHash []byte) bool {
	return subtle.ConstantTimeCompare(hashAPIKey(apiKey), storedHash) == 1
}

func (s *ClientService) GetClientsByIDs(ids []string) ([]models.Client, error) {
	var clients []models.Client
	err := s.db.Where("id IN ?", ids).Find(&clients).Error
	return clients, err
}

func GenerateAPIKey(keyType string) string {
	return GenerateAPIKeyWithPrefix(keyType, "")
}

func GenerateAPIKeyWithPrefix(keyType, customPrefix string) string {
	var prefix string
	if customPrefix != "" {
		prefix = customPrefix
	} else {
		switch keyType {
		case "anthropic":
			prefix = "sk-ant-"
		case "openai":
			prefix = "sk-"
		default:
			prefix = "gm_"
		}
	}
	return prefix + uuid.New().String()
}

func generateAPIKey() string {
	return GenerateAPIKey("gemini")
}

func hashAPIKey(apiKey string) []byte {
	hash := sha256.Sum256([]byte(apiKey))
	return hash[:]
}
