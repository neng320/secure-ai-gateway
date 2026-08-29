package services

import (
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"log"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"ai-gateway/internal/audit"
	"ai-gateway/internal/config"
	"ai-gateway/internal/models"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// 稳定错误 sentinel（P1-05C）。handler 一律 errors.Is 判断，禁止字符串匹配。
var (
	// ErrClientNotFound: id 不存在。
	ErrClientNotFound = errors.New("client not found")
	// ErrClientRevoked: terminal state——REVOKED 后 Resume/Rotate/Suspend/再 Revoke 均拒绝。
	ErrClientRevoked = errors.New("client is revoked")
	// ErrInvalidLifecycleTransition: 非法的状态迁移（例如已 SUSPENDED 再 Suspend）。
	ErrInvalidLifecycleTransition = errors.New("invalid lifecycle transition")
	// ErrInvalidLifecycleReason: reason 不符合 policy（缺失/过长/控制字符/非法 UTF-8）。
	ErrInvalidLifecycleReason = errors.New("invalid lifecycle reason")
)

// validateLifecycleReason: 规范化 + policy 校验（§5）。
// required=true 时非空；最大 256 Unicode code points；UTF-8 valid；
// 拒绝 CR/LF 与控制字符。返回 TrimSpace 后的规范化结果。
func validateLifecycleReason(reason string, required bool) (string, error) {
	normalized := strings.TrimSpace(reason)
	if required && normalized == "" {
		return "", fmt.Errorf("%w: reason required", ErrInvalidLifecycleReason)
	}
	if !utf8.ValidString(normalized) {
		return "", fmt.Errorf("%w: reason must be valid UTF-8", ErrInvalidLifecycleReason)
	}
	if len([]rune(normalized)) > 256 {
		return "", fmt.Errorf("%w: reason too long", ErrInvalidLifecycleReason)
	}
	for _, r := range normalized {
		if r == '\n' || r == '\r' || unicode.IsControl(r) {
			return "", fmt.Errorf("%w: reason contains control characters", ErrInvalidLifecycleReason)
		}
	}
	return normalized, nil
}

type ClientService struct {
	db    *gorm.DB
	audit *audit.Service
}

func NewClientService(db *gorm.DB) *ClientService {
	return &ClientService{db: db, audit: audit.NewService(db)}
}

// lifecycleTransitionError: 条件更新 RowsAffected==0 时，区分 client 不存在 /
// 已 revoked / 非目标状态（§3 terminal invariants 的 sentinel 映射）。
func lifecycleTransitionError(tx *gorm.DB, id, op string) error {
	var c models.Client
	err := tx.Select("id", "revoked_at", "is_active").Where("id = ?", id).First(&c).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return ErrClientNotFound
	}
	if err != nil {
		return err
	}
	if c.RevokedAt != nil {
		return ErrClientRevoked
	}
	return fmt.Errorf("%w: %s: client is not in the expected state", ErrInvalidLifecycleTransition, op)
}

// CreateClient: 生成 key → client + CLIENT_CREATED audit 同事务 → commit 成功
// 后才向调用者返回 plaintext key（§11）。actor 由服务端可信身份注入（§6）。
func (s *ClientService) CreateClient(name, description, keyType, keyPrefix string, cfg *config.Config, actor string) (*models.Client, string, error) {
	return s.createClient(name, description, keyType, keyPrefix, cfg, actor, nil)
}

// CreateClientWithSettings: 在同一 transaction 内创建 client、写入 allowlisted
// settings 并 append CLIENT_CREATED audit。settingsFactory 在 transaction 内以
// 服务端生成的 client ID 为参数，可安全生成与 ID 绑定的 provider-key envelope；
// 任一 factory/settings/audit 错误都会 rollback 整个 create。
func (s *ClientService) CreateClientWithSettings(name, description, keyType, keyPrefix string, cfg *config.Config, actor string, settingsFactory func(string) (map[string]interface{}, error)) (*models.Client, string, error) {
	return s.createClient(name, description, keyType, keyPrefix, cfg, actor, settingsFactory)
}

func (s *ClientService) createClient(name, description, keyType, keyPrefix string, cfg *config.Config, actor string, settingsFactory func(string) (map[string]interface{}, error)) (*models.Client, string, error) {
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

	err := s.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(client).Error; err != nil {
			return fmt.Errorf("failed to create client: %w", err)
		}
		if settingsFactory != nil {
			settings, err := settingsFactory(client.ID)
			if err != nil {
				return err
			}
			filtered, err := filterSettings(settings)
			if err != nil {
				return err
			}
			if len(filtered) != 0 {
				filtered["updated_at"] = time.Now()
				if err := tx.Model(&models.Client{}).Where("id = ?", client.ID).Updates(filtered).Error; err != nil {
					return fmt.Errorf("failed to save client settings: %w", err)
				}
			}
		}
		return s.audit.RecordTx(tx, models.AuditEvent{
			Action: audit.ActionClientCreated, ActorType: "admin", ActorID: actor,
			TargetType: "client", TargetID: client.ID,
		})
	})
	if err != nil {
		return nil, "", err
	}

	return client, apiKey, nil
}

func (s *ClientService) GetClientByAPIKey(apiKey string) (*models.Client, error) {
	apiKeyHash := hashAPIKey(apiKey)
	// P1-04.2：key 前缀也是凭证材料——日志只允许哈希片段
	log.Printf("[CLIENT] Looking up API key (hash: %x)", apiKeyHash[:8])

	var client models.Client
	// REVOKED client 的 api_key_hash 为 SQL NULL → 任何 key 均无法命中 → 401
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

// UpdateLastSeen: 单列 bounded update（不触碰任何 lifecycle 字段）。
func (s *ClientService) UpdateLastSeen(clientID string) error {
	return s.db.Model(&models.Client{}).Where("id = ?", clientID).Update("last_seen", time.Now()).Error
}

// allowedSettingsColumns: settings 更新的列白名单（§4）——结构上排除
// api_key_hash / is_active / revoked_at / revoked_by / revocation_reason。
// 白名单外字段一律拒绝（fail-closed），普通 settings 更新不可能触碰 lifecycle 真相。
var allowedSettingsColumns = map[string]bool{
	"name":                      true,
	"description":               true,
	"backend":                   true,
	"backend_api_key_encrypted": true,
	"backend_base_url":          true,
	"backend_default_model":     true,
	"backend_models":            true,
	"fallback_models":           true,
	"system_prompt":             true,
	"tool_mode":                 true,
	"server_tools":              true,
	"rate_limit_minute":         true,
	"rate_limit_hour":           true,
	"rate_limit_day":            true,
	"quota_input_tokens_day":    true,
	"quota_output_tokens_day":   true,
	"quota_requests_day":        true,
	"max_input_tokens":          true,
	"max_output_tokens":         true,
}

// ErrInvalidSettingsField: 尝试经 settings 更新写入白名单外字段。
var ErrInvalidSettingsField = errors.New("invalid settings field")

func filterSettings(updates map[string]interface{}) (map[string]interface{}, error) {
	filtered := make(map[string]interface{}, len(updates))
	for key, value := range updates {
		if !allowedSettingsColumns[key] {
			return nil, fmt.Errorf("%w: %q is not an allowlisted settings column", ErrInvalidSettingsField, key)
		}
		filtered[key] = value
	}
	return filtered, nil
}

// UpdateClientSettings: allowlisted settings update（只写白名单列 + UpdatedAt；
// 部分字段更新，未提供的列保持不变）。不产生 audit event（非 lifecycle action）；
// 任何路径都无法清 RevokedAt / 改 RevokedBy / 写回 APIKeyHash / 把 IsActive
// 重新设 true（§3 terminal invariants）。
func (s *ClientService) UpdateClientSettings(id string, updates map[string]interface{}) error {
	filtered, err := filterSettings(updates)
	if err != nil {
		return err
	}
	filtered["updated_at"] = time.Now()

	// SQLite 对值未变化的行 RowsAffected=0——存在性必须显式预检，不能靠 RowsAffected 判 not-found
	var n int64
	if err := s.db.Model(&models.Client{}).Where("id = ?", id).Count(&n).Error; err != nil {
		return err
	}
	if n == 0 {
		return ErrClientNotFound
	}
	return s.db.Model(&models.Client{}).Where("id = ?", id).Updates(filtered).Error
}

// UpdateClientModels: dedicated bounded update（FetchClientModels/UpdateClientModels
// 不再整行 Save）——只写 backend_models + updated_at。
func (s *ClientService) UpdateClientModels(id, modelList string) error {
	return s.db.Model(&models.Client{}).Where("id = ?", id).
		Updates(map[string]interface{}{"backend_models": modelList, "updated_at": time.Now()}).Error
}

// SuspendClient: ACTIVE → SUSPENDED（§13）。reason required；hash 保留；
// 每次成功恰好 1 条 CLIENT_SUSPENDED event（与 mutation 同事务）。
func (s *ClientService) SuspendClient(id, actor, reason string) error {
	normalized, err := validateLifecycleReason(reason, true)
	if err != nil {
		return err
	}
	return s.db.Transaction(func(tx *gorm.DB) error {
		res := tx.Model(&models.Client{}).Where("id = ? AND revoked_at IS NULL AND is_active = ?", id, true).
			Updates(map[string]interface{}{"is_active": false, "updated_at": time.Now()})
		if res.Error != nil {
			return res.Error
		}
		if res.RowsAffected == 0 {
			return lifecycleTransitionError(tx, id, "suspend")
		}
		return s.audit.RecordTx(tx, models.AuditEvent{
			Action: audit.ActionClientSuspended, ActorType: "admin", ActorID: actor,
			TargetType: "client", TargetID: id, Reason: normalized,
		})
	})
}

// ResumeClient: SUSPENDED → ACTIVE（§13）。reason optional（提供则仍过同一 validator）；
// hash 保留；CLIENT_RESUMED event 同事务。
func (s *ClientService) ResumeClient(id, actor, reason string) error {
	normalized, err := validateLifecycleReason(reason, false)
	if err != nil {
		return err
	}
	return s.db.Transaction(func(tx *gorm.DB) error {
		res := tx.Model(&models.Client{}).Where("id = ? AND revoked_at IS NULL AND is_active = ?", id, false).
			Updates(map[string]interface{}{"is_active": true, "updated_at": time.Now()})
		if res.Error != nil {
			return res.Error
		}
		if res.RowsAffected == 0 {
			return lifecycleTransitionError(tx, id, "resume")
		}
		return s.audit.RecordTx(tx, models.AuditEvent{
			Action: audit.ActionClientResumed, ActorType: "admin", ActorID: actor,
			TargetType: "client", TargetID: id, Reason: normalized,
		})
	})
}

// RevokeClient: Permanent REVOKE（§2/§12/§14）。单事务：
//
//	存在性 → 未 revoked → reason 合法（已预校验）→ actor 服务端可信 →
//	IsActive=false / RevokedAt / RevokedBy / RevocationReason / api_key_hash=SQL NULL /
//	CLIENT_REVOKED audit → commit。
//
// api_key_hash 必须是 NULL 而非 empty []byte——unique index 下多个 revoked client
// 若都写 empty blob 会碰撞。
func (s *ClientService) RevokeClient(id, actor, reason string) error {
	normalized, err := validateLifecycleReason(reason, true)
	if err != nil {
		return err
	}
	return s.db.Transaction(func(tx *gorm.DB) error {
		now := time.Now()
		res := tx.Model(&models.Client{}).Where("id = ? AND revoked_at IS NULL", id).
			Updates(map[string]interface{}{
				"is_active":         false,
				"revoked_at":        now,
				"revoked_by":        actor,
				"revocation_reason": normalized,
				"api_key_hash":      nil, // SQL NULL：revoked key 永久失效且不重写
				"updated_at":        now,
			})
		if res.Error != nil {
			return res.Error
		}
		if res.RowsAffected == 0 {
			return lifecycleTransitionError(tx, id, "revoke")
		}
		return s.audit.RecordTx(tx, models.AuditEvent{
			Action: audit.ActionClientRevoked, ActorType: "admin", ActorID: actor,
			TargetType: "client", TargetID: id, Reason: normalized,
		})
	})
}

// RegenerateAPIKey: 新 key + CLIENT_KEY_ROTATED audit 同事务（§11/§12）。
// REVOKED 或不存在 → ErrClientRevoked / ErrClientNotFound 且 key==""；
// audit fail → 整体 rollback（旧 hash 原样、old key 继续有效、new key 不返回）。
func (s *ClientService) RegenerateAPIKey(clientID, keyType, keyPrefix, actor, reason string) (string, error) {
	normalizedReason, err := validateLifecycleReason(reason, true) // ROTATE 必须带 reason（§5）
	if err != nil {
		return "", err
	}

	apiKey := GenerateAPIKeyWithPrefix(keyType, keyPrefix)
	apiKeyHash := hashAPIKey(apiKey)

	err = s.db.Transaction(func(tx *gorm.DB) error {
		res := tx.Model(&models.Client{}).Where("id = ? AND revoked_at IS NULL", clientID).
			Updates(map[string]interface{}{
				"api_key_hash": apiKeyHash,
				"key_prefix":   keyPrefix,
				"updated_at":   time.Now(),
			})
		if res.Error != nil {
			return res.Error
		}
		if res.RowsAffected == 0 {
			return lifecycleTransitionError(tx, clientID, "rotate")
		}
		return s.audit.RecordTx(tx, models.AuditEvent{
			Action: audit.ActionClientKeyRotated, ActorType: "admin", ActorID: actor,
			TargetType: "client", TargetID: clientID, Reason: normalizedReason,
		})
	})
	if err != nil {
		// 任何失败路径都不返回未入库的新明文 key
		return "", err
	}
	return apiKey, nil
}

// DeleteClient: ALL OR NOTHING + audit（§9/§15）。
// 同一事务：append CLIENT_DELETED → request_logs cleanup → daily_usages cleanup →
// Client delete（任一步失败整体 rollback）；AuditEvent 与 clients 无 FK——
// CLIENT_DELETED 在 client 行删除后永久保留 target_id。
func (s *ClientService) DeleteClient(id, actor, reason string) error {
	normalized, err := validateLifecycleReason(reason, true) // DELETE 必须带 reason（§5）
	if err != nil {
		return err
	}
	return s.db.Transaction(func(tx *gorm.DB) error {
		if err := s.audit.RecordTx(tx, models.AuditEvent{
			Action: audit.ActionClientDeleted, ActorType: "admin", ActorID: actor,
			TargetType: "client", TargetID: id, Reason: normalized,
		}); err != nil {
			return err
		}
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
