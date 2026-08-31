// Package auth 提供管理员会话的服务端存储与校验（SEC-001 修复核心）。
//
// 会话模型：
//
//	Login 成功 → crypto/rand 生成 256-bit 原始 token（hex，64 字符）
//	          → 原始 token 放入 Cookie（HttpOnly / SameSite=Strict）
//	          → 库中仅存 SHA-256(token)
//	每次请求 → 读 Cookie → 哈希 → Store.Validate（存在 / 未撤销 / 未过期）
//
// 权威有效期在服务端（expires_at），浏览器侧 Cookie Expires 仅是副本。
package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"time"

	"ai-gateway/internal/audit"
	"ai-gateway/internal/models"

	"gorm.io/gorm"
)

// SessionCookieName 是会话 Cookie 的唯一权威名称（login/logout/RequireAuth 统一引用）。
const SessionCookieName = "admin_session"

// TokenBytes: 256-bit 随机会话令牌（hex 编码后 64 字符）。
const TokenBytes = 32

// SessionDuration: 默认服务端会话有效期。
const SessionDuration = 24 * time.Hour

var (
	ErrSessionNotFound = errors.New("auth: session not found")
	ErrSessionExpired  = errors.New("auth: session expired")
	ErrSessionRevoked  = errors.New("auth: session revoked")
)

// GenerateToken 返回新的随机会话令牌（hex 字符串，64 字符）。
func GenerateToken() (string, error) {
	b := make([]byte, TokenBytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// HashToken: 原始 token 绝不入库，库中只存其 SHA-256。
func HashToken(rawToken string) []byte {
	sum := sha256.Sum256([]byte(rawToken))
	return sum[:]
}

// Store 是管理会话的持久化抽象（P1-01C 签发、P1-01D 校验、P1-01E 吊销共用）。
type Store interface {
	// Create 生成新会话并返回原始 token（仅此一次可见）。
	Create(ctx context.Context, username string, expiresAt time.Time) (rawToken string, err error)
	// Validate 校验原始 token：存在、未撤销、未过期时返回用户名。
	Validate(ctx context.Context, rawToken string) (username string, err error)
	// Revoke 吊销会话；token 不存在时返回 ErrSessionNotFound。
	Revoke(ctx context.Context, rawToken string) error
	// RevokeAllForUser 吊销该用户全部有效会话（改密/全端下线用）。
	RevokeAllForUser(ctx context.Context, username string) error
}

// AuditedStore owns the session mutation and its audit append in one SQLite
// transaction. Handlers must not fall back to the unaudited Store methods for
// successful login/logout paths.
type AuditedStore interface {
	Store
	CreateAudited(ctx context.Context, username string, expiresAt time.Time) (rawToken string, err error)
	RevokeAudited(ctx context.Context, rawToken string) error
}

// SQLiteStore 基于 gorm + models.AdminSession 的 Store 实现。
type SQLiteStore struct {
	db *gorm.DB
}

func NewSQLiteStore(db *gorm.DB) *SQLiteStore {
	return &SQLiteStore{db: db}
}

var _ Store = (*SQLiteStore)(nil)
var _ AuditedStore = (*SQLiteStore)(nil)

func (s *SQLiteStore) Create(ctx context.Context, username string, expiresAt time.Time) (string, error) {
	rawToken, err := GenerateToken()
	if err != nil {
		return "", err
	}
	sess := models.AdminSession{
		Username:  username,
		TokenHash: HashToken(rawToken),
		CreatedAt: time.Now().UTC(),
		ExpiresAt: expiresAt.UTC(),
	}
	if err := s.db.WithContext(ctx).Create(&sess).Error; err != nil {
		return "", err
	}
	return rawToken, nil
}

// CreateAudited creates a session and records ADMIN_LOGIN_SUCCEEDED in the
// same transaction. The raw token is returned only after commit.
func (s *SQLiteStore) CreateAudited(ctx context.Context, username string, expiresAt time.Time) (string, error) {
	rawToken, err := GenerateToken()
	if err != nil {
		return "", err
	}
	tx := s.db.WithContext(ctx).Begin()
	if tx.Error != nil {
		return "", tx.Error
	}
	defer tx.Rollback()
	sess := models.AdminSession{
		Username:  username,
		TokenHash: HashToken(rawToken),
		CreatedAt: time.Now().UTC(),
		ExpiresAt: expiresAt.UTC(),
	}
	if err := tx.Create(&sess).Error; err != nil {
		return "", err
	}
	if err := audit.NewService(s.db).RecordTx(tx, models.AuditEvent{
		Action: audit.ActionAdminLoginSucceeded, ActorType: "admin", ActorID: username,
		TargetType: "admin", TargetID: "admin",
	}); err != nil {
		return "", err
	}
	if err := tx.Commit().Error; err != nil {
		return "", err
	}
	return rawToken, nil
}

func (s *SQLiteStore) Validate(ctx context.Context, rawToken string) (string, error) {
	if rawToken == "" {
		return "", ErrSessionNotFound
	}
	var sess models.AdminSession
	err := s.db.WithContext(ctx).Where("token_hash = ?", HashToken(rawToken)).First(&sess).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return "", ErrSessionNotFound
		}
		return "", err
	}
	if sess.RevokedAt != nil {
		return "", ErrSessionRevoked
	}
	if time.Now().UTC().After(sess.ExpiresAt.UTC()) {
		return "", ErrSessionExpired
	}
	return sess.Username, nil
}

func (s *SQLiteStore) Revoke(ctx context.Context, rawToken string) error {
	res := s.db.WithContext(ctx).Model(&models.AdminSession{}).
		Where("token_hash = ? AND revoked_at IS NULL", HashToken(rawToken)).
		Update("revoked_at", time.Now().UTC())
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return ErrSessionNotFound
	}
	return nil
}

// RevokeAudited resolves the authoritative session row, revokes it, and
// records ADMIN_LOGOUT in the same transaction. Non-active sessions are
// idempotent no-ops from the handler's perspective and never create audit
// events.
func (s *SQLiteStore) RevokeAudited(ctx context.Context, rawToken string) error {
	if rawToken == "" {
		return ErrSessionNotFound
	}
	tx := s.db.WithContext(ctx).Begin()
	if tx.Error != nil {
		return tx.Error
	}
	defer tx.Rollback()
	var sess models.AdminSession
	if err := tx.Where("token_hash = ?", HashToken(rawToken)).First(&sess).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ErrSessionNotFound
		}
		return err
	}
	if sess.RevokedAt != nil {
		return ErrSessionRevoked
	}
	if time.Now().UTC().After(sess.ExpiresAt.UTC()) {
		return ErrSessionExpired
	}
	revokedAt := time.Now().UTC()
	result := tx.Model(&models.AdminSession{}).
		Where("id = ? AND revoked_at IS NULL", sess.ID).
		Update("revoked_at", revokedAt)
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected != 1 {
		return ErrSessionNotFound
	}
	if err := audit.NewService(s.db).RecordTx(tx, models.AuditEvent{
		Action: audit.ActionAdminLogout, ActorType: "admin", ActorID: sess.Username,
		TargetType: "admin", TargetID: "admin",
	}); err != nil {
		return err
	}
	return tx.Commit().Error
}

func (s *SQLiteStore) RevokeAllForUser(ctx context.Context, username string) error {
	return s.db.WithContext(ctx).Model(&models.AdminSession{}).
		Where("username = ? AND revoked_at IS NULL", username).
		Update("revoked_at", time.Now().UTC()).Error
}
