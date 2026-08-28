package models

import (
	"time"
)

// AdminSession: 管理会话的服务端权威记录（P1-01B 启用，SEC-001 修复的数据层）。
// Cookie 中保存原始随机 token（256-bit hex）；数据库只存其 SHA-256 哈希，
// 因此数据库单独泄漏不能得到可直接使用的会话。
type AdminSession struct {
	ID        int64      `gorm:"primaryKey;autoIncrement" json:"id"`
	Username  string     `gorm:"type:varchar(255);index" json:"username"`
	TokenHash []byte     `gorm:"type:blob;uniqueIndex" json:"-"`
	CreatedAt time.Time  `json:"created_at"`
	ExpiresAt time.Time  `json:"expires_at"`
	RevokedAt *time.Time `json:"revoked_at,omitempty"`
}
