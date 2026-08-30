package models

import "time"

// AuditEvent: 通用审计事件模型（P1-05C application append-only foundation）。
//
// 设计边界（详见 docs/adr/ADR-008-client-lifecycle-audit-foundation.md）：
//   - 通用结构，供 P1-08 扩展；不做 ClientLifecycleEvent 专表
//   - 与 clients 之间【禁止】FK ON DELETE CASCADE——Client 删除后审计必须保留
//   - 最小字段集：action/actor/target/bounded reason/timestamp/event id；
//     绝不含 API key / APIKeyHash / Provider Key / Authorization / 正文 / 任意 JSON payload
//   - EventID 由服务端生成（UUIDv4），唯一索引
type AuditEvent struct {
	ID           int64     `gorm:"primaryKey;autoIncrement" json:"id"`
	EventID      string    `gorm:"type:varchar(64);uniqueIndex" json:"event_id"`
	Action       string    `gorm:"type:varchar(64);index" json:"action"`
	ActorType    string    `gorm:"type:varchar(32)" json:"actor_type"`
	ActorID      string    `gorm:"type:varchar(255);index" json:"actor_id"`
	TargetType   string    `gorm:"type:varchar(32);index" json:"target_type"`
	TargetID     string    `gorm:"type:varchar(36);index" json:"target_id"`
	Reason       string    `gorm:"type:varchar(256)" json:"reason"`
	CreatedAt    time.Time `gorm:"index" json:"created_at"`
	ChainVersion string    `gorm:"type:varchar(16);index" json:"chain_version"`
	PrevHash     string    `gorm:"type:varchar(64);index" json:"prev_hash"`
	EventHash    string    `gorm:"type:varchar(64);index" json:"event_hash"`
}

// AuditChainState stores the single current audit-chain head. It has no client
// foreign key and is a serialization point, not a second event history.
type AuditChainState struct {
	ID           uint64    `gorm:"primaryKey" json:"id"`
	ChainVersion string    `gorm:"type:varchar(16)" json:"chain_version"`
	HeadHash     string    `gorm:"type:varchar(64)" json:"head_hash"`
	UpdatedAt    time.Time `gorm:"index" json:"updated_at"`
}
