package models

import (
	"time"
)

type Client struct {
	ID          string `gorm:"primaryKey;type:varchar(36)" json:"id"`
	Name        string `gorm:"type:varchar(255);not null" json:"name"`
	Description string `gorm:"type:text" json:"description"`
	APIKeyHash  []byte `gorm:"type:blob;uniqueIndex" json:"-"`
	IsActive    bool   `gorm:"default:true" json:"is_active"`
	// KeyPrefix is the custom prefix for the API key (e.g., "sk-", "gm_", "myapp_")
	KeyPrefix string `gorm:"type:varchar(20)" json:"key_prefix,omitempty"`
	// Backend is the provider type (e.g. "gemini", "openai", "anthropic", "mistral", "ollama", "lmstudio", etc.)
	Backend string `gorm:"type:varchar(50);default:'gemini'" json:"backend"`
	// BackendAPIKey is the upstream LLM API key for this client
	// LEGACY 明文字段（SEC-002 迁移来源；迁移完成后必须为空）——不修改类型/不删除
	BackendAPIKey string `gorm:"type:varchar(500)" json:"-"`
	// BackendAPIKeyEncrypted: 新安全存储（P1-03C1 additive），AEAD 信封；AutoMigrate 仅新增列
	BackendAPIKeyEncrypted string `gorm:"type:text" json:"-"`
	// BackendBaseURL allows per-client URL override (required for Azure, useful for Ollama/LM Studio)
	BackendBaseURL string `gorm:"type:varchar(500)" json:"backend_base_url,omitempty"`
	// BackendDefaultModel is the default model to use when the request does not specify one
	BackendDefaultModel string `gorm:"type:varchar(200)" json:"backend_default_model,omitempty"`
	// BackendModels is a JSON array of available models fetched from the backend
	BackendModels string `gorm:"type:text" json:"backend_models,omitempty"`
	// FallbackModels is a comma-separated list of model names to try if the primary model fails
	FallbackModels string `gorm:"type:varchar(500)" json:"fallback_models,omitempty"`
	// SystemPrompt is an optional system prompt prepended to every request from this client
	SystemPrompt string `gorm:"type:text" json:"system_prompt,omitempty"`
	// ToolMode determines how tool calls are handled:
	// - "pass-through" (default): gateway forwards tool_calls to client, client executes
	// - "gateway": gateway attempts to execute tools internally
	ToolMode string `gorm:"type:varchar(20);default:'pass-through'" json:"tool_mode"`
	// ServerTools enables server-provided tools in addition to client-provided ones
	ServerTools          bool `gorm:"default:false" json:"server_tools"`
	RateLimitMinute      int  `gorm:"default:60" json:"rate_limit_minute"`
	RateLimitHour        int  `gorm:"default:1000" json:"rate_limit_hour"`
	RateLimitDay         int  `gorm:"default:10000" json:"rate_limit_day"`
	QuotaInputTokensDay  int  `gorm:"default:1000000" json:"quota_input_tokens_day"`
	QuotaOutputTokensDay int  `gorm:"default:500000" json:"quota_output_tokens_day"`
	QuotaRequestsDay     int  `gorm:"default:1000" json:"quota_requests_day"`
	MaxInputTokens       int  `gorm:"default:1000000" json:"max_input_tokens"`
	MaxOutputTokens      int  `gorm:"default:8192" json:"max_output_tokens"`
	// LastSeen tracks the last time this client made a request (used for "active" status)
	LastSeen  time.Time `json:"last_seen"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`

	// P1-05C · Permanent Revocation（additive nullable；无独立 Status 字段——
	// REVOKED 由 RevokedAt != nil 推导，避免第二份状态真相）。
	// json:"-" 防止通过通用 Client JSON 泄露管理侧 lifecycle metadata。
	RevokedAt        *time.Time `gorm:"index" json:"-"`
	RevokedBy        string     `gorm:"type:varchar(255)" json:"-"`
	RevocationReason string     `gorm:"type:varchar(256)" json:"-"`
}

// ClientLifecycleState: 派生状态（P1-05C）——不持久化，只从 RevokedAt + IsActive 推导。
type ClientLifecycleState string

const (
	ClientStateActive    ClientLifecycleState = "ACTIVE"
	ClientStateSuspended ClientLifecycleState = "SUSPENDED"
	ClientStateRevoked   ClientLifecycleState = "REVOKED"
)

func (c *Client) LifecycleState() ClientLifecycleState {
	if c.RevokedAt != nil {
		return ClientStateRevoked
	}
	if !c.IsActive {
		return ClientStateSuspended
	}
	return ClientStateActive
}

// HasBackendKey: 是否配置了 per-client Provider Key（legacy 明文或 encrypted 信封）。
// 仅供 Admin UI 判定"已配置"状态展示——绝不返回 key 材料本身（P1-03C3 遮罩显示）。
func (c *Client) HasBackendKey() bool {
	return c.BackendAPIKey != "" || c.BackendAPIKeyEncrypted != ""
}

type RequestLog struct {
	ID int64 `gorm:"primaryKey;autoIncrement" json:"id"`
	// RequestID: 服务器生成的 128-bit crypto/rand 标识（SEC-003/P1-04B），
	// 与响应头 X-Request-ID 及全链路日志一致；绝不信任客户端提供的值。
	RequestID string `gorm:"type:varchar(64);index" json:"request_id"`
	ClientID  string `gorm:"type:varchar(36);index" json:"client_id"`
	// P1-05B：FK → clients.id，ON DELETE CASCADE。约束随 CREATE TABLE 内联创建
	// （新库 AutoMigrate 生效）；遗留旧库缺 FK 时 DeleteClient 事务内显式清理仍成立。
	// 主要价值：Delete 之后任何 late-write INSERT 直接违反外键（被 LogRequest 静默吞掉），
	// 从数据库层面杜绝 in-flight 旧请求重新制造孤儿行。
	Client Client `gorm:"foreignKey:ClientID;references:ID;constraint:OnUpdate:CASCADE,OnDelete:CASCADE" json:"-"`
	// Provider: canonical provider/backend 名称；不含 URL/query/key。
	Provider     string `gorm:"type:varchar(50)" json:"provider"`
	Model        string `gorm:"type:varchar(100)" json:"model"`
	StatusCode   int    `json:"status_code"`
	InputTokens  int    `gorm:"default:0" json:"input_tokens"`
	OutputTokens int    `gorm:"default:0" json:"output_tokens"`
	LatencyMs    int    `json:"latency_ms"`
	// ErrorCode: bounded 稳定错误码（UPSTREAM_NETWORK_ERROR/UPSTREAM_AUTH_ERROR/UPSTREAM_RATE_LIMIT/
	// UPSTREAM_4XX/UPSTREAM_5XX/INVALID_REQUEST/INTERNAL_ERROR）——无用户正文、无 URL、无 secret。
	ErrorCode string `gorm:"type:varchar(32)" json:"error_code"`
	// LEGACY PRIVACY MIGRATION FIELD (SEC-003 / P1-04B)：
	//   新写入必须恒为空（metadata-only）；列仅为兼容旧库与 P1-04D scrub 落点保留，
	//   禁止本批 DROP/RENAME；json:"-" 防止任何 JSON 路径暴露。
	RequestBody  string    `gorm:"type:text" json:"-"`
	ErrorMessage string    `gorm:"type:text" json:"-"`
	IsStreaming  bool      `gorm:"default:false" json:"is_streaming"`
	HasTools     bool      `gorm:"default:false" json:"has_tools"`
	ToolNames    string    `gorm:"type:varchar(500)" json:"tool_names"`
	CreatedAt    time.Time `gorm:"index" json:"created_at"`
}

type DailyUsage struct {
	ID       int64  `gorm:"primaryKey;autoIncrement" json:"id"`
	ClientID string `gorm:"type:varchar(36);uniqueIndex:idx_client_date" json:"client_id"`
	// P1-05B：FK → clients.id，ON DELETE CASCADE（同 RequestLog；late-write 防线）。
	Client            Client    `gorm:"foreignKey:ClientID;references:ID;constraint:OnUpdate:CASCADE,OnDelete:CASCADE" json:"-"`
	Date              time.Time `gorm:"uniqueIndex:idx_client_date;index" json:"date"`
	TotalRequests     int       `gorm:"default:0" json:"total_requests"`
	TotalInputTokens  int       `gorm:"default:0" json:"total_input_tokens"`
	TotalOutputTokens int       `gorm:"default:0" json:"total_output_tokens"`
}

// AdminSession 已迁移至 internal/models/admin_session.go（P1-01B 重定义：token_hash/expires_at/revoked_at）

type Stats struct {
	TotalRequestsToday     int64   `json:"total_requests_today"`
	TotalInputTokensToday  int64   `json:"total_input_tokens_today"`
	TotalOutputTokensToday int64   `json:"total_output_tokens_today"`
	ActiveClients          int64   `json:"active_clients"`
	TotalClients           int64   `json:"total_clients"`
	ErrorRate              float64 `json:"error_rate"`
}

type ClientStats struct {
	ClientID          string  `json:"client_id"`
	ClientName        string  `json:"client_name"`
	RequestsToday     int     `json:"requests_today"`
	InputTokensToday  int     `json:"input_tokens_today"`
	OutputTokensToday int     `json:"output_tokens_today"`
	RequestsLimit     int     `json:"requests_limit"`
	InputTokensLimit  int     `json:"input_tokens_limit"`
	OutputTokensLimit int     `json:"output_tokens_limit"`
	MaxInputTokens    int     `json:"max_input_tokens"`
	MaxOutputTokens   int     `json:"max_output_tokens"`
	ErrorRate         float64 `json:"error_rate"`
}

type RateLimitInfo struct {
	Allowed     bool `json:"allowed"`
	Remaining   int  `json:"remaining"`
	ResetInSecs int  `json:"reset_in_secs"`
}

type QuotaInfo struct {
	Allowed           bool `json:"allowed"`
	RemainingRequests int  `json:"remaining_requests"`
	RemainingInput    int  `json:"remaining_input_tokens"`
	RemainingOutput   int  `json:"remaining_output_tokens"`
}
