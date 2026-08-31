package config

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
	"gopkg.in/yaml.v3"
)

type Config struct {
	Server      ServerConfig              `yaml:"server"`
	Admin       AdminConfig               `yaml:"admin"`
	Providers   map[string]ProviderConfig `yaml:"providers"`
	Defaults    DefaultsConfig            `yaml:"defaults"`
	Database    DatabaseConfig            `yaml:"database"`
	Logging     LoggingConfig             `yaml:"logging"`
	Prometheus  PrometheusConfig          `yaml:"prometheus"`
	ServerTools ServerToolsConfig         `yaml:"server_tools"`

	// Deprecated: kept for backward compat with existing config files.
	// On load, this is migrated into Providers["gemini"].
	// json:"-"（P1-03C3.1）：兼容 secret 结构同样绝不进入任何 JSON 序列化路径；
	// yaml 兼容性不受影响。
	Gemini *LegacyGeminiConfig `yaml:"gemini,omitempty" json:"-"`
}

// ProviderConfig is the unified configuration for any upstream AI backend.
type ProviderConfig struct {
	// Type identifies the backend: gemini, openai, anthropic, mistral, ollama, lmstudio
	Type string `yaml:"type" json:"type"`
	// APIKey: LEGACY 明文字段（SEC-002 迁移来源，迁移完成后必须为空）。
	// json:"-"（P1-03C2.1）：legacy 明文与密文信封同样绝不允许进入任何 JSON 序列化路径。
	APIKey string `yaml:"api_key,omitempty" json:"-"`
	// APIKeyEncrypted: 新安全存储（P1-03C1 additive），AEAD 信封 enc:v1:...
	APIKeyEncrypted string   `yaml:"api_key_encrypted,omitempty" json:"-"`
	BaseURL         string   `yaml:"base_url,omitempty" json:"base_url,omitempty"`
	DefaultModel    string   `yaml:"default_model,omitempty" json:"default_model,omitempty"`
	AllowedModels   []string `yaml:"allowed_models,omitempty" json:"allowed_models,omitempty"`
	TimeoutSeconds  int      `yaml:"timeout_seconds,omitempty" json:"timeout_seconds,omitempty"`
}

// LegacyGeminiConfig supports the old config.yaml format with a top-level gemini: key.
// APIKey json:"-"（P1-03C3.1）：即便有人直接 Marshal 未经 Load 转换的 legacy Config，
// 兼容结构的明文 key 也不得出现在 JSON 输出中。
type LegacyGeminiConfig struct {
	APIKey         string   `yaml:"api_key" json:"-"`
	DefaultModel   string   `yaml:"default_model"`
	AllowedModels  []string `yaml:"allowed_models"`
	TimeoutSeconds int      `yaml:"timeout_seconds"`
}

type ServerConfig struct {
	Host  string         `yaml:"host"`
	Port  int            `yaml:"port"`
	HTTPS HTTPSConfig    `yaml:"https"` // Deprecated (P1-01F.1)：enabled=true 时拒绝启动，字段仅为旧配置兼容解析
	Admin ListenerConfig `yaml:"admin"`
	// Metrics 监听面仅在 prometheus.enabled=true 时启动
	Metrics ListenerConfig `yaml:"metrics"`
}

// HTTPSConfig Deprecated（P1-01F.1）：网关不再内建 TLS，仅保留字段使旧配置可解析。
// TLS 由反向代理终止；Cookie Secure 将在 P1-02 改为独立的 admin.cookie_secure 配置。
type HTTPSConfig struct {
	Enabled  bool   `yaml:"enabled"`
	CertFile string `yaml:"cert_file"`
	KeyFile  string `yaml:"key_file"`
}

// ListenerConfig: 独立监听面地址（P1-01F）。
// 默认 loopback——Admin/Metrics 绝不默认公网；显式配置其他地址属运营者自主决定（启动时告警）。
type ListenerConfig struct {
	Host string `yaml:"host"`
	Port int    `yaml:"port"`
}

type AdminConfig struct {
	Username      string `yaml:"username"`
	PasswordHash  string `yaml:"password_hash"`
	SessionSecret string `yaml:"session_secret"`
	// CookieSecure: Admin 会话 Cookie 的 Secure 属性（P1-02A），与已废弃的
	// server.https 完全解耦。生产经 HTTPS 访问 Admin 面时必须显式设为 true；
	// 默认 false 以支持 loopback / SSH 隧道的纯 HTTP 开发访问。
	CookieSecure bool `yaml:"cookie_secure"`
	// 登录防爆破（P1-02D）：username 维度、本地内存状态、重启清零。
	// 默认 5 次失败锁定 15 分钟。
	LoginMaxFailures    int `yaml:"login_max_failures"`
	LoginLockoutMinutes int `yaml:"login_lockout_minutes"`
}

type DefaultsConfig struct {
	RateLimit RateLimitDefaults `yaml:"rate_limit"`
	Quota     QuotaDefaults     `yaml:"quota"`
}

type RateLimitDefaults struct {
	RequestsPerMinute int `yaml:"requests_per_minute"`
	RequestsPerHour   int `yaml:"requests_per_hour"`
	RequestsPerDay    int `yaml:"requests_per_day"`
}

type QuotaDefaults struct {
	MaxInputTokensPerDay  int `yaml:"max_input_tokens_per_day"`
	MaxOutputTokensPerDay int `yaml:"max_output_tokens_per_day"`
	MaxRequestsPerDay     int `yaml:"max_requests_per_day"`
	MaxInputTokens        int `yaml:"max_input_tokens"`
	MaxOutputTokens       int `yaml:"max_output_tokens"`
}

type DatabaseConfig struct {
	Path string `yaml:"path"`
}

type LoggingConfig struct {
	Level string `yaml:"level"`
	File  string `yaml:"file"`
	// RequestBodyCapture: 临时诊断正文捕获（SEC-003 / P1-04C）。
	// 默认 OFF；启用须显式 expires_at（RFC3339，未来，且距校验时刻 ≤24h）。
	// 正文仅存内存（bounded），绝不写 SQLite/文件/日志。
	RequestBodyCapture RequestBodyCaptureConfig `yaml:"request_body_capture"`
}

// RequestBodyCaptureConfig: 诊断捕获配置。
// 硬约束：max_bytes 默认 16KiB / 硬上限 64KiB；max_entries 默认 100 / 硬上限 1000；
// 超限 fail closed（拒绝启动）。
type RequestBodyCaptureConfig struct {
	Enabled    bool   `yaml:"enabled"`
	ExpiresAt  string `yaml:"expires_at"`
	MaxBytes   int    `yaml:"max_bytes"`
	MaxEntries int    `yaml:"max_entries"`
}

const (
	CaptureMaxBytesDefault   = 16 * 1024
	CaptureMaxBytesHardCap   = 64 * 1024
	CaptureMaxEntriesDefault = 100
	CaptureMaxEntriesHardCap = 1000
	CaptureMaxWindow         = 24 * time.Hour
)

// CaptureSettings: 校验后的捕获运行参数（Enabled=false 时其余字段无意义）。
type CaptureSettings struct {
	Enabled    bool
	ExpiresAt  time.Time
	MaxBytes   int
	MaxEntries int
}

// ResolveRequestBodyCapture: 校验并解析捕获配置（SEC-003 fail-closed）。
//   - 未启用 → OFF（其余字段不生效）
//   - 启用时：expires_at 必须为合法 RFC3339 且严格在未来、窗口 ≤24h
//   - max_bytes/max_entries：0 取默认；负数或超硬上限 → 错误（拒绝启动）
func (l LoggingConfig) ResolveRequestBodyCapture(now time.Time) (CaptureSettings, error) {
	c := l.RequestBodyCapture
	if !c.Enabled {
		return CaptureSettings{}, nil
	}
	raw := strings.TrimSpace(c.ExpiresAt)
	if raw == "" {
		return CaptureSettings{}, fmt.Errorf("request_body_capture.enabled=true requires expires_at (RFC3339, within 24h)")
	}
	exp, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		return CaptureSettings{}, fmt.Errorf("request_body_capture.expires_at is not valid RFC3339")
	}
	if !exp.After(now) {
		// P1-04.1（原 P1-04C 契约）：服务在 expiry 之后启动 → 安全视为 disabled，
		// 非 fatal（避免一次临时诊断配置过期造成服务不可用）。malformed/>24h 仍 fail-closed。
		return CaptureSettings{}, nil
	}
	if exp.Sub(now) > CaptureMaxWindow {
		return CaptureSettings{}, fmt.Errorf("request_body_capture window exceeds hard maximum of 24h")
	}
	maxBytes := c.MaxBytes
	if maxBytes == 0 {
		maxBytes = CaptureMaxBytesDefault
	}
	if maxBytes < 0 || maxBytes > CaptureMaxBytesHardCap {
		return CaptureSettings{}, fmt.Errorf("request_body_capture.max_bytes must be within [1, %d]", CaptureMaxBytesHardCap)
	}
	maxEntries := c.MaxEntries
	if maxEntries == 0 {
		maxEntries = CaptureMaxEntriesDefault
	}
	if maxEntries < 0 || maxEntries > CaptureMaxEntriesHardCap {
		return CaptureSettings{}, fmt.Errorf("request_body_capture.max_entries must be within [1, %d]", CaptureMaxEntriesHardCap)
	}
	return CaptureSettings{Enabled: true, ExpiresAt: exp, MaxBytes: maxBytes, MaxEntries: maxEntries}, nil
}

type PrometheusConfig struct {
	Enabled  bool   `yaml:"enabled"`
	Username string `yaml:"username"`
	Password string `yaml:"password"`
}

type ServerToolsConfig struct {
	Enabled bool     `yaml:"enabled"`
	Tools   []string `yaml:"tools"`
}

func (c *LoggingConfig) IsDebug() bool {
	return c.Level == "debug"
}

var configPath string

func Load(path string) (*Config, error) {
	configPath = path
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return createDefaultConfig(path)
		}
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config: %w", err)
	}

	// P1-01F.1：网关内建 TLS 已废弃（配置真实性）。
	// https.enabled=true 时必须拒绝启动——静默降级为明文 HTTP 会让用户误以为
	// 流量已加密，从而泄露管理会话与 Provider Key。TLS 一律由反向代理（Caddy 等）终止。
	if cfg.Server.HTTPS.Enabled {
		return nil, fmt.Errorf(
			"server.https is DEPRECATED and unsupported since P1-01F.1: " +
				"the gateway serves plain HTTP on loopback/private listeners; " +
				"terminate TLS at a reverse proxy (e.g. Caddy) in front of it. " +
				"Remove the server.https section (or set enabled: false) from the config and restart")
	}

	// 监听面默认值（P1-01F）：API 默认 loopback（生产由反代同机转发）；
	// Admin/Metrics 强制默认 loopback，绝不默认公网。
	if cfg.Server.Host == "" {
		cfg.Server.Host = "127.0.0.1"
	}
	if cfg.Server.Port == 0 {
		cfg.Server.Port = 8090
	}
	if cfg.Server.Admin.Host == "" {
		cfg.Server.Admin.Host = "127.0.0.1"
	}
	if cfg.Server.Admin.Port == 0 {
		cfg.Server.Admin.Port = 8091
	}
	if cfg.Server.Metrics.Host == "" {
		cfg.Server.Metrics.Host = "127.0.0.1"
	}
	if cfg.Server.Metrics.Port == 0 {
		cfg.Server.Metrics.Port = 9090
	}
	if cfg.Admin.LoginMaxFailures <= 0 {
		cfg.Admin.LoginMaxFailures = 5
	}
	if cfg.Admin.LoginLockoutMinutes <= 0 {
		cfg.Admin.LoginLockoutMinutes = 15
	}

	if cfg.Providers == nil {
		cfg.Providers = make(map[string]ProviderConfig)
	}

	// Migrate legacy gemini: section into providers map
	if cfg.Gemini != nil {
		if _, exists := cfg.Providers["gemini"]; !exists {
			timeout := cfg.Gemini.TimeoutSeconds
			if timeout == 0 {
				timeout = 120
			}
			cfg.Providers["gemini"] = ProviderConfig{
				Type:           "gemini",
				APIKey:         cfg.Gemini.APIKey,
				DefaultModel:   cfg.Gemini.DefaultModel,
				AllowedModels:  cfg.Gemini.AllowedModels,
				TimeoutSeconds: timeout,
			}
		}
		cfg.Gemini = nil
	}

	// Ensure timeout defaults for all providers
	for name, p := range cfg.Providers {
		if p.TimeoutSeconds == 0 {
			p.TimeoutSeconds = 120
			cfg.Providers[name] = p
		}
		if p.Type == "" {
			p.Type = name
			cfg.Providers[name] = p
		}
	}

	if cfg.Defaults.RateLimit.RequestsPerMinute == 0 {
		cfg.Defaults.RateLimit.RequestsPerMinute = 60
	}

	cfg, err = ensureDefaults(cfg, path)
	if err != nil {
		return nil, err
	}

	return &cfg, nil
}

// LoadExistingForMigration: 面向离线迁移引擎的纯读取加载器（P1-03C2.1）。
//
// 与 Load 的语义差异（迁移安全性硬约束）：
//   - 文件不存在   → 错误（绝不 createDefaultConfig）
//   - 解析失败     → 错误（绝不修改文件）
//   - 不生成 default password / session secret / prometheus password（ensureDefaults 不参与）
//   - 全程不写任何文件；不触碰包级 configPath 状态
//
// 仅做内存中的规范化（不落盘）：legacy 顶层 gemini 段并入 Providers、
// provider Type/TimeoutSeconds 缺省补齐——迁移引擎需要按 provider 名清点。
func LoadExistingForMigration(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("config: read %s: %w", path, err)
	}
	cfg, err := ParseExistingForMigration(data)
	if err != nil {
		return nil, fmt.Errorf("config: parse %s: %w", path, err)
	}
	return cfg, nil
}

// ParseExistingForMigration parses a config snapshot without filesystem
// access, default generation, or package-level source-path mutation.
func ParseExistingForMigration(data []byte) (*Config, error) {
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}

	if cfg.Providers == nil {
		cfg.Providers = make(map[string]ProviderConfig)
	}

	if cfg.Gemini != nil {
		if _, exists := cfg.Providers["gemini"]; !exists {
			timeout := cfg.Gemini.TimeoutSeconds
			if timeout == 0 {
				timeout = 120
			}
			cfg.Providers["gemini"] = ProviderConfig{
				Type:           "gemini",
				APIKey:         cfg.Gemini.APIKey,
				DefaultModel:   cfg.Gemini.DefaultModel,
				AllowedModels:  cfg.Gemini.AllowedModels,
				TimeoutSeconds: timeout,
			}
		}
		cfg.Gemini = nil
	}

	for name, p := range cfg.Providers {
		if p.TimeoutSeconds == 0 {
			p.TimeoutSeconds = 120
			cfg.Providers[name] = p
		}
		if p.Type == "" {
			p.Type = name
			cfg.Providers[name] = p
		}
	}
	return &cfg, nil
}

// GetProvider returns the provider config for a given name, or nil if not found.
func (c *Config) GetProvider(name string) *ProviderConfig {
	p, ok := c.Providers[name]
	if !ok {
		return nil
	}
	return &p
}

// ProviderNames returns a sorted list of configured provider names.
func (c *Config) ProviderNames() []string {
	names := make([]string, 0, len(c.Providers))
	for name := range c.Providers {
		names = append(names, name)
	}
	return names
}

func createDefaultConfig(path string) (*Config, error) {
	secret := generateRandomString(32)

	cfg := &Config{
		Server: ServerConfig{
			Host: "127.0.0.1",
			Port: 8090,
			HTTPS: HTTPSConfig{
				Enabled: false,
			},
			Admin: ListenerConfig{
				Host: "127.0.0.1",
				Port: 8091,
			},
			Metrics: ListenerConfig{
				Host: "127.0.0.1",
				Port: 9090,
			},
		},
		Admin: AdminConfig{
			Username: "admin",
			// P1-04.4：首启不再生成/打印明文密码——走既有私有 /setup 流程
			//（用户自行设置密码；SetupHandler.IsSetupRequired 据此判定）
			PasswordHash:  "__SETUP_REQUIRED__",
			SessionSecret: secret,
			CookieSecure:  false, // 默认支持 loopback/SSH 隧道 HTTP 开发；生产走 HTTPS 访问 Admin 面时显式置 true
		},
		Providers: map[string]ProviderConfig{
			"gemini": {
				Type:           "gemini",
				DefaultModel:   "gemini-flash-lite-latest",
				AllowedModels:  []string{"gemini-2.0-flash", "gemini-2.0-flash-lite"},
				TimeoutSeconds: 120,
			},
		},
		Defaults: DefaultsConfig{
			RateLimit: RateLimitDefaults{
				RequestsPerMinute: 60,
				RequestsPerHour:   1000,
				RequestsPerDay:    10000,
			},
			Quota: QuotaDefaults{
				MaxInputTokensPerDay:  1000000,
				MaxOutputTokensPerDay: 500000,
				MaxRequestsPerDay:     1000,
				MaxInputTokens:        1000000,
				MaxOutputTokens:       8192,
			},
		},
		Database: DatabaseConfig{
			Path: "./data/gateway.db",
		},
		Logging: LoggingConfig{
			Level: "info",
			File:  "./logs/gateway.log",
		},
	}

	if err := saveConfig(cfg, path); err != nil {
		return nil, err
	}

	// P1-04.4：stdout 绝不出现任何生成密码材料（注释豁免机制已整体废除）
	fmt.Printf("\n===========================================\n")
	fmt.Printf("  Initial setup required!\n")
	fmt.Printf("  Set the admin password via the private admin listener:\n")
	fmt.Printf("    http://127.0.0.1:8091/setup\n")
	fmt.Printf("  (loopback-only by default; see server.admin in config.yaml)\n")
	fmt.Printf("===========================================\n\n")

	return cfg, nil
}

func ensureDefaults(cfg Config, path string) (Config, error) {
	changed := false

	// If password hash is empty, mark for setup wizard
	if cfg.Admin.PasswordHash == "" {
		cfg.Admin.PasswordHash = "__SETUP_REQUIRED__"
		changed = true
	}

	if cfg.Admin.SessionSecret == "" {
		cfg.Admin.SessionSecret = generateRandomString(32)
		changed = true
	}

	if cfg.Prometheus.Enabled && cfg.Prometheus.Username == "" {
		cfg.Prometheus.Username = "prometheus"
		cfg.Prometheus.Password = generateRandomString(20)
		changed = true
		fmt.Printf("\n===========================================\n")
		fmt.Printf("  Prometheus credentials generated and saved to config.\n")
		fmt.Printf("===========================================\n\n")
	}

	if cfg.Prometheus.Enabled && cfg.Prometheus.Username != "" && cfg.Prometheus.Password == "" {
		cfg.Prometheus.Password = generateRandomString(20)
		changed = true
		fmt.Printf("\n===========================================\n")
		fmt.Printf("  Prometheus password generated and saved to config.\n")
		fmt.Printf("===========================================\n\n")
	}

	if changed {
		if err := saveConfig(&cfg, path); err != nil {
			return cfg, err
		}
	}

	return cfg, nil
}

func saveConfig(cfg *Config, path string) error {
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	dir := ""
	for i := len(path) - 1; i >= 0; i-- {
		if path[i] == '/' {
			dir = path[:i]
			break
		}
	}

	if dir != "" {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("failed to create config directory: %w", err)
		}
	}

	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("failed to write config: %w", err)
	}

	return nil
}

// SaveConfig exports saveConfig for external use
func SaveConfig(cfg *Config, path string) error {
	return saveConfig(cfg, path)
}

// ResetAdminPassword generates a new password hash for the admin user
func ResetAdminPassword(cfg *Config, password string) error {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("failed to hash password: %w", err)
	}
	cfg.Admin.PasswordHash = string(hash)
	return nil
}

func generateRandomString(length int) string {
	b := make([]byte, length)
	rand.Read(b)
	return hex.EncodeToString(b)[:length]
}

// SourcePath: 返回当前加载的配置文件路径（Setup 等需要持久化到同一文件的组件使用）。
// 尚未 Load 过时返回 ""。
func SourcePath() string {
	return configPath
}

// MarshalYAML: 将配置序列化为 YAML（迁移引擎等需要"序列化与保存分离"的场景使用）。
func MarshalYAML(cfg *Config) ([]byte, error) {
	return yaml.Marshal(cfg)
}

func Save(cfg *Config) {
	if configPath == "" {
		return
	}
	saveConfig(cfg, configPath)
}
