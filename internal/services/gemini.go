package services

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"ai-gateway/internal/config"
	"ai-gateway/internal/models"

	"github.com/mattn/go-sqlite3"
	"gorm.io/gorm"
)

type GeminiService struct {
	db              *gorm.DB
	cfg             *config.Config
	onRequestLogged func() // called after each request is logged, used for live dashboard updates
}

func NewGeminiService(db *gorm.DB, cfg *config.Config) *GeminiService {
	return &GeminiService{db: db, cfg: cfg}
}

// GetConfig returns the service's config for access to provider configurations.
func (s *GeminiService) GetConfig() *config.Config {
	return s.cfg
}

// geminiProvider returns the gemini provider config, or a zero-value if not configured.
func (s *GeminiService) geminiProvider() config.ProviderConfig {
	if p := s.cfg.GetProvider("gemini"); p != nil {
		return *p
	}
	return config.ProviderConfig{TimeoutSeconds: 120}
}

// SetOnRequestLogged registers a callback that fires after each request is logged.
// Used by the dashboard WebSocket hub to push live updates.
func (s *GeminiService) SetOnRequestLogged(fn func()) {
	s.onRequestLogged = fn
}

type GeminiRequest struct {
	Contents          []Content         `json:"contents"`
	GenerationConfig  *GenerationConfig `json:"generationConfig,omitempty"`
	SystemInstruction *Content          `json:"systemInstruction,omitempty"`
}

type Content struct {
	Role  string `json:"role,omitempty"`
	Parts []Part `json:"parts"`
}

type Part struct {
	Text string `json:"text,omitempty"`
}

type GenerationConfig struct {
	MaxOutputTokens int      `json:"maxOutputTokens,omitempty"`
	Temperature     float64  `json:"temperature,omitempty"`
	TopP            float64  `json:"topP,omitempty"`
	TopK            int      `json:"topK,omitempty"`
	CandidateCount  int      `json:"candidateCount,omitempty"`
	StopSequences   []string `json:"stopSequences,omitempty"`
}

type GeminiResponse struct {
	Candidates     []Candidate     `json:"candidates"`
	PromptFeedback *PromptFeedback `json:"promptFeedback,omitempty"`
	UsageMetadata  *UsageMetadata  `json:"usageMetadata,omitempty"`
}

type Candidate struct {
	Content       Content        `json:"content"`
	FinishReason  string         `json:"finishReason"`
	Index         int            `json:"index"`
	SafetyRatings []SafetyRating `json:"safetyRatings"`
}

type PromptFeedback struct {
	SafetyRatings []SafetyRating `json:"safetyRatings"`
}

type SafetyRating struct {
	Category    string `json:"category"`
	Probability string `json:"probability"`
}

type UsageMetadata struct {
	PromptTokenCount     int `json:"promptTokenCount"`
	CandidatesTokenCount int `json:"candidatesTokenCount"`
	TotalTokenCount      int `json:"totalTokenCount"`
}

// resolveModel applies the allowed model check and falls back to the default if needed.
func (s *GeminiService) resolveModel(model string) string {
	gp := s.geminiProvider()
	if !s.isModelAllowed(model) {
		if gp.DefaultModel != "" {
			model = gp.DefaultModel
		}
	}
	return model
}

func (s *GeminiService) ForwardRequest(model string, body []byte) ([]byte, int, error) {
	gp := s.geminiProvider()
	model = s.resolveModel(model)

	log.Printf("[GEMINI] ForwardRequest model=%s, default=%s, allowed=%v", model, gp.DefaultModel, gp.AllowedModels)

	baseURL := gp.BaseURL
	if baseURL == "" {
		baseURL = "https://generativelanguage.googleapis.com/v1beta"
	}
	// SEC-002（P1-03C3）：key 走 x-goog-api-key header，不再进 URL/query
	url := fmt.Sprintf("%s/models/%s:generateContent", baseURL, model)

	req, err := http.NewRequest("POST", url, bytes.NewReader(body))
	if err != nil {
		return nil, 0, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-goog-api-key", gp.APIKey)

	client := &http.Client{
		Timeout: time.Duration(gp.TimeoutSeconds) * time.Second,
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, resp.StatusCode, fmt.Errorf("failed to read response: %w", err)
	}

	return respBody, resp.StatusCode, nil
}

// ForwardStreamRequest calls Gemini's streamGenerateContent endpoint and returns
// the raw HTTP response. The caller is responsible for closing the response body.
func (s *GeminiService) ForwardStreamRequest(model string, body []byte) (*http.Response, string, error) {
	gp := s.geminiProvider()
	model = s.resolveModel(model)

	log.Printf("[GEMINI] ForwardStreamRequest model=%s, default=%s, allowed=%v", model, gp.DefaultModel, gp.AllowedModels)

	baseURL := gp.BaseURL
	if baseURL == "" {
		baseURL = "https://generativelanguage.googleapis.com/v1beta"
	}
	// SEC-002（P1-03C3）：key 走 header，不进 URL/query
	url := fmt.Sprintf("%s/models/%s:streamGenerateContent?alt=sse", baseURL, model)

	req, err := http.NewRequest("POST", url, bytes.NewReader(body))
	if err != nil {
		return nil, model, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-goog-api-key", gp.APIKey)

	client := &http.Client{
		Timeout: time.Duration(gp.TimeoutSeconds) * time.Second,
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, model, fmt.Errorf("failed to send request: %w", err)
	}

	return resp, model, nil
}

// RequestRecord: metadata-only 请求日志条目（SEC-003 / P1-04B）。
//
// 结构化 API 的设计目的：业务调用点【根本不存在】requestBody / raw error text
// 可以传给持久层——持久层不可能收到正文。字段只含元数据；ErrorCode 为 bounded
// 稳定错误码（ClassifyUpstreamError），无用户正文/URL/secret。
type RequestRecord struct {
	RequestID    string
	ClientID     string
	Provider     string
	Model        string
	StatusCode   int
	InputTokens  int
	OutputTokens int
	LatencyMs    int
	ErrorCode    string
	IsStreaming  bool
	HasTools     bool
	ToolNames    string
}

// bounded 稳定错误码集合（SEC-003）。固定取值、固定语义，禁止拼接任何动态文本。
const (
	ErrCodeUpstreamNetwork = "UPSTREAM_NETWORK_ERROR"
	ErrCodeUpstreamAuth    = "UPSTREAM_AUTH_ERROR"
	ErrCodeUpstreamRate    = "UPSTREAM_RATE_LIMIT"
	ErrCodeUpstream4xx     = "UPSTREAM_4XX"
	ErrCodeUpstream5xx     = "UPSTREAM_5XX"
	ErrCodeInvalidRequest  = "INVALID_REQUEST"
	ErrCodeInternal        = "INTERNAL_ERROR"
)

// ClassifyUpstreamError: 把 upstream 状态/传输错误归类为 bounded 错误码。
// 绝不返回包含 upstream 响应体或错误文本的值。
func ClassifyUpstreamError(statusCode int, err error) string {
	switch {
	case statusCode >= 400 && statusCode <= 499:
		if statusCode == 401 || statusCode == 403 {
			return ErrCodeUpstreamAuth
		}
		if statusCode == 429 {
			return ErrCodeUpstreamRate
		}
		return ErrCodeUpstream4xx
	case statusCode >= 500:
		return ErrCodeUpstream5xx
	case err != nil:
		return ErrCodeUpstreamNetwork
	default:
		return ""
	}
}

// isClientGoneForeignKey: 已通过认证的 in-flight 请求在 Admin Delete 之后完成的
// late-write INSERT 会违反 request_logs/daily_usages 的 FK（SQLITE_CONSTRAINT_FOREIGNKEY）。
// gorm 对 sqlite 驱动会翻译成 gorm.ErrForeignKeyViolated；这里再按原生错误码双保险，
// 避免依赖翻译行为。命中即“client 已删除”，写路径静默跳过——请求本身正常结束，
// 但绝不会为已删除 client 重新制造持久行（P1-05B IN_FLIGHT_DELETE_LATE_WRITE gate）。
func isClientGoneForeignKey(err error) bool {
	if errors.Is(err, gorm.ErrForeignKeyViolated) {
		return true
	}
	var se sqlite3.Error
	if errors.As(err, &se) && se.ExtendedCode == sqlite3.ErrConstraintForeignKey {
		return true
	}
	return false
}

// LogRequest: 持久化一条 metadata-only 请求日志（SEC-003 / P1-04B）。
// RequestBody / ErrorMessage 为 legacy scrub 字段，新写入恒为空——
// 由本函数强制置空，调用方无法（也无需）传入正文。
func (s *GeminiService) LogRequest(rec RequestRecord) error {
	entry := &models.RequestLog{
		RequestID:    rec.RequestID,
		ClientID:     rec.ClientID,
		Provider:     rec.Provider,
		Model:        rec.Model,
		StatusCode:   rec.StatusCode,
		InputTokens:  rec.InputTokens,
		OutputTokens: rec.OutputTokens,
		LatencyMs:    rec.LatencyMs,
		ErrorCode:    rec.ErrorCode,
		RequestBody:  "", // legacy privacy field：恒空（P1-04B）
		ErrorMessage: "", // legacy privacy field：恒空（P1-04B）
		IsStreaming:  rec.IsStreaming,
		HasTools:     rec.HasTools,
		ToolNames:    rec.ToolNames,
		CreatedAt:    time.Now(),
	}

	if err := s.db.Create(entry).Error; err != nil {
		if isClientGoneForeignKey(err) {
			// P1-05B：client 已被删除——禁止 late-write 重建行；请求正常结束
			return nil
		}
		return fmt.Errorf("failed to log request: %w", err)
	}

	err := s.updateDailyUsage(rec.ClientID, rec.InputTokens, rec.OutputTokens, rec.StatusCode)

	// Notify dashboard hub about the new request
	if s.onRequestLogged != nil {
		s.onRequestLogged()
	}

	return err
}

func (s *GeminiService) updateDailyUsage(clientID string, inputTokens, outputTokens, statusCode int) error {
	today := time.Now().Truncate(24 * time.Hour)

	var usage models.DailyUsage
	err := s.db.Where("client_id = ? AND date = ?", clientID, today).First(&usage).Error

	if err != nil && err != gorm.ErrRecordNotFound {
		return err
	}

	if err == gorm.ErrRecordNotFound {
		usage = models.DailyUsage{
			ClientID: clientID,
			Date:     today,
		}
	}

	usage.TotalRequests++
	usage.TotalInputTokens += inputTokens
	usage.TotalOutputTokens += outputTokens

	if err := s.db.Save(&usage).Error; err != nil {
		if isClientGoneForeignKey(err) {
			// P1-05B：同上——client 已删除，usage 行不得重建
			return nil
		}
		return fmt.Errorf("failed to update daily usage: %w", err)
	}

	return nil
}

func (s *GeminiService) isModelAllowed(model string) bool {
	for _, allowed := range s.geminiProvider().AllowedModels {
		if model == allowed {
			return true
		}
	}
	return false
}

func (s *GeminiService) GetAllowedModels() []string {
	return s.geminiProvider().AllowedModels
}

func (s *GeminiService) GetDefaultModel() string {
	return s.geminiProvider().DefaultModel
}

func ParseGeminiResponse(body []byte) (int, int, error) {
	var resp GeminiResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return 0, 0, nil
	}

	if resp.UsageMetadata == nil {
		return 0, 0, nil
	}

	return resp.UsageMetadata.PromptTokenCount, resp.UsageMetadata.CandidatesTokenCount, nil
}

// GetAPIKey: 返回 gemini provider 的 API Key（proxy 流式路径 header 用）。
func (s *GeminiService) GetAPIKey() string {
	return s.geminiProvider().APIKey
}

// GetBaseURL: proxy 流式路径使用的 base URL。
// P1-04B 起尊重 provider 配置的 BaseURL（与 ForwardRequest/ForwardStreamRequest 语义一致，
// 同时使 proxy 流式路径可本地测试）；未配置时回退官方端点。
func (s *GeminiService) GetBaseURL() string {
	if p := s.cfg.GetProvider("gemini"); p != nil && p.BaseURL != "" {
		return p.BaseURL
	}
	return "https://generativelanguage.googleapis.com/v1beta"
}

func (s *GeminiService) TestConnection() (string, bool, error) {
	gp := s.geminiProvider()
	if gp.APIKey == "" {
		return "API key not configured", false, nil
	}

	// SEC-002（P1-03C3）：key 走 header
	req, err := http.NewRequest("GET", "https://generativelanguage.googleapis.com/v1/models", nil)
	if err != nil {
		return "Failed to create request: " + err.Error(), false, err
	}
	req.Header.Set("x-goog-api-key", gp.APIKey)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "Failed to connect: " + err.Error(), false, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return "API returned status: " + resp.Status, false, nil
	}

	return "Connected successfully", true, nil
}

func (s *GeminiService) FetchAvailableModels() ([]string, error) {
	gp := s.geminiProvider()
	if gp.APIKey == "" {
		return nil, fmt.Errorf("API key not configured")
	}

	models := make([]string, 0)

	for _, baseURL := range []string{"https://generativelanguage.googleapis.com/v1", "https://generativelanguage.googleapis.com/v1beta"} {
		// SEC-002（P1-03C3）：key 走 header
		req, err := http.NewRequest("GET", baseURL+"/models", nil)
		if err != nil {
			continue
		}
		req.Header.Set("x-goog-api-key", gp.APIKey)

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		if resp.StatusCode != 200 {
			continue
		}

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			continue
		}

		var result struct {
			Models []struct {
				Name string `json:"name"`
			} `json:"models"`
		}

		if err := json.Unmarshal(body, &result); err != nil {
			continue
		}

		for _, m := range result.Models {
			modelName := m.Name
			if strings.HasPrefix(modelName, "models/") {
				modelName = strings.TrimPrefix(modelName, "models/")
			}
			found := false
			for _, existing := range models {
				if existing == modelName {
					found = true
					break
				}
			}
			if !found {
				models = append(models, modelName)
			}
		}
	}

	if len(models) == 0 {
		return nil, fmt.Errorf("no models found - check API key")
	}

	return models, nil
}
