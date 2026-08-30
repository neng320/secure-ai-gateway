package handlers

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"ai-gateway/internal/capture"
	"ai-gateway/internal/middleware"
	"ai-gateway/internal/models"
	"ai-gateway/internal/services"

	"github.com/go-chi/chi/v5"
)

type ProxyHandler struct {
	geminiService *services.GeminiService
	statsService  *services.StatsService
	capture       *capture.Store // MEMORY-ONLY 诊断捕获（SEC-003/P1-04C）；nil = 关闭
}

func NewProxyHandler(geminiService *services.GeminiService, statsService *services.StatsService, captureStore *capture.Store) *ProxyHandler {
	return &ProxyHandler{geminiService: geminiService, statsService: statsService, capture: captureStore}
}

func (h *ProxyHandler) RegisterRoutes(r chi.Router) {
	for _, prefix := range []string{"/v1", "/v1beta"} {
		r.Route(prefix, func(r chi.Router) {
			r.Group(func(r chi.Router) {
				r.Use(middleware.Recovery)

				r.Post("/models/{model}:generateContent", h.GenerateContent)
				r.Post("/models/{model}:streamGenerateContent", h.StreamGenerateContent)
				r.Get("/models", h.ListModels)
				r.Get("/models/{model}", h.GetModel)
			})
		})
	}
}

func (h *ProxyHandler) GenerateContent(w http.ResponseWriter, r *http.Request) {
	client := middleware.GetClientFromContext(r.Context())
	if client == nil {
		http.Error(w, `{"error": "Unauthorized"}`, http.StatusUnauthorized)
		return
	}

	model := chi.URLParam(r, "model")
	if model == "" {
		model = "gemini-flash-lite-latest"
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, `{"error": "Failed to read request body"}`, http.StatusBadRequest)
		return
	}

	if h.statsService != nil {
		h.statsService.IncrementRequestsInProgress()
	}

	if err := h.enforceRequestLimits(client, body); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Error-Code", "REQUEST_LIMIT_EXCEEDED")
		http.Error(w, err.Error(), http.StatusBadRequest)
		if h.statsService != nil {
			h.statsService.DecrementRequestsInProgress()
		}
		return
	}

	// SEC-003（P1-04C）：诊断捕获在 cap 之前——始终为原始 inbound payload（且默认关闭）
	h.capture.Capture(middleware.GetRequestID(r), body)

	body = h.capOutputTokens(client, body)

	start := time.Now()
	respBody, statusCode, err := h.geminiService.ForwardRequest(model, body)
	latencyMs := int(time.Since(start).Milliseconds())

	inputTokens, outputTokens, _ := services.ParseGeminiResponse(respBody)

	// SEC-003（P1-04B）：metadata-only 持久化——raw 错误文本/正文不再可传给持久层
	h.geminiService.LogRequest(services.RequestRecord{
		RequestID:    middleware.GetRequestID(r),
		ClientID:     client.ID,
		Provider:     "gemini",
		Model:        model,
		StatusCode:   statusCode,
		InputTokens:  inputTokens,
		OutputTokens: outputTokens,
		LatencyMs:    latencyMs,
		ErrorCode:    services.ClassifyUpstreamError(statusCode, err),
		IsStreaming:  false,
		HasTools:     false,
		Reservation:  services.UsageReservationFromContext(r.Context()),
	})
	RecordRequest(client.ID, model, fmt.Sprintf("%d", statusCode), inputTokens, outputTokens, latencyMs)

	if h.statsService != nil {
		h.statsService.DecrementRequestsInProgress()
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-RateLimit-Limit-Minute", strconv.Itoa(client.RateLimitMinute))
	w.Header().Set("X-RateLimit-Limit-Hour", strconv.Itoa(client.RateLimitHour))
	w.Header().Set("X-RateLimit-Limit-Day", strconv.Itoa(client.RateLimitDay))
	w.Header().Set("X-TokenLimit-Input", strconv.Itoa(client.MaxInputTokens))
	w.Header().Set("X-TokenLimit-Output", strconv.Itoa(client.MaxOutputTokens))

	w.WriteHeader(statusCode)
	if respBody != nil {
		w.Write(respBody)
	}
}

func (h *ProxyHandler) enforceRequestLimits(client *models.Client, body []byte) error {
	inputTokens := estimateInputTokens(string(body))

	if client.MaxInputTokens > 0 && inputTokens > client.MaxInputTokens {
		return &APIError{
			Err: APIErrorBody{
				Message: "Input token count exceeds limit",
				Code:    "MAX_INPUT_TOKENS_EXCEEDED",
				Status:  "INVALID_ARGUMENT",
				Details: []map[string]interface{}{
					{"limit": client.MaxInputTokens, "received": inputTokens},
				},
			},
		}
	}

	return nil
}

func (h *ProxyHandler) capOutputTokens(client *models.Client, body []byte) []byte {
	if client.MaxOutputTokens == 0 {
		return body
	}

	var req map[string]interface{}
	if err := json.Unmarshal(body, &req); err != nil {
		return body
	}

	generationConfig, ok := req["generationConfig"].(map[string]interface{})
	if !ok {
		req["generationConfig"] = map[string]interface{}{
			"maxOutputTokens": client.MaxOutputTokens,
		}
	} else {
		if current, ok := generationConfig["maxOutputTokens"].(float64); !ok || int(current) > client.MaxOutputTokens {
			generationConfig["maxOutputTokens"] = client.MaxOutputTokens
		}
	}

	newBody, _ := json.Marshal(req)
	return newBody
}

func estimateInputTokens(text string) int {
	// Conservative upper bound only. This is deliberately not presented as an
	// exact tokenizer; a byte can account for at most one token in the V1 gate.
	return len(text)
}

func (h *ProxyHandler) StreamGenerateContent(w http.ResponseWriter, r *http.Request) {
	client := middleware.GetClientFromContext(r.Context())
	if client == nil {
		http.Error(w, `{"error": "Unauthorized"}`, http.StatusUnauthorized)
		return
	}

	model := chi.URLParam(r, "model")
	if model == "" {
		model = "gemini-flash-lite-latest"
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, `{"error": "Failed to read request body"}`, http.StatusBadRequest)
		return
	}

	if h.statsService != nil {
		h.statsService.IncrementRequestsInProgress()
	}

	if err := h.enforceRequestLimits(client, body); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		if h.statsService != nil {
			h.statsService.DecrementRequestsInProgress()
		}
		return
	}

	// SEC-003（P1-04B）：补齐 gemini 流式路径的 metadata-only RequestLog
	// （此前该路径完全无 RequestLog；正文照旧不入持久层）
	streamStart := time.Now()

	// SEC-003（P1-04C）：诊断捕获在 cap 之前（原始 inbound payload；默认关闭）
	h.capture.Capture(middleware.GetRequestID(r), body)

	body = h.capOutputTokens(client, body)

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Transfer-Encoding", "chunked")

	// SEC-002（P1-03C3）：key 走 header（原实现 URL 以 "key=" 结尾且从未拼接——顺带修复该断链）
	baseURL := h.geminiService.GetBaseURL()
	url := baseURL + "/models/" + model + ":streamGenerateContent"

	req, err := http.NewRequest("POST", url, strings.NewReader(string(body)))
	if err != nil {
		http.Error(w, `{"error": "Failed to create request"}`, http.StatusInternalServerError)
		return
	}

	req.Header.Set("Content-Type", "application/json")
	if apiKey := h.geminiService.GetAPIKey(); apiKey != "" {
		req.Header.Set("x-goog-api-key", apiKey)
	}

	clientHTTP := &http.Client{
		Timeout: 120 * time.Second,
	}

	resp, err := clientHTTP.Do(req)
	if err != nil {
		http.Error(w, `{"error": "Failed to forward request"}`, http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, `{"error": "Streaming not supported"}`, http.StatusInternalServerError)
		return
	}

	var inputTokens, outputTokens int
	var usageFound bool
	scanner := bufio.NewScanner(resp.Body)
	// Keep stream parsing bounded: Gemini SSE data lines are expected to be
	// small, and an oversized line is treated as an incomplete stream.
	scanner.Buffer(make([]byte, 4<<10), 1<<20)
	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "data:") {
			payload := strings.TrimSpace(strings.TrimPrefix(trimmed, "data:"))
			if payload != "" && payload != "[DONE]" {
				var chunk services.GeminiResponse
				if json.Unmarshal([]byte(payload), &chunk) == nil && chunk.UsageMetadata != nil {
					inputTokens = chunk.UsageMetadata.PromptTokenCount
					outputTokens = chunk.UsageMetadata.CandidatesTokenCount
					usageFound = true
				}
			}
		}
		_, _ = io.WriteString(w, line+"\n")
		flusher.Flush()
	}
	if err := scanner.Err(); err != nil {
		// A partial/oversized stream has no chargeable completion. The quota
		// middleware's deferred Release will clear any reservation.
		return
	}
	if resp.StatusCode < http.StatusBadRequest && !usageFound {
		if reservation := services.UsageReservationFromContext(r.Context()); reservation != nil {
			// Missing provider metadata must not become a zero-token bypass.
			inputTokens, outputTokens = reservation.ConservativeUsage()
		}
	}

	h.geminiService.LogRequest(services.RequestRecord{
		RequestID:    middleware.GetRequestID(r),
		ClientID:     client.ID,
		Provider:     "gemini",
		Model:        model,
		StatusCode:   resp.StatusCode,
		InputTokens:  inputTokens,
		OutputTokens: outputTokens,
		LatencyMs:    int(time.Since(streamStart).Milliseconds()),
		ErrorCode:    services.ClassifyUpstreamError(resp.StatusCode, nil),
		IsStreaming:  true,
		Reservation:  services.UsageReservationFromContext(r.Context()),
	})

	if h.statsService != nil {
		h.statsService.DecrementRequestsInProgress()
	}
}

func (h *ProxyHandler) ListModels(w http.ResponseWriter, r *http.Request) {
	models := h.geminiService.GetAllowedModels()

	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"models":[`))
	for i, m := range models {
		if i > 0 {
			w.Write([]byte(","))
		}
		w.Write([]byte(`{"name":"` + m + `","version":"v1","displayName":"` + m + `"}`))
	}
	w.Write([]byte(`]}`))
}

func (h *ProxyHandler) GetModel(w http.ResponseWriter, r *http.Request) {
	model := chi.URLParam(r, "model")

	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"name":"` + model + `","version":"v1","displayName":"` + model + `"}`))
}

type APIError struct {
	Err APIErrorBody `json:"error"`
}

type APIErrorBody struct {
	Message string                   `json:"message"`
	Code    string                   `json:"code"`
	Status  string                   `json:"status"`
	Details []map[string]interface{} `json:"details,omitempty"`
}

func writeStructuredAPIError(r *http.Request, w http.ResponseWriter, statusCode int, apiErr *APIError) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("x-request-id", middleware.GetRequestID(r))
	w.WriteHeader(statusCode)
	_ = json.NewEncoder(w).Encode(apiErr)
}

func (e *APIError) Error() string {
	b, _ := json.Marshal(e.Err)
	return string(b)
}
