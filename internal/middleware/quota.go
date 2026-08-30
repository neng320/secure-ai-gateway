package middleware

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"ai-gateway/internal/models"
	"ai-gateway/internal/services"

	"gorm.io/gorm"
)

func IsQuotaRequest(r *http.Request) bool {
	switch requestKindFor(r) {
	case requestKindOpenAIChat, requestKindGeminiGenerate, requestKindGeminiStream:
		return true
	default:
		return false
	}
}

func NewQuotaMiddleware(db *gorm.DB) func(http.Handler) http.Handler {
	ledger := services.NewUsageLedger(db)
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !IsQuotaRequest(r) {
				next.ServeHTTP(w, r)
				return
			}
			client := GetClientFromContext(r.Context())
			body, ok := RequestBodyFromContext(r.Context())
			if !ok {
				var err error
				body, err = ReadRequestBody(r)
				if err != nil {
					writeQuotaError(w, services.ErrQuotaConfiguration)
					return
				}
			}
			r.Body = io.NopCloser(bytes.NewReader(body))
			inputReservation, outputReservation := requestReservations(client, body)
			reservation, err := ledger.Reserve(client, inputReservation, outputReservation)
			if err != nil {
				writeQuotaError(w, err)
				return
			}
			defer reservation.Release()
			next.ServeHTTP(w, r.WithContext(services.WithUsageReservation(r.Context(), reservation)))
		})
	}
}

func requestReservations(client *models.Client, body []byte) (int, int) {
	if client == nil {
		return 0, 0
	}
	input := len(body)
	if client.MaxInputTokens > 0 && input > client.MaxInputTokens {
		input = client.MaxInputTokens
	}
	output := client.MaxOutputTokens
	var request struct {
		MaxTokens        int `json:"max_tokens"`
		GenerationConfig struct {
			MaxOutputTokens int `json:"maxOutputTokens"`
		} `json:"generationConfig"`
	}
	if json.Unmarshal(body, &request) == nil {
		if request.MaxTokens > 0 && request.MaxTokens < output {
			output = request.MaxTokens
		}
		if request.GenerationConfig.MaxOutputTokens > 0 && request.GenerationConfig.MaxOutputTokens < output {
			output = request.GenerationConfig.MaxOutputTokens
		}
	}
	return input, output
}

func writeQuotaError(w http.ResponseWriter, err error) {
	status := http.StatusTooManyRequests
	code := "QUOTA_REQUESTS_EXCEEDED"
	message := "daily quota exceeded"
	if errors.Is(err, services.ErrQuotaRequestsExceeded) {
		// Keep the default request-quota code and 429 status.
	} else if errors.Is(err, services.ErrQuotaInputExceeded) {
		code = "QUOTA_INPUT_TOKENS_EXCEEDED"
	} else if errors.Is(err, services.ErrQuotaOutputExceeded) {
		code = "QUOTA_OUTPUT_TOKENS_EXCEEDED"
	} else if errors.Is(err, services.ErrQuotaConfiguration) {
		status = http.StatusInternalServerError
		code = "QUOTA_CONFIGURATION_INVALID"
		message = "quota configuration invalid"
	} else if err != nil {
		status = http.StatusInternalServerError
		code = "QUOTA_UNAVAILABLE"
		message = "quota service unavailable"
	}
	w.Header().Set("Content-Type", "application/json")
	if status == http.StatusTooManyRequests {
		w.Header().Set("Retry-After", "86400")
	}
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"error": map[string]string{"code": code, "message": message},
	})
}
