package middleware

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"strings"
	"unicode"
	"unicode/utf8"

	"ai-gateway/internal/models"
)

const (
	DefaultRequestBodyMaxBytes int64 = 10 << 20
	maxJSONDepth                     = 64
	maxModelRunes                    = 200
	maxCollectionItems               = 4096
	maxProtocolTokenValue            = 1_000_000
)

type requestBodyContextKey struct{}

func WithRequestBody(ctx context.Context, body []byte) context.Context {
	return context.WithValue(ctx, requestBodyContextKey{}, body)
}

func RequestBodyFromContext(ctx context.Context) ([]byte, bool) {
	body, ok := ctx.Value(requestBodyContextKey{}).([]byte)
	return body, ok
}

// ReadRequestBody returns the validator's bounded body when the public router
// has already read it. Direct handler callers retain the legacy fallback.
func ReadRequestBody(r *http.Request) ([]byte, error) {
	if body, ok := RequestBodyFromContext(r.Context()); ok {
		return body, nil
	}
	return io.ReadAll(r.Body)
}

type requestKind uint8

const (
	requestKindUnknown requestKind = iota
	requestKindOpenAIChat
	requestKindCountTokens
	requestKindGeminiGenerate
	requestKindGeminiStream
)

func requestKindFor(r *http.Request) requestKind {
	if r.Method != http.MethodPost {
		return requestKindUnknown
	}
	switch r.URL.Path {
	case "/v1/chat/completions", "/chat/completions", "/v1/messages":
		return requestKindOpenAIChat
	case "/v1/messages/count_tokens":
		return requestKindCountTokens
	}
	for _, prefix := range []string{"/v1/models/", "/v1beta/models/"} {
		if !strings.HasPrefix(r.URL.Path, prefix) {
			continue
		}
		modelAction := strings.TrimPrefix(r.URL.Path, prefix)
		if strings.HasSuffix(modelAction, ":streamGenerateContent") {
			return requestKindGeminiStream
		}
		if strings.HasSuffix(modelAction, ":generateContent") {
			return requestKindGeminiGenerate
		}
	}
	return requestKindUnknown
}

type validationFailure struct {
	status  int
	code    string
	message string
}

func RequestValidation(maxBytes int64) func(http.Handler) http.Handler {
	if maxBytes <= 0 {
		maxBytes = DefaultRequestBodyMaxBytes
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			kind := requestKindFor(r)
			if kind == requestKindUnknown {
				next.ServeHTTP(w, r)
				return
			}

			if failure := validateRequestHeaders(r); failure != nil {
				writeRequestValidationError(w, failure)
				return
			}

			body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBytes))
			if err != nil {
				var tooLarge *http.MaxBytesError
				if errors.As(err, &tooLarge) {
					writeRequestValidationError(w, &validationFailure{
						status:  http.StatusRequestEntityTooLarge,
						code:    "REQUEST_TOO_LARGE",
						message: "request body exceeds maximum size",
					})
					return
				}
				writeRequestValidationError(w, &validationFailure{
					status:  http.StatusBadRequest,
					code:    "REQUEST_BODY_READ_FAILED",
					message: "request body could not be read",
				})
				return
			}
			if failure := validateInputLimit(body, GetClientFromContext(r.Context())); failure != nil {
				writeRequestValidationError(w, failure)
				return
			}

			object, failure := decodeJSONObject(body)
			if failure != nil {
				writeRequestValidationError(w, failure)
				return
			}
			if failure = validateRequestObject(kind, r, object, GetClientFromContext(r.Context())); failure != nil {
				writeRequestValidationError(w, failure)
				return
			}

			ctx := WithRequestBody(r.Context(), body)
			r = r.WithContext(ctx)
			r.Body = io.NopCloser(bytes.NewReader(body))
			next.ServeHTTP(w, r)
		})
	}
}

func validateInputLimit(body []byte, client *models.Client) *validationFailure {
	if client != nil && client.MaxInputTokens > 0 && len(body) > client.MaxInputTokens {
		return &validationFailure{
			status:  http.StatusBadRequest,
			code:    "MAX_INPUT_TOKENS_EXCEEDED",
			message: "request input exceeds client limit",
		}
	}
	return nil
}

func validateRequestHeaders(r *http.Request) *validationFailure {
	contentType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || !strings.EqualFold(contentType, "application/json") {
		return &validationFailure{
			status:  http.StatusUnsupportedMediaType,
			code:    "UNSUPPORTED_MEDIA_TYPE",
			message: "content type must be application/json",
		}
	}
	encoding := strings.TrimSpace(r.Header.Get("Content-Encoding"))
	if encoding != "" && !strings.EqualFold(encoding, "identity") {
		return &validationFailure{
			status:  http.StatusUnsupportedMediaType,
			code:    "UNSUPPORTED_CONTENT_ENCODING",
			message: "content encoding is not supported",
		}
	}
	return nil
}

func decodeJSONObject(body []byte) (map[string]json.RawMessage, *validationFailure) {
	if !utf8.Valid(body) {
		return nil, &validationFailure{status: http.StatusBadRequest, code: "INVALID_JSON", message: "request body is not valid UTF-8"}
	}
	if maxJSONDepthExceeded(body, maxJSONDepth) {
		return nil, &validationFailure{status: http.StatusBadRequest, code: "REQUEST_TOO_DEEP", message: "request JSON nesting is too deep"}
	}

	decoder := json.NewDecoder(bytes.NewReader(body))
	var raw json.RawMessage
	if err := decoder.Decode(&raw); err != nil {
		return nil, &validationFailure{status: http.StatusBadRequest, code: "INVALID_JSON", message: "request body is not valid JSON"}
	}
	var trailing json.RawMessage
	if err := decoder.Decode(&trailing); err != io.EOF {
		return nil, &validationFailure{status: http.StatusBadRequest, code: "INVALID_JSON_TRAILING", message: "request body contains trailing JSON data"}
	}

	var object map[string]json.RawMessage
	if err := json.Unmarshal(raw, &object); err != nil || object == nil {
		return nil, &validationFailure{status: http.StatusBadRequest, code: "REQUEST_BODY_NOT_OBJECT", message: "request JSON top level must be an object"}
	}
	return object, nil
}

func maxJSONDepthExceeded(body []byte, maxDepth int) bool {
	depth := 0
	inString := false
	escaped := false
	for _, b := range body {
		if inString {
			if escaped {
				escaped = false
				continue
			}
			if b == '\\' {
				escaped = true
				continue
			}
			if b == '"' {
				inString = false
			}
			continue
		}
		switch b {
		case '"':
			inString = true
		case '{', '[':
			depth++
			if depth > maxDepth {
				return true
			}
		case '}', ']':
			if depth > 0 {
				depth--
			}
		}
	}
	return false
}

func validateRequestObject(kind requestKind, r *http.Request, object map[string]json.RawMessage, client *models.Client) *validationFailure {
	switch kind {
	case requestKindOpenAIChat:
		if failure := validateModel(object["model"], true); failure != nil {
			return failure
		}
		if failure := validateMessages(object["messages"]); failure != nil {
			return failure
		}
		if raw, ok := object["stream"]; ok {
			var stream bool
			if isJSONNull(raw) || json.Unmarshal(raw, &stream) != nil {
				return &validationFailure{status: http.StatusBadRequest, code: "STREAM_INVALID", message: "stream must be a boolean"}
			}
		}
		return validateOpenAITokens(object, client)
	case requestKindCountTokens:
		if raw, ok := object["prompt"]; ok {
			var prompt string
			if isJSONNull(raw) || json.Unmarshal(raw, &prompt) != nil {
				return &validationFailure{status: http.StatusBadRequest, code: "PROMPT_INVALID", message: "prompt must be a string"}
			}
		}
		return nil
	case requestKindGeminiGenerate, requestKindGeminiStream:
		model := geminiModelFromPath(r.URL.Path)
		if failure := validateModelString(model, true); failure != nil {
			return failure
		}
		if failure := validateContents(object["contents"]); failure != nil {
			return failure
		}
		return validateGeminiTokens(object, client)
	default:
		return nil
	}
}

func validateModel(raw json.RawMessage, required bool) *validationFailure {
	if len(raw) == 0 {
		if required {
			return &validationFailure{status: http.StatusBadRequest, code: "MODEL_REQUIRED", message: "model is required"}
		}
		return nil
	}
	var model string
	if json.Unmarshal(raw, &model) != nil {
		return &validationFailure{status: http.StatusBadRequest, code: "MODEL_INVALID", message: "model must be a string"}
	}
	return validateModelString(model, required)
}

func validateModelString(model string, required bool) *validationFailure {
	if strings.TrimSpace(model) == "" {
		if required {
			return &validationFailure{status: http.StatusBadRequest, code: "MODEL_REQUIRED", message: "model is required"}
		}
		return nil
	}
	if !utf8.ValidString(model) {
		return &validationFailure{status: http.StatusBadRequest, code: "MODEL_INVALID", message: "model must be valid UTF-8"}
	}
	if utf8.RuneCountInString(model) > maxModelRunes {
		return &validationFailure{status: http.StatusBadRequest, code: "MODEL_TOO_LONG", message: "model is too long"}
	}
	for _, r := range model {
		if unicode.IsControl(r) {
			return &validationFailure{status: http.StatusBadRequest, code: "MODEL_CONTROL_CHARACTER", message: "model contains a control character"}
		}
	}
	return nil
}

func validateMessages(raw json.RawMessage) *validationFailure {
	if len(raw) == 0 {
		return &validationFailure{status: http.StatusBadRequest, code: "MESSAGES_REQUIRED", message: "messages is required"}
	}
	var messages []json.RawMessage
	if json.Unmarshal(raw, &messages) != nil {
		return &validationFailure{status: http.StatusBadRequest, code: "MESSAGES_INVALID", message: "messages must be an array"}
	}
	if len(messages) == 0 {
		return &validationFailure{status: http.StatusBadRequest, code: "MESSAGES_REQUIRED", message: "messages must not be empty"}
	}
	if len(messages) > maxCollectionItems {
		return &validationFailure{status: http.StatusBadRequest, code: "MESSAGES_TOO_MANY", message: "messages contains too many items"}
	}
	for _, rawMessage := range messages {
		var message map[string]json.RawMessage
		if json.Unmarshal(rawMessage, &message) != nil || message == nil {
			return &validationFailure{status: http.StatusBadRequest, code: "MESSAGE_INVALID", message: "each message must be an object"}
		}
		if role, ok := message["role"]; ok {
			var value string
			if isJSONNull(role) || json.Unmarshal(role, &value) != nil {
				return &validationFailure{status: http.StatusBadRequest, code: "MESSAGE_ROLE_INVALID", message: "message role must be a string"}
			}
		}
	}
	return nil
}

func validateContents(raw json.RawMessage) *validationFailure {
	if len(raw) == 0 {
		return &validationFailure{status: http.StatusBadRequest, code: "CONTENTS_REQUIRED", message: "contents is required"}
	}
	var contents []json.RawMessage
	if json.Unmarshal(raw, &contents) != nil {
		return &validationFailure{status: http.StatusBadRequest, code: "CONTENTS_INVALID", message: "contents must be an array"}
	}
	if len(contents) == 0 || len(contents) > maxCollectionItems {
		code := "CONTENTS_REQUIRED"
		message := "contents must not be empty"
		if len(contents) > maxCollectionItems {
			code = "CONTENTS_TOO_MANY"
			message = "contents contains too many items"
		}
		return &validationFailure{status: http.StatusBadRequest, code: code, message: message}
	}
	for _, rawContent := range contents {
		var content map[string]json.RawMessage
		if json.Unmarshal(rawContent, &content) != nil || content == nil {
			return &validationFailure{status: http.StatusBadRequest, code: "CONTENT_INVALID", message: "each content must be an object"}
		}
		parts, ok := content["parts"]
		if !ok {
			return &validationFailure{status: http.StatusBadRequest, code: "PARTS_REQUIRED", message: "content parts is required"}
		}
		var partList []json.RawMessage
		if json.Unmarshal(parts, &partList) != nil || len(partList) == 0 {
			return &validationFailure{status: http.StatusBadRequest, code: "PARTS_INVALID", message: "content parts must be a non-empty array"}
		}
		if len(partList) > maxCollectionItems {
			return &validationFailure{status: http.StatusBadRequest, code: "PARTS_TOO_MANY", message: "content parts contains too many items"}
		}
		for _, rawPart := range partList {
			var part map[string]json.RawMessage
			if json.Unmarshal(rawPart, &part) != nil || part == nil {
				return &validationFailure{status: http.StatusBadRequest, code: "PART_INVALID", message: "each content part must be an object"}
			}
			if text, ok := part["text"]; ok {
				var value string
				if isJSONNull(text) || json.Unmarshal(text, &value) != nil {
					return &validationFailure{status: http.StatusBadRequest, code: "PART_TEXT_INVALID", message: "part text must be a string"}
				}
			}
		}
	}
	return nil
}

func validateOpenAITokens(object map[string]json.RawMessage, client *models.Client) *validationFailure {
	for _, field := range []string{"max_tokens", "max_output_tokens"} {
		if raw, ok := object[field]; ok {
			value, failure := parseTokenValue(raw)
			if failure != nil {
				return failure
			}
			if client != nil && client.MaxOutputTokens > 0 && value > int64(client.MaxOutputTokens) {
				return &validationFailure{status: http.StatusBadRequest, code: "MAX_OUTPUT_TOKENS_EXCEEDED", message: "requested output tokens exceed client limit"}
			}
		}
	}
	return nil
}

func validateGeminiTokens(object map[string]json.RawMessage, client *models.Client) *validationFailure {
	raw, ok := object["generationConfig"]
	if !ok {
		return nil
	}
	var config map[string]json.RawMessage
	if json.Unmarshal(raw, &config) != nil || config == nil {
		return &validationFailure{status: http.StatusBadRequest, code: "GENERATION_CONFIG_INVALID", message: "generationConfig must be an object"}
	}
	maxOutput, ok := config["maxOutputTokens"]
	if !ok {
		return nil
	}
	value, failure := parseTokenValue(maxOutput)
	if failure != nil {
		return failure
	}
	if client != nil && client.MaxOutputTokens > 0 && value > int64(client.MaxOutputTokens) {
		return &validationFailure{status: http.StatusBadRequest, code: "MAX_OUTPUT_TOKENS_EXCEEDED", message: "requested output tokens exceed client limit"}
	}
	return nil
}

func parseTokenValue(raw json.RawMessage) (int64, *validationFailure) {
	var value int64
	if isJSONNull(raw) || json.Unmarshal(raw, &value) != nil || value < 0 {
		return 0, &validationFailure{status: http.StatusBadRequest, code: "MAX_TOKENS_INVALID", message: "max tokens must be a non-negative integer"}
	}
	if value > maxProtocolTokenValue {
		return 0, &validationFailure{status: http.StatusBadRequest, code: "MAX_TOKENS_TOO_LARGE", message: "max tokens exceeds protocol limit"}
	}
	return value, nil
}

func isJSONNull(raw json.RawMessage) bool {
	return bytes.Equal(bytes.TrimSpace(raw), []byte("null"))
}

func geminiModelFromPath(path string) string {
	for _, prefix := range []string{"/v1/models/", "/v1beta/models/"} {
		if !strings.HasPrefix(path, prefix) {
			continue
		}
		modelAction := strings.TrimPrefix(path, prefix)
		for _, action := range []string{":streamGenerateContent", ":generateContent"} {
			if strings.HasSuffix(modelAction, action) {
				return strings.TrimSuffix(modelAction, action)
			}
		}
	}
	return ""
}

func writeRequestValidationError(w http.ResponseWriter, failure *validationFailure) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(failure.status)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"error": map[string]string{
			"code":    failure.code,
			"message": failure.message,
		},
	})
}
