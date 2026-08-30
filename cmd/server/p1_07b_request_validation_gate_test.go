package main

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"

	"ai-gateway/internal/models"
)

func p107bDepthBody(depth int) string {
	nested := "0"
	for i := 0; i < depth; i++ {
		nested = `{"x":` + nested + `}`
	}
	return `{"model":"test-model","messages":[{"role":"user","content":"hello"}],"extra":` + nested + `}`
}

func p107bGzipBody(t *testing.T, body string) []byte {
	t.Helper()
	var compressed bytes.Buffer
	writer := gzip.NewWriter(&compressed)
	if _, err := writer.Write([]byte(body)); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return compressed.Bytes()
}

func p107bPublicRequest(t *testing.T, env *p106b1PublicGateway, path, apiKey string, body []byte, contentType, contentEncoding string, contentLength int64) (*http.Response, error) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, env.api.URL+path, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+apiKey)
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	if contentEncoding != "" {
		req.Header.Set("Content-Encoding", contentEncoding)
	}
	if contentLength != 0 {
		req.ContentLength = contentLength
	}
	return http.DefaultClient.Do(req)
}

func p107bResponseCode(t *testing.T, response *http.Response) string {
	t.Helper()
	defer response.Body.Close()
	var payload struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
		t.Fatal(err)
	}
	return payload.Error.Code
}

func TestP107B_PublicInvalidRequestsNeverReachUpstream(t *testing.T) {
	valid := `{"model":"test-model","messages":[{"role":"user","content":"hello"}]}`
	oversized := []byte(strings.Repeat("A", (10<<20)+1))
	cases := []struct {
		name            string
		path            string
		body            []byte
		contentType     string
		contentEncoding string
		contentLength   int64
		status          int
		code            string
	}{
		{name: "known length oversized", path: "/v1/chat/completions", body: oversized, contentType: "application/json", contentLength: int64(len(oversized)), status: http.StatusRequestEntityTooLarge, code: "REQUEST_TOO_LARGE"},
		{name: "chunked oversized", path: "/v1/chat/completions", body: oversized, contentType: "application/json", contentLength: -1, status: http.StatusRequestEntityTooLarge, code: "REQUEST_TOO_LARGE"},
		{name: "malformed json", path: "/v1/chat/completions", body: []byte(`{"model":`), contentType: "application/json", status: http.StatusBadRequest, code: "INVALID_JSON"},
		{name: "trailing json", path: "/v1/chat/completions", body: []byte(valid + `{}`), contentType: "application/json", status: http.StatusBadRequest, code: "INVALID_JSON_TRAILING"},
		{name: "depth bomb", path: "/v1/chat/completions", body: []byte(p107bDepthBody(65)), contentType: "application/json", status: http.StatusBadRequest, code: "REQUEST_TOO_DEEP"},
		{name: "top-level array", path: "/v1/chat/completions", body: []byte(`[]`), contentType: "application/json", status: http.StatusBadRequest, code: "REQUEST_BODY_NOT_OBJECT"},
		{name: "wrong content type", path: "/v1/chat/completions", body: []byte(valid), contentType: "text/plain", status: http.StatusUnsupportedMediaType, code: "UNSUPPORTED_MEDIA_TYPE"},
		{name: "gzip", path: "/v1/chat/completions", body: p107bGzipBody(t, valid), contentType: "application/json", contentEncoding: "gzip", status: http.StatusUnsupportedMediaType, code: "UNSUPPORTED_CONTENT_ENCODING"},
		{name: "empty model", path: "/v1/chat/completions", body: []byte(`{"model":"","messages":[{"role":"user","content":"hello"}]}`), contentType: "application/json", status: http.StatusBadRequest, code: "MODEL_REQUIRED"},
		{name: "model control character", path: "/v1/chat/completions", body: []byte(`{"model":"test\u0001model","messages":[{"role":"user","content":"hello"}]}`), contentType: "application/json", status: http.StatusBadRequest, code: "MODEL_CONTROL_CHARACTER"},
		{name: "output above client limit", path: "/v1/chat/completions", body: []byte(`{"model":"test-model","messages":[{"role":"user","content":"hello"}],"max_tokens":9000}`), contentType: "application/json", status: http.StatusBadRequest, code: "MAX_OUTPUT_TOKENS_EXCEEDED"},
		{name: "count tokens malformed", path: "/v1/messages/count_tokens", body: []byte(`{"prompt":`), contentType: "application/json", status: http.StatusBadRequest, code: "INVALID_JSON"},
		{name: "count tokens wrong prompt type", path: "/v1/messages/count_tokens", body: []byte(`{"prompt":123}`), contentType: "application/json", status: http.StatusBadRequest, code: "PROMPT_INVALID"},
		{name: "messages missing model", path: "/v1/messages", body: []byte(`{"messages":[{"role":"user","content":"hello"}]}`), contentType: "application/json", status: http.StatusBadRequest, code: "MODEL_REQUIRED"},
		{name: "messages item wrong type", path: "/v1/messages", body: []byte(`{"model":"test-model","messages":[1]}`), contentType: "application/json", status: http.StatusBadRequest, code: "MESSAGE_INVALID"},
		{name: "messages role wrong type", path: "/v1/messages", body: []byte(`{"model":"test-model","messages":[{"role":1}]}`), contentType: "application/json", status: http.StatusBadRequest, code: "MESSAGE_ROLE_INVALID"},
		{name: "gemini missing contents", path: "/v1/models/test-model:generateContent", body: []byte(`{}`), contentType: "application/json", status: http.StatusBadRequest, code: "CONTENTS_REQUIRED"},
		{name: "gemini contents wrong type", path: "/v1/models/test-model:generateContent", body: []byte(`{"contents":{}}`), contentType: "application/json", status: http.StatusBadRequest, code: "CONTENTS_INVALID"},
		{name: "gemini parts wrong type", path: "/v1/models/test-model:generateContent", body: []byte(`{"contents":[{"parts":{}}]}`), contentType: "application/json", status: http.StatusBadRequest, code: "PARTS_INVALID"},
		{name: "gemini part text wrong type", path: "/v1/models/test-model:generateContent", body: []byte(`{"contents":[{"parts":[{"text":1}]}]}`), contentType: "application/json", status: http.StatusBadRequest, code: "PART_TEXT_INVALID"},
		{name: "gemini output above client limit", path: "/v1/models/test-model:generateContent", body: []byte(`{"contents":[{"parts":[{"text":"hello"}]}],"generationConfig":{"maxOutputTokens":9000}}`), contentType: "application/json", status: http.StatusBadRequest, code: "MAX_OUTPUT_TOKENS_EXCEEDED"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := newP106b1PublicGateway(t)
			client, apiKey, err := env.deps.clientService.CreateClient("p107b7-"+tc.name, "", "gemini", "sk-", env.deps.cfg, "test-admin")
			if err != nil {
				t.Fatal(err)
			}
			response, err := p107bPublicRequest(t, env, tc.path, apiKey, tc.body, tc.contentType, tc.contentEncoding, tc.contentLength)
			if err != nil {
				t.Fatal(err)
			}
			if response.StatusCode != tc.status {
				response.Body.Close()
				t.Fatalf("%s status=%d want=%d", tc.path, response.StatusCode, tc.status)
			}
			code := p107bResponseCode(t, response)
			if code != tc.code {
				t.Fatalf("%s code=%q want=%q", tc.path, code, tc.code)
			}
			if response.Header.Get("X-Request-ID") == "" {
				t.Fatalf("%s lost server RequestID header", tc.path)
			}
			if got := atomic.LoadInt32(env.calls); got != 0 {
				t.Fatalf("invalid %s reached upstream %d time(s)", tc.path, got)
			}
			var usageRows int64
			if err := env.deps.db.Model(&models.DailyUsage{}).Where("client_id = ?", client.ID).Count(&usageRows).Error; err != nil {
				t.Fatal(err)
			}
			if usageRows != 0 {
				t.Fatalf("invalid %s must not create a daily usage reservation row", tc.path)
			}
		})
	}
}

func TestP107B_PublicValidExtensionsAndStreamRemainAccepted(t *testing.T) {
	validCases := []struct {
		name string
		path string
		body string
	}{
		{name: "unknown extension", path: "/v1/chat/completions", body: `{"model":"provider/model-v2:1.0_test","messages":[{"role":"user","content":"hello"}],"vendor_extension":{"nested":true}}`},
		{name: "valid OpenAI stream", path: "/v1/chat/completions", body: `{"model":"test-model","messages":[{"role":"user","content":"hello"}],"stream":true}`},
		{name: "valid Gemini", path: "/v1/models/test-model:generateContent", body: `{"contents":[{"parts":[{"text":"hello"}]}]}`},
		{name: "valid Gemini stream", path: "/v1/models/test-model:streamGenerateContent", body: `{"contents":[{"parts":[{"text":"hello"}]}]}`},
	}
	for _, tc := range validCases {
		t.Run(tc.name, func(t *testing.T) {
			env := newP106b1PublicGateway(t)
			client, apiKey, err := env.deps.clientService.CreateClient("p107b7-valid-"+tc.name, "", "gemini", "sk-", env.deps.cfg, "test-admin")
			if err != nil {
				t.Fatal(err)
			}
			if err := env.deps.db.Model(&models.Client{}).Where("id = ?", client.ID).Update("backend_models", `["test-model"]`).Error; err != nil {
				t.Fatal(err)
			}
			response, err := p107bPublicRequest(t, env, tc.path, apiKey, []byte(tc.body), "application/json; charset=utf-8", "identity", 0)
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			if response.StatusCode != http.StatusOK {
				t.Fatalf("valid %s rejected with status=%d", tc.name, response.StatusCode)
			}
			if response.Header.Get("X-Request-ID") == "" {
				t.Fatal("valid request lost server RequestID response header")
			}
			if got := atomic.LoadInt32(env.calls); got == 0 {
				t.Fatalf("valid %s did not reach local upstream canary", tc.name)
			}
		})
	}
}

func TestP107B_PublicMessageCollectionBoundIsEnforcedBeforeQuota(t *testing.T) {
	messages := make([]string, 4097)
	for i := range messages {
		messages[i] = `{"role":"user","content":"x"}`
	}
	body := []byte(`{"model":"test-model","messages":[` + strings.Join(messages, ",") + `]}`)
	env := newP106b1PublicGateway(t)
	_, apiKey, err := env.deps.clientService.CreateClient("p107b7-many-messages", "", "gemini", "sk-", env.deps.cfg, "test-admin")
	if err != nil {
		t.Fatal(err)
	}
	request, err := p107bPublicRequest(t, env, "/v1/chat/completions", apiKey, body, "application/json", "", 0)
	if err != nil {
		t.Fatal(err)
	}
	if request.StatusCode != http.StatusBadRequest {
		request.Body.Close()
		t.Fatalf("messages collection bound status=%d want 400", request.StatusCode)
	}
	if code := p107bResponseCode(t, request); code != "MESSAGES_TOO_MANY" {
		t.Fatalf("messages collection bound code=%q want MESSAGES_TOO_MANY", code)
	}
	if request.Header.Get("X-Request-ID") == "" {
		t.Fatal("messages collection validation lost RequestID")
	}
	if got := atomic.LoadInt32(env.calls); got != 0 {
		t.Fatalf("messages collection validation reached upstream %d time(s)", got)
	}
}
