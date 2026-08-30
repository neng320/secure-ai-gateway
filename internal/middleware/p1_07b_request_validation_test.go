package middleware

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"ai-gateway/internal/models"
)

func p107bValidationClient() *models.Client {
	return &models.Client{ID: "p107b-validation-client", MaxInputTokens: 1000, MaxOutputTokens: 128}
}

func p107bValidationRequest(method, path, body, contentType, contentEncoding string) *http.Request {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	if contentEncoding != "" {
		req.Header.Set("Content-Encoding", contentEncoding)
	}
	return req.WithContext(context.WithValue(req.Context(), ClientContextKey, p107bValidationClient()))
}

func p107bRunValidation(req *http.Request) (int, string, int, string) {
	calls := 0
	h := RequestValidation(10 << 20)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		body, err := ReadRequestBody(r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		_ = body
		w.WriteHeader(http.StatusOK)
	}))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	var response struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &response)
	return w.Code, response.Error.Code, calls, w.Body.String()
}

func TestP107B_RequestValidationRejectsUnsafeInputsBeforeDownstream(t *testing.T) {
	depth := "0"
	for i := 0; i < 65; i++ {
		depth = `{"x":` + depth + `}`
	}
	valid := `{"model":"test-model","messages":[{"role":"user","content":"hello"}]}`
	cases := []struct {
		name          string
		body          string
		contentType   string
		contentEncode string
		code          string
		status        int
	}{
		{name: "malformed json", body: `{"model":`, contentType: "application/json", code: "INVALID_JSON", status: http.StatusBadRequest},
		{name: "trailing value", body: valid + `{}`, contentType: "application/json", code: "INVALID_JSON_TRAILING", status: http.StatusBadRequest},
		{name: "top-level array", body: `[]`, contentType: "application/json", code: "REQUEST_BODY_NOT_OBJECT", status: http.StatusBadRequest},
		{name: "top-level null", body: `null`, contentType: "application/json", code: "REQUEST_BODY_NOT_OBJECT", status: http.StatusBadRequest},
		{name: "wrong content type", body: valid, contentType: "text/plain", code: "UNSUPPORTED_MEDIA_TYPE", status: http.StatusUnsupportedMediaType},
		{name: "gzip", body: valid, contentType: "application/json", contentEncode: "gzip", code: "UNSUPPORTED_CONTENT_ENCODING", status: http.StatusUnsupportedMediaType},
		{name: "stream wrong type", body: `{"model":"test-model","messages":[{"role":"user","content":"hello"}],"stream":"true"}`, contentType: "application/json", code: "STREAM_INVALID", status: http.StatusBadRequest},
		{name: "input above client limit", body: `{"model":"test-model","messages":[{"role":"user","content":"` + strings.Repeat("x", 1000) + `"}]}`, contentType: "application/json", code: "MAX_INPUT_TOKENS_EXCEEDED", status: http.StatusBadRequest},
		{name: "empty model", body: `{"model":"","messages":[{"role":"user","content":"hello"}]}`, contentType: "application/json", code: "MODEL_REQUIRED", status: http.StatusBadRequest},
		{name: "model too long", body: `{"model":"` + strings.Repeat("m", 201) + `","messages":[{"role":"user","content":"hello"}]}`, contentType: "application/json", code: "MODEL_TOO_LONG", status: http.StatusBadRequest},
		{name: "control character model", body: `{"model":"test\u0001model","messages":[{"role":"user","content":"hello"}]}`, contentType: "application/json", code: "MODEL_CONTROL_CHARACTER", status: http.StatusBadRequest},
		{name: "negative max tokens", body: `{"model":"test-model","messages":[{"role":"user","content":"hello"}],"max_tokens":-1}`, contentType: "application/json", code: "MAX_TOKENS_INVALID", status: http.StatusBadRequest},
		{name: "null max tokens", body: `{"model":"test-model","messages":[{"role":"user","content":"hello"}],"max_tokens":null}`, contentType: "application/json", code: "MAX_TOKENS_INVALID", status: http.StatusBadRequest},
		{name: "fractional max tokens", body: `{"model":"test-model","messages":[{"role":"user","content":"hello"}],"max_tokens":1.5}`, contentType: "application/json", code: "MAX_TOKENS_INVALID", status: http.StatusBadRequest},
		{name: "string max tokens", body: `{"model":"test-model","messages":[{"role":"user","content":"hello"}],"max_tokens":"1"}`, contentType: "application/json", code: "MAX_TOKENS_INVALID", status: http.StatusBadRequest},
		{name: "max output tokens alias above client limit", body: `{"model":"test-model","messages":[{"role":"user","content":"hello"}],"max_output_tokens":129}`, contentType: "application/json", code: "MAX_OUTPUT_TOKENS_EXCEEDED", status: http.StatusBadRequest},
		{name: "output above client limit", body: `{"model":"test-model","messages":[{"role":"user","content":"hello"}],"max_tokens":129}`, contentType: "application/json", code: "MAX_OUTPUT_TOKENS_EXCEEDED", status: http.StatusBadRequest},
		{name: "depth bomb", body: `{"model":"test-model","messages":[{"role":"user","content":"hello"}],"extra":` + depth + `}`, contentType: "application/json", code: "REQUEST_TOO_DEEP", status: http.StatusBadRequest},
		{name: "messages wrong type", body: `{"model":"test-model","messages":{}}`, contentType: "application/json", code: "MESSAGES_INVALID", status: http.StatusBadRequest},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			status, code, calls, body := p107bRunValidation(p107bValidationRequest(http.MethodPost, "/v1/chat/completions", tc.body, tc.contentType, tc.contentEncode))
			if status != tc.status || code != tc.code || calls != 0 {
				t.Fatalf("status=%d code=%q calls=%d body=%s; want status=%d code=%q calls=0", status, code, calls, body, tc.status, tc.code)
			}
		})
	}
}

func TestP107B_RequestValidationRejectsOversizedKnownAndChunkedBodies(t *testing.T) {
	body := strings.Repeat("A", (10<<20)+1)
	for _, contentLength := range []int64{int64(len(body)), -1} {
		req := p107bValidationRequest(http.MethodPost, "/v1/chat/completions", body, "application/json", "")
		req.ContentLength = contentLength
		status, code, calls, responseBody := p107bRunValidation(req)
		if status != http.StatusRequestEntityTooLarge || code != "REQUEST_TOO_LARGE" || calls != 0 {
			t.Fatalf("content length %d: status=%d code=%q calls=%d body=%s", contentLength, status, code, calls, responseBody)
		}
	}
}

func TestP107B_RequestValidationRejectsInvalidUTF8(t *testing.T) {
	body := append([]byte(`{"model":"test`), 0xff)
	body = append(body, []byte(`","messages":[{"role":"user","content":"hello"}]}`)...)
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	status, code, calls, responseBody := p107bRunValidation(req.WithContext(context.WithValue(req.Context(), ClientContextKey, p107bValidationClient())))
	if status != http.StatusBadRequest || code != "INVALID_JSON" || calls != 0 {
		t.Fatalf("invalid UTF-8 should be rejected before downstream: status=%d code=%q calls=%d body=%s", status, code, calls, responseBody)
	}
}

func TestP107B_RequestValidationPreservesUnknownExtensionsAndValidModelSyntax(t *testing.T) {
	body := `{"model":"provider/model-v2:1.0_test","messages":[{"role":"user","content":"hello"}],"vendor_extension":{"nested":true},"stream":true}`
	status, code, calls, responseBody := p107bRunValidation(p107bValidationRequest(http.MethodPost, "/v1/chat/completions", body, "application/json; charset=utf-8", "identity"))
	if status != http.StatusOK || code != "" || calls != 1 || responseBody != "" {
		t.Fatalf("valid extension/model syntax rejected: status=%d code=%q calls=%d body=%s", status, code, calls, responseBody)
	}
}

func TestP107B_RequestValidationUsesOneBoundedBodyReadForDownstream(t *testing.T) {
	body := `{"model":"test-model","messages":[{"role":"user","content":"hello"}]}`
	reads := 0
	reader := &countingReader{body: []byte(body), reads: &reads}
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", reader)
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(context.WithValue(req.Context(), ClientContextKey, p107bValidationClient()))
	seen := ""
	h := RequestValidation(10 << 20)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, err := ReadRequestBody(r)
		if err != nil {
			t.Fatal(err)
		}
		seen = string(got)
		w.WriteHeader(http.StatusOK)
	}))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK || seen != body || reads == 0 {
		t.Fatalf("body context was not preserved: status=%d seen=%q reads=%d", w.Code, seen, reads)
	}
}

func TestP107B_QuotaAndHandlerReuseValidatedBody(t *testing.T) {
	env := newP106bQuotaEnv(t, 10, 1000, 1000, 1000, 128)
	body := `{"model":"test-model","messages":[{"role":"user","content":"hello"}]}`
	reads := 0
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", &countingReader{body: []byte(body), reads: &reads})
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(context.WithValue(req.Context(), ClientContextKey, env.client))
	seen := ""
	h := RequestValidation(10 << 20)(NewQuotaMiddleware(env.db)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, err := ReadRequestBody(r)
		if err != nil {
			t.Fatal(err)
		}
		seen = string(got)
		w.WriteHeader(http.StatusOK)
	})))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK || seen != body || reads == 0 {
		t.Fatalf("quota/handler did not reuse validated body: status=%d seen=%q reads=%d", w.Code, seen, reads)
	}
}

func TestP107B_RequestValidationSkipsNonBodyGET(t *testing.T) {
	calls := 0
	h := RequestValidation(10 << 20)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if _, err := io.ReadAll(r.Body); err != nil {
			t.Fatal(err)
		}
		w.WriteHeader(http.StatusOK)
	}))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/v1/models", nil))
	if w.Code != http.StatusOK || calls != 1 {
		t.Fatalf("GET model route should bypass body validation: status=%d calls=%d", w.Code, calls)
	}
}

type countingReader struct {
	body  []byte
	off   int
	reads *int
}

func (r *countingReader) Read(p []byte) (int, error) {
	*r.reads++
	if r.off == len(r.body) {
		return 0, io.EOF
	}
	n := copy(p, r.body[r.off:])
	r.off += n
	return n, nil
}
