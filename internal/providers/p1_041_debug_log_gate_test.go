package providers

// P1-04.1 · Provider Runtime Body Log Eradication Gate（SEC-003）
//
// 反转自 P1-04A/P1-04 复验发现的 BLOCKER：DEBUG=1 时 provider 层曾将
// request body / response body / 完整 URL 直接 log.Printf（无限期、非 bounded、
// 非 expiry 的正文日志通道，完全绕过 request_body_capture 的 memory-only 语义）。
//
// 本 Gate：DEBUG=1 下请求成功，但 runtime log 对正文/响应体/URL canary 零命中；
// 另含静态 tripwire（生产源码无 string(body)/string(respBody) 日志 sink）。

import (
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"ai-gateway/internal/config"
)

const (
	p1041ReqCanary  = "P1041_DEBUG_REQUEST_BODY_CANARY"
	p1041RespCanary = "P1041_DEBUG_RESPONSE_BODY_CANARY"
)

func captureLog(t *testing.T) *strings.Builder {
	t.Helper()
	buf := &strings.Builder{}
	prev := log.Writer()
	log.SetOutput(buf)
	t.Cleanup(func() { log.SetOutput(prev) })
	return buf
}

// A. OpenAICompat DEBUG=1：request/response body canary 不进 runtime log
func TestP1041_OpenAICompat_DEBUG_NoBodyInLog(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		if !strings.Contains(string(b), p1041ReqCanary) {
			t.Errorf("upstream 应收到完整请求（功能不回归）")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":"` + p1041RespCanary + `"}}],"usage":{"prompt_tokens":1,"completion_tokens":1}}`))
	}))
	t.Cleanup(upstream.Close)

	t.Setenv("DEBUG", "1")
	buf := captureLog(t)

	p, err := BuildSingleProvider("openai", config.ProviderConfig{
		Type: "openai", BaseURL: upstream.URL + "/v1", APIKey: "sk-test", TimeoutSeconds: 5,
	})
	if err != nil {
		t.Fatal(err)
	}

	respBody, status, err := p.ChatCompletion(&ChatRequest{
		Model:    "test-model",
		Messages: []ChatMessage{{Role: "user", Content: p1041ReqCanary}},
	})
	if err != nil || status != 200 {
		t.Fatalf("[功能回归失败] 请求应成功，实际 status=%d err=%v", status, err)
	}
	if !strings.Contains(string(respBody), p1041RespCanary) {
		t.Fatal("[功能回归失败] 上游响应体应正常返回给调用方（不影响功能）")
	}

	logs := buf.String()
	for _, banned := range []string{p1041ReqCanary, p1041RespCanary, upstream.URL, "Request to ", "Response: "} {
		if strings.Contains(logs, banned) {
			t.Fatalf("[安全回归失败] DEBUG=1 runtime log 含 %q: %q", banned, logs)
		}
	}
	if !strings.Contains(logs, "request model=") || !strings.Contains(logs, "response status=") {
		t.Fatalf("[安全回归失败] DEBUG 应保留 metadata 日志，实际 %q", logs)
	}
	t.Log("[SEC-003 FIXED] OpenAICompat DEBUG=1：仅 metadata，无正文/响应体/URL")
}

// B. Ollama DEBUG=1：同规则
func TestP1041_Ollama_DEBUG_NoBodyInLog(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"message":{"role":"assistant","content":"` + p1041RespCanary + `"}}`))
	}))
	t.Cleanup(upstream.Close)

	t.Setenv("DEBUG", "true")
	buf := captureLog(t)

	p, err := BuildSingleProvider("ollama", config.ProviderConfig{
		Type: "ollama", BaseURL: upstream.URL, TimeoutSeconds: 5,
	})
	if err != nil {
		t.Fatal(err)
	}
	_, status, err := p.ChatCompletion(&ChatRequest{
		Model:    "test-model",
		Messages: []ChatMessage{{Role: "user", Content: p1041ReqCanary}},
	})
	if err != nil || status != 200 {
		t.Fatalf("[功能回归失败] 请求应成功，实际 status=%d err=%v", status, err)
	}

	logs := buf.String()
	for _, banned := range []string{p1041ReqCanary, p1041RespCanary, upstream.URL, "Request to ", "Response: "} {
		if strings.Contains(logs, banned) {
			t.Fatalf("[安全回归失败] DEBUG=1 runtime log 含 %q: %q", banned, logs)
		}
	}
	t.Log("[SEC-003 FIXED] Ollama DEBUG=1：仅 metadata")
}

// FetchModels 响应体（无条件的旧 sink）→ 0 命中
func TestP1041_FetchModels_NoResponseBodyInLog(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":[{"id":"model-a"}],"debug":"` + p1041RespCanary + `"}`))
	}))
	t.Cleanup(upstream.Close)

	buf := captureLog(t) // 无 DEBUG——旧实现该 sink 无条件输出

	p, err := BuildSingleProvider("openai", config.ProviderConfig{
		Type: "openai", BaseURL: upstream.URL + "/v1", APIKey: "sk-test", TimeoutSeconds: 5,
	})
	if err != nil {
		t.Fatal(err)
	}
	models, err := p.FetchModels()
	if err != nil || len(models) == 0 {
		t.Fatalf("[功能回归失败] FetchModels 应成功，实际 %v err=%v", models, err)
	}
	if strings.Contains(buf.String(), p1041RespCanary) {
		t.Fatalf("[安全回归失败] FetchModels log 回显响应体: %q", buf.String())
	}
	t.Log("[SEC-003 FIXED] FetchModels：响应体不再进 log")
}

// vllm ListModels 响应体（无条件的旧 sink）→ 0 命中
func TestP1041_VLLM_NoResponseBodyInLog(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":[{"id":"model-a"}],"debug":"` + p1041RespCanary + `"}`))
	}))
	t.Cleanup(upstream.Close)

	buf := captureLog(t)

	p, err := BuildSingleProvider("vllm", config.ProviderConfig{
		Type: "vllm", BaseURL: upstream.URL, TimeoutSeconds: 5,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.FetchModels(); err != nil {
		t.Fatalf("[功能回归失败] FetchModels 应成功: %v", err)
	}
	if strings.Contains(buf.String(), p1041RespCanary) {
		t.Fatalf("[安全回归失败] vllm log 回显响应体: %q", buf.String())
	}
	t.Log("[SEC-003 FIXED] vllm：响应体不再进 log")
}

// 静态 tripwire：生产源码（排除 _test.go）不得存在 body/respBody 的日志 sink
func TestP1041_StaticTripwire_NoBodyLogSinks(t *testing.T) {
	dirs := []string{"providers", "services", "handlers"}
	for _, d := range dirs {
		matches, err := filepath.Glob("../internal/" + d + "/*.go")
		if err != nil {
			t.Fatal(err)
		}
		for _, f := range matches {
			if strings.HasSuffix(f, "_test.go") {
				continue
			}
			raw, err := os.ReadFile(f)
			if err != nil {
				t.Fatal(err)
			}
			for i, line := range strings.Split(string(raw), "\n") {
				isLog := strings.Contains(line, "log.Printf") || strings.Contains(line, "log.Println") || strings.Contains(line, "fmt.Printf")
				if !isLog {
					continue
				}
				if strings.Contains(line, "string(body)") || strings.Contains(line, "string(respBody)") ||
					strings.Contains(line, "string(u.Body)") {
					t.Fatalf("[安全回归失败] 生产日志 sink 回归 %s:%d: %s", f, i+1, strings.TrimSpace(line))
				}
			}
		}
	}
	t.Log("[SEC-003] 静态 tripwire：provider/service/handler 生产源码无 body 日志 sink")
}
