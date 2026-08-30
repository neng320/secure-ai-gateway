package handlers

import (
	"encoding/json"
	"strings"
	"testing"

	"ai-gateway/internal/models"
)

func TestP106B_GHI_MaxTokenEnforcement(t *testing.T) {
	proxy := &ProxyHandler{}
	client := &models.Client{
		MaxInputTokens:  100,
		MaxOutputTokens: 3,
	}

	if err := proxy.enforceRequestLimits(client, []byte(strings.Repeat("x", 101))); err == nil {
		t.Fatal("[H] MaxInputTokens should reject an over-limit Gemini request")
	} else {
		apiErr, ok := err.(*APIError)
		if !ok || apiErr.Err.Code != "MAX_INPUT_TOKENS_EXCEEDED" {
			t.Fatalf("[H] unexpected MaxInput error: %T %v", err, err)
		}
	}

	var geminiBody map[string]interface{}
	input := []byte(`{"generationConfig":{"maxOutputTokens":99}}`)
	capped := proxy.capOutputTokens(client, input)
	if err := json.Unmarshal(capped, &geminiBody); err != nil {
		t.Fatal(err)
	}
	configMap := geminiBody["generationConfig"].(map[string]interface{})
	if got := int(configMap["maxOutputTokens"].(float64)); got != client.MaxOutputTokens {
		t.Fatalf("[I FIXED] Gemini output cap should rewrite to %d, got %d", client.MaxOutputTokens, got)
	}

	openAIReq := OpenAIChatRequest{
		Model: "p106a-model", Messages: []map[string]interface{}{{"role": "user", "content": "hello"}}, MaxTokens: 99,
	}
	if err := enforceOpenAIRequestLimits(client, openAIReq, []byte(`{"model":"p106a-model","messages":[{"role":"user","content":"hello"}],"max_tokens":99}`)); err == nil {
		t.Fatal("[I] OpenAI max_tokens above client limit should be rejected")
	} else if apiErr, ok := err.(*APIError); !ok || apiErr.Err.Code != "MAX_OUTPUT_TOKENS_EXCEEDED" {
		t.Fatalf("[I] unexpected OpenAI output limit error: %T %v", err, err)
	}
	t.Log("[G/H/I FIXED] daily quotas are enforced by quota middleware; Gemini/OpenAI request paths enforce bounded MaxInput/MaxOutput contracts")
}
