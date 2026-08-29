package handlers

import (
	"encoding/json"
	"strings"
	"testing"

	"ai-gateway/internal/config"
	"ai-gateway/internal/models"
	"ai-gateway/internal/providers"
)

func TestP106A_GHI_QuotaAndMaxTokenCurrentBehavior(t *testing.T) {
	proxy := &ProxyHandler{}
	client := &models.Client{
		QuotaRequestsDay:     0,
		QuotaInputTokensDay:  0,
		QuotaOutputTokensDay: 0,
		MaxInputTokens:       1,
		MaxOutputTokens:      3,
	}

	if err := proxy.enforceRequestLimits(client, []byte(strings.Repeat("x", 8))); err == nil {
		t.Fatal("[H] MaxInputTokens should reject an over-limit Gemini request")
	} else {
		apiErr, ok := err.(*APIError)
		if !ok || apiErr.Err.Code != "MAX_INPUT_TOKENS_EXCEEDED" {
			t.Fatalf("[H] unexpected MaxInput error: %T %v", err, err)
		}
	}

	quotaClient := *client
	quotaClient.MaxInputTokens = 0
	if err := proxy.enforceRequestLimits(&quotaClient, []byte(`{"contents":[]}`)); err != nil {
		t.Fatalf("[G/H/I] daily quota fields must not affect current Gemini preflight: %v", err)
	}

	var geminiBody map[string]interface{}
	input := []byte(`{"generationConfig":{"maxOutputTokens":99}}`)
	capped := proxy.capOutputTokens(client, input)
	if err := json.Unmarshal(capped, &geminiBody); err != nil {
		t.Fatal(err)
	}
	configMap := geminiBody["generationConfig"].(map[string]interface{})
	if got := int(configMap["maxOutputTokens"].(float64)); got != client.MaxOutputTokens {
		t.Fatalf("[I CURRENT] Gemini output cap should rewrite to %d, got %d", client.MaxOutputTokens, got)
	}

	openai := &OpenAIHandler{}
	provider := providers.NewOpenAIProvider("p106a", config.ProviderConfig{DefaultModel: "p106a-model"})
	openAIReq := OpenAIChatRequest{
		Model: "p106a-model", Messages: []map[string]interface{}{{"role": "user", "content": "hello"}}, MaxTokens: 99,
	}
	built := openai.buildChatRequest(openAIReq, provider, client)
	if built.MaxTokens != 99 {
		t.Fatalf("[I] unexpected OpenAI max_tokens behavior: got %d", built.MaxTokens)
	}
	t.Logf("[G/H/I CURRENT] daily quotas do not gate requests; Gemini MaxInput rejects via len/4 heuristic, Gemini MaxOutput caps, OpenAI max_tokens passes through (%d)", built.MaxTokens)
}
