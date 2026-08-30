package main

import (
	"net/http"
	"strings"
	"testing"
)

func TestP107A_PublicRouteRegistrationCurrentMatrix(t *testing.T) {
	env := newTestGateway(t, false, false)
	cases := []struct {
		method string
		path   string
		want   int
	}{
		{http.MethodGet, "/health", http.StatusOK},
		{http.MethodGet, "/health/ready", http.StatusOK},
		{http.MethodGet, "/health/live", http.StatusOK},
		{http.MethodPost, "/v1/chat/completions", http.StatusUnauthorized},
		{http.MethodPost, "/chat/completions", http.StatusUnauthorized},
		{http.MethodPost, "/v1/messages", http.StatusUnauthorized},
		{http.MethodPost, "/v1/messages/count_tokens", http.StatusUnauthorized},
		{http.MethodPost, "/v1/models/test-model:generateContent", http.StatusUnauthorized},
		{http.MethodPost, "/v1beta/models/test-model:generateContent", http.StatusUnauthorized},
		{http.MethodPost, "/v1/models/test-model:streamGenerateContent", http.StatusUnauthorized},
		{http.MethodPost, "/v1beta/models/test-model:streamGenerateContent", http.StatusUnauthorized},
		{http.MethodGet, "/v1/models", http.StatusUnauthorized},
		{http.MethodGet, "/v1/models/test-model", http.StatusUnauthorized},
		{http.MethodGet, "/v1beta/models", http.StatusUnauthorized},
		{http.MethodGet, "/v1beta/models/test-model", http.StatusUnauthorized},
	}
	for _, tc := range cases {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			req, err := http.NewRequest(tc.method, env.api.URL+tc.path, strings.NewReader(`{}`))
			if err != nil {
				t.Fatal(err)
			}
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
			if resp.StatusCode != tc.want {
				t.Fatalf("[CURRENT] route registration %s %s: got %d want %d", tc.method, tc.path, resp.StatusCode, tc.want)
			}
		})
	}
}

func TestP107B_PublicOversizedGenerativeBodyStable413(t *testing.T) {
	env := newTestGateway(t, false, false)
	_, apiKey, err := env.deps.clientService.CreateClient("p107a-body-limit", "", "gemini", "sk-", env.cfg, "test-admin")
	if err != nil {
		t.Fatal(err)
	}
	body := strings.Repeat("A", (10<<20)+1)
	req, err := http.NewRequest(http.MethodPost, env.api.URL+"/v1/chat/completions", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+apiKey)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusUnauthorized {
		env.lastSeen.waitForCompletion(t)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("[FIXED] oversized public generative body status=%d, want 413", resp.StatusCode)
	}
	t.Log("[FIXED] public generative MaxBytesError is caught by request validation as stable 413 REQUEST_TOO_LARGE")
}
