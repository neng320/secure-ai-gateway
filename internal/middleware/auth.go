package middleware

import (
	"context"
	"log"
	"net/http"
	"strings"

	"ai-gateway/internal/models"
	"ai-gateway/internal/services"
)

// P1-05B：AuthMiddleware 的认证缓存机制（缓存字段、失效入口、缓存查询辅助）
// 已整体移除——认证始终直接 DB lookup，rotate/delete/suspend 之后
// 下一请求零 sleep 即反映。

type AuthMiddleware struct {
	clientService *services.ClientService
}

func NewAuthMiddleware(clientService *services.ClientService) *AuthMiddleware {
	return &AuthMiddleware{clientService: clientService}
}

func (m *AuthMiddleware) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			log.Printf("[AUTH] Missing Authorization header for %s %s", r.Method, r.URL.Path)
			http.Error(w, `{"error": "Missing Authorization header"}`, http.StatusUnauthorized)
			return
		}

		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
			// P1-04.3：Authorization 内容（哪怕前 20 字符，短 token 可能整段）是凭证材料——绝不入日志
			log.Printf("[AUTH] invalid authorization format for %s %s", r.Method, r.URL.Path)
			http.Error(w, `{"error": "Invalid Authorization header format"}`, http.StatusUnauthorized)
			return
		}

		apiKey := parts[1]
		// P1-04.3：key 前缀也是凭证——认证尝试只记录 method/path
		log.Printf("[AUTH] authentication attempt for %s %s", r.Method, r.URL.Path)

		client, err := m.clientService.GetClientByAPIKey(apiKey)
		if err != nil {
			log.Printf("[AUTH] Error looking up client: %v", err)
			http.Error(w, `{"error": "Internal server error"}`, http.StatusInternalServerError)
			return
		}

		// P1-05B：SUSPENDED / ROTATED-old / DELETED / random invalid 统一 401 Invalid API key。
		// GetClientByAPIKey 已过滤 is_active=true（查不到即视为不存在），
		// 不提供“这个 key 存在但被 suspend”的 credential-validity oracle。
		// 旧 403 "Client is disabled" 不可达死分支已删除——401 是 deliberate contract。
		if client == nil {
			log.Printf("[AUTH] invalid api key for %s %s", r.Method, r.URL.Path)
			http.Error(w, `{"error": "Invalid API key"}`, http.StatusUnauthorized)
			return
		}

		// Update LastSeen in the background (don't wait)
		go m.clientService.UpdateLastSeen(client.ID)

		log.Printf("[AUTH] authenticated client_id=%s for %s %s", client.ID, r.Method, r.URL.Path)
		ctx := context.WithValue(r.Context(), ClientContextKey, client)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

type contextKey string

const ClientContextKey contextKey = "client"

func GetClientFromContext(ctx context.Context) *models.Client {
	if client, ok := ctx.Value(ClientContextKey).(*models.Client); ok {
		return client
	}
	return nil
}
