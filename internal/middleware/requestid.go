package middleware

// RequestID 中间件（SEC-003 / P1-04B）
//
// 为每个入站 LLM API 请求生成服务器侧 Request ID：
//   - crypto/rand，128-bit 随机 → 32 字符小写 hex
//   - 绝不信任客户端提供的 X-Request-ID（不读取、不透传）
//   - 同一 inbound request 全链一致：响应头 X-Request-ID == DB RequestLog.RequestID
//     == context 中的任何后续使用点
//   - 响应头在 handler 运行前设置，早期错误路径同样携带

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/http"
)

type requestIDKey struct{}

// RequestIDHeader: 对外暴露的响应头名（Go 规范化为 X-Request-ID）。
const RequestIDHeader = "X-Request-ID"

// RequestID: 中间件——生成并注入 request ID + 设置响应头。
func RequestID() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			id := NewRequestID()
			w.Header().Set(RequestIDHeader, id)
			next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), requestIDKey{}, id)))
		})
	}
}

// GetRequestID: 从请求上下文读取 request ID（未经中间件时返回 ""）。
func GetRequestID(r *http.Request) string {
	v, _ := r.Context().Value(requestIDKey{}).(string)
	return v
}

// NewRequestID: 128-bit crypto/rand → 32 hex 字符。
func NewRequestID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		// crypto/rand 失败极罕见（系统熵源故障）；fail-closed 返回空串，
		// 调用方（LogRequest/错误路径）按无 ID 处理，绝不回退到可预测值。
		return ""
	}
	return hex.EncodeToString(b)
}
