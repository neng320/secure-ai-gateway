package middleware

// P1-04.3 · Auth Credential Log Canary Gate（SEC-003）
//
// 反转自复验发现的真实 runtime sink：internal/middleware/auth.go 曾输出
//   - malformed Authorization 的前 20 字符（短 token 可能整段）
//   - Bearer API key 的前 8 字符（认证尝试与失败路径各一处）
// 修复后：任何认证成功/失败路径都不得输出 Authorization 值、Bearer token、
// API key 或其任何前缀片段。
//
// Canary：P1043_CLIENT_API_KEY_CANARY_* / P1043_MALFORMED_AUTH_CANARY_*（明显标记串）。

import (
	"crypto/sha256"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"ai-gateway/internal/models"
	"ai-gateway/internal/services"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

const (
	p1043KeyCanary      = "P1043_CLIENT_API_KEY_CANARY_PAYLOAD"
	p1043MalformedCanay = "P1043_MALFORMED_AUTH_CANARY_PAYLOAD"
)

type authEnv struct {
	db         *gorm.DB
	handler    http.Handler
	clientSvc  *services.ClientService
	logBuf     strings.Builder
	prevWriter func()
}

func newAuthCanaryEnv(t *testing.T) *authEnv {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(t.TempDir()+"/auth.db"), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.AutoMigrate(&models.Client{}, &models.RequestLog{}, &models.DailyUsage{}, &models.AdminSession{}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if sqlDB, e := db.DB(); e == nil {
			_ = sqlDB.Close()
		}
	})

	clientSvc := services.NewClientService(db)
	mw := NewAuthMiddleware(clientSvc)
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	env := &authEnv{db: db, handler: mw.Handler(next), clientSvc: clientSvc}
	env.prevWriter = func() { log.SetOutput(os.Stderr) }
	log.SetOutput(&env.logBuf)
	t.Cleanup(env.prevWriter)
	return env
}

// insertClientWithKey: 直接以指定 key 的哈希入库（控制 key 值为 canary）
func (e *authEnv) insertClientWithKey(t *testing.T, name, key string) {
	t.Helper()
	sum := sha256.Sum256([]byte(key))
	c := &models.Client{
		ID:         name + "-id",
		Name:       name,
		APIKeyHash: sum[:],
		IsActive:   true,
	}
	if err := e.db.Create(c).Error; err != nil {
		t.Fatal(err)
	}
}

func (e *authEnv) doAuth(t *testing.T, authHeader string) *http.Response {
	t.Helper()
	req := httptest.NewRequest("POST", "/v1/chat/completions", nil)
	if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
	}
	w := httptest.NewRecorder()
	e.handler.ServeHTTP(w, req)
	return w.Result()
}

func (e *authEnv) assertNoCredential(t *testing.T, secrets ...string) {
	t.Helper()
	logs := e.logBuf.String()
	for _, s := range secrets {
		if strings.Contains(logs, s) {
			t.Fatalf("[安全回归失败] runtime log 含凭证材料 %q: %q", s, logs)
		}
	}
}

// A. 合法 Bearer Key → 认证成功，log 不含完整 key / 前 8 字符
func TestP1043_ValidBearer_Success_NoKeyInLog(t *testing.T) {
	env := newAuthCanaryEnv(t)
	env.insertClientWithKey(t, "kf-valid", p1043KeyCanary)

	resp := env.doAuth(t, "Bearer "+p1043KeyCanary)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("[功能回归失败] 合法 key 应认证成功，实际 %d", resp.StatusCode)
	}
	if !strings.Contains(env.logBuf.String(), "authenticated client_id=") {
		t.Fatalf("[安全回归失败] 成功路径应输出 client_id metadata，实际 %q", env.logBuf.String())
	}
	env.assertNoCredential(t, p1043KeyCanary, p1043KeyCanary[:8], p1043KeyCanary[:20])
	t.Log("[SEC-003 FIXED] 合法 Bearer：认证成功且无 key 材料")
}

// B. 无效 Bearer Key → 401，log 不含 key / 前缀
func TestP1043_InvalidBearer_NoKeyInLog(t *testing.T) {
	env := newAuthCanaryEnv(t)
	env.insertClientWithKey(t, "kf-invalid", p1043KeyCanary)

	wrong := p1043KeyCanary + "-WRONG"
	resp := env.doAuth(t, "Bearer "+wrong)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("无效 key 应 401，实际 %d", resp.StatusCode)
	}
	if !strings.Contains(env.logBuf.String(), "invalid api key") {
		t.Fatalf("[安全回归失败] 失败路径应输出 bounded metadata，实际 %q", env.logBuf.String())
	}
	env.assertNoCredential(t, wrong, wrong[:8], p1043KeyCanary, p1043KeyCanary[:8])
	t.Log("[SEC-003 FIXED] 无效 Bearer：401 且无 key 材料")
}

// C. malformed（非 Bearer scheme）→ 401，log 不含 header 内容 / canary / 前 20 字符
func TestP1043_MalformedAuth_NoHeaderContentInLog(t *testing.T) {
	env := newAuthCanaryEnv(t)

	resp := env.doAuth(t, "Token "+p1043MalformedCanay)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("malformed 应 401，实际 %d", resp.StatusCode)
	}
	if !strings.Contains(env.logBuf.String(), "invalid authorization format") {
		t.Fatalf("[安全回归失败] 应输出 bounded metadata，实际 %q", env.logBuf.String())
	}
	env.assertNoCredential(t,
		p1043MalformedCanay,
		p1043MalformedCanay[:20],
		"Token "+p1043MalformedCanay,
	)
	t.Log("[SEC-003 FIXED] malformed Authorization：header 内容不进 log")
}

// D. 短 malformed secret（长度 <20）→ 旧实现会整段输出，现在必须 0 泄漏
func TestP1043_ShortMalformed_ZeroLeak(t *testing.T) {
	env := newAuthCanaryEnv(t)

	resp := env.doAuth(t, "Zq7")
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("短 malformed 应 401，实际 %d", resp.StatusCode)
	}
	if strings.Contains(env.logBuf.String(), "Zq7") {
		t.Fatalf("[安全回归失败] 短 token 整段进 log: %q", env.logBuf.String())
	}
	t.Log("[SEC-003 FIXED] 短 malformed secret：零泄漏（旧实现会整段输出）")
}

// 缺失 Authorization → 只允许 method/path metadata
func TestP1043_MissingHeader_MetadataOnly(t *testing.T) {
	env := newAuthCanaryEnv(t)

	resp := env.doAuth(t, "")
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("缺失 header 应 401，实际 %d", resp.StatusCode)
	}
	logs := env.logBuf.String()
	if !strings.Contains(logs, "Missing Authorization header") {
		t.Fatalf("[安全回归失败] 应输出 missing metadata，实际 %q", logs)
	}
	if strings.Contains(logs, "Authorization:") || strings.Contains(logs, "Bearer") {
		t.Fatalf("[安全回归失败] missing 路径泄漏 header 形态: %q", logs)
	}
	t.Log("[SEC-003 FIXED] 缺失 Authorization：仅 metadata")
}
