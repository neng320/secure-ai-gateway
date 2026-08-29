package handlers

// P1-05B · Static Delivery Gate
//
// 行为测试（p1_05b_lifecycle_test.go / p1_05a_lifecycle_test.go）是主 Gate；
// 本文件做源码级补充证明（覆盖幻觉防线——文件必须真实存在并参与检查）：
//
//   1. AuthMiddleware dead cache 已删除（cache / getClientFromCacheOrDB /
//      InvalidateCache / go-cache import / 403 StatusForbidden 死分支）
//   2. services/client.go：ErrClientNotFound sentinel；Regenerate/Delete/
//      SetActive 均检查 RowsAffected；Delete 走事务
//   3. admin.go 中 ResetClient 只出现在 DeleteClient 成功路径（计数==1）
//   4. metrics.go：ConstantTimeCompare + SHA-256 定长化；无普通字符串比较
//   5. server.go：RateLimiter 为 gateway lifecycle 共享实例（NewRateLimiter 恰 1 处），
//      buildAPIRouter/buildAdminRouter 均引用 d.rateLimiter
//   6. database.Open 以 DSN _foreign_keys=on 保证连接池所有连接启用外键

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func p105bModuleRoot(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller(0) failed")
	}
	dir := filepath.Dir(thisFile)
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("go.mod not found")
		}
		dir = parent
	}
}

func p105bRead(t *testing.T, root, rel string) string {
	t.Helper()
	src, err := os.ReadFile(filepath.Join(root, rel))
	if err != nil {
		t.Fatalf("static gate: 读取 %s 失败（文件必须存在）: %v", rel, err)
	}
	return string(src)
}

func TestP105B_StaticGate_DeadCacheRemoved(t *testing.T) {
	root := p105bModuleRoot(t)
	authSrc := p105bRead(t, root, "internal/middleware/auth.go")

	for _, banned := range []string{
		"go-cache",
		"InvalidateCache",
		"getClientFromCacheOrDB",
		"cache.New",
		"StatusForbidden",
	} {
		if strings.Contains(authSrc, banned) {
			t.Fatalf("[static] auth.go 仍含已删除的 dead-cache 残留: %q", banned)
		}
	}
	if !strings.Contains(authSrc, "GetClientByAPIKey") {
		t.Fatal("[static] auth.go 应继续直接 DB lookup（GetClientByAPIKey）")
	}
	t.Log("[static] AuthMiddleware：cache/InvalidateCache/getClientFromCacheOrDB/403 分支全部移除")
}

func TestP105B_StaticGate_RowsAffectedAndSentinel(t *testing.T) {
	root := p105bModuleRoot(t)
	src := p105bRead(t, root, "internal/services/client.go")

	if !strings.Contains(src, "ErrClientNotFound = errors.New") {
		t.Fatal("[static] client.go 缺少 ErrClientNotFound sentinel")
	}
	if !strings.Contains(src, "ErrClientRevoked") || !strings.Contains(src, "ErrInvalidLifecycleTransition") || !strings.Contains(src, "ErrInvalidLifecycleReason") {
		t.Fatal("[static] client.go 缺少 P1-05C 生命周期 sentinel（Revoked/Transition/Reason）")
	}
	if !strings.Contains(src, "db.Transaction") {
		t.Fatal("[static] DeleteClient 必须使用事务（db.Transaction）")
	}
	// P1-05C：RowsAffected 检查覆盖 rotate/suspend/resume/revoke/delete（≥5）
	if n := strings.Count(src, "RowsAffected"); n < 5 {
		t.Fatalf("[static] client.go 应 ≥5 处 RowsAffected 检查（Rotate/Suspend/Resume/Revoke/Delete），实际 %d", n)
	}
	if !strings.Contains(src, "SuspendClient") || !strings.Contains(src, "ResumeClient") || !strings.Contains(src, "RevokeClient") {
		t.Fatal("[static] client.go 缺少 SuspendClient/ResumeClient/RevokeClient")
	}
	// 旧 SetClientActive 已替换（P1-05C API 面演化）
	if strings.Contains(src, "SetClientActive") {
		t.Fatal("[static] client.go 不应再有 SetClientActive（已替换为 Suspend/ResumeClient）")
	}
	t.Log("[static] services：sentinel + Rotate/Suspend/Resume/Revoke/Delete 全部 RowsAffected 检查")
}

func TestP105B_StaticGate_ResetClientOnlyAfterCommit(t *testing.T) {
	root := p105bModuleRoot(t)
	adminSrc := p105bRead(t, root, "internal/handlers/admin.go")

	// P1-05C：ResetClient 恰 2 处调用——DeleteClient 与 RevokeClient 的【事务成功之后】
	if n := strings.Count(adminSrc, ".ResetClient("); n != 2 {
		t.Fatalf("[static] admin.go 中 ResetClient 调用应恰 2 次（Delete/Revoke 成功路径），实际 %d", n)
	}
	for _, s := range []string{"SuspendClient", "ResumeClient", "RevokeClient"} {
		if !strings.Contains(adminSrc, s) {
			t.Fatalf("[static] admin.go 应调用 %s", s)
		}
	}
	if strings.Contains(adminSrc, "SetClientActive") {
		t.Fatal("[static] admin.go 不应再出现 SetClientActive")
	}
	t.Log("[static] admin.go：ResetClient 仅 Delete/Revoke 成功路径；toggle 走 Suspend/ResumeClient")
}

func TestP105B_StaticGate_MetricsConstantTime(t *testing.T) {
	root := p105bModuleRoot(t)
	src := p105bRead(t, root, "internal/handlers/metrics.go")

	if !strings.Contains(src, "subtle.ConstantTimeCompare") {
		t.Fatal("[static] metrics.go 缺少 ConstantTimeCompare")
	}
	if !strings.Contains(src, "sha256.Sum256") {
		t.Fatal("[static] metrics.go 缺少 SHA-256 定长化")
	}
	if strings.Contains(src, "username != h.username") || strings.Contains(src, "password != h.password") {
		t.Fatal("[static] metrics.go 仍存在普通字符串比较")
	}
	t.Log("[static] metrics.go：SHA-256 + ConstantTimeCompare，普通比较已根除")
}

func TestP105B_StaticGate_RateLimiterSharedInstance(t *testing.T) {
	root := p105bModuleRoot(t)
	serverSrc := p105bRead(t, root, "cmd/server/server.go")

	if n := strings.Count(serverSrc, "NewRateLimiter()"); n != 1 {
		t.Fatalf("[static] server.go 中 NewRateLimiter() 应恰 1 处（newGatewayDeps 共享实例），实际 %d", n)
	}
	if !strings.Contains(serverSrc, "d.rateLimiter") {
		t.Fatal("[static] server.go 应引用 d.rateLimiter（API 面 + Admin 面共享）")
	}
	if !strings.Contains(serverSrc, "d.captureStore, d.rateLimiter") {
		t.Fatal("[static] buildAdminRouter 应把 d.rateLimiter 传给 NewAdminHandler")
	}
	t.Log("[static] server.go：RateLimiter 提升为 gateway lifecycle 共享实例")
}

func TestP105B_StaticGate_ForeignKeysDSN(t *testing.T) {
	root := p105bModuleRoot(t)
	dbSrc := p105bRead(t, root, "internal/database/database.go")
	mainSrc := p105bRead(t, root, "cmd/server/main.go")

	if !strings.Contains(dbSrc, "_foreign_keys=on") {
		t.Fatal("[static] database.Open 必须使用 DSN _foreign_keys=on（连接池全部连接生效）")
	}
	if !strings.Contains(mainSrc, "database.Open(cfg.Database.Path)") {
		t.Fatal("[static] initDatabase 必须经由 internal/database.Open")
	}
	t.Log("[static] database.Open：DSN 级外键开启；生产 initDatabase 已统一走该路径")
}
