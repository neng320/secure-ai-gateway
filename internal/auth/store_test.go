package auth

// P1-01B · Session Store 单元测试
// 覆盖：正常创建 / 查询 / 不存在 / 过期 / 吊销 / 重复冲突 / 持久化（跨"重启"）

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"ai-gateway/internal/models"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// newTestStore 返回基于临时文件的 Store，并注册关闭清理（Windows 文件锁）
func newTestStore(t *testing.T) (*SQLiteStore, string) {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "sessions.db")
	db, err := gorm.Open(sqlite.Open(dbPath), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.AutoMigrate(&models.AdminSession{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	t.Cleanup(func() {
		if sqlDB, err := db.DB(); err == nil {
			_ = sqlDB.Close()
		}
	})
	return NewSQLiteStore(db), dbPath
}

func reopenStore(t *testing.T, dbPath string) *SQLiteStore {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(dbPath), &gorm.Config{})
	if err != nil {
		t.Fatalf("reopen sqlite: %v", err)
	}
	t.Cleanup(func() {
		if sqlDB, err := db.DB(); err == nil {
			_ = sqlDB.Close()
		}
	})
	return NewSQLiteStore(db)
}

func TestStore_Create_Returns64HexToken(t *testing.T) {
	s, _ := newTestStore(t)
	token, err := s.Create(context.Background(), "admin", time.Now().Add(time.Hour))
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if len(token) != 64 {
		t.Fatalf("token 应为 64 字符 hex（256-bit），实际 %d", len(token))
	}
	if token != strings.ToLower(token) || strings.ContainsAny(token, "ghijklmnopqrstuvwxyz") {
		t.Fatalf("token 应为小写 hex: %q", token)
	}
}

func TestStore_Create_RawTokenNeverStoredInDB(t *testing.T) {
	s, dbPath := newTestStore(t)
	token, err := s.Create(context.Background(), "admin", time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	db, err := gorm.Open(sqlite.Open(dbPath), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if sqlDB, e := db.DB(); e == nil {
			_ = sqlDB.Close()
		}
	}()
	var rows []models.AdminSession
	if err := db.Find(&rows).Error; err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("期望 1 行会话，实际 %d", len(rows))
	}
	if string(rows[0].TokenHash) != string(HashToken(token)) {
		t.Fatal("库中 hash 与 HashToken(token) 不一致")
	}
	if strings.Contains(string(rows[0].TokenHash), token) {
		t.Fatal("原始 token 泄漏进了库")
	}
}

func TestStore_Create_TwoSessions_DifferentTokens(t *testing.T) {
	s, _ := newTestStore(t)
	t1, _ := s.Create(context.Background(), "admin", time.Now().Add(time.Hour))
	t2, _ := s.Create(context.Background(), "admin", time.Now().Add(time.Hour))
	if t1 == t2 {
		t.Fatal("同一用户两次登录必须得到不同 token")
	}
}

func TestStore_Validate_Roundtrip(t *testing.T) {
	s, _ := newTestStore(t)
	token, _ := s.Create(context.Background(), "admin", time.Now().Add(time.Hour))
	user, err := s.Validate(context.Background(), token)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if user != "admin" {
		t.Fatalf("用户名不符: %q", user)
	}
}

func TestStore_Validate_UnknownToken_NotFound(t *testing.T) {
	s, _ := newTestStore(t)
	random := strings.Repeat("ab", 32)
	if _, err := s.Validate(context.Background(), random); err != ErrSessionNotFound {
		t.Fatalf("期望 ErrSessionNotFound，实际 %v", err)
	}
}

func TestStore_Validate_EmptyToken_NotFound(t *testing.T) {
	s, _ := newTestStore(t)
	if _, err := s.Validate(context.Background(), ""); err != ErrSessionNotFound {
		t.Fatalf("期望 ErrSessionNotFound，实际 %v", err)
	}
}

func TestStore_Validate_Expired_Fails(t *testing.T) {
	s, _ := newTestStore(t)
	token, err := s.Create(context.Background(), "admin", time.Now().Add(-time.Minute)) // 已过期
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Validate(context.Background(), token); err != ErrSessionExpired {
		t.Fatalf("期望 ErrSessionExpired，实际 %v", err)
	}
}

func TestStore_Revoke_ThenValidate_FailsRevoked(t *testing.T) {
	s, _ := newTestStore(t)
	token, _ := s.Create(context.Background(), "admin", time.Now().Add(time.Hour))
	if err := s.Revoke(context.Background(), token); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if _, err := s.Validate(context.Background(), token); err != ErrSessionRevoked {
		t.Fatalf("期望 ErrSessionRevoked，实际 %v", err)
	}
}

func TestStore_Revoke_Twice_SecondReturnsNotFound(t *testing.T) {
	s, _ := newTestStore(t)
	token, _ := s.Create(context.Background(), "admin", time.Now().Add(time.Hour))
	if err := s.Revoke(context.Background(), token); err != nil {
		t.Fatal(err)
	}
	if err := s.Revoke(context.Background(), token); err != ErrSessionNotFound {
		t.Fatalf("二次吊销期望 ErrSessionNotFound，实际 %v", err)
	}
}

func TestStore_Revoke_UnknownToken_NotFound(t *testing.T) {
	s, _ := newTestStore(t)
	if err := s.Revoke(context.Background(), strings.Repeat("cd", 32)); err != ErrSessionNotFound {
		t.Fatalf("期望 ErrSessionNotFound，实际 %v", err)
	}
}

func TestStore_UniqueIndex_PreventsDuplicateTokenHash(t *testing.T) {
	s, dbPath := newTestStore(t)
	token, _ := s.Create(context.Background(), "admin", time.Now().Add(time.Hour))
	db, err := gorm.Open(sqlite.Open(dbPath), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if sqlDB, e := db.DB(); e == nil {
			_ = sqlDB.Close()
		}
	}()
	dup := models.AdminSession{
		Username:  "admin",
		TokenHash: HashToken(token), // 与已有会话同 hash
		CreatedAt: time.Now().UTC(),
		ExpiresAt: time.Now().Add(time.Hour).UTC(),
	}
	if err := db.Create(&dup).Error; err == nil {
		t.Fatal("token_hash 有唯一索引，重复插入应当失败")
	}
}

func TestStore_PersistenceAcrossRestart(t *testing.T) {
	s, dbPath := newTestStore(t)
	ctx := context.Background()
	token, _ := s.Create(ctx, "admin", time.Now().Add(time.Hour))

	reopened := reopenStore(t, dbPath)
	if user, err := reopened.Validate(ctx, token); err != nil || user != "admin" {
		t.Fatalf("重启后有效会话应仍可校验，实际 err=%v user=%q", err, user)
	}

	if err := reopened.Revoke(ctx, token); err != nil {
		t.Fatal(err)
	}
	reopened2 := reopenStore(t, dbPath)
	if _, err := reopened2.Validate(ctx, token); err != ErrSessionRevoked {
		t.Fatalf("重启后吊销状态应保持，实际 %v", err)
	}
}
