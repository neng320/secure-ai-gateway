package main

// P1-04D · 启动 preflight Gate（SEC-003）
//
// legacy 正文残留（request_body/error_message 非空）→ 正常启动拒绝，
// 错误含稳定哨兵 REQUEST_LOG_PRIVACY_MIGRATION_REQUIRED 且只报告行数。

import (
	"path/filepath"
	"strings"
	"testing"

	"ai-gateway/internal/models"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func TestPreflightGate_LegacyPromptContent_Refused(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(filepath.Join(t.TempDir(), "legacy.db")), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.AutoMigrate(&models.RequestLog{}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if sqlDB, e := db.DB(); e == nil {
			_ = sqlDB.Close()
		}
	})
	if err := db.Create(&models.RequestLog{
		ClientID:    "c1",
		Model:       "m",
		RequestBody: "P104_PREFLIGHT_CANARY_LEGACY_PROMPT",
	}).Error; err != nil {
		t.Fatal(err)
	}

	err = ensureRequestLogPrivacyRunnable(db)
	if err == nil {
		t.Fatal("[安全回归失败] legacy 正文残留未被拒绝启动")
	}
	if !strings.Contains(err.Error(), "REQUEST_LOG_PRIVACY_MIGRATION_REQUIRED") {
		t.Fatalf("错误应含稳定哨兵，实际 %v", err)
	}
	// 只报告行数，不输出正文
	if strings.Contains(err.Error(), "P104_PREFLIGHT_CANARY_LEGACY_PROMPT") {
		t.Fatal("[安全回归失败] preflight 错误信息泄露正文 canary")
	}
	if !strings.Contains(err.Error(), "1 request_logs rows") {
		t.Fatalf("错误应含行数，实际 %v", err)
	}
}

func TestPreflightGate_FreshDB_Passes(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(filepath.Join(t.TempDir(), "fresh.db")), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.AutoMigrate(&models.RequestLog{}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if sqlDB, e := db.DB(); e == nil {
			_ = sqlDB.Close()
		}
	})
	if err := ensureRequestLogPrivacyRunnable(db); err != nil {
		t.Fatalf("[安全回归失败] 全新 DB 应通过 preflight，实际 %v", err)
	}
}

func TestPreflightGate_CleanMetadataRows_Pass(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(filepath.Join(t.TempDir(), "clean.db")), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.AutoMigrate(&models.RequestLog{}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if sqlDB, e := db.DB(); e == nil {
			_ = sqlDB.Close()
		}
	})
	// metadata-only 行（正文/错误为空）应通过
	if err := db.Create(&models.RequestLog{ClientID: "c1", Model: "m", StatusCode: 200}).Error; err != nil {
		t.Fatal(err)
	}
	if err := ensureRequestLogPrivacyRunnable(db); err != nil {
		t.Fatalf("[安全回归失败] metadata-only 行应通过，实际 %v", err)
	}
}
