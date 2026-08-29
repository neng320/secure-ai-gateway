package services

// P1-04B · Dashboard WS 负载隐私回归（SEC-003）
//
// 反转自 P1-04A 固化的现状（WS 曾广播 request_body presence bool）：
// 现在 WS 负载必须为纯 metadata——无 request_body 键、无 error_message 键、
// 无正文/错误文本内容；即便 legacy RequestLog 行携带存量数据。

import (
	"encoding/json"
	"strings"
	"testing"

	"ai-gateway/internal/models"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

const p104WSCanary = "P104_CANARY_WS_BROADCAST_CHECK"

func TestP104B_WSPayload_MetadataOnly_NoBody(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(t.TempDir()+"/ws.db"), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.AutoMigrate(&models.Client{}, &models.RequestLog{}, &models.DailyUsage{}, &models.AdminSession{}, &models.AuditEvent{}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if sqlDB, e := db.DB(); e == nil {
			_ = sqlDB.Close()
		}
	})

	// 模拟 legacy 存量行（含正文/错误文本）：WS 仍不得泄露
	if err := db.Create(&models.RequestLog{
		ClientID:     "ws-client",
		Model:        "test-model",
		StatusCode:   200,
		RequestID:    "reqws12345678901234567890123456",
		Provider:     "openai",
		RequestBody:  p104WSCanary,
		ErrorMessage: p104WSCanary,
	}).Error; err != nil {
		t.Fatal(err)
	}

	hub := NewDashboardHub(NewStatsService(db))
	payload := hub.buildPayload()
	if payload == nil {
		t.Fatal("buildPayload 返回 nil")
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal(payload, &parsed); err != nil {
		t.Fatalf("WS 负载非法 JSON: %v", err)
	}
	raw := string(payload)

	if strings.Contains(raw, p104WSCanary) {
		t.Fatal("[安全回归失败] WS 负载泄露 legacy 正文/错误文本")
	}
	for _, banned := range []string{"request_body", "error_message"} {
		if strings.Contains(raw, `"`+banned+`"`) {
			t.Fatalf("[安全回归失败] WS 负载含 %q 键", banned)
		}
	}
	for _, want := range []string{`"request_id"`, `"provider"`, `"error_code"`} {
		if !strings.Contains(raw, want) {
			t.Fatalf("[安全回归失败] WS 负载缺 %s", want)
		}
	}
}
