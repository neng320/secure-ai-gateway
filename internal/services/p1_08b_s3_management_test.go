package services

import (
	"errors"
	"reflect"
	"strings"
	"testing"

	"ai-gateway/internal/audit"
	"ai-gateway/internal/config"
	"ai-gateway/internal/database"
	"ai-gateway/internal/models"

	"gorm.io/gorm"
)

func newP108BS3Env(t *testing.T) (*gorm.DB, *ClientService, *config.Config) {
	t.Helper()
	db, err := database.Open(t.TempDir() + "/s3.db")
	if err != nil {
		t.Fatal(err)
	}
	if err := db.AutoMigrate(&models.Client{}, &models.RequestLog{}, &models.DailyUsage{}, &models.AdminSession{}); err != nil {
		t.Fatal(err)
	}
	if err := audit.MigrateIntegrity(db); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if sqlDB, err := db.DB(); err == nil {
			_ = sqlDB.Close()
		}
	})
	cfg := &config.Config{
		Defaults: config.DefaultsConfig{
			RateLimit: config.RateLimitDefaults{RequestsPerMinute: 60, RequestsPerHour: 1000, RequestsPerDay: 10000},
			Quota:     config.QuotaDefaults{MaxInputTokensPerDay: 1000000, MaxOutputTokensPerDay: 500000, MaxRequestsPerDay: 1000, MaxInputTokens: 1000000, MaxOutputTokens: 8192},
		},
	}
	return db, NewClientService(db), cfg
}

func createP108BS3Client(t *testing.T, svc *ClientService, cfg *config.Config, name string) *models.Client {
	t.Helper()
	client, _, err := svc.CreateClient(name, "", "openai", "sk-", cfg, "creator-admin")
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func s3Actions(t *testing.T, db *gorm.DB, clientID string) []string {
	t.Helper()
	var events []models.AuditEvent
	if err := db.Where("target_type = ? AND target_id = ?", "client", clientID).Order("id ASC").Find(&events).Error; err != nil {
		t.Fatal(err)
	}
	actions := make([]string, len(events))
	for i, event := range events {
		actions[i] = event.Action
	}
	return actions
}

func s3Head(t *testing.T, db *gorm.DB) string {
	t.Helper()
	var state models.AuditChainState
	if err := db.First(&state, 1).Error; err != nil {
		t.Fatal(err)
	}
	return state.HeadHash
}

func s3EventCount(t *testing.T, db *gorm.DB) int64 {
	t.Helper()
	var count int64
	if err := db.Model(&models.AuditEvent{}).Count(&count).Error; err != nil {
		t.Fatal(err)
	}
	return count
}

func installS3AuditInsertFailure(t *testing.T, db *gorm.DB, action string) {
	t.Helper()
	statement := "CREATE TRIGGER s3_reject_audit_insert BEFORE INSERT ON audit_events WHEN NEW.action = '" + action + "' BEGIN SELECT RAISE(ABORT, 'TEST_AUDIT_INSERT_FAILED'); END"
	if err := db.Exec(statement).Error; err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Exec("DROP TRIGGER IF EXISTS s3_reject_audit_insert").Error })
}

func TestP108B_S3_NewActionsAreAllowlisted(t *testing.T) {
	for _, action := range []string{audit.ActionClientSettingsUpdated, audit.ActionClientProviderSecretChanged, audit.ActionClientModelsUpdated} {
		if !audit.IsKnownAction(action) {
			t.Fatalf("new action %q is not in the audit allowlist", action)
		}
	}
}

func TestP108B_S3_SettingsEventCategoriesAndOrder(t *testing.T) {
	db, svc, cfg := newP108BS3Env(t)
	client := createP108BS3Client(t, svc, cfg, "s3-categories")
	baseline := len(s3Actions(t, db, client.ID))

	if err := svc.UpdateClientSettings(client.ID, "trusted-session-admin", map[string]interface{}{"name": "general-updated"}); err != nil {
		t.Fatal(err)
	}
	if got := s3Actions(t, db, client.ID)[baseline:]; !reflect.DeepEqual(got, []string{audit.ActionClientSettingsUpdated}) {
		t.Fatalf("general update actions=%v", got)
	}
	baseline = len(s3Actions(t, db, client.ID))
	if err := svc.UpdateClientSettings(client.ID, "trusted-session-admin", map[string]interface{}{"backend_api_key_encrypted": "P108B-S3-PROVIDER-SECRET-CANARY"}); err != nil {
		t.Fatal(err)
	}
	if got := s3Actions(t, db, client.ID)[baseline:]; !reflect.DeepEqual(got, []string{audit.ActionClientProviderSecretChanged}) {
		t.Fatalf("secret update actions=%v", got)
	}
	baseline = len(s3Actions(t, db, client.ID))
	if err := svc.UpdateClientSettings(client.ID, "trusted-session-admin", map[string]interface{}{"backend_api_key_encrypted": ""}); err != nil {
		t.Fatal(err)
	}
	if got := s3Actions(t, db, client.ID)[baseline:]; !reflect.DeepEqual(got, []string{audit.ActionClientProviderSecretChanged}) {
		t.Fatalf("secret clear actions=%v", got)
	}
	baseline = len(s3Actions(t, db, client.ID))
	if err := svc.UpdateClientSettings(client.ID, "trusted-session-admin", map[string]interface{}{"backend_models": "[\"model-a\"]"}); err != nil {
		t.Fatal(err)
	}
	if got := s3Actions(t, db, client.ID)[baseline:]; !reflect.DeepEqual(got, []string{audit.ActionClientModelsUpdated}) {
		t.Fatalf("model update actions=%v", got)
	}
	baseline = len(s3Actions(t, db, client.ID))
	if err := svc.UpdateClientSettings(client.ID, "trusted-session-admin", map[string]interface{}{
		"name":                      "combined-updated",
		"backend_api_key_encrypted": "P108B-S3-PROVIDER-SECRET-CANARY-2",
		"backend_models":            "[\"model-b\"]",
	}); err != nil {
		t.Fatal(err)
	}
	want := []string{audit.ActionClientSettingsUpdated, audit.ActionClientProviderSecretChanged, audit.ActionClientModelsUpdated}
	if got := s3Actions(t, db, client.ID)[baseline:]; !reflect.DeepEqual(got, want) {
		t.Fatalf("combined update actions=%v want=%v", got, want)
	}
	var events []models.AuditEvent
	if err := db.Where("target_id = ?", client.ID).Order("id ASC").Find(&events).Error; err != nil {
		t.Fatal(err)
	}
	for _, event := range events {
		if strings.Contains(event.Action+event.ActorID+event.TargetID+event.Reason, "P108B-S3-PROVIDER-SECRET-CANARY") {
			t.Fatal("provider secret canary leaked into audit metadata")
		}
	}
}

func TestP108B_S3_CombinedAuditFailureRollsBackAllSettings(t *testing.T) {
	db, svc, cfg := newP108BS3Env(t)
	client := createP108BS3Client(t, svc, cfg, "s3-combined-rollback")
	before, err := svc.GetClientByID(client.ID)
	if err != nil || before == nil {
		t.Fatal("client missing before rollback test")
	}
	countBefore, headBefore := s3EventCount(t, db), s3Head(t, db)
	installS3AuditInsertFailure(t, db, audit.ActionClientProviderSecretChanged)
	err = svc.UpdateClientSettings(client.ID, "trusted-session-admin", map[string]interface{}{
		"name":                      "must-rollback",
		"backend_api_key_encrypted": "P108B-S3-PROVIDER-SECRET-CANARY",
		"backend_models":            "[\"must-rollback\"]",
	})
	if err == nil {
		t.Fatal("provider audit failure must fail combined settings update")
	}
	after, err := svc.GetClientByID(client.ID)
	if err != nil || after == nil {
		t.Fatal("client missing after rollback test")
	}
	if !reflect.DeepEqual(before, after) || s3EventCount(t, db) != countBefore || s3Head(t, db) != headBefore {
		t.Fatalf("combined settings audit failure leaked mutation: before=%+v after=%+v count=%d/%d head=%s/%s", before, after, s3EventCount(t, db), countBefore, s3Head(t, db), headBefore)
	}
}

func TestP108B_S3_ModelsAuditFailureRollsBack(t *testing.T) {
	db, svc, cfg := newP108BS3Env(t)
	client := createP108BS3Client(t, svc, cfg, "s3-model-rollback")
	if err := svc.UpdateClientModels(client.ID, "trusted-session-admin", "[\"before\"]"); err != nil {
		t.Fatal(err)
	}
	before, err := svc.GetClientByID(client.ID)
	if err != nil || before == nil {
		t.Fatal("client missing before model rollback test")
	}
	countBefore, headBefore := s3EventCount(t, db), s3Head(t, db)
	installS3AuditInsertFailure(t, db, audit.ActionClientModelsUpdated)
	if err := svc.UpdateClientModels(client.ID, "trusted-session-admin", "[\"after\"]"); err == nil {
		t.Fatal("model audit failure must fail model update")
	}
	after, err := svc.GetClientByID(client.ID)
	if err != nil || after == nil {
		t.Fatal("client missing after model rollback test")
	}
	if !reflect.DeepEqual(before, after) || s3EventCount(t, db) != countBefore || s3Head(t, db) != headBefore {
		t.Fatalf("model audit failure leaked mutation: before=%+v after=%+v", before, after)
	}
}

func TestP108B_S3_InvalidAndNotFoundProduceNoAudit(t *testing.T) {
	db, svc, cfg := newP108BS3Env(t)
	client := createP108BS3Client(t, svc, cfg, "s3-invalid")
	countBefore, headBefore := s3EventCount(t, db), s3Head(t, db)
	if err := svc.UpdateClientSettings(client.ID, "trusted-session-admin", map[string]interface{}{"is_active": true}); !errors.Is(err, ErrInvalidSettingsField) {
		t.Fatalf("invalid field error=%v", err)
	}
	if err := svc.UpdateClientSettings("missing-client", "trusted-session-admin", map[string]interface{}{"name": "nope"}); !errors.Is(err, ErrClientNotFound) {
		t.Fatalf("missing settings error=%v", err)
	}
	if err := svc.UpdateClientModels("missing-client", "trusted-session-admin", "[]"); !errors.Is(err, ErrClientNotFound) {
		t.Fatalf("missing models error=%v", err)
	}
	if s3EventCount(t, db) != countBefore || s3Head(t, db) != headBefore {
		t.Fatal("invalid/not-found operations changed audit state")
	}
}

func TestP108B_S4_EmptyClientSettingsIsTrueNoOp(t *testing.T) {
	db, svc, cfg := newP108BS3Env(t)
	client := createP108BS3Client(t, svc, cfg, "s4-empty-settings")
	before, err := svc.GetClientByID(client.ID)
	if err != nil || before == nil {
		t.Fatal("client missing before empty settings test")
	}
	countBefore, headBefore := s3EventCount(t, db), s3Head(t, db)
	if err := svc.UpdateClientSettings(client.ID, "trusted-session-admin", map[string]interface{}{}); err != nil {
		t.Fatal(err)
	}
	after, err := svc.GetClientByID(client.ID)
	if err != nil || after == nil {
		t.Fatal("client missing after empty settings test")
	}
	if !reflect.DeepEqual(before, after) || s3EventCount(t, db) != countBefore || s3Head(t, db) != headBefore {
		t.Fatalf("empty settings was not a true no-op: before=%+v after=%+v", before, after)
	}
}

func TestP108B_S3_CreateWithSettingsStillOnlyCreatesOneEvent(t *testing.T) {
	db, svc, cfg := newP108BS3Env(t)
	client, _, err := svc.CreateClientWithSettings("s3-create", "", "openai", "sk-", cfg, "trusted-session-admin", func(string) (map[string]interface{}, error) {
		return map[string]interface{}{
			"name":                      "created-with-settings",
			"backend_api_key_encrypted": "P108B-S3-PROVIDER-SECRET-CANARY",
			"backend_models":            "[\"created-model\"]",
		}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := s3Actions(t, db, client.ID); !reflect.DeepEqual(got, []string{audit.ActionClientCreated}) {
		t.Fatalf("create with settings actions=%v", got)
	}
}
