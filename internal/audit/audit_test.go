package audit

import (
	"strings"
	"testing"
	"time"

	"ai-gateway/internal/database"
	"ai-gateway/internal/models"

	"gorm.io/gorm"
)

func newAuditTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := database.Open(t.TempDir() + "/audit.db")
	if err != nil {
		t.Fatal(err)
	}
	if err := db.AutoMigrate(&models.AuditEvent{}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if sqlDB, err := db.DB(); err == nil {
			_ = sqlDB.Close()
		}
	})
	return db
}

func TestRecordTx_AppendAndList(t *testing.T) {
	db := newAuditTestDB(t)
	svc := NewService(db)

	if err := db.Transaction(func(tx *gorm.DB) error {
		return svc.RecordTx(tx, models.AuditEvent{
			Action:    ActionClientCreated,
			ActorType: "admin",
			ActorID:   "test-admin",
			TargetID:  "client-1",
			Reason:    "  created for test  ",
		})
	}); err != nil {
		t.Fatal(err)
	}
	events, err := svc.List("client", "client-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || events[0].EventID == "" || events[0].CreatedAt.IsZero() {
		t.Fatalf("expected generated event ID/time, got %+v", events)
	}
	if events[0].Reason != "created for test" || events[0].TargetType != "client" {
		t.Fatalf("expected normalized reason/default target, got %+v", events[0])
	}
	if time.Since(events[0].CreatedAt) > time.Minute {
		t.Fatalf("event timestamp is not server-current: %v", events[0].CreatedAt)
	}
}

func TestRecordTx_RejectsUnboundedOrControlFields(t *testing.T) {
	db := newAuditTestDB(t)
	svc := NewService(db)
	cases := []models.AuditEvent{
		{Action: ActionClientCreated, ActorType: "admin", ActorID: strings.Repeat("a", 256), TargetID: "client-1"},
		{Action: ActionClientCreated, ActorType: "admin", ActorID: "admin", TargetID: "client-1", Reason: "bad\nreason"},
		{Action: ActionClientCreated, ActorType: "admin", ActorID: "admin", TargetID: ""},
	}
	for _, event := range cases {
		if err := svc.RecordTx(db, event); err == nil {
			t.Fatalf("expected invalid event to be rejected: %+v", event)
		}
	}
}

func TestRecordTx_UnknownActionDoesNotEchoInput(t *testing.T) {
	db := newAuditTestDB(t)
	secret := "P105C_AUDIT_ACTION_CANARY"
	err := NewService(db).RecordTx(db, models.AuditEvent{
		Action:    secret,
		ActorType: "admin",
		ActorID:   "admin",
		TargetID:  "client-1",
	})
	if err == nil || strings.Contains(err.Error(), secret) {
		t.Fatalf("unknown action error must be generic and non-echoing: %v", err)
	}
}
