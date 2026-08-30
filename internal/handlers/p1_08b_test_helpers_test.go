package handlers

import (
	"testing"

	"ai-gateway/internal/audit"

	"gorm.io/gorm"
)

func migrateHandlerAudit(t *testing.T, db *gorm.DB) {
	t.Helper()
	if err := audit.MigrateIntegrity(db); err != nil {
		t.Fatal(err)
	}
}
