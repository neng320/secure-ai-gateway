package services

import (
	"testing"

	"ai-gateway/internal/audit"

	"gorm.io/gorm"
)

func migrateServiceAudit(t *testing.T, db *gorm.DB) {
	t.Helper()
	if err := audit.MigrateIntegrity(db); err != nil {
		t.Fatal(err)
	}
}
