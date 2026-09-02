package database

import (
	"context"
	"database/sql"
	"testing"

	"ai-gateway/internal/audit"

	_ "github.com/mattn/go-sqlite3"
)

func TestP108B_S7_PinnedOwnershipSpansAuditAndMaintenanceTransactions(t *testing.T) {
	path := t.TempDir() + "/gateway.db"
	bootstrap, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := bootstrap.Exec("CREATE TABLE request_logs (id INTEGER PRIMARY KEY, request_body TEXT NOT NULL, error_message TEXT NOT NULL)").Error; err != nil {
		t.Fatal(err)
	}
	if sqlDB, err := bootstrap.DB(); err == nil {
		_ = sqlDB.Close()
	}

	pinned, err := OpenPinned(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = pinned.Close() }()
	if err := pinned.AcquireExclusive(); err != nil {
		t.Fatal(err)
	}

	competitor, err := sql.Open("sqlite3", path+"?_busy_timeout=0")
	if err != nil {
		t.Fatal(err)
	}
	defer competitor.Close()
	if err := audit.MigrateIntegrity(pinned.DB); err != nil {
		t.Fatalf("audit migration lost pinned ownership: %v", err)
	}
	if _, err := audit.VerifyIntegrityReadOnly(pinned.DB); err != nil {
		t.Fatalf("audit verification lost pinned ownership: %v", err)
	}
	competitorConn, err := competitor.Conn(context.Background())
	if err == nil {
		defer competitorConn.Close()
		if _, err := competitorConn.ExecContext(context.Background(), "BEGIN IMMEDIATE"); err == nil {
			_, _ = competitorConn.ExecContext(context.Background(), "ROLLBACK")
			t.Fatal("competitor acquired mutation ownership during the pinned audit prerequisite")
		}
	}

	tx, err := pinned.BeginExclusive()
	if err != nil {
		t.Fatal(err)
	}
	operation, err := audit.NewService(pinned.DB).BeginMaintenanceTx(tx, audit.MaintenanceKindRequestLogScrub)
	if err != nil {
		_ = tx.Rollback().Error
		t.Fatal(err)
	}
	if operation.TargetID == "" {
		_ = tx.Rollback().Error
		t.Fatal("maintenance operation did not generate a target ID")
	}
	if err := tx.Commit().Error; err != nil {
		t.Fatal(err)
	}
	if competitorConn != nil {
		if _, err := competitorConn.ExecContext(context.Background(), "BEGIN IMMEDIATE"); err == nil {
			_, _ = competitorConn.ExecContext(context.Background(), "ROLLBACK")
			t.Fatal("competitor acquired mutation ownership after logical commit")
		}
	}
}
