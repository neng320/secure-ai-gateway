package database_test

import (
	"bytes"
	"os"
	"testing"

	"ai-gateway/internal/database"
)

func TestP108B_S2_ReadOnlyOpenRejectsWrites(t *testing.T) {
	path := t.TempDir() + "/readonly.db"
	db, err := database.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Exec("CREATE TABLE canary (id INTEGER PRIMARY KEY, value TEXT)").Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Exec("INSERT INTO canary (id, value) VALUES (1, 'before')").Error; err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if sqlDB, err := db.DB(); err == nil {
		_ = sqlDB.Close()
	}

	readonly, err := database.OpenReadOnly(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if sqlDB, err := readonly.DB(); err == nil {
			_ = sqlDB.Close()
		}
	}()
	for _, statement := range []string{
		"CREATE TABLE should_fail (id INTEGER)",
		"INSERT INTO canary (id, value) VALUES (2, 'nope')",
		"UPDATE canary SET value = 'changed' WHERE id = 1",
	} {
		if err := readonly.Exec(statement).Error; err == nil {
			t.Fatalf("read-only handle accepted %s", statement)
		}
	}
	var value string
	if err := readonly.Raw("SELECT value FROM canary WHERE id = 1").Scan(&value).Error; err != nil {
		t.Fatal(err)
	}
	if value != "before" {
		t.Fatalf("read-only query observed mutation: %q", value)
	}
	if sqlDB, err := readonly.DB(); err == nil {
		_ = sqlDB.Close()
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("read-only write canary changed database bytes")
	}
}

func TestP108B_S2_ReadOnlyOpenMissingDBDoesNotCreate(t *testing.T) {
	path := t.TempDir() + "/missing.db"
	if _, err := database.OpenReadOnly(path); err == nil {
		t.Fatal("OpenReadOnly must reject a missing database")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("OpenReadOnly created or changed missing database: %v", err)
	}
}
