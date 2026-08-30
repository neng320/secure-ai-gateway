package configaudit

import (
	"bytes"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
	"time"

	"ai-gateway/internal/audit"
	"ai-gateway/internal/configstore"
	"ai-gateway/internal/database"
	"ai-gateway/internal/models"

	"gorm.io/gorm"
)

type fakeFileStore struct {
	snapshot  configstore.Snapshot
	writeCall int
	failOn    int
}

func (f *fakeFileStore) ReadSnapshot(string) (configstore.Snapshot, error) {
	return f.snapshot, nil
}

func (f *fakeFileStore) AtomicReplace(_ string, _ []byte, _ fs.FileMode) error {
	f.writeCall++
	if f.writeCall == f.failOn {
		return errors.New("injected config replace failure")
	}
	return nil
}

func newCoordinatorTest(t *testing.T) (*gorm.DB, *audit.Service, string, []byte) {
	t.Helper()
	db, err := database.Open(filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
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
	configPath := filepath.Join(t.TempDir(), "config.yaml")
	before := []byte("# preserve this exact config\nserver_tools:\n  enabled: false\n")
	if err := os.WriteFile(configPath, before, 0600); err != nil {
		t.Fatal(err)
	}
	return db, audit.NewService(db), configPath, before
}

func coordinatorTestEvent() models.AuditEvent {
	return models.AuditEvent{Action: audit.ActionServerToolsUpdated, ActorType: "admin", ActorID: "trusted-admin", TargetType: "server", TargetID: "server-tools", CreatedAt: time.Now().UTC()}
}

func coordinatorGlobalProviderEvent() models.AuditEvent {
	return models.AuditEvent{Action: audit.ActionGlobalProviderSecretChanged, ActorType: "cli", ActorID: "set-provider-key", TargetType: "provider", TargetID: "openai", CreatedAt: time.Now().UTC()}
}

func TestP108B_S4_CoordinatorSuccessAppliesAfterAudit(t *testing.T) {
	_, service, path, before := newCoordinatorTest(t)
	candidate := []byte("server_tools:\n  enabled: true\n")
	applied := false
	originalStat, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := New(service).Run(Mutation{ConfigPath: path, Candidate: candidate, Event: coordinatorTestEvent(), Apply: func() { applied = true }}); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, candidate) || !applied || bytes.Equal(got, before) {
		t.Fatalf("coordinator success state mismatch: got=%q applied=%v", got, applied)
	}
	if gotStat, err := os.Stat(path); err != nil || gotStat.Mode().Perm() != originalStat.Mode().Perm() {
		t.Fatalf("config mode widened after replacement: %v", err)
	}
	if leftovers, err := filepath.Glob(filepath.Join(filepath.Dir(path), ".config.yaml.tmp-*")); err != nil || len(leftovers) != 0 {
		t.Fatalf("unexpected temporary config artifacts: %v err=%v", leftovers, err)
	}
}

func TestP108B_S4_AuditFailureRestoresExactBytes(t *testing.T) {
	db, service, path, before := newCoordinatorTest(t)
	if err := db.Exec("CREATE TRIGGER s4_reject_audit BEFORE INSERT ON audit_events WHEN NEW.action = 'SERVER_TOOLS_UPDATED' BEGIN SELECT RAISE(ABORT, 'TEST_AUDIT_INSERT_FAILED'); END").Error; err != nil {
		t.Fatal(err)
	}
	applied := false
	err := New(service).Run(Mutation{ConfigPath: path, Candidate: []byte("candidate"), Event: coordinatorTestEvent(), Apply: func() { applied = true }})
	if err == nil || applied {
		t.Fatalf("audit failure must fail before apply: err=%v applied=%v", err, applied)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(after, before) {
		t.Fatalf("audit failure did not restore exact config bytes: %q", after)
	}
	var count int64
	if err := db.Model(&models.AuditEvent{}).Count(&count).Error; err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("audit failure left %d audit event(s)", count)
	}
}

func TestP108B_S4_GlobalProviderAuditFailureRestoresExactBytes(t *testing.T) {
	db, service, path, before := newCoordinatorTest(t)
	if err := db.Exec("CREATE TRIGGER s4_reject_global BEFORE INSERT ON audit_events WHEN NEW.action = 'GLOBAL_PROVIDER_SECRET_CHANGED' BEGIN SELECT RAISE(ABORT, 'TEST_AUDIT_INSERT_FAILED'); END").Error; err != nil {
		t.Fatal(err)
	}
	if err := New(service).Run(Mutation{ConfigPath: path, Candidate: []byte("candidate-global"), Event: coordinatorGlobalProviderEvent()}); err == nil {
		t.Fatal("global provider audit failure must fail")
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(after, before) {
		t.Fatal("global provider audit failure did not restore exact config bytes")
	}
	var count int64
	if err := db.Model(&models.AuditEvent{}).Count(&count).Error; err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("global provider audit failure left %d audit event(s)", count)
	}
}

func TestP108B_S4_CoordinatorWriteFailureHasNoAudit(t *testing.T) {
	_, service, path, before := newCoordinatorTest(t)
	store := &fakeFileStore{snapshot: configstore.Snapshot{Bytes: before, Mode: 0600}, failOn: 1}
	if err := NewWithFileStore(service, store).Run(Mutation{ConfigPath: path, Candidate: []byte("candidate"), Event: coordinatorTestEvent()}); err == nil {
		t.Fatal("injected config write failure must fail")
	}
	if store.writeCall != 1 {
		t.Fatalf("unexpected write calls=%d", store.writeCall)
	}
}

func TestP108B_S4_CoordinatorRestoreFailureIsStable(t *testing.T) {
	db, service, path, before := newCoordinatorTest(t)
	if err := db.Exec("CREATE TRIGGER s4_reject_audit BEFORE INSERT ON audit_events WHEN NEW.action = 'SERVER_TOOLS_UPDATED' BEGIN SELECT RAISE(ABORT, 'TEST_AUDIT_INSERT_FAILED'); END").Error; err != nil {
		t.Fatal(err)
	}
	store := &fakeFileStore{snapshot: configstore.Snapshot{Bytes: before, Mode: 0600}, failOn: 2}
	if err := NewWithFileStore(service, store).Run(Mutation{ConfigPath: path, Candidate: []byte("candidate"), Event: coordinatorTestEvent()}); !errors.Is(err, ErrConfigAuditRollbackFailed) {
		t.Fatalf("restore failure must return ErrConfigAuditRollbackFailed, got %v", err)
	}
}
