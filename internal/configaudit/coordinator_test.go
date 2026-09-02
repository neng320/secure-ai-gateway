package configaudit

import (
	"bytes"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"ai-gateway/internal/audit"
	"ai-gateway/internal/configlock"
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

type rollbackBlockingFileStore struct {
	rollbackStarted chan struct{}
	releaseRollback chan struct{}
	writes          int32
}

type scriptedFileStore struct {
	candidatePostRename bool
	candidatePreRename  bool
	restorePreRename    bool
	restoreDirSync      bool
	candidateErr        error
	restoreErr          error
	calls               int
}

func (f *scriptedFileStore) ReadSnapshot(path string) (configstore.Snapshot, error) {
	return configstore.ReadSnapshot(path)
}

func (f *scriptedFileStore) AtomicReplace(path string, data []byte, mode fs.FileMode) (configstore.ReplaceResult, error) {
	f.calls++
	switch f.calls {
	case 1:
		if f.candidatePreRename {
			return configstore.ReplaceResult{}, f.candidateErr
		}
		if f.candidatePostRename {
			if _, err := configstore.AtomicReplace(path, data, mode); err != nil {
				return configstore.ReplaceResult{}, err
			}
			return configstore.ReplaceResult{Renamed: true}, f.candidateErr
		}
	case 2:
		if f.restorePreRename {
			return configstore.ReplaceResult{}, f.restoreErr
		}
		if f.restoreDirSync {
			if _, err := configstore.AtomicReplace(path, data, mode); err != nil {
				return configstore.ReplaceResult{}, err
			}
			return configstore.ReplaceResult{Renamed: true}, f.restoreErr
		}
	}
	return configstore.AtomicReplace(path, data, mode)
}

func (f *rollbackBlockingFileStore) ReadSnapshot(path string) (configstore.Snapshot, error) {
	return configstore.ReadSnapshot(path)
}

func (f *rollbackBlockingFileStore) AtomicReplace(path string, data []byte, mode fs.FileMode) (configstore.ReplaceResult, error) {
	if atomic.AddInt32(&f.writes, 1) == 2 {
		close(f.rollbackStarted)
		<-f.releaseRollback
	}
	return configstore.AtomicReplace(path, data, mode)
}

func (f *fakeFileStore) ReadSnapshot(string) (configstore.Snapshot, error) {
	return f.snapshot, nil
}

func (f *fakeFileStore) AtomicReplace(_ string, _ []byte, _ fs.FileMode) (configstore.ReplaceResult, error) {
	f.writeCall++
	if f.writeCall == f.failOn {
		return configstore.ReplaceResult{}, errors.New("injected config replace failure")
	}
	return configstore.ReplaceResult{Renamed: true, DirectorySynced: true}, nil
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

func fixedBuild(candidate []byte, event models.AuditEvent, apply func()) func(configstore.Snapshot) (BuildResult, error) {
	return func(configstore.Snapshot) (BuildResult, error) {
		return BuildResult{Candidate: candidate, Event: event, Apply: apply}, nil
	}
}

func TestP108B_S4_CoordinatorSuccessAppliesAfterAudit(t *testing.T) {
	_, service, path, before := newCoordinatorTest(t)
	candidate := []byte("server_tools:\n  enabled: true\n")
	applied := false
	originalStat, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := New(service).RunLocked(Mutation{ConfigPath: path, Build: fixedBuild(candidate, coordinatorTestEvent(), func() { applied = true })}); err != nil {
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

func TestP108B_S4_CoordinatorAppliesOnlyAfterAuditSuccess(t *testing.T) {
	db, service, path, _ := newCoordinatorTest(t)
	var observedAuditCount int64
	applied := 0
	if err := New(service).RunLocked(Mutation{
		ConfigPath: path,
		Build: fixedBuild([]byte("candidate-after-audit"), coordinatorTestEvent(), func() {
			applied++
			if err := db.Model(&models.AuditEvent{}).Count(&observedAuditCount).Error; err != nil {
				t.Errorf("count audit events from Apply: %v", err)
			}
		}),
	}); err != nil {
		t.Fatal(err)
	}
	if applied != 1 || observedAuditCount != 1 {
		t.Fatalf("Apply ordering mismatch: applied=%d observedAuditCount=%d", applied, observedAuditCount)
	}
}

func TestP108B_S4_AuditFailureRestoresExactBytes(t *testing.T) {
	db, service, path, before := newCoordinatorTest(t)
	if err := db.Exec("CREATE TRIGGER s4_reject_audit BEFORE INSERT ON audit_events WHEN NEW.action = 'SERVER_TOOLS_UPDATED' BEGIN SELECT RAISE(ABORT, 'TEST_AUDIT_INSERT_FAILED'); END").Error; err != nil {
		t.Fatal(err)
	}
	applied := false
	err := New(service).RunLocked(Mutation{ConfigPath: path, Build: fixedBuild([]byte("candidate"), coordinatorTestEvent(), func() { applied = true })})
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
	if err := New(service).RunLocked(Mutation{ConfigPath: path, Build: fixedBuild([]byte("candidate-global"), coordinatorGlobalProviderEvent(), nil)}); err == nil {
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
	if err := NewWithFileStore(service, store).RunLocked(Mutation{ConfigPath: path, Build: fixedBuild([]byte("candidate"), coordinatorTestEvent(), nil)}); err == nil {
		t.Fatal("injected config write failure must fail")
	}
	if store.writeCall != 1 {
		t.Fatalf("unexpected write calls=%d", store.writeCall)
	}
}

func TestP108B_S4_CandidatePostRenameDirectorySyncFailureCompensates(t *testing.T) {
	db, service, path, before := newCoordinatorTest(t)
	originalStat, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	candidateErr := errors.New("candidate directory durability failure")
	store := &scriptedFileStore{
		candidatePostRename: true,
		candidateErr:        candidateErr,
	}
	applied := false
	err = NewWithFileStore(service, store).RunLocked(Mutation{
		ConfigPath: path,
		Build: fixedBuild([]byte("candidate-post-rename"), coordinatorTestEvent(), func() {
			applied = true
		}),
	})
	if !errors.Is(err, candidateErr) {
		t.Fatalf("expected original candidate persistence error, got %v", err)
	}
	if applied || store.calls != 2 {
		t.Fatalf("post-rename failure must compensate before apply: applied=%v calls=%d", applied, store.calls)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(after, before) {
		t.Fatalf("post-rename failure did not restore exact bytes: %q", after)
	}
	if info, err := os.Stat(path); err != nil || info.Mode().Perm() != originalStat.Mode().Perm() {
		t.Fatalf("post-rename failure did not restore exact mode: info=%v err=%v", info, err)
	}
	var count int64
	if err := db.Model(&models.AuditEvent{}).Count(&count).Error; err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("post-rename failure left %d audit event(s)", count)
	}
}

func TestP108B_S4_CandidatePreRenameFailureDoesNotCompensate(t *testing.T) {
	db, service, path, before := newCoordinatorTest(t)
	candidateErr := errors.New("candidate pre-rename failure")
	store := &scriptedFileStore{
		candidatePreRename: true,
		candidateErr:       candidateErr,
	}
	applied := false
	err := NewWithFileStore(service, store).RunLocked(Mutation{
		ConfigPath: path,
		Build: fixedBuild([]byte("candidate-pre-rename"), coordinatorTestEvent(), func() {
			applied = true
		}),
	})
	if !errors.Is(err, candidateErr) {
		t.Fatalf("expected original pre-rename error, got %v", err)
	}
	if applied || store.calls != 1 {
		t.Fatalf("pre-rename failure must not trigger compensation: applied=%v calls=%d", applied, store.calls)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(after, before) {
		t.Fatalf("pre-rename failure changed exact bytes: %q", after)
	}
	var count int64
	if err := db.Model(&models.AuditEvent{}).Count(&count).Error; err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("pre-rename failure left %d audit event(s)", count)
	}
}

func TestP108B_S4_RestoreDirectorySyncFailureReturnsStableError(t *testing.T) {
	db, service, path, before := newCoordinatorTest(t)
	store := &scriptedFileStore{
		candidatePostRename: true,
		candidateErr:        errors.New("candidate persistence failed"),
		restoreDirSync:      true,
		restoreErr:          errors.New("restore failed snapshot-secret-marker"),
	}
	err := NewWithFileStore(service, store).RunLocked(Mutation{
		ConfigPath: path,
		Build:      fixedBuild([]byte("candidate-secret-marker"), coordinatorTestEvent(), nil),
	})
	if !errors.Is(err, ErrConfigAuditRollbackFailed) {
		t.Fatalf("restore directory sync failure must be stable, got %v", err)
	}
	if bytes.Contains([]byte(err.Error()), []byte("snapshot-secret-marker")) || bytes.Contains([]byte(err.Error()), []byte("candidate-secret-marker")) {
		t.Fatalf("rollback error exposed config data: %v", err)
	}
	var count int64
	if err := db.Model(&models.AuditEvent{}).Count(&count).Error; err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("uncertain restore left %d audit event(s)", count)
	}
	_ = before
}

func TestP108B_S4_TransactionalFailureRestoresConfigAndRollsBackDatabase(t *testing.T) {
	db, service, path, before := newCoordinatorTest(t)
	if err := db.Exec("CREATE TABLE transaction_probe (id INTEGER PRIMARY KEY, value TEXT NOT NULL)").Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Exec("CREATE TRIGGER s4_reject_transaction BEFORE INSERT ON audit_events WHEN NEW.action = 'SERVER_TOOLS_UPDATED' BEGIN SELECT RAISE(ABORT, 'TEST_AUDIT_INSERT_FAILED'); END").Error; err != nil {
		t.Fatal(err)
	}
	originalStat, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	applied := false
	err = New(service).RunLockedTransactional(Mutation{
		ConfigPath: path,
		Build: fixedBuild([]byte("candidate-transaction"), coordinatorTestEvent(), func() {
			applied = true
		}),
	}, db, func(tx *gorm.DB) error {
		return tx.Exec("INSERT INTO transaction_probe(value) VALUES (?)", "must-rollback").Error
	})
	if err == nil || applied {
		t.Fatalf("transactional audit failure must fail before apply: err=%v applied=%v", err, applied)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(after, before) {
		t.Fatalf("transactional audit failure did not restore exact bytes: %q", after)
	}
	if info, err := os.Stat(path); err != nil || info.Mode().Perm() != originalStat.Mode().Perm() {
		t.Fatalf("transactional audit failure did not restore exact mode: info=%v err=%v", info, err)
	}
	var rows int64
	if err := db.Table("transaction_probe").Count(&rows).Error; err != nil {
		t.Fatal(err)
	}
	if rows != 0 {
		t.Fatalf("transaction mutation was not rolled back: rows=%d", rows)
	}
	var events int64
	if err := db.Model(&models.AuditEvent{}).Count(&events).Error; err != nil {
		t.Fatal(err)
	}
	if events != 0 {
		t.Fatalf("failed audit transaction left %d event(s)", events)
	}
}

func TestP108B_S4_CoordinatorRestoreFailureIsStable(t *testing.T) {
	db, service, path, before := newCoordinatorTest(t)
	if err := db.Exec("CREATE TRIGGER s4_reject_audit BEFORE INSERT ON audit_events WHEN NEW.action = 'SERVER_TOOLS_UPDATED' BEGIN SELECT RAISE(ABORT, 'TEST_AUDIT_INSERT_FAILED'); END").Error; err != nil {
		t.Fatal(err)
	}
	store := &fakeFileStore{snapshot: configstore.Snapshot{Bytes: before, Mode: 0600}, failOn: 2}
	if err := NewWithFileStore(service, store).RunLocked(Mutation{ConfigPath: path, Build: fixedBuild([]byte("candidate"), coordinatorTestEvent(), nil)}); !errors.Is(err, ErrConfigAuditRollbackFailed) {
		t.Fatalf("restore failure must return ErrConfigAuditRollbackFailed, got %v", err)
	}
}

func TestP108B_S41_SameProcessConfigMutationsSerialized(t *testing.T) {
	db, service, path, _ := newCoordinatorTest(t)
	coordinator := New(service)
	entered := make(chan struct{})
	release := make(chan struct{})
	firstDone := make(chan error, 1)
	secondBuilt := make(chan struct{})

	go func() {
		firstDone <- coordinator.RunLocked(Mutation{
			ConfigPath: path,
			Build: func(configstore.Snapshot) (BuildResult, error) {
				close(entered)
				<-release
				return BuildResult{Candidate: []byte("candidate-a"), Event: coordinatorTestEvent()}, nil
			},
		})
	}()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("first mutation did not reach its locked builder")
	}

	secondErr := coordinator.RunLocked(Mutation{
		ConfigPath: path,
		Build: func(configstore.Snapshot) (BuildResult, error) {
			close(secondBuilt)
			return BuildResult{Candidate: []byte("candidate-b"), Event: coordinatorGlobalProviderEvent()}, nil
		},
	})
	if !errors.Is(secondErr, configlock.ErrConfigMutationLocked) {
		t.Fatalf("contending mutation must fail closed with stable lock sentinel: %v", secondErr)
	}
	select {
	case <-secondBuilt:
		t.Fatal("contending mutation built a candidate while the first lock was held")
	default:
	}

	close(release)
	select {
	case err := <-firstDone:
		if err != nil {
			t.Fatalf("first mutation failed: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("first mutation did not finish after release")
	}
	lockPath, err := configlock.LockPath(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(lockPath); !os.IsNotExist(err) {
		t.Fatalf("config lock was not cleaned up: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "candidate-a" {
		t.Fatalf("unexpected serialized mutation result: %q", got)
	}
	_ = db
}

func TestP108B_S41_ConcurrentRollbackCannotClobberSuccess(t *testing.T) {
	db, service, path, before := newCoordinatorTest(t)
	if err := db.Exec("CREATE TRIGGER s41_reject_first BEFORE INSERT ON audit_events WHEN NEW.action = 'SERVER_TOOLS_UPDATED' BEGIN SELECT RAISE(ABORT, 'TEST_AUDIT_INSERT_FAILED'); END").Error; err != nil {
		t.Fatal(err)
	}
	blockingStore := &rollbackBlockingFileStore{
		rollbackStarted: make(chan struct{}),
		releaseRollback: make(chan struct{}),
	}
	coordinator := NewWithFileStore(service, blockingStore)
	firstDone := make(chan error, 1)
	secondBuilt := make(chan struct{})

	go func() {
		firstDone <- coordinator.RunLocked(Mutation{
			ConfigPath: path,
			Build: func(configstore.Snapshot) (BuildResult, error) {
				return BuildResult{Candidate: []byte("candidate-failed"), Event: coordinatorTestEvent()}, nil
			},
		})
	}()
	select {
	case <-blockingStore.rollbackStarted:
	case <-time.After(time.Second):
		t.Fatal("first mutation did not reach its locked rollback")
	}

	secondAttemptDone := make(chan error, 1)
	go func() {
		secondAttemptDone <- coordinator.RunLocked(Mutation{
			ConfigPath: path,
			Build: func(configstore.Snapshot) (BuildResult, error) {
				close(secondBuilt)
				return BuildResult{Candidate: []byte("candidate-success"), Event: coordinatorGlobalProviderEvent()}, nil
			},
		})
	}()
	select {
	case err := <-secondAttemptDone:
		if !errors.Is(err, configlock.ErrConfigMutationLocked) {
			t.Fatalf("concurrent contender must fail closed during rollback: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("concurrent contender did not return while rollback held the lock")
	}
	select {
	case <-secondBuilt:
		t.Fatal("success mutation entered while failed mutation was compensating")
	default:
	}

	close(blockingStore.releaseRollback)
	select {
	case err := <-firstDone:
		if err == nil {
			t.Fatal("triggered audit failure unexpectedly succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("failed mutation did not finish after rollback release")
	}
	if err := coordinator.RunLocked(Mutation{
		ConfigPath: path,
		Build: func(configstore.Snapshot) (BuildResult, error) {
			return BuildResult{Candidate: []byte("candidate-success"), Event: coordinatorGlobalProviderEvent()}, nil
		},
	}); err != nil {
		t.Fatalf("success mutation failed after rollback: %v", err)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "candidate-success" {
		t.Fatalf("rollback clobbered the later success: %q (before=%q)", got, before)
	}
	var events []models.AuditEvent
	if err := db.Order("id ASC").Find(&events).Error; err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || events[0].Action != audit.ActionGlobalProviderSecretChanged {
		t.Fatalf("unexpected audit history after serialized rollback: %+v", events)
	}
	if err := service.VerifyAuditChain(); err != nil {
		t.Fatalf("serialized rollback left an invalid audit chain: %v", err)
	}
}

func TestP108B_S41_LockCleanup(t *testing.T) {
	_, service, path, _ := newCoordinatorTest(t)
	lockPath, err := configlock.LockPath(path)
	if err != nil {
		t.Fatal(err)
	}
	err = New(service).RunLocked(Mutation{
		ConfigPath: path,
		Build: func(configstore.Snapshot) (BuildResult, error) {
			return BuildResult{}, errors.New("injected builder failure")
		},
	})
	if err == nil {
		t.Fatal("builder failure must fail")
	}
	if _, err := os.Stat(lockPath); !os.IsNotExist(err) {
		t.Fatalf("lock artifact survived handled mutation error: %v", err)
	}
}
