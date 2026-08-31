package configaudit

import (
	"errors"
	"fmt"
	"io/fs"

	"ai-gateway/internal/audit"
	"ai-gateway/internal/configlock"
	"ai-gateway/internal/configstore"
	"ai-gateway/internal/models"
)

var ErrConfigAuditRollbackFailed = errors.New("config audit rollback failed")

type FileStore interface {
	ReadSnapshot(path string) (configstore.Snapshot, error)
	AtomicReplace(path string, data []byte, mode fs.FileMode) error
}

type osFileStore struct{}

func (osFileStore) ReadSnapshot(path string) (configstore.Snapshot, error) {
	return configstore.ReadSnapshot(path)
}

func (osFileStore) AtomicReplace(path string, data []byte, mode fs.FileMode) error {
	return configstore.AtomicReplace(path, data, mode)
}

type BuildResult struct {
	Candidate []byte
	Event     models.AuditEvent
	Audit     *audit.Service
	Apply     func()
	Cleanup   func()
}

type Mutation struct {
	ConfigPath string
	Build      func(configstore.Snapshot) (BuildResult, error)
}

type Coordinator struct {
	audit *audit.Service
	files FileStore
}

func New(auditService *audit.Service) *Coordinator {
	return &Coordinator{audit: auditService, files: osFileStore{}}
}

func NewWithFileStore(auditService *audit.Service, files FileStore) *Coordinator {
	return &Coordinator{audit: auditService, files: files}
}

// RunLocked serializes the complete config + audit protocol across processes.
// Build receives the authoritative snapshot only after the lock is held.
func (c *Coordinator) RunLocked(m Mutation) (err error) {
	if c == nil || c.files == nil || m.ConfigPath == "" || m.Build == nil {
		return fmt.Errorf("config audit mutation is invalid")
	}
	lock, err := configlock.Acquire(m.ConfigPath)
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := lock.Close(); err == nil && closeErr != nil {
			err = closeErr
		}
	}()

	snapshot, err := c.files.ReadSnapshot(lock.CanonicalConfigPath())
	if err != nil {
		return err
	}
	result, err := m.Build(snapshot)
	if err != nil {
		return err
	}
	if result.Cleanup != nil {
		defer result.Cleanup()
	}
	if len(result.Candidate) == 0 {
		return fmt.Errorf("config audit candidate is empty")
	}
	auditService := result.Audit
	if auditService == nil {
		auditService = c.audit
	}
	if auditService == nil {
		return fmt.Errorf("config audit service is unavailable")
	}
	if err := c.files.AtomicReplace(lock.CanonicalConfigPath(), result.Candidate, snapshot.Mode); err != nil {
		return err
	}
	if err := auditService.Record(result.Event); err != nil {
		if restoreErr := c.files.AtomicReplace(lock.CanonicalConfigPath(), snapshot.Bytes, snapshot.Mode); restoreErr != nil {
			return fmt.Errorf("%w: %v", ErrConfigAuditRollbackFailed, restoreErr)
		}
		return err
	}
	if result.Apply != nil {
		result.Apply()
	}
	return nil
}
