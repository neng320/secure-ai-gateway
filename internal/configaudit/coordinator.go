package configaudit

import (
	"errors"
	"fmt"
	"io/fs"

	"ai-gateway/internal/audit"
	"ai-gateway/internal/configlock"
	"ai-gateway/internal/configstore"
	"ai-gateway/internal/models"
	"gorm.io/gorm"
)

var ErrConfigAuditRollbackFailed = errors.New("config audit rollback failed")
var errConfigReplaceIncomplete = errors.New("config replacement durability incomplete")

type FileStore interface {
	ReadSnapshot(path string) (configstore.Snapshot, error)
	AtomicReplace(path string, data []byte, mode fs.FileMode) (configstore.ReplaceResult, error)
}

type osFileStore struct{}

func (osFileStore) ReadSnapshot(path string) (configstore.Snapshot, error) {
	return configstore.ReadSnapshot(path)
}

func (osFileStore) AtomicReplace(path string, data []byte, mode fs.FileMode) (configstore.ReplaceResult, error) {
	return configstore.AtomicReplace(path, data, mode)
}

type BuildResult struct {
	Candidate []byte
	Event     models.AuditEvent
	Audit     *audit.Service
	DB        *gorm.DB
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
	return c.runLocked(m, func(result BuildResult) error {
		auditService, err := c.auditService(result)
		if err != nil {
			return err
		}
		return auditService.Record(result.Event)
	})
}

// RunLockedTransactional extends the same lock/compensation protocol with a
// required SQLite mutation. The callback cannot omit the audit append because
// RecordTx is unconditionally executed in the same transaction afterward.
func (c *Coordinator) RunLockedTransactional(m Mutation, db *gorm.DB, mutate func(*gorm.DB) error) error {
	if mutate == nil {
		return fmt.Errorf("config audit transaction is invalid")
	}
	return c.runLocked(m, func(result BuildResult) error {
		auditService, err := c.auditService(result)
		if err != nil {
			return err
		}
		transactionDB := result.DB
		if transactionDB == nil {
			transactionDB = db
		}
		if transactionDB == nil {
			return fmt.Errorf("config audit database is unavailable")
		}
		return transactionDB.Transaction(func(tx *gorm.DB) error {
			if err := mutate(tx); err != nil {
				return err
			}
			return auditService.RecordTx(tx, result.Event)
		})
	})
}

func (c *Coordinator) runLocked(m Mutation, afterPersist func(BuildResult) error) (err error) {
	if c == nil || c.files == nil || m.ConfigPath == "" || m.Build == nil || afterPersist == nil {
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
	candidateResult, candidateErr := c.files.AtomicReplace(lock.CanonicalConfigPath(), result.Candidate, snapshot.Mode)
	if candidateErr == nil && (!candidateResult.Renamed || !candidateResult.DirectorySynced) {
		candidateErr = errConfigReplaceIncomplete
	}
	if candidateErr != nil {
		if candidateResult.Renamed {
			if restoreErr := c.restoreSnapshot(lock.CanonicalConfigPath(), snapshot); restoreErr != nil {
				return restoreErr
			}
		}
		return candidateErr
	}
	if err := afterPersist(result); err != nil {
		if restoreErr := c.restoreSnapshot(lock.CanonicalConfigPath(), snapshot); restoreErr != nil {
			return restoreErr
		}
		return err
	}
	if result.Apply != nil {
		result.Apply()
	}
	return nil
}

func (c *Coordinator) restoreSnapshot(path string, snapshot configstore.Snapshot) error {
	result, err := c.files.AtomicReplace(path, snapshot.Bytes, snapshot.Mode)
	if err != nil || !result.Renamed || !result.DirectorySynced {
		return ErrConfigAuditRollbackFailed
	}
	return nil
}

func (c *Coordinator) auditService(result BuildResult) (*audit.Service, error) {
	auditService := result.Audit
	if auditService == nil {
		auditService = c.audit
	}
	if auditService == nil {
		return nil, fmt.Errorf("config audit service is unavailable")
	}
	return auditService, nil
}
