package configaudit

import (
	"errors"
	"fmt"
	"io/fs"

	"ai-gateway/internal/audit"
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

type Mutation struct {
	ConfigPath string
	Candidate  []byte
	Event      models.AuditEvent
	Apply      func()
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

func (c *Coordinator) Run(m Mutation) error {
	if c == nil || c.audit == nil || c.files == nil || m.ConfigPath == "" || len(m.Candidate) == 0 {
		return fmt.Errorf("config audit mutation is invalid")
	}
	snapshot, err := c.files.ReadSnapshot(m.ConfigPath)
	if err != nil {
		return err
	}
	if err := c.files.AtomicReplace(m.ConfigPath, m.Candidate, snapshot.Mode); err != nil {
		return err
	}
	if err := c.audit.Record(m.Event); err != nil {
		if restoreErr := c.files.AtomicReplace(m.ConfigPath, snapshot.Bytes, snapshot.Mode); restoreErr != nil {
			return fmt.Errorf("%w: %v", ErrConfigAuditRollbackFailed, restoreErr)
		}
		return err
	}
	if m.Apply != nil {
		m.Apply()
	}
	return nil
}
