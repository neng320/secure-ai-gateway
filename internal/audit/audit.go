package audit

// P1-05C · Generic AuditEvent Foundation（application append-only）
//
// 生产 Audit service 只提供：
//   Append（同事务写入）与 Read。
// 不提供 Update / Delete——生产代码绝不允许
//   db.Model(&AuditEvent{}).Updates(...) 或 db.Delete(&AuditEvent{}...)。
//
// 边界声明：本包是 application append-only foundation，不是 P1-08 的
// 数据库级 tamper-evidence / hash chain / retention / operator anti-tamper。
// 完整不可变审计子系统由 P1-08 负责（见 docs/adr/ADR-008）。

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"ai-gateway/internal/models"

	"github.com/google/uuid"
	"github.com/mattn/go-sqlite3"
	"gorm.io/gorm"
)

var (
	ErrAuditTransactionRequired = errors.New("audit transaction required")
	ErrAuditIntegrity           = errors.New("audit integrity failure")
	ErrAuditMigrationRequired   = errors.New("audit schema migration required")
	ErrAuditBusy                = errors.New("audit busy")
)

// 固定 action 常量（§10）——禁止自由字符串拼接；审计写入按白名单校验。
const (
	ActionClientCreated               = "CLIENT_CREATED"
	ActionClientKeyRotated            = "CLIENT_KEY_ROTATED"
	ActionClientSuspended             = "CLIENT_SUSPENDED"
	ActionClientResumed               = "CLIENT_RESUMED"
	ActionClientRevoked               = "CLIENT_REVOKED"
	ActionClientDeleted               = "CLIENT_DELETED"
	ActionClientSettingsUpdated       = "CLIENT_SETTINGS_UPDATED"
	ActionClientProviderSecretChanged = "CLIENT_PROVIDER_SECRET_CHANGED"
	ActionClientModelsUpdated         = "CLIENT_MODELS_UPDATED"
	ActionServerToolsUpdated          = "SERVER_TOOLS_UPDATED"
	ActionGlobalProviderSecretChanged = "GLOBAL_PROVIDER_SECRET_CHANGED"
)

// allowedActions: 审计写入白名单（静态 Gate 断言生产 action 只能来自常量）。
var allowedActions = map[string]bool{
	ActionClientCreated:               true,
	ActionClientKeyRotated:            true,
	ActionClientSuspended:             true,
	ActionClientResumed:               true,
	ActionClientRevoked:               true,
	ActionClientDeleted:               true,
	ActionClientSettingsUpdated:       true,
	ActionClientProviderSecretChanged: true,
	ActionClientModelsUpdated:         true,
	ActionServerToolsUpdated:          true,
	ActionGlobalProviderSecretChanged: true,
}

func IsKnownAction(action string) bool {
	return allowedActions[action]
}

type Service struct {
	db *gorm.DB
}

type activeSQLTransaction interface {
	gorm.ConnPool
	Commit() error
	Rollback() error
}

func NewService(db *gorm.DB) *Service {
	return &Service{db: db}
}

func (s *Service) Record(e models.AuditEvent) error {
	return s.db.Transaction(func(tx *gorm.DB) error {
		return s.RecordTx(tx, e)
	})
}

func normalizeAuditDBError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, sql.ErrTxDone) {
		return ErrAuditTransactionRequired
	}
	var sqliteErr sqlite3.Error
	if errors.As(err, &sqliteErr) && (sqliteErr.Code == sqlite3.ErrBusy || sqliteErr.Code == sqlite3.ErrLocked) {
		return ErrAuditBusy
	}
	return err
}

func validateBoundedField(name, value string, maxRunes int, required bool) error {
	if required && strings.TrimSpace(value) == "" {
		return fmt.Errorf("audit: invalid %s", name)
	}
	if !utf8.ValidString(value) || len([]rune(value)) > maxRunes {
		return fmt.Errorf("audit: invalid %s", name)
	}
	for _, r := range value {
		if unicode.IsControl(r) {
			return fmt.Errorf("audit: invalid %s", name)
		}
	}
	return nil
}

// RecordTx: 在【调用方事务内】append 一条 event——lifecycle mutation 与 audit
// 必须是同一个 SQLite transaction（§9）；audit INSERT 失败 → 整个 mutation
// rollback。EventID 由服务端生成（UUIDv4），CreatedAt 取 server time。
func (s *Service) RecordTx(tx *gorm.DB, e models.AuditEvent) error {
	if tx == nil || tx.Statement == nil {
		return ErrAuditTransactionRequired
	}
	if _, ok := tx.Statement.ConnPool.(activeSQLTransaction); !ok {
		return ErrAuditTransactionRequired
	}
	if !IsKnownAction(e.Action) {
		return fmt.Errorf("audit: unknown action")
	}
	if e.TargetType == "" {
		e.TargetType = "client"
	}
	e.Reason = strings.TrimSpace(e.Reason)
	for _, field := range []struct {
		name     string
		value    string
		maxRunes int
		required bool
	}{
		{name: "action", value: e.Action, maxRunes: 64, required: true},
		{name: "actor_type", value: e.ActorType, maxRunes: 32, required: true},
		{name: "actor_id", value: e.ActorID, maxRunes: 255, required: true},
		{name: "target_type", value: e.TargetType, maxRunes: 32, required: true},
		{name: "target_id", value: e.TargetID, maxRunes: 36, required: true},
		{name: "reason", value: e.Reason, maxRunes: 256},
	} {
		if err := validateBoundedField(field.name, field.value, field.maxRunes, field.required); err != nil {
			return err
		}
	}
	if err := acquireChainWriteLock(tx); err != nil {
		return err
	}
	state, tail, err := loadConsistentChainTail(tx)
	if err != nil {
		return err
	}
	e.EventID = uuid.New().String()
	e.CreatedAt = time.Now().UTC()
	e.ChainVersion = chainVersionV1
	e.PrevHash = state.HeadHash
	if tail != nil && e.PrevHash != tail.EventHash {
		return ErrAuditIntegrity
	}
	e.EventHash = eventHash(e)
	if err := tx.Create(&e).Error; err != nil {
		return normalizeAuditDBError(err)
	}
	result := tx.Model(&models.AuditChainState{}).Where("id = ?", 1).
		Updates(map[string]interface{}{"chain_version": chainVersionV1, "head_hash": e.EventHash, "updated_at": time.Now().UTC()})
	if result.Error != nil {
		return normalizeAuditDBError(result.Error)
	}
	if result.RowsAffected != 1 {
		return ErrAuditIntegrity
	}
	return nil
}

func acquireChainWriteLock(tx *gorm.DB) error {
	result := tx.Exec("UPDATE audit_chain_states SET head_hash = head_hash WHERE id = ?", 1)
	if result.Error != nil {
		return normalizeAuditDBError(result.Error)
	}
	if result.RowsAffected != 1 {
		return ErrAuditIntegrity
	}
	return nil
}

func loadConsistentChainTail(tx *gorm.DB) (models.AuditChainState, *models.AuditEvent, error) {
	var state models.AuditChainState
	if err := tx.Where("id = ?", 1).First(&state).Error; err != nil {
		return state, nil, ErrAuditIntegrity
	}
	if state.ID != 1 || state.ChainVersion != chainVersionV1 || !validHashOrGenesis(state.HeadHash) {
		return state, nil, ErrAuditIntegrity
	}
	var tail models.AuditEvent
	err := tx.Order("id DESC").First(&tail).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		if state.HeadHash != "" {
			return state, nil, ErrAuditIntegrity
		}
		return state, nil, nil
	}
	if err != nil {
		return state, nil, ErrAuditIntegrity
	}
	if tail.ChainVersion != chainVersionV1 || !validHash(tail.EventHash) || eventHash(tail) != tail.EventHash || state.HeadHash != tail.EventHash {
		return state, nil, ErrAuditIntegrity
	}
	return state, &tail, nil
}

func (s *Service) VerifyAuditChain() error {
	return verifyAuditChainDB(s.db)
}

// List: 只读查询（按 target；时间正序）。
func (s *Service) List(targetType, targetID string) ([]models.AuditEvent, error) {
	var events []models.AuditEvent
	err := s.db.Where("target_type = ? AND target_id = ?", targetType, targetID).
		Order("id ASC").Find(&events).Error
	return events, err
}
