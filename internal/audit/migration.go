package audit

import (
	"fmt"
	"strings"
	"time"

	"ai-gateway/internal/models"

	"gorm.io/gorm"
)

const (
	auditUpdateTriggerName = "audit_events_no_update"
	auditDeleteTriggerName = "audit_events_no_delete"
	auditImmutableMessage  = "AUDIT_EVENT_IMMUTABLE"
)

const (
	auditUpdateTriggerSQL = "CREATE TRIGGER audit_events_no_update BEFORE UPDATE ON audit_events BEGIN SELECT RAISE(ABORT, 'AUDIT_EVENT_IMMUTABLE'); END"
	auditDeleteTriggerSQL = "CREATE TRIGGER audit_events_no_delete BEFORE DELETE ON audit_events BEGIN SELECT RAISE(ABORT, 'AUDIT_EVENT_IMMUTABLE'); END"
)

type auditHistoryClass uint8

const (
	auditFreshEmpty auditHistoryClass = iota
	auditLegacyAllUnchained
	auditFullyChained
)

// MigrateIntegrity owns all AuditEvent schema changes, legacy backfill,
// verification, and mutation-trigger installation in one SQLite transaction.
func MigrateIntegrity(db *gorm.DB) error {
	if db == nil {
		return ErrAuditIntegrity
	}
	return db.Transaction(func(tx *gorm.DB) error {
		if err := tx.AutoMigrate(&models.AuditEvent{}, &models.AuditChainState{}); err != nil {
			return fmt.Errorf("%w: audit schema migration failed", ErrAuditIntegrity)
		}

		triggers, err := loadTriggerDefinitions(tx)
		if err != nil {
			return err
		}
		events, err := loadAuditEvents(tx)
		if err != nil {
			return err
		}
		states, err := loadChainStates(tx)
		if err != nil {
			return err
		}
		class, err := classifyAuditHistory(events, states)
		if err != nil {
			return err
		}
		if class == auditLegacyAllUnchained && len(triggers) != 0 {
			return auditIntegrityError("legacy history has existing mutation triggers")
		}

		switch class {
		case auditFreshEmpty:
			if err := createChainState(tx, "", time.Now().UTC()); err != nil {
				return err
			}
		case auditLegacyAllUnchained:
			if err := backfillLegacyEvents(tx, events); err != nil {
				return err
			}
		case auditFullyChained:
			// Existing chained history is immutable: verify it, never backfill it.
		default:
			return ErrAuditIntegrity
		}

		if err := verifyAuditChainDB(tx); err != nil {
			return err
		}
		if err := ensureExactMutationTriggers(tx, triggers); err != nil {
			return err
		}
		return nil
	})
}

func loadAuditEvents(db *gorm.DB) ([]models.AuditEvent, error) {
	var events []models.AuditEvent
	if err := db.Order("id ASC").Find(&events).Error; err != nil {
		return nil, auditIntegrityError("audit history unavailable")
	}
	return events, nil
}

func loadChainStates(db *gorm.DB) ([]models.AuditChainState, error) {
	var states []models.AuditChainState
	if err := db.Order("id ASC").Find(&states).Error; err != nil {
		return nil, auditIntegrityError("chain state unavailable")
	}
	return states, nil
}

func classifyAuditHistory(events []models.AuditEvent, states []models.AuditChainState) (auditHistoryClass, error) {
	if len(states) > 1 {
		return 0, auditIntegrityError("invalid chain state singleton")
	}
	if len(events) == 0 {
		if len(states) == 0 {
			return auditFreshEmpty, nil
		}
		state := states[0]
		if state.ID != 1 || state.ChainVersion != chainVersionV1 || state.HeadHash != "" {
			return 0, auditIntegrityError("invalid empty chain state")
		}
		return auditFullyChained, nil
	}

	allEmpty := true
	allComplete := true
	for _, event := range events {
		empty := event.ChainVersion == "" && event.PrevHash == "" && event.EventHash == ""
		complete := event.ChainVersion == chainVersionV1 && validHashOrGenesis(event.PrevHash) && validHash(event.EventHash)
		allEmpty = allEmpty && empty
		allComplete = allComplete && complete
	}
	if allEmpty {
		if len(states) != 0 {
			return 0, auditIntegrityError("legacy history has partial chain state")
		}
		return auditLegacyAllUnchained, nil
	}
	if allComplete {
		if len(states) != 1 || states[0].ID != 1 || states[0].ChainVersion != chainVersionV1 || !validHash(states[0].HeadHash) {
			return 0, auditIntegrityError("chained history has incomplete state")
		}
		return auditFullyChained, nil
	}
	return 0, auditIntegrityError("mixed or partial audit chain")
}

func createChainState(tx *gorm.DB, headHash string, now time.Time) error {
	state := models.AuditChainState{ID: 1, ChainVersion: chainVersionV1, HeadHash: headHash, UpdatedAt: now}
	if err := tx.Create(&state).Error; err != nil {
		return fmt.Errorf("%w: chain state create failed", ErrAuditIntegrity)
	}
	return nil
}

func backfillLegacyEvents(tx *gorm.DB, events []models.AuditEvent) error {
	previous := ""
	for _, event := range events {
		event.ChainVersion = chainVersionV1
		event.PrevHash = previous
		event.EventHash = eventHash(event)
		result := tx.Exec("UPDATE audit_events SET chain_version = ?, prev_hash = ?, event_hash = ? WHERE id = ?",
			event.ChainVersion, event.PrevHash, event.EventHash, event.ID)
		if result.Error != nil || result.RowsAffected != 1 {
			return fmt.Errorf("%w: legacy audit backfill failed", ErrAuditIntegrity)
		}
		previous = event.EventHash
	}
	if err := createChainState(tx, previous, time.Now().UTC()); err != nil {
		return err
	}
	return nil
}

type auditTriggerDefinition struct {
	Name string
	SQL  string
}

func loadTriggerDefinitions(db *gorm.DB) (map[string]string, error) {
	var rows []auditTriggerDefinition
	if err := db.Raw("SELECT name, sql FROM sqlite_master WHERE type = 'trigger' AND tbl_name = 'audit_events'").Scan(&rows).Error; err != nil {
		return nil, auditIntegrityError("audit trigger metadata unavailable")
	}
	definitions := make(map[string]string, len(rows))
	for _, row := range rows {
		definitions[row.Name] = row.SQL
	}
	return definitions, nil
}

func normalizeTriggerSQL(sql string) string {
	return strings.Join(strings.Fields(strings.ToLower(sql)), " ")
}

func ensureExactMutationTriggers(tx *gorm.DB, existing map[string]string) error {
	want := map[string]string{
		auditUpdateTriggerName: auditUpdateTriggerSQL,
		auditDeleteTriggerName: auditDeleteTriggerSQL,
	}
	for name, definition := range existing {
		wantDefinition, ok := want[name]
		if !ok || normalizeTriggerSQL(definition) != normalizeTriggerSQL(wantDefinition) {
			return auditIntegrityError("audit trigger definition mismatch")
		}
	}
	for name, definition := range want {
		if _, ok := existing[name]; ok {
			continue
		}
		if err := tx.Exec(definition).Error; err != nil {
			return fmt.Errorf("%w: audit trigger installation failed", ErrAuditIntegrity)
		}
	}
	return nil
}
