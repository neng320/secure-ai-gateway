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

const (
	createAuditEventsTableSQL = `CREATE TABLE audit_events (
		id integer PRIMARY KEY AUTOINCREMENT,
		event_id varchar(64),
		action varchar(64),
		actor_type varchar(32),
		actor_id varchar(255),
		target_type varchar(32),
		target_id varchar(36),
		reason varchar(256),
		created_at datetime,
		chain_version varchar(16),
		prev_hash varchar(64),
		event_hash varchar(64)
	)`
	createChainStateTableSQL = `CREATE TABLE audit_chain_states (
		id integer PRIMARY KEY,
		chain_version varchar(16),
		head_hash varchar(64),
		updated_at datetime
	)`
)

var auditEventIndexSQL = []string{
	"CREATE UNIQUE INDEX IF NOT EXISTS idx_audit_events_event_id ON audit_events(event_id)",
	"CREATE INDEX IF NOT EXISTS idx_audit_events_action ON audit_events(action)",
	"CREATE INDEX IF NOT EXISTS idx_audit_events_actor_id ON audit_events(actor_id)",
	"CREATE INDEX IF NOT EXISTS idx_audit_events_target_type ON audit_events(target_type)",
	"CREATE INDEX IF NOT EXISTS idx_audit_events_target_id ON audit_events(target_id)",
	"CREATE INDEX IF NOT EXISTS idx_audit_events_created_at ON audit_events(created_at)",
	"CREATE INDEX IF NOT EXISTS idx_audit_events_chain_version ON audit_events(chain_version)",
	"CREATE INDEX IF NOT EXISTS idx_audit_events_prev_hash ON audit_events(prev_hash)",
	"CREATE INDEX IF NOT EXISTS idx_audit_events_event_hash ON audit_events(event_hash)",
}

var chainStateIndexSQL = []string{
	"CREATE INDEX IF NOT EXISTS idx_audit_chain_states_updated_at ON audit_chain_states(updated_at)",
}

type auditHistoryClass uint8

const (
	auditFreshEmpty auditHistoryClass = iota
	auditLegacyAllUnchained
	auditFullyChained
)

type auditSchemaFamily uint8

const (
	auditSchemaFreshNoTable auditSchemaFamily = iota
	auditSchemaLegacyP105C
	auditSchemaCurrentChain
	auditSchemaCurrentEmptyNoState
)

type sqliteTableColumn struct {
	Name string `gorm:"column:name"`
	Type string `gorm:"column:type"`
	PK   int    `gorm:"column:pk"`
}

type auditSchemaSnapshot struct {
	eventTableExists bool
	stateTableExists bool
	eventColumns     map[string]sqliteTableColumn
	stateColumns     map[string]sqliteTableColumn
	triggers         map[string]string
	family           auditSchemaFamily
}

var legacyAuditColumns = map[string]string{
	"id":          "integer",
	"event_id":    "varchar(64)",
	"action":      "varchar(64)",
	"actor_type":  "varchar(32)",
	"actor_id":    "varchar(255)",
	"target_type": "varchar(32)",
	"target_id":   "varchar(36)",
	"reason":      "varchar(256)",
	"created_at":  "datetime",
}

var chainAuditColumns = map[string]string{
	"chain_version": "varchar(16)",
	"prev_hash":     "varchar(64)",
	"event_hash":    "varchar(64)",
}

var chainStateColumns = map[string]string{
	"id":            "integer",
	"chain_version": "varchar(16)",
	"head_hash":     "varchar(64)",
	"updated_at":    "datetime",
}

// MigrateIntegrity owns all AuditEvent schema changes, legacy backfill,
// verification, and mutation-trigger installation in one SQLite transaction.
// The pre-migration schema is classified before any audit DDL is executed.
func MigrateIntegrity(db *gorm.DB) error {
	if db == nil {
		return ErrAuditIntegrity
	}
	return db.Transaction(func(tx *gorm.DB) error {
		schema, err := inspectAuditSchema(tx)
		if err != nil {
			return err
		}

		switch schema.family {
		case auditSchemaFreshNoTable:
			if err := createFreshAuditSchema(tx); err != nil {
				return err
			}
			if err := insertChainState(tx, ""); err != nil {
				return err
			}
		case auditSchemaLegacyP105C:
			if err := addLegacyChainColumns(tx); err != nil {
				return err
			}
			if err := createChainStateTable(tx); err != nil {
				return err
			}
			events, err := loadAuditEvents(tx)
			if err != nil {
				return err
			}
			if err := backfillLegacyEvents(tx, events); err != nil {
				return err
			}
		case auditSchemaCurrentEmptyNoState:
			if err := createChainStateTable(tx); err != nil {
				return err
			}
			events, err := loadAuditEvents(tx)
			if err != nil {
				return err
			}
			if len(events) == 0 {
				if err := insertChainState(tx, ""); err != nil {
					return err
				}
			} else if err := backfillLegacyEvents(tx, events); err != nil {
				return err
			}
		case auditSchemaCurrentChain:
			// The current schema has already been classified and is verified below.
		default:
			return ErrAuditIntegrity
		}

		if err := verifyAuditChainDB(tx); err != nil {
			return err
		}
		if err := ensureExactMutationTriggers(tx, schema.triggers); err != nil {
			return err
		}
		return nil
	})
}

func inspectAuditSchema(db *gorm.DB) (auditSchemaSnapshot, error) {
	schema := auditSchemaSnapshot{eventColumns: map[string]sqliteTableColumn{}, stateColumns: map[string]sqliteTableColumn{}}
	var err error
	schema.eventTableExists, err = sqliteTableExists(db, "audit_events")
	if err != nil {
		return schema, auditIntegrityError("audit event schema unavailable")
	}
	schema.stateTableExists, err = sqliteTableExists(db, "audit_chain_states")
	if err != nil {
		return schema, auditIntegrityError("chain state schema unavailable")
	}
	schema.triggers, err = loadTriggerDefinitions(db)
	if err != nil {
		return schema, err
	}
	if !schema.eventTableExists {
		if schema.stateTableExists || len(schema.triggers) != 0 {
			return schema, auditIntegrityError("audit schema has orphaned integrity objects")
		}
		schema.family = auditSchemaFreshNoTable
		return schema, nil
	}

	schema.eventColumns, err = loadTableColumns(db, "audit_events")
	if err != nil {
		return schema, auditIntegrityError("audit event schema unavailable")
	}
	if !hasExpectedColumns(schema.eventColumns, legacyAuditColumns) {
		return schema, auditIntegrityError("audit event legacy schema is incomplete")
	}
	chainColumnCount := countColumns(schema.eventColumns, chainAuditColumns)
	switch chainColumnCount {
	case 0:
		if schema.stateTableExists || len(schema.triggers) != 0 {
			return schema, auditIntegrityError("legacy audit schema has partial integrity objects")
		}
		schema.family = auditSchemaLegacyP105C
		return schema, nil
	case len(chainAuditColumns):
		if schema.stateTableExists {
			schema.stateColumns, err = loadTableColumns(db, "audit_chain_states")
			if err != nil || !hasExpectedColumns(schema.stateColumns, chainStateColumns) {
				return schema, auditIntegrityError("chain state schema is incomplete")
			}
			if err := validateExistingTriggerDefinitions(schema.triggers); err != nil {
				return schema, err
			}
			schema.family = auditSchemaCurrentChain
			return schema, nil
		}
		if len(schema.triggers) != 0 {
			return schema, auditIntegrityError("chained audit schema has triggers but no chain state")
		}
		events, loadErr := loadAuditEvents(db)
		if loadErr != nil {
			return schema, loadErr
		}
		for _, event := range events {
			if event.ChainVersion != "" || event.PrevHash != "" || event.EventHash != "" {
				return schema, auditIntegrityError("chained audit history has no chain state")
			}
		}
		schema.family = auditSchemaCurrentEmptyNoState
		return schema, nil
	default:
		return schema, auditIntegrityError("audit event chain schema is partial")
	}
}

func sqliteTableExists(db *gorm.DB, name string) (bool, error) {
	var count int64
	if err := db.Raw("SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name = ?", name).Scan(&count).Error; err != nil {
		return false, err
	}
	return count == 1, nil
}

func loadTableColumns(db *gorm.DB, table string) (map[string]sqliteTableColumn, error) {
	var columns []sqliteTableColumn
	if err := db.Raw("PRAGMA table_info(" + table + ")").Scan(&columns).Error; err != nil {
		return nil, err
	}
	result := make(map[string]sqliteTableColumn, len(columns))
	for _, column := range columns {
		result[strings.ToLower(column.Name)] = column
	}
	return result, nil
}

func normalizeSQLiteType(value string) string {
	return strings.ToLower(strings.Join(strings.Fields(strings.TrimSpace(value)), ""))
}

func hasExpectedColumns(actual map[string]sqliteTableColumn, expected map[string]string) bool {
	for name, wantType := range expected {
		column, ok := actual[name]
		if !ok || normalizeSQLiteType(column.Type) != normalizeSQLiteType(wantType) {
			return false
		}
		if name == "id" && column.PK != 1 {
			return false
		}
	}
	return true
}

func countColumns(actual map[string]sqliteTableColumn, expected map[string]string) int {
	count := 0
	for name := range expected {
		if _, ok := actual[name]; ok {
			count++
		}
	}
	return count
}

func createFreshAuditSchema(tx *gorm.DB) error {
	if err := tx.Exec(createAuditEventsTableSQL).Error; err != nil {
		return fmt.Errorf("%w: audit event table creation failed", ErrAuditIntegrity)
	}
	for _, statement := range auditEventIndexSQL {
		if err := tx.Exec(statement).Error; err != nil {
			return fmt.Errorf("%w: audit event index creation failed", ErrAuditIntegrity)
		}
	}
	return createChainStateTable(tx)
}

func addLegacyChainColumns(tx *gorm.DB) error {
	for _, statement := range []string{
		"ALTER TABLE audit_events ADD COLUMN chain_version varchar(16)",
		"ALTER TABLE audit_events ADD COLUMN prev_hash varchar(64)",
		"ALTER TABLE audit_events ADD COLUMN event_hash varchar(64)",
	} {
		if err := tx.Exec(statement).Error; err != nil {
			return fmt.Errorf("%w: audit chain column migration failed", ErrAuditIntegrity)
		}
	}
	for _, statement := range auditEventIndexSQL[6:] {
		if err := tx.Exec(statement).Error; err != nil {
			return fmt.Errorf("%w: audit chain index creation failed", ErrAuditIntegrity)
		}
	}
	return nil
}

func createChainStateTable(tx *gorm.DB) error {
	if err := tx.Exec(createChainStateTableSQL).Error; err != nil {
		return fmt.Errorf("%w: chain state table creation failed", ErrAuditIntegrity)
	}
	for _, statement := range chainStateIndexSQL {
		if err := tx.Exec(statement).Error; err != nil {
			return fmt.Errorf("%w: chain state index creation failed", ErrAuditIntegrity)
		}
	}
	return nil
}

func insertChainState(tx *gorm.DB, headHash string) error {
	state := models.AuditChainState{ID: 1, ChainVersion: chainVersionV1, HeadHash: headHash, UpdatedAt: time.Now().UTC()}
	if err := tx.Create(&state).Error; err != nil {
		return fmt.Errorf("%w: chain state create failed", ErrAuditIntegrity)
	}
	return nil
}

func loadAuditEvents(db *gorm.DB) ([]models.AuditEvent, error) {
	var events []models.AuditEvent
	if err := db.Order("id ASC").Find(&events).Error; err != nil {
		return nil, auditIntegrityError("audit history unavailable")
	}
	return events, nil
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
	return insertChainState(tx, previous)
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

func validateExistingTriggerDefinitions(existing map[string]string) error {
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
	return nil
}

func ensureExactMutationTriggers(tx *gorm.DB, existing map[string]string) error {
	if err := validateExistingTriggerDefinitions(existing); err != nil {
		return err
	}
	want := map[string]string{
		auditUpdateTriggerName: auditUpdateTriggerSQL,
		auditDeleteTriggerName: auditDeleteTriggerSQL,
	}
	for name, definition := range want {
		if _, ok := existing[name]; ok {
			continue
		}
		if err := tx.Exec(definition).Error; err != nil {
			return fmt.Errorf("%w: audit trigger installation failed", ErrAuditIntegrity)
		}
	}
	installed, err := loadTriggerDefinitions(tx)
	if err != nil {
		return err
	}
	if len(installed) != len(want) {
		return auditIntegrityError("audit trigger set incomplete")
	}
	for name, definition := range want {
		if installed[name] == "" || normalizeTriggerSQL(installed[name]) != normalizeTriggerSQL(definition) {
			return auditIntegrityError("audit trigger definition mismatch")
		}
	}
	return nil
}
