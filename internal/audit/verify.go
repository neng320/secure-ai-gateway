package audit

import (
	"encoding/hex"
	"fmt"
	"strings"

	"ai-gateway/internal/models"

	"gorm.io/gorm"
)

// VerificationSummary is the bounded output of offline audit verification.
// It intentionally contains no event fields or operational configuration.
type VerificationSummary struct {
	EventCount int64
	HeadHash   string
}

func auditIntegrityError(reason string) error {
	return fmt.Errorf("%w: %s", ErrAuditIntegrity, reason)
}

func validHash(value string) bool {
	if len(value) != 64 || strings.ToLower(value) != value {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func validHashOrGenesis(value string) bool {
	return value == "" || validHash(value)
}

func verifyAuditChainDB(db *gorm.DB) error {
	var states []models.AuditChainState
	if err := db.Order("id ASC").Find(&states).Error; err != nil {
		return auditIntegrityError("chain state unavailable")
	}
	if len(states) != 1 || states[0].ID != 1 {
		return auditIntegrityError("invalid chain state singleton")
	}
	state := states[0]
	if state.ChainVersion != chainVersionV1 || !validHashOrGenesis(state.HeadHash) {
		return auditIntegrityError("unsupported chain state")
	}

	var events []models.AuditEvent
	if err := db.Order("id ASC").Find(&events).Error; err != nil {
		return auditIntegrityError("audit history unavailable")
	}
	previous := ""
	for index, event := range events {
		if event.ChainVersion != chainVersionV1 || event.EventID == "" || !IsKnownAction(event.Action) || event.CreatedAt.IsZero() {
			return auditIntegrityError("invalid audit event")
		}
		if index == 0 && event.PrevHash != "" {
			return auditIntegrityError("invalid genesis")
		}
		if index > 0 && event.PrevHash != previous {
			return auditIntegrityError("audit chain link mismatch")
		}
		if !validHashOrGenesis(event.PrevHash) || !validHash(event.EventHash) || eventHash(event) != event.EventHash {
			return auditIntegrityError("audit event hash mismatch")
		}
		previous = event.EventHash
	}
	if state.HeadHash != previous {
		return auditIntegrityError("chain state head mismatch")
	}
	return nil
}

// VerifyIntegrityReadOnly verifies an already-migrated audit database in one
// read transaction. It never calls migration or performs repair DDL/DML.
func VerifyIntegrityReadOnly(db *gorm.DB) (VerificationSummary, error) {
	if db == nil {
		return VerificationSummary{}, ErrAuditIntegrity
	}
	var summary VerificationSummary
	err := db.Transaction(func(tx *gorm.DB) error {
		schema, err := inspectAuditSchema(tx)
		if err != nil {
			return err
		}
		if schema.family == auditSchemaFreshNoTable || schema.family == auditSchemaLegacyP105C {
			return ErrAuditMigrationRequired
		}
		if schema.family != auditSchemaCurrentChain {
			return ErrAuditIntegrity
		}
		if err := verifyExpectedAuditIndexes(tx, auditIndexSpecs); err != nil {
			return err
		}
		if err := verifyExactMutationTriggers(schema.triggers); err != nil {
			return err
		}
		if err := verifyAuditChainDB(tx); err != nil {
			return err
		}
		if err := tx.Model(&models.AuditEvent{}).Count(&summary.EventCount).Error; err != nil {
			return auditIntegrityError("audit history unavailable")
		}
		var state models.AuditChainState
		if err := tx.Where("id = ?", 1).First(&state).Error; err != nil {
			return auditIntegrityError("chain state unavailable")
		}
		summary.HeadHash = state.HeadHash
		return nil
	})
	return summary, err
}
