package audit

import (
	"encoding/hex"
	"fmt"
	"strings"

	"ai-gateway/internal/models"

	"gorm.io/gorm"
)

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
