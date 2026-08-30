package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"strings"

	"ai-gateway/internal/models"
)

const chainVersionV1 = "v1"

func canonicalEventBytes(event models.AuditEvent) []byte {
	fields := []string{
		event.ChainVersion,
		event.PrevHash,
		event.EventID,
		event.Action,
		event.ActorType,
		event.ActorID,
		event.TargetType,
		event.TargetID,
		event.Reason,
		strconv.FormatInt(event.CreatedAt.UTC().UnixNano(), 10),
	}

	var encoded strings.Builder
	encoded.WriteString("AUDIT-EVENT-V1|")
	for _, field := range fields {
		value := []byte(field)
		encoded.WriteString(strconv.Itoa(len(value)))
		encoded.WriteByte(':')
		encoded.Write(value)
		encoded.WriteByte('|')
	}
	return []byte(encoded.String())
}

func eventHash(event models.AuditEvent) string {
	digest := sha256.Sum256(canonicalEventBytes(event))
	return hex.EncodeToString(digest[:])
}
