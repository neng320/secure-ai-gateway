package audit

import (
	"errors"
	"unicode"
	"unicode/utf8"

	"ai-gateway/internal/models"
)

const (
	DefaultAuditQueryLimit = 50
	MaxAuditQueryLimit     = 100
)

var ErrInvalidAuditQuery = errors.New("invalid audit query")

// Query is the bounded, exact-match query contract used by the Admin viewer.
// BeforeID uses the same signed domain as AuditEvent.ID; zero means the first
// page and negative values are invalid.
type Query struct {
	BeforeID   int64
	Limit      int
	Action     string
	ActorType  string
	ActorID    string
	TargetType string
	TargetID   string
}

type Page struct {
	Events       []models.AuditEvent
	NextBeforeID int64
	HasMore      bool
}

var allowedAuditActorTypes = map[string]struct{}{
	"admin": {},
	"cli":   {},
	"setup": {},
}

var allowedAuditTargetTypes = map[string]struct{}{
	"admin":           {},
	"client":          {},
	"provider":        {},
	"request-capture": {},
	"server":          {},
}

const auditViewerProjection = "id, event_id, action, actor_type, actor_id, target_type, target_id, reason, created_at, chain_version, prev_hash, event_hash"

func validateAuditQueryText(value string, maxRunes int, vocabulary map[string]struct{}) error {
	if value == "" || !utf8.ValidString(value) || len([]rune(value)) > maxRunes {
		return ErrInvalidAuditQuery
	}
	for _, r := range value {
		if unicode.IsControl(r) {
			return ErrInvalidAuditQuery
		}
	}
	if vocabulary != nil {
		if _, ok := vocabulary[value]; !ok {
			return ErrInvalidAuditQuery
		}
	}
	return nil
}

func normalizeAuditQuery(query Query) (Query, error) {
	if query.Limit == 0 {
		query.Limit = DefaultAuditQueryLimit
	}
	if query.Limit < 1 || query.Limit > MaxAuditQueryLimit {
		return Query{}, ErrInvalidAuditQuery
	}
	if query.BeforeID < 0 {
		return Query{}, ErrInvalidAuditQuery
	}
	if query.Action != "" && !IsKnownAction(query.Action) {
		return Query{}, ErrInvalidAuditQuery
	}
	if query.ActorType != "" {
		if err := validateAuditQueryText(query.ActorType, 32, allowedAuditActorTypes); err != nil {
			return Query{}, err
		}
	}
	if query.TargetType != "" {
		if err := validateAuditQueryText(query.TargetType, 32, allowedAuditTargetTypes); err != nil {
			return Query{}, err
		}
	}
	if query.ActorID != "" {
		if err := validateAuditQueryText(query.ActorID, 255, nil); err != nil {
			return Query{}, err
		}
	}
	if query.TargetID != "" {
		if err := validateAuditQueryText(query.TargetID, 36, nil); err != nil {
			return Query{}, err
		}
	}
	return query, nil
}

// QueryPage performs SELECT-only keyset pagination. The fixed projection and
// fixed WHERE clauses are deliberate: request input is always a placeholder
// value and future AuditEvent fields do not become viewer-visible implicitly.
func (s *Service) QueryPage(query Query) (Page, error) {
	if s == nil || s.db == nil {
		return Page{}, ErrInvalidAuditQuery
	}
	query, err := normalizeAuditQuery(query)
	if err != nil {
		return Page{}, err
	}

	db := s.db.Select(auditViewerProjection).Order("id DESC").Limit(query.Limit + 1)
	if query.BeforeID != 0 {
		db = db.Where("id < ?", query.BeforeID)
	}
	if query.Action != "" {
		db = db.Where("action = ?", query.Action)
	}
	if query.ActorType != "" {
		db = db.Where("actor_type = ?", query.ActorType)
	}
	if query.ActorID != "" {
		db = db.Where("actor_id = ?", query.ActorID)
	}
	if query.TargetType != "" {
		db = db.Where("target_type = ?", query.TargetType)
	}
	if query.TargetID != "" {
		db = db.Where("target_id = ?", query.TargetID)
	}

	var events []models.AuditEvent
	if err := db.Find(&events).Error; err != nil {
		return Page{}, err
	}
	page := Page{Events: events}
	if len(page.Events) > query.Limit {
		page.HasMore = true
		page.Events = page.Events[:query.Limit]
		page.NextBeforeID = page.Events[len(page.Events)-1].ID
	}
	return page, nil
}
