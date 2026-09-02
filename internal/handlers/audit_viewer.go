package handlers

import (
	"errors"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"ai-gateway/internal/audit"
)

type AuditViewRow struct {
	ID           int64
	EventID      string
	Action       string
	ActorType    string
	ActorID      string
	TargetType   string
	TargetID     string
	Reason       string
	CreatedAt    time.Time
	ChainVersion string
	PrevHash     string
	EventHash    string
}

type AuditViewPage struct {
	Events        []AuditViewRow
	NextURL       string
	HasMore       bool
	Limit         int
	Action        string
	ActorType     string
	ActorID       string
	TargetType    string
	TargetID      string
	ActionOptions []string
	ActorTypes    []string
	TargetTypes   []string
}

var auditViewerQueryParameters = map[string]struct{}{
	"before_id":   {},
	"limit":       {},
	"action":      {},
	"actor_type":  {},
	"actor_id":    {},
	"target_type": {},
	"target_id":   {},
}

func parseAuditQuery(values url.Values) (audit.Query, error) {
	for name := range values {
		if _, ok := auditViewerQueryParameters[name]; !ok {
			return audit.Query{}, audit.ErrInvalidAuditQuery
		}
	}
	query := audit.Query{}
	readSingle := func(name string) (string, bool, error) {
		items, ok := values[name]
		if !ok {
			return "", false, nil
		}
		if len(items) != 1 || items[0] == "" {
			return "", true, audit.ErrInvalidAuditQuery
		}
		return items[0], true, nil
	}

	if raw, present, err := readSingle("limit"); err != nil {
		return audit.Query{}, err
	} else if present {
		limit, parseErr := strconv.ParseInt(raw, 10, 32)
		if parseErr != nil || limit < 1 || limit > audit.MaxAuditQueryLimit {
			return audit.Query{}, audit.ErrInvalidAuditQuery
		}
		query.Limit = int(limit)
	}
	if raw, present, err := readSingle("before_id"); err != nil {
		return audit.Query{}, err
	} else if present {
		beforeID, parseErr := strconv.ParseInt(raw, 10, 64)
		if parseErr != nil || beforeID <= 0 {
			return audit.Query{}, audit.ErrInvalidAuditQuery
		}
		query.BeforeID = beforeID
	}
	for _, field := range []struct {
		name  string
		value *string
	}{
		{name: "action", value: &query.Action},
		{name: "actor_type", value: &query.ActorType},
		{name: "actor_id", value: &query.ActorID},
		{name: "target_type", value: &query.TargetType},
		{name: "target_id", value: &query.TargetID},
	} {
		raw, present, err := readSingle(field.name)
		if err != nil {
			return audit.Query{}, err
		}
		if present {
			*field.value = raw
		}
	}
	if query.Limit == 0 {
		query.Limit = audit.DefaultAuditQueryLimit
	}
	return query, nil
}

func auditViewerActions() []string {
	return []string{
		audit.ActionClientCreated,
		audit.ActionClientKeyRotated,
		audit.ActionClientSuspended,
		audit.ActionClientResumed,
		audit.ActionClientRevoked,
		audit.ActionClientDeleted,
		audit.ActionClientSettingsUpdated,
		audit.ActionClientProviderSecretChanged,
		audit.ActionClientModelsUpdated,
		audit.ActionServerToolsUpdated,
		audit.ActionGlobalProviderSecretChanged,
		audit.ActionAdminLoginSucceeded,
		audit.ActionAdminLogout,
		audit.ActionSetupCompleted,
		audit.ActionRequestBodyCaptureRead,
		audit.ActionAdminPasswordReset,
		audit.ActionProviderSecretMigrationStarted,
		audit.ActionProviderSecretMigration,
		audit.ActionRequestLogScrubStarted,
		audit.ActionRequestLogScrub,
	}
}

func auditViewerTypes() ([]string, []string) {
	return []string{"admin", "cli", "setup"}, []string{"admin", "client", "provider", "request-capture", "server", "maintenance-operation"}
}

func auditViewPageFromQuery(page audit.Page, query audit.Query) AuditViewPage {
	rows := make([]AuditViewRow, len(page.Events))
	for i, event := range page.Events {
		rows[i] = AuditViewRow{
			ID: event.ID, EventID: event.EventID, Action: event.Action,
			ActorType: event.ActorType, ActorID: event.ActorID,
			TargetType: event.TargetType, TargetID: event.TargetID,
			Reason: event.Reason, CreatedAt: event.CreatedAt,
			ChainVersion: event.ChainVersion, PrevHash: event.PrevHash, EventHash: event.EventHash,
		}
	}
	actorTypes, targetTypes := auditViewerTypes()
	view := AuditViewPage{
		Events: rows, HasMore: page.HasMore, Limit: query.Limit,
		Action: query.Action, ActorType: query.ActorType, ActorID: query.ActorID,
		TargetType: query.TargetType, TargetID: query.TargetID,
		ActionOptions: auditViewerActions(), ActorTypes: actorTypes, TargetTypes: targetTypes,
	}
	if page.HasMore {
		params := url.Values{}
		params.Set("before_id", strconv.FormatInt(page.NextBeforeID, 10))
		params.Set("limit", strconv.Itoa(query.Limit))
		if query.Action != "" {
			params.Set("action", query.Action)
		}
		if query.ActorType != "" {
			params.Set("actor_type", query.ActorType)
		}
		if query.ActorID != "" {
			params.Set("actor_id", query.ActorID)
		}
		if query.TargetType != "" {
			params.Set("target_type", query.TargetType)
		}
		if query.TargetID != "" {
			params.Set("target_id", query.TargetID)
		}
		view.NextURL = "/admin/audit?" + params.Encode()
	}
	return view
}

func (h *AdminHandler) ShowAuditLog(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	actor, ok := adminActorFromContext(r.Context())
	if !ok {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	query, err := parseAuditQuery(r.URL.Query())
	if err != nil {
		http.Error(w, "Invalid audit query", http.StatusBadRequest)
		return
	}
	if h.clientService == nil || h.clientService.AuditService() == nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	page, err := h.clientService.AuditService().QueryPage(query)
	if err != nil {
		if errors.Is(err, audit.ErrInvalidAuditQuery) {
			http.Error(w, "Invalid audit query", http.StatusBadRequest)
			return
		}
		logAuditViewerError(r, err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	h.render(r, w, "audit.html", PageData{
		Title: "Audit Log", User: actor, Data: auditViewPageFromQuery(page, query),
	})
}

func (h *AdminHandler) auditNoStore(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Pragma", "no-cache")
		next.ServeHTTP(w, r)
	})
}

func logAuditViewerError(r *http.Request, err error) {
	if r != nil && r.URL != nil {
		log.Printf("[ADMIN] audit viewer query failed for %s: %v", r.URL.Path, err)
	}
}
