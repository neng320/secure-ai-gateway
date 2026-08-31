package audit

import (
	"errors"
	"fmt"
	"testing"

	"ai-gateway/internal/models"
)

func recordS6QueryEvent(t *testing.T, svc *Service, action, actorType, actorID, targetType, targetID string) {
	t.Helper()
	if err := svc.Record(modelsAuditEventForS6(action, actorType, actorID, targetType, targetID)); err != nil {
		t.Fatal(err)
	}
}

func modelsAuditEventForS6(action, actorType, actorID, targetType, targetID string) models.AuditEvent {
	return models.AuditEvent{Action: action, ActorType: actorType, ActorID: actorID, TargetType: targetType, TargetID: targetID}
}

func TestP108B_S6_QueryDefaultLimit(t *testing.T) {
	db := newAuditTestDB(t)
	svc := NewService(db)
	for i := 0; i < DefaultAuditQueryLimit+1; i++ {
		recordS6QueryEvent(t, svc, ActionClientCreated, "admin", "query-admin", "client", fmt.Sprintf("client-%03d", i))
	}

	page, err := svc.QueryPage(Query{})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Events) != DefaultAuditQueryLimit || !page.HasMore || page.NextBeforeID == 0 {
		t.Fatalf("default page = len:%d hasMore:%v next:%d", len(page.Events), page.HasMore, page.NextBeforeID)
	}
}

func TestP108B_S6_QueryLimitCap(t *testing.T) {
	db := newAuditTestDB(t)
	svc := NewService(db)
	for _, limit := range []int{-1, MaxAuditQueryLimit + 1} {
		if _, err := svc.QueryPage(Query{Limit: limit}); !errors.Is(err, ErrInvalidAuditQuery) {
			t.Fatalf("limit %d error = %v", limit, err)
		}
	}
}

func TestP108B_S6_CursorPaginationNoDuplicates(t *testing.T) {
	db := newAuditTestDB(t)
	svc := NewService(db)
	for i := 0; i < 5; i++ {
		recordS6QueryEvent(t, svc, ActionClientCreated, "admin", "query-admin", "client", fmt.Sprintf("client-%d", i))
	}

	first, err := svc.QueryPage(Query{Limit: 2})
	if err != nil {
		t.Fatal(err)
	}
	second, err := svc.QueryPage(Query{Limit: 2, BeforeID: first.NextBeforeID})
	if err != nil {
		t.Fatal(err)
	}
	if len(first.Events) != 2 || len(second.Events) != 2 {
		t.Fatalf("unexpected page sizes: %d, %d", len(first.Events), len(second.Events))
	}
	if first.Events[1].ID <= second.Events[0].ID {
		t.Fatalf("cursor did not move backwards: first tail=%d second head=%d", first.Events[1].ID, second.Events[0].ID)
	}
	for _, older := range second.Events {
		for _, newer := range first.Events {
			if older.ID == newer.ID {
				t.Fatalf("duplicate event id %d across pages", older.ID)
			}
		}
	}
}

func TestP108B_S6_CursorStableAcrossConcurrentAppend(t *testing.T) {
	db := newAuditTestDB(t)
	svc := NewService(db)
	for i := 0; i < 4; i++ {
		recordS6QueryEvent(t, svc, ActionClientCreated, "admin", "query-admin", "client", fmt.Sprintf("original-%d", i))
	}

	first, err := svc.QueryPage(Query{Limit: 2})
	if err != nil {
		t.Fatal(err)
	}
	recordS6QueryEvent(t, svc, ActionClientCreated, "admin", "query-admin", "client", "new-event")
	second, err := svc.QueryPage(Query{Limit: 2, BeforeID: first.NextBeforeID})
	if err != nil {
		t.Fatal(err)
	}
	if len(second.Events) != 2 || second.Events[0].TargetID != "original-1" || second.Events[1].TargetID != "original-0" {
		t.Fatalf("new append shifted cursor page: %+v", second.Events)
	}
}

func TestP108B_S6_ExactFilters(t *testing.T) {
	db := newAuditTestDB(t)
	svc := NewService(db)
	recordS6QueryEvent(t, svc, ActionClientCreated, "admin", "alice", "client", "client-a")
	recordS6QueryEvent(t, svc, ActionClientDeleted, "cli", "set-provider-key", "provider", "openai")

	page, err := svc.QueryPage(Query{Limit: 100, Action: ActionClientCreated, ActorType: "admin", ActorID: "alice", TargetType: "client", TargetID: "client-a"})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Events) != 1 || page.Events[0].TargetID != "client-a" {
		t.Fatalf("exact filters returned %+v", page.Events)
	}
}

func TestP108B_S6_InvalidFiltersRejected(t *testing.T) {
	db := newAuditTestDB(t)
	svc := NewService(db)
	cases := []Query{
		{Action: "UNKNOWN"},
		{ActorType: "operator"},
		{TargetType: "unknown"},
		{ActorID: "bad\nactor"},
		{ActorID: string(make([]byte, 1))},
		{TargetID: "bad\ttarget"},
	}
	for _, query := range cases {
		if _, err := svc.QueryPage(query); !errors.Is(err, ErrInvalidAuditQuery) {
			t.Fatalf("query %+v error = %v", query, err)
		}
	}
}

func TestP108B_S6_WildcardsDoNotBroaden(t *testing.T) {
	db := newAuditTestDB(t)
	svc := NewService(db)
	recordS6QueryEvent(t, svc, ActionClientCreated, "admin", "literal%", "client", "literal*")
	recordS6QueryEvent(t, svc, ActionClientCreated, "admin", "other", "client", "other")

	page, err := svc.QueryPage(Query{Limit: 100, ActorID: "literal%", TargetID: "literal*"})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Events) != 1 || page.Events[0].ActorID != "literal%" {
		t.Fatalf("wildcard-like exact values broadened result: %+v", page.Events)
	}
}
