package audit

import (
	"errors"
	"math"
	"strings"
	"testing"

	"ai-gateway/internal/models"
)

func TestP108B_S61_CursorFieldsMatchAuditEventID(t *testing.T) {
	var event models.AuditEvent
	var query Query
	var page Page
	query.BeforeID = event.ID
	event.ID = page.NextBeforeID
}

func TestP108B_S61_BeforeIDDomain(t *testing.T) {
	db := newAuditTestDB(t)
	svc := NewService(db)
	for _, beforeID := range []int64{0, 1, math.MaxInt64} {
		if _, err := svc.QueryPage(Query{BeforeID: beforeID, Limit: 1}); err != nil {
			t.Fatalf("before_id=%d error=%v", beforeID, err)
		}
	}
	if _, err := svc.QueryPage(Query{BeforeID: -1, Limit: 1}); !errors.Is(err, ErrInvalidAuditQuery) {
		t.Fatalf("negative service cursor error=%v", err)
	}
}

func TestP108B_S61_ExactPageBoundaries(t *testing.T) {
	for _, tc := range []struct {
		name          string
		rows          int
		expectHasMore bool
	}{
		{name: "less than limit", rows: 2, expectHasMore: false},
		{name: "exact limit", rows: 3, expectHasMore: false},
		{name: "limit plus one", rows: 4, expectHasMore: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db := newAuditTestDB(t)
			svc := NewService(db)
			for i := 0; i < tc.rows; i++ {
				recordS6QueryEvent(t, svc, ActionClientCreated, "admin", "boundary-admin", "client", "boundary-"+string(rune('a'+i)))
			}
			page, err := svc.QueryPage(Query{Limit: 3})
			if err != nil {
				t.Fatal(err)
			}
			if page.HasMore != tc.expectHasMore {
				t.Fatalf("has_more=%v want=%v", page.HasMore, tc.expectHasMore)
			}
			if !page.HasMore && page.NextBeforeID != 0 {
				t.Fatalf("next cursor=%d for terminal page", page.NextBeforeID)
			}
			if page.HasMore && page.NextBeforeID != page.Events[len(page.Events)-1].ID {
				t.Fatalf("next cursor=%d want last returned id=%d", page.NextBeforeID, page.Events[len(page.Events)-1].ID)
			}
		})
	}
}

func TestP108B_S61_FilterWithCursor(t *testing.T) {
	db := newAuditTestDB(t)
	svc := NewService(db)
	for i := 0; i < 5; i++ {
		recordS6QueryEvent(t, svc, ActionClientCreated, "admin", "matching-admin", "client", "matching-"+string(rune('a'+i)))
		recordS6QueryEvent(t, svc, ActionClientDeleted, "cli", "unrelated-cli", "provider", "unrelated-"+string(rune('a'+i)))
	}
	first, err := svc.QueryPage(Query{Limit: 2, Action: ActionClientCreated, ActorID: "matching-admin", TargetType: "client"})
	if err != nil {
		t.Fatal(err)
	}
	recordS6QueryEvent(t, svc, ActionClientDeleted, "cli", "unrelated-new", "provider", "unrelated-new")
	second, err := svc.QueryPage(Query{Limit: 2, BeforeID: first.NextBeforeID, Action: ActionClientCreated, ActorID: "matching-admin", TargetType: "client"})
	if err != nil {
		t.Fatal(err)
	}
	if len(first.Events) != 2 || len(second.Events) != 2 {
		t.Fatalf("page sizes=%d,%d", len(first.Events), len(second.Events))
	}
	seen := map[int64]bool{}
	for _, event := range append(first.Events, second.Events...) {
		if seen[event.ID] {
			t.Fatalf("duplicate matching event id=%d", event.ID)
		}
		seen[event.ID] = true
		if event.Action != ActionClientCreated || event.ActorID != "matching-admin" || event.TargetType != "client" {
			t.Fatalf("nonmatching event returned: %+v", event)
		}
	}
	if second.Events[0].TargetID != "matching-c" || second.Events[1].TargetID != "matching-b" {
		t.Fatalf("filter cursor skipped original matching rows: %+v", second.Events)
	}
}

func TestP108B_S61_ActorTargetIDBoundaries(t *testing.T) {
	db := newAuditTestDB(t)
	svc := NewService(db)
	for name, query := range map[string]Query{
		"actor 255": {Limit: 1, ActorID: strings.Repeat("界", 255)},
		"target 36": {Limit: 1, TargetID: strings.Repeat("界", 36)},
	} {
		if _, err := svc.QueryPage(query); err != nil {
			t.Errorf("%s error=%v", name, err)
		}
	}
	for name, query := range map[string]Query{
		"actor 256": {Limit: 1, ActorID: strings.Repeat("界", 256)},
		"target 37": {Limit: 1, TargetID: strings.Repeat("界", 37)},
	} {
		if _, err := svc.QueryPage(query); !errors.Is(err, ErrInvalidAuditQuery) {
			t.Errorf("%s error=%v", name, err)
		}
	}
}

func TestP108B_S61_NextCursorDomain(t *testing.T) {
	db := newAuditTestDB(t)
	svc := NewService(db)
	for i := 0; i < 3; i++ {
		recordS6QueryEvent(t, svc, ActionClientCreated, "admin", "cursor-admin", "client", "cursor-"+string(rune('a'+i)))
	}
	page, err := svc.QueryPage(Query{Limit: 2})
	if err != nil {
		t.Fatal(err)
	}
	var cursor int64 = page.NextBeforeID
	if cursor != page.Events[len(page.Events)-1].ID || cursor <= 0 || cursor > math.MaxInt64 {
		t.Fatalf("cursor=%d last=%d", cursor, page.Events[len(page.Events)-1].ID)
	}
	second, err := svc.QueryPage(Query{Limit: 2, BeforeID: cursor})
	if err != nil || len(second.Events) != 1 {
		t.Fatalf("second page error=%v events=%d", err, len(second.Events))
	}
}
