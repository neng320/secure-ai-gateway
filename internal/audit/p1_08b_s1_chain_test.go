package audit

import (
	"testing"
	"time"

	"ai-gateway/internal/models"
)

func TestP108B_S1_CanonicalGoldenVector(t *testing.T) {
	event := models.AuditEvent{
		ChainVersion: "v1",
		PrevHash:     "",
		EventID:      "evt-0001",
		Action:       "CLIENT_CREATED",
		ActorType:    "admin",
		ActorID:      "alice",
		TargetType:   "client",
		TargetID:     "client-1",
		Reason:       "created",
		CreatedAt:    time.Unix(1788064496, 123456789).UTC(),
	}

	wantCanonical := "AUDIT-EVENT-V1|2:v1|0:|8:evt-0001|14:CLIENT_CREATED|5:admin|5:alice|6:client|8:client-1|7:created|19:1788064496123456789|"
	if got := string(canonicalEventBytes(event)); got != wantCanonical {
		t.Fatalf("canonical bytes mismatch:\n got: %s\nwant: %s", got, wantCanonical)
	}
	if got := eventHash(event); got != "b812007f2e85bb0f08a0606cdd9bf3abe02804d45b1c5f84ce353a080ec99bc4" {
		t.Fatalf("golden hash mismatch: got %s", got)
	}
}

func TestP108B_S1_CanonicalUnicodeAndDelimiterSafe(t *testing.T) {
	event := models.AuditEvent{
		ChainVersion: "v1",
		PrevHash:     "prev|hash",
		EventID:      "é|evt",
		Action:       "CLIENT_CREATED",
		ActorType:    "管理员",
		ActorID:      "a:b|中",
		TargetType:   "client",
		TargetID:     "目标",
		Reason:       "理由:|ok",
		CreatedAt:    time.Unix(1788064496, 123456789).UTC(),
	}

	want := "AUDIT-EVENT-V1|2:v1|9:prev|hash|6:é|evt|14:CLIENT_CREATED|9:管理员|7:a:b|中|6:client|6:目标|10:理由:|ok|19:1788064496123456789|"
	if got := string(canonicalEventBytes(event)); got != want {
		t.Fatalf("UTF-8 byte-length/delimiter-safe encoding mismatch:\n got: %s\nwant: %s", got, want)
	}
	if got := eventHash(event); got != "ca2150b1fe30007aee353cec06ab48f2a1055aa2855eee419e7f49cb9e3c651a" {
		t.Fatalf("Unicode golden hash mismatch: got %s", got)
	}
}

func TestP108B_S1_CanonicalSameInstantDifferentTimezone(t *testing.T) {
	utc := time.Date(2026, time.August, 30, 4, 34, 56, 123456789, time.UTC)
	beijing := time.Date(2026, time.August, 30, 12, 34, 56, 123456789, time.FixedZone("CST", 8*60*60))
	base := models.AuditEvent{
		ChainVersion: "v1",
		EventID:      "evt-tz",
		Action:       "CLIENT_CREATED",
		ActorType:    "admin",
		ActorID:      "alice",
		TargetType:   "client",
		TargetID:     "client-1",
		Reason:       "timezone",
	}

	first := base
	first.CreatedAt = utc
	second := base
	second.CreatedAt = beijing
	if string(canonicalEventBytes(first)) != string(canonicalEventBytes(second)) {
		t.Fatal("same instant in different timezones must have identical canonical bytes")
	}
	if eventHash(first) != eventHash(second) {
		t.Fatal("same instant in different timezones must have identical event hash")
	}
}

func TestP108B_S1_CanonicalFieldMutationChangesHash(t *testing.T) {
	event := models.AuditEvent{
		ChainVersion: "v1",
		EventID:      "evt-mutation",
		Action:       "CLIENT_CREATED",
		ActorType:    "admin",
		ActorID:      "alice",
		TargetType:   "client",
		TargetID:     "client-1",
		Reason:       "original",
		CreatedAt:    time.Unix(1788064496, 123456789).UTC(),
	}
	mutated := event
	mutated.Reason = "changed"
	if eventHash(event) == eventHash(mutated) {
		t.Fatal("changing a bound event field must change EventHash")
	}
}
