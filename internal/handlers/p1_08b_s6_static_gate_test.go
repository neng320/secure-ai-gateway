package handlers

import (
	"strings"
	"testing"
)

func TestP108B_S6_StaticReadOnlyGate(t *testing.T) {
	root := p105bModuleRoot(t)
	viewerSrc := p105bRead(t, root, "internal/handlers/audit_viewer.go")
	querySrc := p105bRead(t, root, "internal/audit/query.go")
	adminSrc := p105bRead(t, root, "internal/handlers/admin.go")

	for _, forbidden := range []string{
		"Record(", "RecordTx(", "List(", "Update(", "Delete(",
		"UPDATE audit_events", "DELETE FROM audit_events", "DROP audit_events",
		"ClearAudit", "DeleteAudit", "UpdateAudit", "PurgeAudit",
	} {
		if strings.Contains(viewerSrc, forbidden) {
			t.Fatalf("viewer production code contains forbidden mutation/unbounded marker %q", forbidden)
		}
	}
	for _, forbidden := range []string{"SELECT *", "LIKE", "GLOB", "fmt.Sprintf", "UPDATE audit_events", "DELETE FROM audit_events"} {
		if strings.Contains(querySrc, forbidden) {
			t.Fatalf("bounded query production code contains forbidden marker %q", forbidden)
		}
	}
	if !strings.Contains(adminSrc, `r.Get("/admin/audit", h.ShowAuditLog)`) {
		t.Fatal("admin audit viewer route is not registered as GET")
	}
}

func TestP108B_S6_UnboundedListNotUsed(t *testing.T) {
	root := p105bModuleRoot(t)
	viewerSrc := p105bRead(t, root, "internal/handlers/audit_viewer.go")
	if strings.Contains(viewerSrc, ".List(") || strings.Contains(viewerSrc, "List(") {
		t.Fatal("Admin viewer must use bounded QueryPage, not unbounded List")
	}
	if !strings.Contains(viewerSrc, "QueryPage(") {
		t.Fatal("Admin viewer does not call bounded QueryPage")
	}
}
