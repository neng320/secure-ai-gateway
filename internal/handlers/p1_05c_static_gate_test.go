package handlers

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func p105cUsesAuditEvent(expr ast.Expr) bool {
	found := false
	ast.Inspect(expr, func(node ast.Node) bool {
		switch n := node.(type) {
		case *ast.Ident:
			found = found || n.Name == "AuditEvent"
		case *ast.SelectorExpr:
			found = found || n.Sel.Name == "AuditEvent"
		}
		return !found
	})
	return found
}

func TestP105C_StaticGate_AuditAppendOnly(t *testing.T) {
	root := p105bModuleRoot(t)
	var forbidden []string
	var productionFiles int

	for _, base := range []string{filepath.Join(root, "internal"), filepath.Join(root, "cmd")} {
		err := filepath.WalkDir(base, func(path string, entry os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
				return nil
			}
			productionFiles++
			file, parseErr := parser.ParseFile(token.NewFileSet(), path, nil, 0)
			if parseErr != nil {
				return parseErr
			}
			ast.Inspect(file, func(node ast.Node) bool {
				call, ok := node.(*ast.CallExpr)
				if !ok {
					return true
				}
				selector, ok := call.Fun.(*ast.SelectorExpr)
				if !ok || (selector.Sel.Name != "Update" && selector.Sel.Name != "Updates" && selector.Sel.Name != "Delete") {
					return true
				}
				if p105cUsesAuditEvent(call.Fun) {
					forbidden = append(forbidden, path+":"+selector.Sel.Name)
				}
				for _, arg := range call.Args {
					if p105cUsesAuditEvent(arg) {
						forbidden = append(forbidden, path+":"+selector.Sel.Name)
						break
					}
				}
				return true
			})
			return nil
		})
		if err != nil {
			t.Fatalf("[static] scan production Go files: %v", err)
		}
	}

	if productionFiles == 0 {
		t.Fatal("[static] no production Go files scanned")
	}
	if len(forbidden) != 0 {
		t.Fatalf("[static] AuditEvent production path must not update/delete events: %v", forbidden)
	}
	auditSrc := p105bRead(t, root, "internal/audit/audit.go")
	if !strings.Contains(auditSrc, "func (s *Service) RecordTx") || !strings.Contains(auditSrc, "return tx.Create(&e).Error") {
		t.Fatal("[static] audit service must expose transactional append through RecordTx")
	}
	for _, action := range []string{
		"ActionClientCreated",
		"ActionClientKeyRotated",
		"ActionClientSuspended",
		"ActionClientResumed",
		"ActionClientRevoked",
		"ActionClientDeleted",
	} {
		if !strings.Contains(auditSrc, action) {
			t.Fatalf("[static] missing fixed audit action constant %q", action)
		}
	}
	t.Log("[static] AuditEvent production path is append/read-only with fixed actions")
}

func TestP105C_StaticGate_TrustedActorAndBoundedClientWrites(t *testing.T) {
	root := p105bModuleRoot(t)
	adminSrc := p105bRead(t, root, "internal/handlers/admin.go")
	for _, forgedField := range []string{
		`FormValue("actor")`,
		`FormValue("actor_id")`,
		`FormValue("revoked_by")`,
		`Form.Get("actor")`,
		`Form.Get("actor_id")`,
		`Form.Get("revoked_by")`,
	} {
		if strings.Contains(adminSrc, forgedField) {
			t.Fatalf("[static] Admin lifecycle actor must not come from form field %s", forgedField)
		}
	}
	if !strings.Contains(adminSrc, "h.cfg.Admin.Username") || !strings.Contains(adminSrc, "h.clientService.RevokeClient") {
		t.Fatal("[static] Admin revoke must use configured server actor and audited service API")
	}
	if !strings.Contains(adminSrc, "h.clientService.CreateClientWithSettings") || strings.Contains(adminSrc, "compensation: client creation aborted") {
		t.Fatal("[static] Admin create must use the atomic create-with-settings service path")
	}
	if strings.Contains(adminSrc, "h.clientService.UpdateClient(") {
		t.Fatal("[static] Admin settings path must not call generic Client update")
	}
	for _, marker := range []string{
		`{{if eq .LifecycleState "REVOKED"}}`,
		`name="active" value="false"`,
		`name="active" value="true"`,
		`name="reason"`,
		`{{$root.CSRFToken}}`,
	} {
		if !strings.Contains(adminSrc, marker) {
			t.Fatalf("[static] client list lifecycle UI missing %s", marker)
		}
	}

	clientSrc := p105bRead(t, root, "internal/services/client.go")
	if !strings.Contains(clientSrc, "allowedSettingsColumns") || !strings.Contains(clientSrc, "UpdateClientSettings") || !strings.Contains(clientSrc, "UpdateClientModels") || !strings.Contains(clientSrc, "Updates(filtered)") {
		t.Fatal("[static] client settings/models paths must use dedicated bounded update APIs")
	}
	allowlistStart := strings.Index(clientSrc, "var allowedSettingsColumns")
	if allowlistStart < 0 {
		t.Fatal("[static] could not isolate settings allowlist")
	}
	allowlistEnd := strings.Index(clientSrc[allowlistStart:], "}\n\n// ErrInvalidSettingsField")
	if allowlistEnd < 0 {
		t.Fatal("[static] could not isolate settings allowlist")
	}
	allowlist := clientSrc[allowlistStart : allowlistStart+allowlistEnd]
	for _, forbidden := range []string{"api_key_hash", "is_active", "revoked_at", "revoked_by", "revocation_reason"} {
		if strings.Contains(allowlist, `"`+forbidden+`"`) {
			t.Fatalf("[static] settings allowlist contains lifecycle column %q", forbidden)
		}
	}
	if strings.Contains(clientSrc, ".Save(") {
		t.Fatal("[static] client service must not use whole-row Save")
	}
	if got := strings.Count(clientSrc, "s.audit.RecordTx"); got != 6 {
		t.Fatalf("[static] six lifecycle mutations must each append one audit event, found %d RecordTx calls", got)
	}
	for _, rel := range []string{"internal/handlers/admin.go", "internal/handlers/openai.go"} {
		if strings.Contains(p105bRead(t, root, rel), ".Save(") {
			t.Fatalf("[static] %s must not whole-row Save Client", rel)
		}
	}
	t.Log("[static] lifecycle actor is trusted server identity; Client writes are allowlisted/bounded")
}
