package handlers

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"ai-gateway/internal/audit"
)

func TestP108B_S5_StaticAuditActionAndAuthGates(t *testing.T) {
	root := p105bModuleRoot(t)
	auditSrc := p105bRead(t, root, "internal/audit/audit.go")
	for _, action := range []string{
		"ActionAdminLoginSucceeded",
		"ActionAdminLogout",
		"ActionSetupCompleted",
		"ActionRequestBodyCaptureRead",
		"ActionAdminPasswordReset",
	} {
		if !strings.Contains(auditSrc, action) {
			t.Fatalf("missing fixed Slice 5 audit action %q", action)
		}
	}
	if strings.Contains(auditSrc, "ADMIN_LOGIN_FAILED") {
		t.Fatal("failed login must not have a persisted audit action")
	}

	adminSrc := p105bRead(t, root, "internal/handlers/admin.go")
	loginStart := strings.Index(adminSrc, "func (h *AdminHandler) HandleLogin")
	logoutStart := strings.Index(adminSrc, "func (h *AdminHandler) HandleLogout")
	captureStart := strings.Index(adminSrc, "func (h *AdminHandler) GetCapturedRequestBody")
	if loginStart < 0 || logoutStart < 0 || captureStart < 0 {
		t.Fatal("Slice 5 admin handlers not found")
	}
	loginBlock := adminSrc[loginStart:logoutStart]
	logoutBlock := adminSrc[logoutStart:captureStart]
	captureBlock := adminSrc[captureStart:]
	if !strings.Contains(loginBlock, "CreateAudited") || strings.Contains(loginBlock, "sessionStore.Create") {
		t.Fatal("successful login must use the audited session store without fallback")
	}
	if strings.Index(loginBlock, "CreateAudited") > strings.Index(loginBlock, "RecordSuccess") {
		t.Fatal("login limiter success must follow the committed audited session")
	}
	if !strings.Contains(logoutBlock, "RevokeAudited") || strings.Contains(logoutBlock, "sessionStore.Revoke") {
		t.Fatal("logout must use the audited session store without fallback")
	}
	if !strings.Contains(captureBlock, "ActionRequestBodyCaptureRead") || !strings.Contains(captureBlock, "AuditService().Record") || strings.Index(captureBlock, "AuditService().Record") > strings.Index(captureBlock, "w.Write(entry.Body)") {
		t.Fatal("capture body must be written only after its audit append succeeds")
	}

	setupSrc := p105bRead(t, root, "internal/handlers/setup.go")
	if strings.Contains(setupSrc, "config.SaveConfig") || !strings.Contains(setupSrc, "RunLockedTransactional") || !strings.Contains(setupSrc, "ActionSetupCompleted") || !strings.Contains(setupSrc, "AdminSession") {
		t.Fatal("Setup must use the shared locked transactional audit path")
	}
}

func TestP108B_S5_StaticCredentialEntropyGate(t *testing.T) {
	root := p105bModuleRoot(t)
	for _, name := range []string{"internal/config/config.go", "internal/handlers/setup.go"} {
		src := p105bRead(t, root, name)
		if !strings.Contains(src, "internal/securegen") {
			t.Fatalf("%s does not use shared securegen", name)
		}
		for _, forbidden := range []string{"crypto/rand", "rand.Read", "generateRandomString"} {
			if strings.Contains(src, forbidden) {
				t.Fatalf("%s retains forbidden direct entropy path %q", name, forbidden)
			}
		}
	}
	securegenSrc := p105bRead(t, root, "internal/securegen/hex.go")
	for _, required := range []string{"crypto/rand", "io.ReadFull", "func Hex("} {
		if !strings.Contains(securegenSrc, required) {
			t.Fatalf("securegen missing required entropy implementation %q", required)
		}
	}
}

func TestP108B_S7_MaintenanceViewerStatic(t *testing.T) {
	root := p105bModuleRoot(t)
	viewerSrc := p105bRead(t, root, "internal/handlers/audit_viewer.go")
	querySrc := p105bRead(t, root, "internal/audit/query.go")
	adminSrc := p105bRead(t, root, "internal/handlers/admin.go")
	wantActions := []string{
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
	if got := auditViewerActions(); !reflect.DeepEqual(got, wantActions) {
		t.Fatalf("viewer actions changed beyond the four maintenance actions: got=%v want=%v", got, wantActions)
	}
	_, targetTypes := auditViewerTypes()
	if len(targetTypes) != 6 || targetTypes[len(targetTypes)-1] != "maintenance-operation" {
		t.Fatalf("unexpected viewer target types: %v", targetTypes)
	}
	if !strings.Contains(querySrc, "\"maintenance-operation\": {}") {
		t.Fatal("query target whitelist does not allow maintenance-operation")
	}
	if audit.MaxAuditQueryLimit != 100 {
		t.Fatalf("audit query max limit changed: %d", audit.MaxAuditQueryLimit)
	}
	if !strings.Contains(adminSrc, "r.Get(\"/admin/audit\", h.ShowAuditLog)") {
		t.Fatal("audit viewer GET route is missing")
	}
	for _, method := range []string{"Post", "Put", "Patch", "Delete"} {
		if strings.Contains(adminSrc, "r."+method+"(\"/admin/audit") {
			t.Fatalf("audit viewer has forbidden %s mutation route", method)
		}
	}
	for _, forbidden := range []string{"prune", "clear", "truncate", "export", "DELETE FROM audit_events", "UPDATE audit_events"} {
		if strings.Contains(viewerSrc+querySrc, forbidden) {
			t.Fatalf("audit viewer/query contains forbidden retention or mutation marker %q", forbidden)
		}
	}
}

func TestP108B_S5_StaticResetPasswordGates(t *testing.T) {
	root := p105bModuleRoot(t)
	mainSrc, err := os.ReadFile(filepath.Join(root, "cmd", "server", "main.go"))
	if err != nil {
		t.Fatal(err)
	}
	mainText := string(mainSrc)
	if !strings.Contains(mainText, `flag.Bool("reset-password"`) || strings.Contains(mainText, `flag.String("reset-password"`) || !strings.Contains(mainText, "flag.NArg()") {
		t.Fatal("reset-password must be a boolean operation flag, never a string secret argument")
	}
	if !strings.Contains(mainText, `flag.Bool("reset-password-stdin"`) || !strings.Contains(mainText, "runResetAdminPassword") {
		t.Fatal("reset password stdin dispatch is missing")
	}
	resetStart := strings.Index(mainText, "// Handle password reset flag")
	loggerStart := strings.Index(mainText, "logger.Init(")
	if resetStart < 0 || loggerStart < 0 || resetStart > loggerStart {
		t.Fatal("password reset must dispatch before logger/runtime startup")
	}
	resetSrc, err := os.ReadFile(filepath.Join(root, "cmd", "server", "reset_password.go"))
	if err != nil {
		t.Fatal(err)
	}
	resetText := string(resetSrc)
	for _, marker := range []string{"newAdminPasswordReader", "OpenReadOnly", "VerifyIntegrityReadOnly", "RunLockedTransactional", "ActionAdminPasswordReset", "AdminSession"} {
		if !strings.Contains(resetText, marker) {
			t.Fatalf("reset password security boundary missing %q", marker)
		}
	}
}
