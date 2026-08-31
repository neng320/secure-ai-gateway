package handlers

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
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
