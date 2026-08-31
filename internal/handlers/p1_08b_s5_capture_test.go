package handlers

import (
	"context"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"ai-gateway/internal/audit"
	"ai-gateway/internal/auth"
	"ai-gateway/internal/capture"
	"ai-gateway/internal/models"
	"gorm.io/gorm"
)

const s5CaptureCanary = "P108B-S5-CAPTURE-BODY-CANARY"

func s5CaptureRead(t *testing.T, env *p104Env, token, requestID string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/admin/request-bodies/"+requestID, nil)
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: token})
	w := httptest.NewRecorder()
	env.admin.ServeHTTP(w, req)
	return w
}

func s5CaptureEvents(t *testing.T, env *p104Env, requestID string) []models.AuditEvent {
	t.Helper()
	var events []models.AuditEvent
	if err := env.db.Where("action = ? AND target_id = ?", audit.ActionRequestBodyCaptureRead, requestID).Order("id ASC").Find(&events).Error; err != nil {
		t.Fatal(err)
	}
	return events
}

func TestP108B_S5_CaptureReadAuditedBeforeDisclosure(t *testing.T) {
	env := newP104EnvWithStore(t, nil, capture.NewStore(true, time.Now().Add(time.Hour), 4096, 10))
	requestID := "s5-capture-request-001"
	env.capture.Capture(requestID, []byte(s5CaptureCanary))
	token := p104AdminSession(t, env)
	resp := s5CaptureRead(t, env, token, requestID)
	if resp.Result().StatusCode != http.StatusOK || !strings.Contains(resp.Body.String(), s5CaptureCanary) {
		t.Fatalf("capture read status/body mismatch: status=%d body=%q", resp.Result().StatusCode, resp.Body.String())
	}
	if resp.Header().Get("Cache-Control") != "no-store" || resp.Header().Get("Pragma") != "no-cache" {
		t.Fatal("capture read must remain non-cacheable")
	}
	events := s5CaptureEvents(t, env, requestID)
	if len(events) != 1 || events[0].ActorType != "admin" || events[0].ActorID != env.cfg.Admin.Username || events[0].TargetType != "request-capture" || events[0].Reason != "" {
		t.Fatalf("capture read audit mismatch: %+v", events)
	}
	if strings.Contains(events[0].Action+events[0].ActorType+events[0].ActorID+events[0].TargetType+events[0].TargetID+events[0].Reason, s5CaptureCanary) {
		t.Fatal("capture body canary reached audit metadata")
	}
}

func TestP108B_S5_CaptureAuditFailureDoesNotDiscloseBody(t *testing.T) {
	env := newP104EnvWithStore(t, nil, capture.NewStore(true, time.Now().Add(time.Hour), 4096, 10))
	requestID := "s5-capture-request-002"
	env.capture.Capture(requestID, []byte(s5CaptureCanary))
	token := p104AdminSession(t, env)
	var countBefore int64
	if err := env.db.Model(&models.AuditEvent{}).Count(&countBefore).Error; err != nil {
		t.Fatal(err)
	}
	var stateBefore models.AuditChainState
	if err := env.db.First(&stateBefore, 1).Error; err != nil {
		t.Fatal(err)
	}
	if err := env.db.Exec("CREATE TRIGGER s5_reject_capture BEFORE INSERT ON audit_events WHEN NEW.action = 'REQUEST_BODY_CAPTURE_READ' BEGIN SELECT RAISE(ABORT, 'TEST_CAPTURE_AUDIT_FAILED'); END").Error; err != nil {
		t.Fatal(err)
	}
	resp := s5CaptureRead(t, env, token, requestID)
	if resp.Result().StatusCode != http.StatusInternalServerError {
		t.Fatalf("capture audit failure status=%d body=%q", resp.Result().StatusCode, resp.Body.String())
	}
	if strings.Contains(resp.Body.String(), s5CaptureCanary) {
		t.Fatal("capture body was disclosed after audit failure")
	}
	if resp.Header().Get("Cache-Control") != "no-store" || resp.Header().Get("Pragma") != "no-cache" {
		t.Fatal("capture audit failure must remain non-cacheable")
	}
	if _, ok := env.capture.Get(requestID); !ok {
		t.Fatal("capture entry was released after audit failure")
	}
	var countAfter int64
	if err := env.db.Model(&models.AuditEvent{}).Count(&countAfter).Error; err != nil {
		t.Fatal(err)
	}
	var stateAfter models.AuditChainState
	if err := env.db.First(&stateAfter, 1).Error; err != nil {
		t.Fatal(err)
	}
	if countAfter != countBefore || stateAfter.HeadHash != stateBefore.HeadHash || len(s5CaptureEvents(t, env, requestID)) != 0 {
		t.Fatal("capture audit failure changed audit state")
	}
}

func TestP108B_S5_MissingCaptureNoAudit(t *testing.T) {
	env := newP104EnvWithStore(t, nil, capture.NewStore(true, time.Now().Add(time.Hour), 4096, 10))
	token := p104AdminSession(t, env)
	countBefore, _ := s5AuthAuditState(t, env)
	resp := s5CaptureRead(t, env, token, "missing-capture-request")
	if resp.Result().StatusCode != http.StatusNotFound {
		t.Fatalf("missing capture status=%d", resp.Result().StatusCode)
	}
	countAfter, _ := s5AuthAuditState(t, env)
	if countAfter != countBefore || len(s5CaptureEvents(t, env, "missing-capture-request")) != 0 {
		t.Fatal("missing capture created an audit event")
	}
}

func TestP108B_S5_CapturePrivacyCanary(t *testing.T) {
	env := newP104EnvWithStore(t, nil, capture.NewStore(true, time.Now().Add(time.Hour), 4096, 10))
	var logOutput strings.Builder
	previousLogWriter := log.Writer()
	log.SetOutput(&logOutput)
	t.Cleanup(func() { log.SetOutput(previousLogWriter) })
	requestID := "s5-capture-request-003"
	env.capture.Capture(requestID, []byte(s5CaptureCanary))
	token := p104AdminSession(t, env)
	for i := 0; i < 2; i++ {
		resp := s5CaptureRead(t, env, token, requestID)
		if resp.Result().StatusCode != http.StatusOK || !strings.Contains(resp.Body.String(), s5CaptureCanary) {
			t.Fatalf("capture read %d failed: status=%d body=%q", i, resp.Result().StatusCode, resp.Body.String())
		}
	}
	events := s5CaptureEvents(t, env, requestID)
	if len(events) != 2 {
		t.Fatalf("each successful disclosure must be audited exactly once: %+v", events)
	}
	for _, event := range events {
		if strings.Contains(event.Action+event.ActorType+event.ActorID+event.TargetType+event.TargetID+event.Reason, s5CaptureCanary) {
			t.Fatal("capture canary reached audit metadata")
		}
	}
	if strings.Contains(logOutput.String(), s5CaptureCanary) {
		t.Fatal("capture canary reached runtime logs")
	}
	if sqlDB, err := env.db.DB(); err == nil {
		_ = sqlDB.Close()
	}
	for _, suffix := range []string{"", "-wal", "-shm", "-journal"} {
		path := env.dbPath + suffix
		data, err := os.ReadFile(path)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(data), s5CaptureCanary) {
			t.Fatalf("capture canary reached SQLite file %s", path)
		}
	}
}

func TestP108B_S5_CaptureExpiryDuringAuditDoesNotDiscloseBody(t *testing.T) {
	expiresAt := time.Now().Add(time.Second)
	env := newP104EnvWithStore(t, nil, capture.NewStore(true, expiresAt, 4096, 10))
	requestID := "s5-capture-request-expiry"
	env.capture.Capture(requestID, []byte(s5CaptureCanary))
	rawToken, err := auth.NewSQLiteStore(env.db).Create(context.Background(), env.cfg.Admin.Username, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	auditEntered := make(chan struct{})
	releaseAudit := make(chan struct{})
	if err := env.db.Callback().Create().Before("gorm:create").Register("s5_capture_expiry_barrier", func(tx *gorm.DB) {
		if tx.Statement.Schema != nil && tx.Statement.Schema.Name == "AuditEvent" {
			close(auditEntered)
			<-releaseAudit
		}
	}); err != nil {
		t.Fatal(err)
	}
	responseDone := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		responseDone <- s5CaptureRead(t, env, rawToken, requestID)
	}()
	select {
	case <-auditEntered:
	case <-time.After(time.Second):
		t.Fatal("capture audit did not reach barrier")
	}
	if delay := time.Until(expiresAt); delay > 0 {
		timer := time.NewTimer(delay + 10*time.Millisecond)
		<-timer.C
	}
	close(releaseAudit)
	select {
	case resp := <-responseDone:
		if resp.Result().StatusCode != http.StatusNotFound || strings.Contains(resp.Body.String(), s5CaptureCanary) {
			t.Fatalf("expired capture was disclosed after delayed audit: status=%d body=%q", resp.Result().StatusCode, resp.Body.String())
		}
	case <-time.After(time.Second):
		t.Fatal("capture request did not finish after audit release")
	}
	if len(s5CaptureEvents(t, env, requestID)) != 1 {
		t.Fatal("capture read should remain auditable even when the entry expires during audit")
	}
}

func s5AuthAuditState(t *testing.T, env *p104Env) (int64, string) {
	t.Helper()
	var count int64
	if err := env.db.Model(&models.AuditEvent{}).Count(&count).Error; err != nil {
		t.Fatal(err)
	}
	var state models.AuditChainState
	if err := env.db.First(&state, 1).Error; err != nil {
		t.Fatal(err)
	}
	return count, state.HeadHash
}
