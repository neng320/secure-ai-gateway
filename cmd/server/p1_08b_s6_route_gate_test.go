package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestP108B_S6_PublicRouterDoesNotExposeAudit(t *testing.T) {
	text, err := os.ReadFile(filepath.Join("server.go"))
	if err != nil {
		t.Fatal(err)
	}
	serverSrc := string(text)
	apiStart := strings.Index(serverSrc, "func buildAPIRouter")
	adminStart := strings.Index(serverSrc, "func buildAdminRouter")
	if apiStart < 0 || adminStart < 0 || apiStart >= adminStart {
		t.Fatal("router definitions not found")
	}
	if strings.Contains(serverSrc[apiStart:adminStart], "/admin/audit") {
		t.Fatal("public API router exposes admin audit viewer")
	}
}

func TestP108B_S6_MetricsRouterDoesNotExposeAudit(t *testing.T) {
	text, err := os.ReadFile(filepath.Join("server.go"))
	if err != nil {
		t.Fatal(err)
	}
	serverSrc := string(text)
	metricsStart := strings.Index(serverSrc, "func buildMetricsRouter")
	if metricsStart < 0 {
		t.Fatal("metrics router definition not found")
	}
	if strings.Contains(serverSrc[metricsStart:], "/admin/audit") {
		t.Fatal("metrics router exposes admin audit viewer")
	}
}
