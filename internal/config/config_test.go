package config

// P1-01F.1 · Native TLS Configuration Truthfulness 回归测试
//
// 底线：https.enabled=true 绝不能被静默接受（否则网关以明文 HTTP 启动，
// 用户误以为流量已加密）。必须拒绝启动并说明废弃与迁移方式。

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeConfig(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

// [P1-01F.1 安全回归] https.enabled=true 必须拒绝启动（DEPRECATED）。
func TestLoad_HTTPSEnabled_RejectedAsDeprecated(t *testing.T) {
	path := writeConfig(t, `server:
    host: 127.0.0.1
    port: 8090
    https:
        enabled: true
        cert_file: cert.pem
        key_file: key.pem
`)
	_, err := Load(path)
	if err == nil {
		t.Fatal("[安全回归失败] https.enabled=true 被静默接受——网关将以明文 HTTP 启动且用户误以为已加密")
	}
	if !strings.Contains(err.Error(), "server.https") || !strings.Contains(err.Error(), "DEPRECATED") {
		t.Fatalf("错误信息应说明 server.https 已废弃及迁移方式，实际: %v", err)
	}
}

// [P1-01F.1 兼容] https.enabled=false（老配置常见形态）必须照常解析。
func TestLoad_HTTPSDisabled_Ok(t *testing.T) {
	path := writeConfig(t, `server:
    host: 127.0.0.1
    port: 8090
    https:
        enabled: false
        cert_file: ""
        key_file: ""
`)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("https.enabled=false 应正常解析，实际: %v", err)
	}
	if cfg.Server.HTTPS.Enabled {
		t.Fatal("HTTPS.Enabled 应为 false")
	}
	if cfg.Server.Admin.Host != "127.0.0.1" || cfg.Server.Admin.Port != 8091 {
		t.Fatalf("监听面默认值未生效: %+v", cfg.Server.Admin)
	}
}

// [P1-01F.1 兼容] 完全没有 https 段的新配置必须照常解析。
func TestLoad_HTTPSOmitted_Ok(t *testing.T) {
	path := writeConfig(t, `server:
    host: 127.0.0.1
    port: 8090
`)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("无 https 段应正常解析，实际: %v", err)
	}
	if cfg.Server.Admin.Port != 8091 {
		t.Fatalf("Admin 默认端口应 8091，实际 %d", cfg.Server.Admin.Port)
	}
}
