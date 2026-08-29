package config

// P1-04C · Request Body Capture 配置校验 Gate（SEC-003 fail-closed）

import (
	"strings"
	"testing"
	"time"
)

const c21Now = "2026-08-29T12:00:00Z"

func resolveFor(t *testing.T, l LoggingConfig) (CaptureSettings, error) {
	t.Helper()
	now, err := time.Parse(time.RFC3339, c21Now)
	if err != nil {
		t.Fatal(err)
	}
	return l.ResolveRequestBodyCapture(now)
}

// 1. config omitted → OFF
func TestCaptureConfig_Omitted_DefaultOff(t *testing.T) {
	settings, err := resolveFor(t, LoggingConfig{})
	if err != nil {
		t.Fatalf("未配置不应报错: %v", err)
	}
	if settings.Enabled {
		t.Fatal("默认必须 OFF")
	}
}

// 2. enabled + no expiry → reject
func TestCaptureConfig_EnabledWithoutExpiry_Rejected(t *testing.T) {
	_, err := resolveFor(t, LoggingConfig{RequestBodyCapture: RequestBodyCaptureConfig{Enabled: true}})
	if err == nil || !strings.Contains(err.Error(), "expires_at") {
		t.Fatalf("[安全回归失败] enabled 无 expiry 应拒绝，实际 err=%v", err)
	}
}

// 3. malformed expiry → reject
func TestCaptureConfig_MalformedExpiry_Rejected(t *testing.T) {
	_, err := resolveFor(t, LoggingConfig{RequestBodyCapture: RequestBodyCaptureConfig{Enabled: true, ExpiresAt: "2099-13-45 99:99"}})
	if err == nil || !strings.Contains(err.Error(), "RFC3339") {
		t.Fatalf("[安全回归失败] 非法 expiry 应拒绝，实际 err=%v", err)
	}
}

// 4. >24h window → reject
func TestCaptureConfig_WindowOverHardCap_Rejected(t *testing.T) {
	_, err := resolveFor(t, LoggingConfig{RequestBodyCapture: RequestBodyCaptureConfig{
		Enabled: true, ExpiresAt: "2026-08-30T12:00:01Z", // now+24h+1s
	}})
	if err == nil || !strings.Contains(err.Error(), "24h") {
		t.Fatalf("[安全回归失败] 超过 24h 窗口应拒绝，实际 err=%v", err)
	}
	// 恰好 24h → 接受
	if _, err := resolveFor(t, LoggingConfig{RequestBodyCapture: RequestBodyCaptureConfig{
		Enabled: true, ExpiresAt: "2026-08-30T12:00:00Z",
	}}); err != nil {
		t.Fatalf("恰好 24h 应接受，实际 %v", err)
	}
}

// 5. max_bytes 超硬上限 / 负数 → reject；0 → 默认 16KiB
func TestCaptureConfig_MaxBytesBounds(t *testing.T) {
	_, err := resolveFor(t, LoggingConfig{RequestBodyCapture: RequestBodyCaptureConfig{
		Enabled: true, ExpiresAt: "2026-08-30T11:00:00Z", MaxBytes: CaptureMaxBytesHardCap + 1,
	}})
	if err == nil {
		t.Fatal("[安全回归失败] max_bytes 超硬上限应拒绝")
	}
	_, err = resolveFor(t, LoggingConfig{RequestBodyCapture: RequestBodyCaptureConfig{
		Enabled: true, ExpiresAt: "2026-08-30T11:00:00Z", MaxBytes: -1,
	}})
	if err == nil {
		t.Fatal("[安全回归失败] 负 max_bytes 应拒绝")
	}
	settings, err := resolveFor(t, LoggingConfig{RequestBodyCapture: RequestBodyCaptureConfig{
		Enabled: true, ExpiresAt: "2026-08-30T11:00:00Z",
	}})
	if err != nil || settings.MaxBytes != CaptureMaxBytesDefault {
		t.Fatalf("0 应取默认 16KiB，实际 %+v err=%v", settings, err)
	}
}

// 6. max_entries 超硬上限 / 负数 → reject；0 → 默认 100
func TestCaptureConfig_MaxEntriesBounds(t *testing.T) {
	_, err := resolveFor(t, LoggingConfig{RequestBodyCapture: RequestBodyCaptureConfig{
		Enabled: true, ExpiresAt: "2026-08-30T11:00:00Z", MaxEntries: CaptureMaxEntriesHardCap + 1,
	}})
	if err == nil {
		t.Fatal("[安全回归失败] max_entries 超硬上限应拒绝")
	}
	_, err = resolveFor(t, LoggingConfig{RequestBodyCapture: RequestBodyCaptureConfig{
		Enabled: true, ExpiresAt: "2026-08-30T11:00:00Z", MaxEntries: -5,
	}})
	if err == nil {
		t.Fatal("[安全回归失败] 负 max_entries 应拒绝")
	}
	settings, err := resolveFor(t, LoggingConfig{RequestBodyCapture: RequestBodyCaptureConfig{
		Enabled: true, ExpiresAt: "2026-08-30T11:00:00Z",
	}})
	if err != nil || settings.MaxEntries != CaptureMaxEntriesDefault {
		t.Fatalf("0 应取默认 100，实际 %+v err=%v", settings, err)
	}
}

// 过期时刻（expires_at 已在过去）→ fail-safe disable（非 fatal；P1-04.1 恢复原契约）
func TestCaptureConfig_ExpiredAtResolve_DisabledNotFatal(t *testing.T) {
	settings, err := resolveFor(t, LoggingConfig{RequestBodyCapture: RequestBodyCaptureConfig{
		Enabled: true, ExpiresAt: "2026-08-29T11:59:59Z",
	}})
	if err != nil {
		t.Fatalf("[安全回归失败] 过期配置应 fail-safe disable 而非启动失败，实际 err=%v", err)
	}
	if settings.Enabled {
		t.Fatal("[安全回归失败] 过期配置必须解析为 disabled")
	}
}
