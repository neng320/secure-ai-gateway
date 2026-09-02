package config

// P1-04.4 · Bootstrap Secret Output Canary（SEC-003）
//
// 反转自复验 BLOCKER：config.Load 的 bootstrap 路径曾把生成的明文
// Admin/Prometheus 密码直接 fmt.Printf 到 stdout（systemd/docker/redirect
// 环境下即持久日志）。修复后：任何 bootstrap 路径 stdout 0 密码材料。
//
// 测试捕获 os.Stdout（fmt.Printf 直接写 os.Stdout，小输出无管道死锁风险）。

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func failConfigCredentialEntropy(t *testing.T, calls *int) {
	t.Helper()
	original := credentialGenerator
	credentialGenerator = func(int) (string, error) {
		if calls != nil {
			(*calls)++
		}
		return "", errors.New("secure entropy unavailable")
	}
	t.Cleanup(func() { credentialGenerator = original })
}

func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	fn()
	_ = w.Close()
	os.Stdout = old
	data, _ := io.ReadAll(r)
	_ = r.Close()
	return string(data)
}

// A. missing config → 正常 Load、stdout 零密码材料、返回 __SETUP_REQUIRED__
func TestP1044_FreshConfig_NoPasswordStdout(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")

	var cfg *Config
	out := captureStdout(t, func() {
		var err error
		cfg, err = Load(path)
		if err != nil {
			t.Fatal(err)
		}
	})

	if cfg.Admin.PasswordHash != "__SETUP_REQUIRED__" {
		t.Fatalf("[安全回归失败] fresh config 应进入 setup 流程（__SETUP_REQUIRED__），实际 %q", cfg.Admin.PasswordHash)
	}
	if cfg.Admin.SessionSecret == "" {
		t.Fatal("session secret 应保留（随机生成）")
	}
	// 断言精确到泄漏形态：旧实现的 "Password: <明文>" 行；提示语中提及"password"单词不算材料
	if strings.Contains(out, "Password:") || strings.Contains(out, "password:") {
		t.Fatalf("[安全回归失败] bootstrap stdout 含 Password 行: %q", out)
	}
	if !strings.Contains(out, "Initial setup required") {
		t.Fatalf("应输出无材料的 setup 指引，实际 %q", out)
	}
	// 落盘的配置文件同样不含明文密码（只有哈希占位）
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "password: ") && !strings.Contains(string(raw), "password_hash: __SETUP_REQUIRED__") {
		t.Fatalf("[安全回归失败] 落盘配置含明文密码字段: %q", string(raw))
	}
}

// B. Prometheus enabled + username 空 → 自动生成，stdout 0 密码
func TestP1044_PrometheusBootstrap_UsernameEmpty_NoPasswordStdout(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte("prometheus:\n  enabled: true\n"), 0600); err != nil {
		t.Fatal(err)
	}

	var cfg *Config
	out := captureStdout(t, func() {
		var err error
		cfg, err = Load(path)
		if err != nil {
			t.Fatal(err)
		}
	})

	if cfg.Prometheus.Password == "" {
		t.Fatal("自动生成的 Prometheus 密码应已写入配置")
	}
	if strings.Contains(out, cfg.Prometheus.Password) {
		t.Fatalf("[安全回归失败] stdout 泄露 Prometheus 明文密码: %q", out)
	}
	if strings.Contains(out, "Password:") {
		t.Fatalf("[安全回归失败] stdout 含 Password 行: %q", out)
	}
	t.Log("[SEC-003 FIXED] Prometheus bootstrap（username 空）：stdout 零材料")
}

// C. Prometheus enabled + password 空 → 同规则
func TestP1044_PrometheusBootstrap_PasswordEmpty_NoPasswordStdout(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte("prometheus:\n  enabled: true\n  username: prometheus\n"), 0600); err != nil {
		t.Fatal(err)
	}

	var cfg *Config
	out := captureStdout(t, func() {
		var err error
		cfg, err = Load(path)
		if err != nil {
			t.Fatal(err)
		}
	})

	if cfg.Prometheus.Password == "" {
		t.Fatal("自动生成的 Prometheus 密码应已写入配置")
	}
	if strings.Contains(out, cfg.Prometheus.Password) {
		t.Fatalf("[安全回归失败] stdout 泄露 Prometheus 明文密码: %q", out)
	}
	t.Log("[SEC-003 FIXED] Prometheus bootstrap（password 空）：stdout 零材料")
}

func TestP108B_S5_FreshConfigEntropyFailureDoesNotCreateFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	failConfigCredentialEntropy(t, nil)

	var loadErr error
	out := captureStdout(t, func() {
		_, loadErr = Load(path)
	})
	if loadErr == nil {
		t.Fatal("fresh config accepted session-secret entropy failure")
	}
	if strings.Contains(loadErr.Error(), "Initial setup required") || strings.Contains(out, "Initial setup required") {
		t.Fatalf("entropy failure emitted success/bootstrap output: err=%q out=%q", loadErr, out)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("fresh config was created after entropy failure: %v", err)
	}
}

func TestP108B_S5_EnsureDefaultsSessionEntropyFailureKeepsBytes(t *testing.T) {
	path := writeConfig(t, "admin:\n  password_hash: configured\n")
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	failConfigCredentialEntropy(t, nil)
	_, err = Load(path)
	if err == nil {
		t.Fatal("missing session-secret entropy was accepted")
	}
	after, readErr := os.ReadFile(path)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if string(before) != string(after) {
		t.Fatal("session-secret entropy failure changed config bytes")
	}
	if strings.Contains(string(after), "session_secret: \"\"") {
		t.Fatal("empty session secret was persisted")
	}
}

func TestP108B_S5_EnsureDefaultsPrometheusUsernameMissingEntropyFailureKeepsBytes(t *testing.T) {
	path := writeConfig(t, "admin:\n  session_secret: existing-session\nprometheus:\n  enabled: true\n")
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	failConfigCredentialEntropy(t, nil)
	_, err = Load(path)
	if err == nil {
		t.Fatal("Prometheus entropy failure with missing username was accepted")
	}
	after, readErr := os.ReadFile(path)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if string(before) != string(after) {
		t.Fatal("Prometheus entropy failure changed config bytes")
	}
	if strings.Contains(string(after), "username: prometheus") || strings.Contains(string(after), "password:") {
		t.Fatal("partial Prometheus credentials were persisted")
	}
}

func TestP108B_S5_EnsureDefaultsPrometheusPasswordMissingEntropyFailureKeepsBytes(t *testing.T) {
	path := writeConfig(t, "admin:\n  session_secret: existing-session\nprometheus:\n  enabled: true\n  username: prometheus\n")
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	failConfigCredentialEntropy(t, nil)
	_, err = Load(path)
	if err == nil {
		t.Fatal("Prometheus password entropy failure was accepted")
	}
	after, readErr := os.ReadFile(path)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if string(before) != string(after) {
		t.Fatal("Prometheus password entropy failure changed config bytes")
	}
}

func TestP108B_S5_SecondCredentialEntropyFailureDoesNotPersistFirst(t *testing.T) {
	path := writeConfig(t, "admin:\n  password_hash: configured\nprometheus:\n  enabled: true\n")
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	original := credentialGenerator
	credentialGenerator = func(length int) (string, error) {
		calls++
		if calls == 1 {
			return strings.Repeat("a", length), nil
		}
		return "", errors.New("secure entropy unavailable")
	}
	t.Cleanup(func() { credentialGenerator = original })
	_, err = Load(path)
	if err == nil {
		t.Fatal("second credential entropy failure was accepted")
	}
	if calls != 2 {
		t.Fatalf("credential generation calls=%d, want 2", calls)
	}
	after, readErr := os.ReadFile(path)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if string(before) != string(after) {
		t.Fatal("first generated credential was persisted after second failure")
	}
	if strings.Contains(err.Error(), strings.Repeat("a", 32)) || strings.Contains(err.Error(), strings.Repeat("a", 20)) {
		t.Fatal("entropy failure error leaked generated credential")
	}
}
