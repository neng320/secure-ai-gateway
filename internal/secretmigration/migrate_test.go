package secretmigration

// P1-03C2 · 迁移引擎测试（全部在 t.TempDir() fixture 上执行，绝不触碰真实数据）

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"ai-gateway/internal/config"
	"ai-gateway/internal/models"
	"ai-gateway/internal/secrets"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

const (
	testMasterKeyB64    = "jJx0mGVJyJGKpLPUaUhSvUNqWYIVD3NtQazmOYnH8nk="
	testMasterKeyB64Alt = "GROnfCSaRXSkQ9VpR8kjD9Xc1vLGZ0zGKivSgNzTuw0="
	canaryGlobal        = "P103C2_CANARY_GLOBAL_PROVIDER_SECRET"
	canaryClientA       = "P103C2_CANARY_CLIENT_A_SECRET"
	canaryClientB       = "P103C2_CANARY_CLIENT_B_SECRET"
)

func testKey(t *testing.T) []byte {
	t.Helper()
	key, err := base64Decode(testMasterKeyB64)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func base64Decode(s string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(s)
}

// fixture: 临时目录内构造 config.yaml + gateway.db fixture
type fixture struct {
	dir     string
	cfgPath string
	dbPath  string
	db      *gorm.DB
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	dbPath := filepath.Join(dir, "gateway.db")

	if err := os.WriteFile(cfgPath, []byte("server:\n  host: 127.0.0.1\n  port: 8090\ndatabase:\n  path: "+dbPath+"\nadmin:\n  username: admin\nproviders: {}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	db, err := gorm.Open(sqlite.Open(dbPath), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.AutoMigrate(&models.Client{}, &models.RequestLog{}, &models.DailyUsage{}, &models.AdminSession{}, &models.AuditEvent{}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if sqlDB, e := db.DB(); e == nil {
			_ = sqlDB.Close()
		}
	})
	return &fixture{dir: dir, cfgPath: cfgPath, dbPath: dbPath, db: db}
}

// addGlobal: 向 config.yaml 写入一个 provider（legacy 明文或 encrypted）
func (f *fixture) addGlobal(t *testing.T, name, legacy, encrypted string) {
	s := readCfgFile(t, f.cfgPath)
	entry := "  " + name + ":\n    type: " + name + "\n"
	if legacy != "" {
		entry += "    api_key: " + legacy + "\n"
	}
	if encrypted != "" {
		entry += "    api_key_encrypted: " + encrypted + "\n"
	}
	s = strings.Replace(s, "providers: {}\n", "providers:\n"+entry, 1)
	if !strings.Contains(s, "providers:\n") {
		s = strings.Replace(s, "providers: {}\n", "providers:\n"+entry, 1)
	}
	writeCfgFile(t, f.cfgPath, s)
}

// addClient: 直接插入一个 client 行
func (f *fixture) addClient(t *testing.T, id, legacy, encrypted string) {
	c := &models.Client{ID: id, Name: id, Backend: "openai", BackendAPIKey: legacy, BackendAPIKeyEncrypted: encrypted}
	if err := f.db.Create(c).Error; err != nil {
		t.Fatal(err)
	}
}

func readCfgFile(t *testing.T, path string) string {
	t.Helper()
	s, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(s)
}

func writeCfgFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
}

func runMigration(t *testing.T, f *fixture, masterKeyB64 string) (*Result, error) {
	t.Helper()
	key, err := base64Decode(masterKeyB64)
	if err != nil {
		t.Fatal(err)
	}
	backupDir := filepath.Join(f.dir, "backups")
	return Run(Options{
		ConfigPath: f.cfgPath,
		BackupDir:  backupDir,
		MasterKey:  key,
		Now:        func() time.Time { return time.Now().UTC() },
	})
}

// reloadConfig: 迁移后重新从磁盘解析配置
func reloadConfig(t *testing.T, f *fixture) *config.Config {
	t.Helper()
	cfg, err := config.Load(f.cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

// reloadClient: 迁移后重新读 client 行
func reloadClient(t *testing.T, f *fixture, id string) *models.Client {
	t.Helper()
	var c models.Client
	if err := f.db.First(&c, "id = ?", id).Error; err != nil {
		t.Fatal(err)
	}
	return &c
}

// ---------------------------------------------------------------------------
// Fixture A：只有 global legacy plaintext
// ---------------------------------------------------------------------------
func TestMigration_FixtureA_GlobalLegacyOnly(t *testing.T) {
	f := newFixture(t)
	f.addGlobal(t, "openai", canaryGlobal, "")

	res, err := runMigration(t, f, testMasterKeyB64)
	if err != nil {
		t.Fatal(err)
	}
	if res.GlobalLegacyOnly != 1 || res.FinalizedGlobal != 1 {
		t.Fatalf("结果不符: %+v", res)
	}

	cfg := reloadConfig(t, f)
	p := cfg.Providers["openai"]
	if p.APIKey != "" {
		t.Fatalf("[安全回归失败] FINALIZE 后 legacy api_key 应为空，实际 %q", p.APIKey)
	}
	if !secrets.IsEncryptedEnvelope(p.APIKeyEncrypted) {
		t.Fatalf("[安全回归失败] api_key_encrypted 应为 enc:v1 信封，实际 %q", p.APIKeyEncrypted)
	}
	// 幂等：重跑应安全（全部 ENCRYPTED_ONLY）
	res2, err := runMigration(t, f, testMasterKeyB64)
	if err != nil {
		t.Fatalf("幂等重跑失败: %v", err)
	}
	if res2.GlobalEncrypted != 1 {
		t.Fatalf("重跑应识别 ENCRYPTED_ONLY，实际 %+v", res2)
	}
}

// ---------------------------------------------------------------------------
// Fixture B：只有 client legacy plaintext
// ---------------------------------------------------------------------------
func TestMigration_FixtureB_ClientLegacyOnly(t *testing.T) {
	f := newFixture(t)
	f.addClient(t, "client-a", canaryClientA, "")

	res, err := runMigration(t, f, testMasterKeyB64)
	if err != nil {
		t.Fatal(err)
	}
	if res.ClientLegacyOnly != 1 || res.FinalizedClients != 1 {
		t.Fatalf("结果不符: %+v", res)
	}
	c := reloadClient(t, f, "client-a")
	if c.BackendAPIKey != "" {
		t.Fatalf("[安全回归失败] FINALIZE 后 legacy backend_api_key 应为空，实际 %q", c.BackendAPIKey)
	}
	if !secrets.IsEncryptedEnvelope(c.BackendAPIKeyEncrypted) {
		t.Fatalf("encrypted 应为信封，实际 %q", c.BackendAPIKeyEncrypted)
	}
}

// ---------------------------------------------------------------------------
// Fixture C：global + 多个 clients
// ---------------------------------------------------------------------------
func TestMigration_FixtureC_GlobalAndClients(t *testing.T) {
	f := newFixture(t)
	f.addGlobal(t, "openai", canaryGlobal, "")
	f.addClient(t, "client-a", canaryClientA, "")
	f.addClient(t, "client-b", canaryClientB, "")

	res, err := runMigration(t, f, testMasterKeyB64)
	if err != nil {
		t.Fatal(err)
	}
	if res.FinalizedGlobal != 1 || res.FinalizedClients != 2 {
		t.Fatalf("结果不符: %+v", res)
	}
	cfg := reloadConfig(t, f)
	if cfg.Providers["openai"].APIKey != "" || !secrets.IsEncryptedEnvelope(cfg.Providers["openai"].APIKeyEncrypted) {
		t.Fatal("global 迁移后状态不符")
	}
	for _, id := range []string{"client-a", "client-b"} {
		c := reloadClient(t, f, id)
		if c.BackendAPIKey != "" || !secrets.IsEncryptedEnvelope(c.BackendAPIKeyEncrypted) {
			t.Fatalf("%s 迁移后状态不符", id)
		}
	}
}

// ---------------------------------------------------------------------------
// Fixture D：MIXED（模拟 PREPARE 后中断）→ 重跑识别并完成
// ---------------------------------------------------------------------------
func TestMigration_FixtureD_Mixed_Resumable(t *testing.T) {
	f := newFixture(t)
	f.addClient(t, "client-a", canaryClientA, "")

	// 手动构造 PREPARE 后中断状态：encrypted 已写入（正确值），legacy 暂留
	mgr := secrets.NewManager(mustNewCipher(t, testMasterKeyB64))
	env, err := mgr.EncryptClientBackendKey("client-a", []byte(canaryClientA))
	if err != nil {
		t.Fatal(err)
	}
	if err := f.db.Model(&models.Client{}).Where("id = ?", "client-a").
		Update("backend_api_key_encrypted", env).Error; err != nil {
		t.Fatal(err)
	}

	// 重跑迁移：应识别 MIXED，verify 通过后 finalize
	res, err := runMigration(t, f, testMasterKeyB64)
	if err != nil {
		t.Fatalf("可恢复迁移失败: %v", err)
	}
	if res.FinalizedClients != 1 {
		t.Fatalf("结果不符: %+v", res)
	}
	c := reloadClient(t, f, "client-a")
	if c.BackendAPIKey != "" || !secrets.IsEncryptedEnvelope(c.BackendAPIKeyEncrypted) {
		t.Fatalf("恢复迁移后状态不符: legacy=%q", c.BackendAPIKey)
	}
}

// ---------------------------------------------------------------------------
// Fixture E：错误 Master Key → verify 首步 key_id 不匹配 → STOP，数据零改动
// （fixture 全部为 ENCRYPTED_ONLY：PREPARE 无 legacy 可处理，verify 即拒绝）
// ---------------------------------------------------------------------------
func TestMigration_FixtureE_WrongMasterKey_Fails(t *testing.T) {
	f := newFixture(t)
	// 用【正确】key 预先加密的两个位置
	mgr := secrets.NewManager(mustNewCipher(t, testMasterKeyB64))
	envG, err := mgr.EncryptGlobalProviderKey("openai", []byte("live-global"))
	if err != nil {
		t.Fatal(err)
	}
	f.addGlobal(t, "openai", "", envG)
	envC, err := mgr.EncryptClientBackendKey("client-enc", []byte("live-client"))
	if err != nil {
		t.Fatal(err)
	}
	f.addClient(t, "client-enc", "", envC)

	// 用【错误】key 迁移：key_id 不匹配 → verify STOP
	if _, err := runMigration(t, f, testMasterKeyB64Alt); err == nil {
		t.Fatal("[安全回归失败] 错误 Master Key 迁移未被拒绝")
	}

	// 数据零改动：信封原样保留（未被 wrong key 重加密/篡改）
	cfg := reloadConfig(t, f)
	if cfg.Providers["openai"].APIKeyEncrypted != envG {
		t.Fatalf("[安全回归失败] global 信封被改动: %q", cfg.Providers["openai"].APIKeyEncrypted)
	}
	c := reloadClient(t, f, "client-enc")
	if c.BackendAPIKeyEncrypted != envC {
		t.Fatalf("[安全回归失败] client 信封被改动: %q", c.BackendAPIKeyEncrypted)
	}
}

// ---------------------------------------------------------------------------
// Fixture F：篡改密文 → STOP
// ---------------------------------------------------------------------------
func TestMigration_FixtureF_TamperedCiphertext_Fails(t *testing.T) {
	f := newFixture(t)
	f.addClient(t, "client-a", canaryClientA, "")

	// 构造 MIXED + 篡改密文（PREPARE 后被人篡改 encrypted）
	mgr := secrets.NewManager(mustNewCipher(t, testMasterKeyB64))
	env, _ := mgr.EncryptClientBackendKey("client-a", []byte(canaryClientA))
	payload := strings.TrimPrefix(env, "enc:v1:"+mgr.KeyID()+":")
	// 破坏 base64url payload 的最后一个字符
	tamperedPayload := payload[:len(payload)-1] + "A"
	if tamperedPayload == payload {
		tamperedPayload = payload[:len(payload)-1] + "B"
	}
	tampered := "enc:v1:" + mgr.KeyID() + ":" + tamperedPayload
	if err := f.db.Model(&models.Client{}).Where("id = ?", "client-a").
		Update("backend_api_key_encrypted", tampered).Error; err != nil {
		t.Fatal(err)
	}

	_, err := runMigration(t, f, testMasterKeyB64)
	if err == nil {
		t.Fatal("[安全回归失败] 篡改密文未导致迁移 STOP")
	}
	// plaintext 不得被 scrub
	c := reloadClient(t, f, "client-a")
	if c.BackendAPIKey != canaryClientA {
		t.Fatal("[安全回归失败] 迁移失败后 legacy 明文被 scrub")
	}
}

// ---------------------------------------------------------------------------
// Mismatch：plaintext 与 encrypted 解密值不同 → STOP，不 scrub
// ---------------------------------------------------------------------------
func TestMigration_MismatchedMixed_STOP(t *testing.T) {
	f := newFixture(t)
	f.addClient(t, "client-a", canaryClientA, "")

	// MIXED 但 encrypted 是"另一个明文"的密文（模拟错误操作）
	mgr := secrets.NewManager(mustNewCipher(t, testMasterKeyB64))
	wrongEnv, _ := mgr.EncryptClientBackendKey("client-a", []byte("P103C2_WRONG_PLAINTEXT"))
	if err := f.db.Model(&models.Client{}).Where("id = ?", "client-a").
		Update("backend_api_key_encrypted", wrongEnv).Error; err != nil {
		t.Fatal(err)
	}

	_, err := runMigration(t, f, testMasterKeyB64)
	if err == nil || !strings.Contains(err.Error(), "VERIFY failed") {
		t.Fatalf("[安全回归失败] MIXED 不一致应 VERIFY STOP，实际 err=%v", err)
	}
	// plaintext 不得被 scrub
	c := reloadClient(t, f, "client-a")
	if c.BackendAPIKey != canaryClientA {
		t.Fatal("[安全回归失败] VERIFY 失败后 legacy 明文被 scrub")
	}
}

// ---------------------------------------------------------------------------
// Wrong AAD：client A 的密文移到 client B → decrypt fail → STOP
// ---------------------------------------------------------------------------
func TestMigration_WrongAAD_STOP(t *testing.T) {
	f := newFixture(t)
	f.addClient(t, "client-a", "", "")
	f.addClient(t, "client-b", canaryClientB, "")

	// client B 的密文写入 client A 的 encrypted 字段（AAD 仍是 client-b）
	mgr := secrets.NewManager(mustNewCipher(t, testMasterKeyB64))
	envB, _ := mgr.EncryptClientBackendKey("client-b", []byte(canaryClientB))
	if err := f.db.Model(&models.Client{}).Where("id = ?", "client-a").
		Update("backend_api_key_encrypted", envB).Error; err != nil {
		t.Fatal(err)
	}
	// client A legacy 也留一份 → MIXED
	if err := f.db.Model(&models.Client{}).Where("id = ?", "client-a").
		Update("backend_api_key", "P103C2_COPY_ATTEMPT").Error; err != nil {
		t.Fatal(err)
	}

	_, err := runMigration(t, f, testMasterKeyB64)
	if err == nil {
		t.Fatal("[安全回归失败] 跨 client AAD 密文迁移应 STOP")
	}
}

// ---------------------------------------------------------------------------
// Backup：存在、DB snapshot 非空、manifest 不含 secret
// ---------------------------------------------------------------------------
func TestMigration_BackupCreated(t *testing.T) {
	f := newFixture(t)
	f.addGlobal(t, "openai", canaryGlobal, "")
	f.addClient(t, "client-a", canaryClientA, "")

	res, err := runMigration(t, f, testMasterKeyB64)
	if err != nil {
		t.Fatal(err)
	}

	// DB snapshot 存在且非空
	snap, err := os.ReadFile(filepath.Join(res.BackupDir, "gateway.db"))
	if err != nil || len(snap) < 100 {
		t.Fatalf("DB snapshot 缺失或过小: %v %d", err, len(snap))
	}
	// DB snapshot 应含迁移前的 client 明文（备份本意；文件属敏感，offline 保存）
	if !strings.Contains(string(snap), canaryClientA) {
		t.Fatal("DB snapshot 应为迁移前状态（含 client legacy 明文）")
	}

	// config 副本应含迁移前的 global 明文
	cfgCopy, err := os.ReadFile(filepath.Join(res.BackupDir, "config.yaml"))
	if err != nil || !strings.Contains(string(cfgCopy), canaryGlobal) {
		t.Fatal("config 副本缺失或内容不符")
	}

	// manifest 不含 secret 材料
	manifestRaw, err := os.ReadFile(filepath.Join(res.BackupDir, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	m := string(manifestRaw)
	if strings.Contains(m, canaryGlobal) || strings.Contains(m, canaryClientA) || strings.Contains(m, testMasterKeyB64) {
		t.Fatal("[安全回归失败] manifest 泄露 secret 材料")
	}
	if !strings.Contains(m, "master_key_id") || !strings.Contains(m, "config_sha256") || !strings.Contains(m, "db_snapshot_sha256") {
		t.Fatal("manifest 缺少必需字段")
	}
}

func mustNewCipher(t *testing.T, keyB64 string) *secrets.AESGCMCipher {
	t.Helper()
	key, err := base64Decode(keyB64)
	if err != nil {
		t.Fatal(err)
	}
	c, err := secrets.NewAESGCMCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	return c
}
