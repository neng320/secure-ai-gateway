package secretmigration

// P1-03C2 · 迁移引擎测试（全部在 t.TempDir() fixture 上执行，绝不触碰真实数据）

import (
	"bytes"
	"encoding/base64"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"ai-gateway/internal/audit"
	"ai-gateway/internal/config"
	"ai-gateway/internal/configaudit"
	"ai-gateway/internal/configstore"
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
	if err := db.AutoMigrate(&models.Client{}, &models.RequestLog{}, &models.DailyUsage{}, &models.AdminSession{}); err != nil {
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

func s7OptionsWithKey(t *testing.T, f *fixture, backupDir string) Options {
	t.Helper()
	return Options{
		ConfigPath: f.cfgPath,
		BackupDir:  backupDir,
		MasterKey:  testKey(t),
		Now:        func() time.Time { return time.Unix(1700000000, 0).UTC() },
	}
}

func s7MaintenanceEvents(t *testing.T, db *gorm.DB) []models.AuditEvent {
	t.Helper()
	var events []models.AuditEvent
	if err := db.Where("action IN ?", []string{
		audit.ActionProviderSecretMigrationStarted,
		audit.ActionProviderSecretMigration,
	}).Order("id ASC").Find(&events).Error; err != nil {
		t.Fatal(err)
	}
	return events
}

func s7CountAction(t *testing.T, db *gorm.DB, action string) int64 {
	t.Helper()
	var count int64
	if err := db.Model(&models.AuditEvent{}).Where("action = ?", action).Count(&count).Error; err != nil {
		t.Fatal(err)
	}
	return count
}

func s7CreateLegacyAudit(t *testing.T, f *fixture) {
	t.Helper()
	if err := f.db.Exec(`CREATE TABLE audit_events (
		id integer PRIMARY KEY AUTOINCREMENT,
		event_id varchar(64), action varchar(64), actor_type varchar(32),
		actor_id varchar(255), target_type varchar(32), target_id varchar(36),
		reason varchar(256), created_at datetime
	)`).Error; err != nil {
		t.Fatal(err)
	}
	for _, statement := range []string{
		"CREATE UNIQUE INDEX idx_audit_events_event_id ON audit_events(event_id)",
		"CREATE INDEX idx_audit_events_action ON audit_events(action)",
		"CREATE INDEX idx_audit_events_actor_id ON audit_events(actor_id)",
		"CREATE INDEX idx_audit_events_target_type ON audit_events(target_type)",
		"CREATE INDEX idx_audit_events_target_id ON audit_events(target_id)",
		"CREATE INDEX idx_audit_events_created_at ON audit_events(created_at)",
	} {
		if err := f.db.Exec(statement).Error; err != nil {
			t.Fatal(err)
		}
	}
	if err := f.db.Exec(`INSERT INTO audit_events
		(id, event_id, action, actor_type, actor_id, target_type, target_id, reason, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		1, "legacy-event-1", audit.ActionClientCreated, "admin", "legacy-admin",
		"client", "legacy-client", "legacy-history", time.Unix(1699999000, 0).UTC()).Error; err != nil {
		t.Fatal(err)
	}
}

func s7SeedCurrentAudit(t *testing.T, f *fixture) {
	t.Helper()
	if err := audit.MigrateIntegrity(f.db); err != nil {
		t.Fatal(err)
	}
	if err := audit.NewService(f.db).Record(models.AuditEvent{
		Action:     audit.ActionClientCreated,
		ActorType:  "test",
		ActorID:    "s7-test",
		TargetType: "client",
		TargetID:   "s7-client",
		Reason:     "",
	}); err != nil {
		t.Fatal(err)
	}
}

func s7ClientSecrets(t *testing.T, f *fixture, id string) (string, string) {
	t.Helper()
	var row struct {
		Legacy    string `gorm:"column:legacy"`
		Encrypted string `gorm:"column:encrypted"`
	}
	if err := f.db.Raw("SELECT backend_api_key AS legacy, backend_api_key_encrypted AS encrypted FROM clients WHERE id = ?", id).Scan(&row).Error; err != nil {
		t.Fatal(err)
	}
	return row.Legacy, row.Encrypted
}

func s7ProviderEvents(t *testing.T, db *gorm.DB) []models.AuditEvent {
	t.Helper()
	return s7MaintenanceEvents(t, db)
}

func TestP108B_S7_LegacyAuditStartedBackupCompletion(t *testing.T) {
	f := newFixture(t)
	s7CreateLegacyAudit(t, f)
	f.addGlobal(t, "openai", canaryGlobal, "")
	f.addClient(t, "client-a", canaryClientA, "")

	res, err := Run(s7OptionsWithKey(t, f, filepath.Join(f.dir, "backups")))
	if err != nil {
		t.Fatal(err)
	}
	events := s7ProviderEvents(t, f.db)
	if len(events) != 2 || events[0].Action != audit.ActionProviderSecretMigrationStarted || events[1].Action != audit.ActionProviderSecretMigration {
		t.Fatalf("expected one STARTED/SUCCESS pair, got %+v", events)
	}
	if events[0].TargetID == "" || events[0].TargetID != events[1].TargetID {
		t.Fatalf("provider maintenance correlation mismatch: %+v", events)
	}
	if len(res.Phases) < 3 || res.Phases[0] != "AUDIT-MIGRATION" || res.Phases[1] != "AUDIT-VERIFIED" || res.Phases[2] != "STARTED" {
		t.Fatalf("audit phase ordering missing: %v", res.Phases)
	}

	snapshot, err := gorm.Open(sqlite.Open(filepath.Join(res.BackupDir, "gateway.db")), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := audit.VerifyIntegrityReadOnly(snapshot); err != nil {
		t.Fatalf("backup audit snapshot is not verifiable: %v", err)
	}
	if got := s7CountAction(t, snapshot, audit.ActionProviderSecretMigrationStarted); got != 1 {
		t.Fatalf("backup must contain committed STARTED, got %d", got)
	}
	var triggerCount int64
	if err := snapshot.Raw("SELECT count(*) FROM sqlite_master WHERE type = 'trigger' AND tbl_name = 'audit_events'").Scan(&triggerCount).Error; err != nil {
		t.Fatal(err)
	}
	if triggerCount != 2 {
		t.Fatalf("backup must contain both audit triggers, got %d", triggerCount)
	}
	if sqlDB, err := snapshot.DB(); err == nil {
		_ = sqlDB.Close()
	}
}

func TestP108B_S7_CurrentAuditCorruptionFailsBeforeStartedOrBackup(t *testing.T) {
	corruptions := []struct {
		name    string
		corrupt func(*testing.T, *fixture)
	}{
		{
			name: "event-hash",
			corrupt: func(t *testing.T, f *fixture) {
				if err := f.db.Exec("DROP TRIGGER audit_events_no_update").Error; err != nil {
					t.Fatal(err)
				}
				if err := f.db.Exec("UPDATE audit_events SET event_hash = ? WHERE id = 1", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").Error; err != nil {
					t.Fatal(err)
				}
				if err := f.db.Exec("CREATE TRIGGER audit_events_no_update BEFORE UPDATE ON audit_events BEGIN SELECT RAISE(ABORT, 'AUDIT_EVENT_IMMUTABLE'); END").Error; err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "state-head",
			corrupt: func(t *testing.T, f *fixture) {
				if err := f.db.Exec("UPDATE audit_chain_states SET head_hash = ? WHERE id = 1", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb").Error; err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "trigger-definition",
			corrupt: func(t *testing.T, f *fixture) {
				if err := f.db.Exec("DROP TRIGGER audit_events_no_update").Error; err != nil {
					t.Fatal(err)
				}
			},
		},
	}
	for _, tc := range corruptions {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			f.addClient(t, "client-a", canaryClientA, "")
			s7SeedCurrentAudit(t, f)
			tc.corrupt(t, f)
			beforeCfg := []byte(readCfgFile(t, f.cfgPath))
			_, err := Run(s7OptionsWithKey(t, f, filepath.Join(f.dir, "backups")))
			if err == nil {
				t.Fatal("corrupt current audit unexpectedly accepted")
			}
			if _, statErr := os.Stat(filepath.Join(f.dir, "backups")); !os.IsNotExist(statErr) {
				t.Fatalf("corrupt audit must fail before backup, stat=%v", statErr)
			}
			if got := s7CountAction(t, f.db, audit.ActionProviderSecretMigrationStarted); got != 0 {
				t.Fatalf("unexpected STARTED count %d", got)
			}
			legacy, encrypted := s7ClientSecrets(t, f, "client-a")
			if legacy != canaryClientA || encrypted != "" {
				t.Fatalf("provider mutation occurred: legacy=%q encrypted=%q", legacy, encrypted)
			}
			if !bytes.Equal(beforeCfg, []byte(readCfgFile(t, f.cfgPath))) {
				t.Fatal("config changed after audit preflight failure")
			}
		})
	}
}

func TestP108B_S7_StartedFailureLeavesNoBackupOrProviderMutation(t *testing.T) {
	f := newFixture(t)
	f.addGlobal(t, "openai", canaryGlobal, "")
	f.addClient(t, "client-a", canaryClientA, "")
	beforeConfig := []byte(readCfgFile(t, f.cfgPath))

	_, err := runWithHooks(s7OptionsWithKey(t, f, filepath.Join(f.dir, "backups")), migrationHooks{
		beforeStarted: func(tx *gorm.DB) error {
			return tx.Exec("CREATE TRIGGER reject_provider_started BEFORE INSERT ON audit_events WHEN NEW.action = 'PROVIDER_SECRET_MIGRATION_STARTED' BEGIN SELECT RAISE(ABORT, 'reject provider start'); END").Error
		},
	})
	if err == nil {
		t.Fatal("injected STARTED failure was accepted")
	}
	if _, statErr := os.Stat(filepath.Join(f.dir, "backups")); !os.IsNotExist(statErr) {
		t.Fatalf("STARTED failure must precede backup, stat=%v", statErr)
	}
	if got := s7CountAction(t, f.db, audit.ActionProviderSecretMigrationStarted); got != 0 {
		t.Fatalf("STARTED rollback left %d events", got)
	}
	legacy, encrypted := s7ClientSecrets(t, f, "client-a")
	if legacy != canaryClientA || encrypted != "" {
		t.Fatalf("provider mutation occurred after STARTED failure: legacy=%q encrypted=%q", legacy, encrypted)
	}
	if !bytes.Equal(beforeConfig, []byte(readCfgFile(t, f.cfgPath))) {
		t.Fatal("config changed after STARTED failure")
	}
}

func TestP108B_S7_BackupFailureLeavesOnePendingAndRerunReusesTarget(t *testing.T) {
	f := newFixture(t)
	f.addClient(t, "client-a", canaryClientA, "")
	blocked := filepath.Join(f.dir, "backup-blocker")
	if err := os.WriteFile(blocked, []byte("not a directory"), 0600); err != nil {
		t.Fatal(err)
	}
	_, err := runWithHooks(s7OptionsWithKey(t, f, filepath.Join(blocked, "nested")), migrationHooks{})
	if err == nil {
		t.Fatal("backup failure was accepted")
	}
	if got := s7CountAction(t, f.db, audit.ActionProviderSecretMigrationStarted); got != 1 {
		t.Fatalf("backup failure must leave exactly one STARTED, got %d", got)
	}
	if got := s7CountAction(t, f.db, audit.ActionProviderSecretMigration); got != 0 {
		t.Fatalf("backup failure unexpectedly completed, got %d", got)
	}
	legacy, encrypted := s7ClientSecrets(t, f, "client-a")
	if legacy != canaryClientA || encrypted != "" {
		t.Fatalf("provider mutation occurred after backup failure: legacy=%q encrypted=%q", legacy, encrypted)
	}

	res, err := Run(s7OptionsWithKey(t, f, filepath.Join(f.dir, "backups")))
	if err != nil {
		t.Fatalf("rerun after backup failure: %v", err)
	}
	events := s7ProviderEvents(t, f.db)
	if len(events) != 2 || events[0].Action != audit.ActionProviderSecretMigrationStarted || events[1].Action != audit.ActionProviderSecretMigration {
		t.Fatalf("rerun did not produce one STARTED/SUCCESS pair: %+v", events)
	}
	if events[0].TargetID != events[1].TargetID {
		t.Fatalf("rerun changed TargetID: %+v", events)
	}
	if res.BackupDir == "" {
		t.Fatal("successful rerun did not create recovery backup")
	}
}

func TestP108B_S7_BackupContainsStartedAndAuditIntegrityObjects(t *testing.T) {
	f := newFixture(t)
	f.addClient(t, "client-a", canaryClientA, "")
	res, err := Run(s7OptionsWithKey(t, f, filepath.Join(f.dir, "backups")))
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := gorm.Open(sqlite.Open(filepath.Join(res.BackupDir, "gateway.db")), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if got := s7CountAction(t, snapshot, audit.ActionProviderSecretMigrationStarted); got != 1 {
		t.Fatalf("snapshot missing committed STARTED: %d", got)
	}
	var objects int64
	if err := snapshot.Raw("SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name IN ('audit_events', 'audit_chain_states')").Scan(&objects).Error; err != nil {
		t.Fatal(err)
	}
	if objects != 2 {
		t.Fatalf("snapshot missing audit tables: %d", objects)
	}
	var triggers int64
	if err := snapshot.Raw("SELECT count(*) FROM sqlite_master WHERE type = 'trigger' AND name IN ('audit_events_no_update', 'audit_events_no_delete')").Scan(&triggers).Error; err != nil {
		t.Fatal(err)
	}
	if triggers != 2 {
		t.Fatalf("snapshot missing audit triggers: %d", triggers)
	}
	if sqlDB, err := snapshot.DB(); err == nil {
		_ = sqlDB.Close()
	}
}

func TestP108B_S7_RequestLogPendingBlocksProviderBeforeBackup(t *testing.T) {
	f := newFixture(t)
	f.addClient(t, "client-a", canaryClientA, "")
	if err := audit.MigrateIntegrity(f.db); err != nil {
		t.Fatal(err)
	}
	if err := f.db.Transaction(func(tx *gorm.DB) error {
		_, err := audit.NewService(f.db).BeginMaintenanceTx(tx, audit.MaintenanceKindRequestLogScrub)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	_, err := Run(s7OptionsWithKey(t, f, filepath.Join(f.dir, "backups")))
	if err == nil {
		t.Fatal("cross-kind pending maintenance was accepted")
	}
	if _, statErr := os.Stat(filepath.Join(f.dir, "backups")); !os.IsNotExist(statErr) {
		t.Fatalf("cross-kind pending must fail before backup, stat=%v", statErr)
	}
	if got := s7CountAction(t, f.db, audit.ActionProviderSecretMigrationStarted); got != 0 {
		t.Fatalf("provider STARTED appended despite cross-kind pending: %d", got)
	}
	if got := s7CountAction(t, f.db, audit.ActionRequestLogScrubStarted); got != 1 {
		t.Fatalf("scrub pending disappeared: %d", got)
	}
	legacy, encrypted := s7ClientSecrets(t, f, "client-a")
	if legacy != canaryClientA || encrypted != "" {
		t.Fatalf("provider mutation occurred with cross-kind pending: legacy=%q encrypted=%q", legacy, encrypted)
	}
}

func TestP108B_S7_MultiplePendingBlocksProviderBeforeBackup(t *testing.T) {
	f := newFixture(t)
	f.addClient(t, "client-a", canaryClientA, "")
	if err := audit.MigrateIntegrity(f.db); err != nil {
		t.Fatal(err)
	}
	for _, event := range []models.AuditEvent{
		{Action: audit.ActionProviderSecretMigrationStarted, ActorType: "cli", ActorID: "migrate-provider-secrets", TargetType: "maintenance-operation", TargetID: "00000000-0000-0000-0000-000000000001"},
		{Action: audit.ActionRequestLogScrubStarted, ActorType: "cli", ActorID: "scrub-request-log-content", TargetType: "maintenance-operation", TargetID: "00000000-0000-0000-0000-000000000002"},
	} {
		if err := audit.NewService(f.db).Record(event); err != nil {
			t.Fatal(err)
		}
	}
	_, err := Run(s7OptionsWithKey(t, f, filepath.Join(f.dir, "backups")))
	if err == nil {
		t.Fatal("multiple pending maintenance operations were accepted")
	}
	if _, statErr := os.Stat(filepath.Join(f.dir, "backups")); !os.IsNotExist(statErr) {
		t.Fatalf("multiple pending must fail before backup, stat=%v", statErr)
	}
	if got := s7CountAction(t, f.db, audit.ActionProviderSecretMigrationStarted); got != 1 {
		t.Fatalf("pending provider STARTED changed: %d", got)
	}
	if got := s7CountAction(t, f.db, audit.ActionRequestLogScrubStarted); got != 1 {
		t.Fatalf("pending scrub STARTED changed: %d", got)
	}
}

func TestP108B_S7_PrepareFailureLeavesPendingAndNoSuccess(t *testing.T) {
	f := newFixture(t)
	f.addGlobal(t, "openai", canaryGlobal, "")
	f.addClient(t, "client-a", canaryClientA, "")
	beforeConfig := []byte(readCfgFile(t, f.cfgPath))
	_, err := runWithHooks(s7OptionsWithKey(t, f, filepath.Join(f.dir, "backups")), migrationHooks{
		beforePrepare: func(*gorm.DB) error { return errors.New("injected prepare failure") },
	})
	if err == nil {
		t.Fatal("injected PREPARE failure was accepted")
	}
	if got := s7CountAction(t, f.db, audit.ActionProviderSecretMigrationStarted); got != 1 {
		t.Fatalf("PREPARE failure should retain STARTED, got %d", got)
	}
	if got := s7CountAction(t, f.db, audit.ActionProviderSecretMigration); got != 0 {
		t.Fatalf("PREPARE failure unexpectedly appended SUCCESS, got %d", got)
	}
	legacy, encrypted := s7ClientSecrets(t, f, "client-a")
	if legacy != canaryClientA || encrypted != "" {
		t.Fatalf("PREPARE failure committed provider mutation: legacy=%q encrypted=%q", legacy, encrypted)
	}
	if !bytes.Equal(beforeConfig, []byte(readCfgFile(t, f.cfgPath))) {
		t.Fatal("PREPARE failure changed config")
	}
}

func TestP108B_S7_VerifyFailureDoesNotFinalizePlaintext(t *testing.T) {
	f := newFixture(t)
	f.addGlobal(t, "openai", canaryGlobal, "")
	f.addClient(t, "client-a", canaryClientA, "")
	_, err := runWithHooks(s7OptionsWithKey(t, f, filepath.Join(f.dir, "backups")), migrationHooks{
		beforeVerify: func(*gorm.DB) error { return errors.New("injected verify failure") },
	})
	if err == nil {
		t.Fatal("injected VERIFY failure was accepted")
	}
	legacy, encrypted := s7ClientSecrets(t, f, "client-a")
	if legacy != canaryClientA || !secrets.IsEncryptedEnvelope(encrypted) {
		t.Fatalf("VERIFY failure did not preserve mixed state: legacy=%q encrypted=%q", legacy, encrypted)
	}
	cfg := reloadConfig(t, f)
	if cfg.Providers["openai"].APIKey != canaryGlobal || !secrets.IsEncryptedEnvelope(cfg.Providers["openai"].APIKeyEncrypted) {
		t.Fatalf("VERIFY failure did not preserve config plaintext: %+v", cfg.Providers["openai"])
	}
	if s7CountAction(t, f.db, audit.ActionProviderSecretMigration) != 0 {
		t.Fatal("VERIFY failure appended SUCCESS")
	}
}

func s7PostRenameFinalizeFailureHook() migrationHooks {
	return migrationHooks{
		replaceConfig: func(kind string, cfg *config.Config, path string, mode fs.FileMode) (configstore.ReplaceResult, error) {
			data, err := config.MarshalYAML(cfg)
			if err != nil {
				return configstore.ReplaceResult{}, err
			}
			result, err := configstore.AtomicReplace(path, data, mode)
			if err != nil || kind != "finalize" {
				return result, err
			}
			result.DirectorySynced = false
			return result, errors.New("injected post-rename directory sync failure")
		},
	}
}

func TestP108B_S7_FinalizeConfigFailureCompensatesSQLiteAndConfig(t *testing.T) {
	f := newFixture(t)
	f.addGlobal(t, "openai", canaryGlobal, "")
	f.addClient(t, "client-a", canaryClientA, "")
	_, err := runWithHooks(s7OptionsWithKey(t, f, filepath.Join(f.dir, "backups")), s7PostRenameFinalizeFailureHook())
	if err == nil {
		t.Fatal("post-rename final config failure was accepted")
	}
	legacy, encrypted := s7ClientSecrets(t, f, "client-a")
	if legacy != canaryClientA || !secrets.IsEncryptedEnvelope(encrypted) {
		t.Fatalf("final DB transaction was not rolled back: legacy=%q encrypted=%q", legacy, encrypted)
	}
	cfg := reloadConfig(t, f)
	if cfg.Providers["openai"].APIKey != canaryGlobal || !secrets.IsEncryptedEnvelope(cfg.Providers["openai"].APIKeyEncrypted) {
		t.Fatalf("config was not restored to PREPARE snapshot: %+v", cfg.Providers["openai"])
	}
	if got := s7CountAction(t, f.db, audit.ActionProviderSecretMigration); got != 0 {
		t.Fatalf("SUCCESS survived final config failure: %d", got)
	}
	if got := s7CountAction(t, f.db, audit.ActionProviderSecretMigrationStarted); got != 1 {
		t.Fatalf("pending STARTED lost after final config failure: %d", got)
	}
}

func TestP108B_S7_ConfigCompensationFailureIsStable(t *testing.T) {
	f := newFixture(t)
	f.addClient(t, "client-a", canaryClientA, "")
	hooks := s7PostRenameFinalizeFailureHook()
	hooks.restoreConfig = func(string, configstore.Snapshot) (configstore.ReplaceResult, error) {
		return configstore.ReplaceResult{}, errors.New("injected restore failure")
	}
	_, err := runWithHooks(s7OptionsWithKey(t, f, filepath.Join(f.dir, "backups")), hooks)
	if !errors.Is(err, configaudit.ErrConfigAuditRollbackFailed) {
		t.Fatalf("expected stable compensation failure, got %v", err)
	}
	legacy, encrypted := s7ClientSecrets(t, f, "client-a")
	if legacy != canaryClientA || !secrets.IsEncryptedEnvelope(encrypted) {
		t.Fatalf("SQLite transaction was not rolled back on compensation failure: legacy=%q encrypted=%q", legacy, encrypted)
	}
}

func TestP108B_S7_FinalSQLiteCommitFailureCompensatesConfig(t *testing.T) {
	f := newFixture(t)
	f.addGlobal(t, "openai", canaryGlobal, "")
	f.addClient(t, "client-a", canaryClientA, "")
	hooks := migrationHooks{commitFinal: func(*gorm.DB) error { return errors.New("injected final commit failure") }}
	_, err := runWithHooks(s7OptionsWithKey(t, f, filepath.Join(f.dir, "backups")), hooks)
	if err == nil {
		t.Fatal("injected final commit failure was accepted")
	}
	legacy, encrypted := s7ClientSecrets(t, f, "client-a")
	if legacy != canaryClientA || !secrets.IsEncryptedEnvelope(encrypted) {
		t.Fatalf("final SQLite rollback failed: legacy=%q encrypted=%q", legacy, encrypted)
	}
	cfg := reloadConfig(t, f)
	if cfg.Providers["openai"].APIKey != canaryGlobal || !secrets.IsEncryptedEnvelope(cfg.Providers["openai"].APIKeyEncrypted) {
		t.Fatalf("commit failure did not restore PREPARE config: %+v", cfg.Providers["openai"])
	}
	if s7CountAction(t, f.db, audit.ActionProviderSecretMigration) != 0 {
		t.Fatal("SUCCESS survived final SQLite commit failure")
	}
}

func TestP108B_S7_SuccessAuditAppendFailureRollsBackFinalize(t *testing.T) {
	f := newFixture(t)
	f.addGlobal(t, "openai", canaryGlobal, "")
	f.addClient(t, "client-a", canaryClientA, "")
	_, err := runWithHooks(s7OptionsWithKey(t, f, filepath.Join(f.dir, "backups")), migrationHooks{
		beforeVerify: func(db *gorm.DB) error {
			return db.Exec("CREATE TRIGGER reject_provider_success BEFORE INSERT ON audit_events WHEN NEW.action = 'PROVIDER_SECRET_MIGRATION' BEGIN SELECT RAISE(ABORT, 'reject provider success'); END").Error
		},
	})
	if err == nil {
		t.Fatal("injected SUCCESS audit failure was accepted")
	}
	legacy, encrypted := s7ClientSecrets(t, f, "client-a")
	if legacy != canaryClientA || !secrets.IsEncryptedEnvelope(encrypted) {
		t.Fatalf("SUCCESS audit failure did not roll back client finalize: legacy=%q encrypted=%q", legacy, encrypted)
	}
	cfg := reloadConfig(t, f)
	if cfg.Providers["openai"].APIKey != canaryGlobal || !secrets.IsEncryptedEnvelope(cfg.Providers["openai"].APIKeyEncrypted) {
		t.Fatalf("SUCCESS audit failure did not leave PREPARE config: %+v", cfg.Providers["openai"])
	}
	if s7CountAction(t, f.db, audit.ActionProviderSecretMigration) != 0 {
		t.Fatal("SUCCESS audit event exists after injected append failure")
	}
	if s7CountAction(t, f.db, audit.ActionProviderSecretMigrationStarted) != 1 {
		t.Fatal("pending STARTED was not preserved after audit append failure")
	}
}

func TestP108B_S7_PreRenameFinalizeFailureLeavesPrepareState(t *testing.T) {
	f := newFixture(t)
	f.addClient(t, "client-a", canaryClientA, "")
	hooks := migrationHooks{
		replaceConfig: func(kind string, cfg *config.Config, path string, mode fs.FileMode) (configstore.ReplaceResult, error) {
			if kind == "finalize" {
				return configstore.ReplaceResult{}, errors.New("injected pre-rename failure")
			}
			data, err := config.MarshalYAML(cfg)
			if err != nil {
				return configstore.ReplaceResult{}, err
			}
			return configstore.AtomicReplace(path, data, mode)
		},
	}
	_, err := runWithHooks(s7OptionsWithKey(t, f, filepath.Join(f.dir, "backups")), hooks)
	if err == nil {
		t.Fatal("injected pre-rename finalize failure was accepted")
	}
	legacy, encrypted := s7ClientSecrets(t, f, "client-a")
	if legacy != canaryClientA || !secrets.IsEncryptedEnvelope(encrypted) {
		t.Fatalf("pre-rename failure did not roll back DB finalize: legacy=%q encrypted=%q", legacy, encrypted)
	}
	if cfg := reloadConfig(t, f); len(cfg.Providers) != 0 {
		t.Fatalf("pre-rename failure unexpectedly changed provider config: %+v", cfg.Providers)
	}
}

func TestP108B_S7_MaintenanceAuditPrivacyCanary(t *testing.T) {
	f := newFixture(t)
	f.addGlobal(t, "openai", canaryGlobal, "")
	f.addClient(t, "client-a", canaryClientA, "")
	backupDir := filepath.Join(f.dir, "backups")
	if _, err := Run(s7OptionsWithKey(t, f, backupDir)); err != nil {
		t.Fatal(err)
	}
	for _, event := range s7ProviderEvents(t, f.db) {
		serialized := strings.Join([]string{event.EventID, event.Action, event.ActorType, event.ActorID, event.TargetType, event.TargetID, event.Reason, event.CreatedAt.String(), event.ChainVersion, event.PrevHash, event.EventHash}, "|")
		for _, secret := range []string{canaryGlobal, canaryClientA, testMasterKeyB64, f.cfgPath, backupDir} {
			if strings.Contains(serialized, secret) {
				t.Fatalf("maintenance audit event leaked sensitive value %q: %+v", secret, event)
			}
		}
	}
}
