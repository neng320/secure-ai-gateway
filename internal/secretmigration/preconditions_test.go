package secretmigration

// P1-03C2.1 · Migration Preconditions Gate
//
// 人工复验发现的破坏性迁移前置缺口，逐项回归：
//   1. config 缺失/解析失败 → STOP，绝不创建/修改文件（曾有 config.Load 会 createDefaultConfig）
//   2. DB 缺失 → STOP，绝不创建空库；schema 显式检查，无 "no such column" 模糊失败
//   3. 备份必须是任何 mutation 之前的快照（config 原始字节 + 迁移前 DB 内容）
//   4. 旧 schema（无 encrypted 列）→ 备份完成后仅 ADD COLUMN 补齐

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"ai-gateway/internal/secrets"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// withEmptyCwd: 进入一次性空目录，用于断言"不在 CWD 产生 config.yaml"
func withEmptyCwd(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Chdir(dir)
	return dir
}

// assertNoBackupRoot: 断言备份根目录从未被创建（前置失败不应有任何落盘副作用）
func assertNoBackupRoot(t *testing.T, root string) {
	t.Helper()
	if _, err := os.Stat(root); !os.IsNotExist(err) {
		t.Fatalf("[安全回归失败] 前置失败不应创建备份根目录 %s", root)
	}
}

// 修正 1：config 不存在 → STOP，不创建文件（含 CWD 不落地）
func TestC21_MissingConfig_StopNoCreate(t *testing.T) {
	cwd := withEmptyCwd(t)
	missing := filepath.Join(t.TempDir(), "config.yaml")
	backupRoot := filepath.Join(t.TempDir(), "bk")

	if _, err := Run(Options{
		ConfigPath: missing,
		BackupDir:  backupRoot,
		MasterKey:  testKey(t),
		Now:        func() time.Time { return time.Now().UTC() },
	}); err == nil {
		t.Fatal("[安全回归失败] config 缺失未导致迁移 STOP")
	}

	if _, err := os.Stat(missing); !os.IsNotExist(err) {
		t.Fatal("[安全回归失败] 迁移为缺失路径创建了 config 文件")
	}
	assertNoBackupRoot(t, backupRoot)
	entries, err := os.ReadDir(cwd)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".yaml") || strings.HasSuffix(e.Name(), ".migrating") {
			t.Fatalf("[安全回归失败] CWD 出现配置残留: %s", e.Name())
		}
	}
}

// 修正 1：解析失败 → STOP，文件字节不变
func TestC21_ParseErrorConfig_StopNoWrite(t *testing.T) {
	withEmptyCwd(t)
	f := newFixture(t)
	writeCfgFile(t, f.cfgPath, "[unclosed\n")
	before, err := os.ReadFile(f.cfgPath)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := runMigration(t, f, testMasterKeyB64); err == nil {
		t.Fatal("[安全回归失败] 解析失败未导致迁移 STOP")
	}
	after, err := os.ReadFile(f.cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatal("[安全回归失败] 解析失败后配置文件被修改")
	}
	assertNoBackupRoot(t, filepath.Join(f.dir, "backups"))
}

// 修正 2：DB 不存在 → STOP，绝不创建空库
func TestC21_MissingDB_StopNoCreate(t *testing.T) {
	withEmptyCwd(t)
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	dbPath := filepath.Join(dir, "gateway.db")
	writeCfgFile(t, cfgPath, "server:\n  host: 127.0.0.1\ndatabase:\n  path: "+dbPath+"\nproviders: {}\n")

	if _, err := Run(Options{
		ConfigPath: cfgPath,
		BackupDir:  filepath.Join(dir, "bk"),
		MasterKey:  testKey(t),
		Now:        func() time.Time { return time.Now().UTC() },
	}); err == nil {
		t.Fatal("[安全回归失败] DB 缺失未导致迁移 STOP")
	}
	if _, err := os.Stat(dbPath); !os.IsNotExist(err) {
		t.Fatal("[安全回归失败] 迁移为缺失路径创建了 SQLite 文件")
	}
	assertNoBackupRoot(t, filepath.Join(dir, "bk"))
}

// 修正 2：clients 表缺失 → 显式 STOP（无备份产生）
func TestC21_DBSchemaMissingClientsTable_Stop(t *testing.T) {
	withEmptyCwd(t)
	f := newFixtureWithoutClientsTable(t)

	err := runMigrationOrFail(t, f)
	if err == nil || !strings.Contains(err.Error(), "clients") {
		t.Fatalf("[安全回归失败] clients 表缺失应显式 STOP，实际 err=%v", err)
	}
	assertNoBackupRoot(t, filepath.Join(f.dir, "backups"))
}

func runMigrationOrFail(t *testing.T, f *fixture) (rerr error) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			rerr = fmt.Errorf("panic: %v", r)
		}
	}()
	_, err := runMigration(t, f, testMasterKeyB64)
	return err
}

// newFixtureWithoutClientsTable: 只有 config + 一个没有任何业务表的空 SQLite 文件
func newFixtureWithoutClientsTable(t *testing.T) *fixture {
	t.Helper()
	f := newFixture(t)
	// 重建一个空库（无 clients 表）
	if sqlDB, err := f.db.DB(); err == nil {
		_ = sqlDB.Close()
	}
	dbPath := f.dbPath
	_ = os.Remove(dbPath)
	raw, err := gorm.Open(sqlite.Open(dbPath), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if err := raw.Exec("CREATE TABLE other (id integer primary key)").Error; err != nil {
		t.Fatal(err)
	}
	if sqlDB, err := raw.DB(); err == nil {
		_ = sqlDB.Close()
	}
	f.db = nil // 本 fixture 不再使用 gorm 句柄
	return f
}

// 修正 2+4：旧 schema（无 backend_api_key_encrypted 列）→
// 备份（快照中无该列）完成后仅 ADD COLUMN，迁移继续并成功
func TestC21_OldSchema_AdditiveColumnAfterBackup(t *testing.T) {
	withEmptyCwd(t)
	f := newOldSchemaFixture(t)
	f.addGlobal(t, "openai", canaryGlobal, "")
	insertOldSchemaClient(t, f, "client-old", canaryClientA)

	preRows := oldSchemaRows(t, f)

	res, err := runMigration(t, f, testMasterKeyB64)
	if err != nil {
		t.Fatalf("旧 schema 迁移应成功（additive 补齐），实际 %v", err)
	}
	if !containsPhase(res.Phases, "SCHEMA-ADD") {
		t.Fatalf("phases 应记录 additive schema 补齐，实际 %v", res.Phases)
	}

	// 迁移后：encrypted 列存在且内容正确，legacy 清空
	post, err := gorm.Open(sqlite.Open(f.dbPath), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = postDBClose(post) }()
	var enc string
	if err := post.Raw("SELECT backend_api_key_encrypted FROM clients WHERE id = ?", "client-old").Scan(&enc).Error; err != nil {
		t.Fatalf("additive 列缺失: %v", err)
	}
	if !secrets.IsEncryptedEnvelope(enc) {
		t.Fatalf("encrypted 应为信封，实际 %q", enc)
	}
	mgr := secrets.NewManager(mustNewCipher(t, testMasterKeyB64))
	pt, err := mgr.DecryptClientBackendKey("client-old", enc)
	if err != nil || string(pt) != canaryClientA {
		t.Fatalf("解密应还原原明文，实际 %q err=%v", string(pt), err)
	}
	var legacy string
	_ = post.Raw("SELECT backend_api_key FROM clients WHERE id = ?", "client-old").Scan(&legacy).Error
	if legacy != "" {
		t.Fatalf("FINALIZE 后 legacy 应为空，实际 %q", legacy)
	}

	// 备份快照必须是升级前的旧 schema：无 encrypted 列，行内容与迁移前一致
	snap := filepath.Join(res.BackupDir, "gateway.db")
	if !columnExistsInFile(t, snap, "clients", "backend_api_key") {
		t.Fatal("备份快照缺 legacy 列（快照损坏）")
	}
	if columnExistsInFile(t, snap, "clients", "backend_api_key_encrypted") {
		t.Fatal("[安全回归失败] 备份快照包含 encrypted 列——备份发生在 schema 变更之后")
	}
	snapRows := oldSchemaRowsInFile(t, snap)
	if len(snapRows) != len(preRows) {
		t.Fatalf("快照行数不符: %d vs %d", len(snapRows), len(preRows))
	}
	for id, key := range preRows {
		if snapRows[id] != key {
			t.Fatalf("快照行 %s 内容不符: %q vs %q", id, snapRows[id], key)
		}
	}
}

func postDBClose(db *gorm.DB) error {
	if sqlDB, err := db.DB(); err == nil {
		return sqlDB.Close()
	}
	return nil
}

func containsPhase(phases []string, want string) bool {
	for _, p := range phases {
		if p == want {
			return true
		}
	}
	return false
}

// newOldSchemaFixture: 手工建旧 schema（无 encrypted 列），模拟 P1-03C1 之前的存量 DB
func newOldSchemaFixture(t *testing.T) *fixture {
	t.Helper()
	f := newFixture(t)
	if sqlDB, err := f.db.DB(); err == nil {
		_ = sqlDB.Close()
	}
	_ = os.Remove(f.dbPath)
	db, err := gorm.Open(sqlite.Open(f.dbPath), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Exec("CREATE TABLE clients (id varchar(36) primary key, name varchar(255), backend varchar(50), backend_api_key varchar(500))").Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Exec("CREATE TABLE other (id integer primary key)").Error; err != nil {
		t.Fatal(err)
	}
	if sqlDB, err := db.DB(); err == nil {
		_ = sqlDB.Close()
	}
	f.db = nil
	return f
}

func insertOldSchemaClient(t *testing.T, f *fixture, id, legacy string) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(f.dbPath), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = postDBClose(db) }()
	if err := db.Exec("INSERT INTO clients (id, name, backend, backend_api_key) VALUES (?, ?, 'openai', ?)", id, id, legacy).Error; err != nil {
		t.Fatal(err)
	}
}

// oldSchemaRows / oldSchemaRowsInFile: 只依赖 legacy 列的内容快照（id → backend_api_key）
func oldSchemaRows(t *testing.T, f *fixture) map[string]string {
	t.Helper()
	return oldSchemaRowsInFile(t, f.dbPath)
}

func oldSchemaRowsInFile(t *testing.T, dbPath string) map[string]string {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(dbPath), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = postDBClose(db) }()
	var rows []struct {
		ID     string
		Legacy string
	}
	if err := db.Raw("SELECT id, backend_api_key AS legacy FROM clients").Scan(&rows).Error; err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	for _, r := range rows {
		out[r.ID] = r.Legacy
	}
	return out
}

func columnExistsInFile(t *testing.T, dbPath, table, column string) bool {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(dbPath), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = postDBClose(db) }()
	var n int64
	if err := db.Raw("SELECT count(*) FROM pragma_table_info('" + table + "') WHERE name = '" + column + "'").Scan(&n).Error; err != nil {
		t.Fatal(err)
	}
	return n > 0
}

// 修正 3：备份必须是 mutation 前快照——
// config（含会触发旧 ensureDefaults 写回的缺失字段）原始字节 == 备份字节；
// DB 行内容 == 迁移前内容；loader 默认值补齐不得污染备份。
func TestC21_BackupIsPreMutationSnapshot(t *testing.T) {
	withEmptyCwd(t)
	f := newFixture(t)
	// admin 段无 password_hash/session_secret —— 旧 config.Load 会在此生成并写回
	writeCfgFile(t, f.cfgPath, "server:\n  host: 127.0.0.1\n  port: 8090\ndatabase:\n  path: "+f.dbPath+"\nadmin:\n  username: admin\nproviders:\n  openai:\n    type: openai\n    api_key: "+canaryGlobal+"\n")
	f.addClient(t, "client-a", canaryClientA, "")

	preCfg, err := os.ReadFile(f.cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	preRows := oldSchemaRows(t, f)

	res, err := runMigration(t, f, testMasterKeyB64)
	if err != nil {
		t.Fatal(err)
	}

	backupCfg, err := os.ReadFile(filepath.Join(res.BackupDir, "config.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if string(backupCfg) != string(preCfg) {
		t.Fatal("[安全回归失败] 备份 config 与迁移前原始字节不一致（loader 默认值污染了备份）")
	}
	sum := sha256.Sum256(preCfg)
	manifestRaw, err := os.ReadFile(filepath.Join(res.BackupDir, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(manifestRaw), hex.EncodeToString(sum[:])) {
		t.Fatal("manifest config_sha256 应为迁移前原始字节的 SHA-256")
	}

	snapRows := oldSchemaRowsInFile(t, filepath.Join(res.BackupDir, "gateway.db"))
	for id, key := range preRows {
		if snapRows[id] != key {
			t.Fatalf("[安全回归失败] 备份 DB 行 %s 与迁移前不符", id)
		}
	}
	if snapRows["client-a"] != canaryClientA {
		t.Fatal("[安全回归失败] 备份 DB 应为迁移前状态（含 legacy 明文）")
	}

	// 成功迁移后的 config 也不得引入生成默认值
	postCfg, err := os.ReadFile(f.cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(postCfg), "__SETUP_REQUIRED__") {
		t.Fatal("[安全回归失败] 迁移写回了 __SETUP_REQUIRED__ 默认值")
	}
	if strings.Contains(string(postCfg), "session_secret: ") && !strings.Contains(string(postCfg), "session_secret: \"\"") {
		t.Fatal("[安全回归失败] 迁移生成了 session secret")
	}
}
