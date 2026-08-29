// Package secretmigration 实现显式、离线、可恢复、fail-closed 的
// Provider Secret 迁移（明文 → AEAD 信封）。
//
// 三相状态机：
//
//	PREPARE  : 明文加密写入 additive encrypted 字段（legacy 明文暂留）
//	VERIFY   : 逐条 decrypt(encrypted) == original plaintext，全部通过才放行
//	FINALIZE : 清空 legacy 明文字段（保留 encrypted）
//
// 原子性边界：DB 用事务；config 用临时文件 + rename 原子替换。
// DB 与 config 无法形成单一事务，因此本引擎：
//   - 迁移前生成专用 recovery snapshot（config 副本 + DB 一致性快照 + manifest）
//   - 幂等可重跑（EMPTY/LEGACY_ONLY/MIXED/ENCRYPTED_ONLY 均可安全识别）
//
// 输出纪律：结果与错误只允许出现数量与位置 ID，绝不出现 secret 材料。
package secretmigration

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"ai-gateway/internal/config"
	"ai-gateway/internal/secrets"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// Options: 迁移引擎输入
type Options struct {
	ConfigPath string           // 实际加载的配置文件路径
	BackupDir  string           // 迁移备份根目录（其下创建 migration-backup-<ts>/）
	MasterKey  []byte           // 已加载的 32 字节 Master Key
	Now        func() time.Time // 可注入时钟（测试）
}

// Result: 迁移结果（只含数量与位置，不含 secret 材料）
type Result struct {
	GlobalLegacyOnly int
	GlobalMixed      int
	GlobalEncrypted  int
	ClientLegacyOnly int
	ClientMixed      int
	ClientEncrypted  int
	FinalizedGlobal  int
	FinalizedClients int
	BackupDir        string
	Phases           []string
}

// Run: 执行完整迁移（backup → prepare → verify → finalize）。
// 任何一步失败立即返回错误；DB 事务回滚、config 不切换（保持上次已提交状态）。
func Run(opts Options) (*Result, error) {
	if opts.ConfigPath == "" {
		return nil, fmt.Errorf("migration: config path is required")
	}
	if opts.BackupDir == "" {
		return nil, fmt.Errorf("migration: backup dir is required")
	}
	if len(opts.MasterKey) != secrets.KeySize {
		return nil, fmt.Errorf("migration: master key must be %d bytes", secrets.KeySize)
	}
	now := opts.Now
	if now == nil {
		now = time.Now
	}

	cipher, err := secrets.NewAESGCMCipher(opts.MasterKey)
	if err != nil {
		return nil, err
	}
	mgr := secrets.NewManager(cipher)

	// ---- Phase -2: 配置纯读取 + 原始字节捕获（P1-03C2.1：任何 mutation 之前）----
	// 绝不使用有副作用的 config.Load（缺失会建默认配置、ensureDefaults 会写回）：
	// 文件缺失 / 解析失败一律 STOP，不创建、不补写、不落任何默认值。
	rawCfg, err := os.ReadFile(opts.ConfigPath)
	if err != nil {
		return nil, fmt.Errorf("migration: config %s: %w (refusing to continue)", opts.ConfigPath, err)
	}
	cfg, err := config.LoadExistingForMigration(opts.ConfigPath)
	if err != nil {
		return nil, fmt.Errorf("migration: load config: %w", err)
	}
	if cfg.Database.Path == "" {
		return nil, fmt.Errorf("migration: database.path is empty in config — stop")
	}

	// ---- Phase -1: DB fail-closed（存在性 + regular file），绝不创建空库 ----
	// 目录 / FIFO / socket / 设备文件等一切非 regular file 一律 STOP（P1-03C3.1）。
	dbPath := cfg.Database.Path
	st, statErr := os.Stat(dbPath)
	if statErr != nil {
		return nil, fmt.Errorf("migration: database %s: %w (refusing to create)", dbPath, statErr)
	}
	if !st.Mode().IsRegular() {
		return nil, fmt.Errorf("migration: database %s is not a regular file — stop", dbPath)
	}

	db, err := gorm.Open(sqlite.Open(dbPath), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		return nil, fmt.Errorf("migration: open db %s: %w", dbPath, err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		return nil, err
	}
	defer func() { _ = sqlDB.Close() }()

	// 显式 schema 检查（P1-03C2.1/C3.1）：全部必要 precondition 必须在任何 mutation
	// （含备份后的 ADD COLUMN）之前验证完毕——后续 SELECT 依赖的 clients.id 与
	// clients.backend_api_key 缺一即明确 STOP，绝不许出现半途 "no such column" 。
	if !tableExists(db, "clients") {
		return nil, fmt.Errorf("migration: schema check failed: table 'clients' not found in %s — stop", dbPath)
	}
	if !columnExists(db, "clients", "id") {
		return nil, fmt.Errorf("migration: schema check failed: column 'clients.id' not found — stop")
	}
	if !columnExists(db, "clients", "backend_api_key") {
		return nil, fmt.Errorf("migration: schema check failed: column 'clients.backend_api_key' not found — stop")
	}
	encryptedColumnReady := columnExists(db, "clients", "backend_api_key_encrypted")

	// manifest 元数据（P1-03C3.1）：全部在任何 mutation 之前取得
	var userVersion int64
	if err := db.Raw("PRAGMA user_version").Scan(&userVersion).Error; err != nil {
		return nil, fmt.Errorf("migration: read sqlite user_version: %w", err)
	}

	res := &Result{Phases: []string{}}

	// ---- Phase 0: BACKUP（VACUUM INTO 一致性快照 + config 原始字节副本 + manifest）----
	// 顺序硬约束（P1-03C2.1）：备份必须先于任何 schema/数据变更；
	// config 备份写入的是上面捕获的原始字节，绝不重新序列化。
	backupDir, err := takeBackup(db, sqlDB, cfg, opts.ConfigPath, rawCfg, opts.BackupDir, mgr.KeyID(), encryptedColumnReady, userVersion, now())
	if err != nil {
		return nil, fmt.Errorf("migration: backup: %w", err)
	}
	res.BackupDir = backupDir
	res.Phases = append(res.Phases, "BACKUP")

	// ---- Phase 0.5: additive schema upgrade（备份之后；仅 ADD COLUMN，绝不 drop/rename）----
	if !encryptedColumnReady {
		if err := db.Exec("ALTER TABLE clients ADD COLUMN backend_api_key_encrypted text").Error; err != nil {
			return nil, fmt.Errorf("migration: additive schema upgrade (ADD COLUMN backend_api_key_encrypted): %w", err)
		}
		res.Phases = append(res.Phases, "SCHEMA-ADD")
	}

	// ---- 清点（只统计数量；位置 ID 仅在 STOP 错误中出现）----
	type globalTarget struct {
		name      string
		legacy    string
		encrypted string
		state     secrets.SecretState
	}
	var globals []globalTarget
	for name, p := range cfg.Providers {
		g := globalTarget{name: name, legacy: p.APIKey, encrypted: p.APIKeyEncrypted, state: secrets.ClassifySecret(p.APIKey, p.APIKeyEncrypted)}
		switch g.state {
		case secrets.SecretLegacyOnly:
			res.GlobalLegacyOnly++
		case secrets.SecretMixed:
			res.GlobalMixed++
		case secrets.SecretEncryptedOnly:
			res.GlobalEncrypted++
		}
		globals = append(globals, g)
	}

	type clientTarget struct {
		id        string
		legacy    string
		encrypted string
		state     secrets.SecretState
	}
	var clients []clientTarget
	var dbRows []struct {
		ID        string
		Legacy    string
		Encrypted string
	}
	if err := db.Raw("SELECT id, backend_api_key AS legacy, backend_api_key_encrypted AS encrypted FROM clients").Scan(&dbRows).Error; err != nil {
		return nil, fmt.Errorf("migration: scan clients: %w", err)
	}
	for _, rr := range dbRows {
		c := clientTarget{id: rr.ID, legacy: rr.Legacy, encrypted: rr.Encrypted, state: secrets.ClassifySecret(rr.Legacy, rr.Encrypted)}
		switch c.state {
		case secrets.SecretLegacyOnly:
			res.ClientLegacyOnly++
		case secrets.SecretMixed:
			res.ClientMixed++
		case secrets.SecretEncryptedOnly:
			res.ClientEncrypted++
		}
		clients = append(clients, c)
	}

	// INVALID（encrypted 字段非 enc: 信封）→ STOP，不做自动修复
	for _, g := range globals {
		if g.state == secrets.SecretInvalidEncrypted {
			return nil, fmt.Errorf("migration: INVALID encrypted form at global:%s — stop, no auto-repair", g.name)
		}
	}
	for _, c := range clients {
		if c.state == secrets.SecretInvalidEncrypted {
			return nil, fmt.Errorf("migration: INVALID encrypted form at client:%s — stop, no auto-repair", c.id)
		}
	}

	// ---- PHASE 1: PREPARE（DB 事务写 encrypted；config 原子替换写 encrypted；legacy 暂留）----
	// 原生 SQL 写入（P1-03C2.1）：迁移引擎承诺的最小 schema 只有 id/backend_api_key(+encrypted)，
	// 不得依赖 gorm Update 自动维护的 updated_at 等列（旧库可能没有）。
	err = db.Transaction(func(tx *gorm.DB) error {
		for _, c := range clients {
			if c.state != secrets.SecretLegacyOnly {
				continue
			}
			env, err := mgr.EncryptClientBackendKey(c.id, []byte(c.legacy))
			if err != nil {
				return fmt.Errorf("prepare client:%s: %w", c.id, err)
			}
			if err := tx.Exec("UPDATE clients SET backend_api_key_encrypted = ? WHERE id = ?", env, c.id).Error; err != nil {
				return fmt.Errorf("prepare client:%s write: %w", c.id, err)
			}
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("migration: PREPARE (db): %w", err)
	}

	cfgCandidate := *cfg // 浅拷贝（PREPARE 仅改 Providers 内值字段，不增删 map 键）
	for i := range globals {
		g := &globals[i]
		if g.state != secrets.SecretLegacyOnly {
			continue
		}
		env, err := mgr.EncryptGlobalProviderKey(g.name, []byte(g.legacy))
		if err != nil {
			return nil, fmt.Errorf("prepare global:%s: %w", g.name, err)
		}
		pc := cfgCandidate.Providers[g.name]
		pc.APIKeyEncrypted = env
		cfgCandidate.Providers[g.name] = pc
	}
	if err := atomicWriteConfig(&cfgCandidate, opts.ConfigPath); err != nil {
		return nil, fmt.Errorf("migration: PREPARE (config): %w", err)
	}
	res.Phases = append(res.Phases, "PREPARE")

	// ---- PHASE 2: VERIFY（重读 DB 与配置，逐条解密比对原明文；任一失败 → 全停，不 scrub）----
	verifyFail := func(kind, ref string) error {
		return fmt.Errorf("migration: VERIFY failed at %s:%s — plaintext NOT scrubbed, migration aborted", kind, ref)
	}
	var dbRows2 []struct {
		ID        string
		Legacy    string
		Encrypted string
	}
	if err := db.Raw("SELECT id, backend_api_key AS legacy, backend_api_key_encrypted AS encrypted FROM clients").Scan(&dbRows2).Error; err != nil {
		return nil, err
	}
	for _, rr := range dbRows2 {
		if rr.Encrypted == "" {
			continue // EMPTY（本次未涉及）
		}
		pt, err := mgr.DecryptClientBackendKey(rr.ID, rr.Encrypted)
		if err != nil {
			return nil, fmt.Errorf("migration: VERIFY client:%s decrypt: %w", rr.ID, err)
		}
		if rr.Legacy != "" && string(pt) != rr.Legacy {
			return nil, verifyFail("client", rr.ID)
		}
	}
	// 纯读取重载（P1-03C2.1）：VERIFY 阶段绝不触发 ensureDefaults 写回
	cfgVerify, err := config.LoadExistingForMigration(opts.ConfigPath)
	if err != nil {
		return nil, err
	}
	for name, p := range cfgVerify.Providers {
		if p.APIKeyEncrypted == "" {
			continue
		}
		pt, err := mgr.DecryptGlobalProviderKey(name, p.APIKeyEncrypted)
		if err != nil {
			return nil, fmt.Errorf("migration: VERIFY global:%s decrypt: %w", name, err)
		}
		if p.APIKey != "" && string(pt) != p.APIKey {
			return nil, verifyFail("global", name)
		}
	}
	res.Phases = append(res.Phases, "VERIFY")

	// ---- PHASE 3: FINALIZE（验证全通过才清 legacy；DB 事务 + config 原子写）----
	err = db.Transaction(func(tx *gorm.DB) error {
		for _, rr := range dbRows2 {
			if rr.Encrypted == "" || rr.Legacy == "" {
				continue
			}
			if err := tx.Exec("UPDATE clients SET backend_api_key = '' WHERE id = ?", rr.ID).Error; err != nil {
				return fmt.Errorf("clear client:%s: %w", rr.ID, err)
			}
			res.FinalizedClients++
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("migration: FINALIZE (db): %w", err)
	}

	cfgFinal := *cfgVerify
	for name, p := range cfgFinal.Providers {
		if p.APIKeyEncrypted != "" && p.APIKey != "" {
			p.APIKey = "" // legacy 明文清空；encrypted 保留
			cfgFinal.Providers[name] = p
			res.FinalizedGlobal++
		}
	}
	if err := atomicWriteConfig(&cfgFinal, opts.ConfigPath); err != nil {
		return nil, fmt.Errorf("migration: FINALIZE (config): %w", err)
	}
	res.Phases = append(res.Phases, "FINALIZE")

	return res, nil
}

// atomicWriteConfig: candidate → 同目录临时文件 → rename 原子替换。
// （不用 fmt.Fprintf 渲染，内容含 % 不受影响；MarshalYAML 由 config 包提供。）
func atomicWriteConfig(cfg *config.Config, path string) error {
	data, err := config.MarshalYAML(cfg)
	if err != nil {
		return err
	}
	tmp := path + ".migrating"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return fmt.Errorf("write temp config: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("rename config: %w", err)
	}
	return nil
}

// MigrationFormatVersion: 迁移快照格式的稳定版本标识（manifest 元数据，非敏感）。
const MigrationFormatVersion = "p1-provider-secret-v1"

// takeBackup: 迁移专用 recovery snapshot。
//   - DB：VACUUM INTO（SQLite 一致性快照；离线模式无并发写者）
//   - config：原始字节副本（P1-03C2.1：调用方在任何 mutation 之前捕获的 rawCfg，绝不重新序列化）
//   - manifest.json：时间/路径/key_id/SHA-256/迁移格式与 schema 状态（P1-03C3.1）；
//     绝不包含 Master Key、plaintext key 或 encrypted envelope
func takeBackup(db *gorm.DB, sqlDB *sql.DB, cfg *config.Config, configPath string, rawCfg []byte, backupRoot, keyID string, encryptedColumnBefore bool, sqliteUserVersion int64, now time.Time) (string, error) {
	ts := now.UTC().Format("20060102T150405Z")
	backupDir := filepath.Join(backupRoot, "migration-backup-"+ts)
	// 绝不覆盖既有备份：时间戳碰撞（同秒重跑）时追加序号
	suffix := 1
	for {
		if _, err := os.Stat(backupDir); os.IsNotExist(err) {
			break
		}
		backupDir = filepath.Join(backupRoot, fmt.Sprintf("migration-backup-%s-%d", ts, suffix))
		suffix++
	}
	if err := os.MkdirAll(backupDir, 0700); err != nil {
		return "", err
	}

	// DB 一致性快照（VACUUM INTO 不支持绑定参数 → 路径单引号转义）
	snapshotPath := filepath.Join(backupDir, "gateway.db")
	safePath := strings.ReplaceAll(snapshotPath, "'", "''")
	res, err := sqlDB.Exec("VACUUM INTO '" + safePath + "'")
	if err != nil {
		return "", fmt.Errorf("vacuum into: %w", err)
	}
	_ = res

	// config 原始字节副本（任何 mutation 之前捕获）
	if err := os.WriteFile(filepath.Join(backupDir, "config.yaml"), rawCfg, 0600); err != nil {
		return "", err
	}

	cfgSum := sha256.Sum256(rawCfg)
	dbSum, err := fileSHA256(snapshotPath)
	if err != nil {
		return "", err
	}

	manifest := map[string]string{
		"timestamp":                now.UTC().Format(time.RFC3339),
		"migration_format_version": MigrationFormatVersion,
		"source_config_path":       configPath,
		"source_db_path":           cfg.Database.Path,
		"master_key_id":            keyID,
		"config_sha256":            hex.EncodeToString(cfgSum[:]),
		"db_snapshot_sha256":       dbSum,
		// snapshot 时 encrypted 列是否已存在（ADD COLUMN additive 升级发生之前的状态）
		"schema_clients_backend_api_key_encrypted_before": strconv.FormatBool(encryptedColumnBefore),
		"sqlite_user_version":                             fmt.Sprintf("%d", sqliteUserVersion),
		"sensitivity":                                     "contains legacy plaintext provider keys - SENSITIVE, encrypt or offline-store, never push",
	}
	manifestRaw, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(filepath.Join(backupDir, "manifest.json"), manifestRaw, 0600); err != nil {
		return "", err
	}
	return backupDir, nil
}

func fileSHA256(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

// tableExists / columnExists: 显式 schema 检查（P1-03C2.1）。
// 表名/列名均为本包内常量调用，不构成注入面；目标是不让 "no such column"
// 这类模糊错误出现在半途——schema 不符合预期在开库后立即明确 STOP。
func tableExists(db *gorm.DB, table string) bool {
	var n int64
	if err := db.Raw("SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name = '" + table + "'").Scan(&n).Error; err != nil {
		return false
	}
	return n > 0
}

func columnExists(db *gorm.DB, table, column string) bool {
	var n int64
	if err := db.Raw("SELECT count(*) FROM pragma_table_info('" + table + "') WHERE name = '" + column + "'").Scan(&n).Error; err != nil {
		return false
	}
	return n > 0
}
