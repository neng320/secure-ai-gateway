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
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"ai-gateway/internal/audit"
	"ai-gateway/internal/config"
	"ai-gateway/internal/configaudit"
	"ai-gateway/internal/configlock"
	"ai-gateway/internal/configstore"
	gatewaydb "ai-gateway/internal/database"
	"ai-gateway/internal/secrets"

	"gorm.io/gorm"
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

var errConfigReplaceIncomplete = errors.New("migration: config replacement durability incomplete")

type migrationHooks struct {
	beforeStarted func(*gorm.DB) error
	beforePrepare func(*gorm.DB) error
	beforeVerify  func(*gorm.DB) error
	replaceConfig func(string, *config.Config, string, fs.FileMode) (configstore.ReplaceResult, error)
	restoreConfig func(string, configstore.Snapshot) (configstore.ReplaceResult, error)
	commitFinal   func(*gorm.DB) error
}

// Run: 执行完整迁移（backup → prepare → verify → finalize）。
// 任何一步失败立即返回错误；DB 事务回滚、config 不切换（保持上次已提交状态）。
func Run(opts Options) (*Result, error) {
	return runWithHooks(opts, migrationHooks{})
}

func runWithHooks(opts Options, hooks migrationHooks) (*Result, error) {
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

	// ---- Phase -2: 配置锁定、纯读取 + 原始字节捕获（任何 mutation 之前）----
	// 绝不使用有副作用的 config.Load（缺失会建默认配置、ensureDefaults 会写回）：
	// 文件缺失 / 解析失败一律 STOP，不创建、不补写、不落任何默认值。
	lock, err := configlock.Acquire(opts.ConfigPath)
	if err != nil {
		return nil, fmt.Errorf("migration: acquire config lock: %w", err)
	}
	defer func() { _ = lock.Close() }()
	configPath := lock.CanonicalConfigPath()
	configSnapshot, err := configstore.ReadSnapshot(configPath)
	if err != nil {
		return nil, fmt.Errorf("migration: config %s: %w (refusing to continue)", configPath, err)
	}
	rawCfg := append([]byte(nil), configSnapshot.Bytes...)
	cfg, err := config.LoadExistingForMigration(configPath)
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

	db, err := gatewaydb.Open(dbPath)
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

	// ---- Phase -0.5: 审计完整性前置条件 + durable STARTED ----
	// MigrateIntegrity 是唯一的审计 schema/legacy-chain owner；完成后再做只读
	// 校验，保证 provider migration 不会在损坏或 partial audit history 上留下
	// recovery backup 或业务 mutation。
	auditService := audit.NewService(db)
	if err := audit.MigrateIntegrity(db); err != nil {
		return nil, fmt.Errorf("migration: audit integrity migration: %w", err)
	}
	res.Phases = append(res.Phases, "AUDIT-MIGRATION")
	if _, err := audit.VerifyIntegrityReadOnly(db); err != nil {
		return nil, fmt.Errorf("migration: audit integrity preflight: %w", err)
	}
	res.Phases = append(res.Phases, "AUDIT-VERIFIED")

	var operation audit.MaintenanceOperation
	if err := db.Transaction(func(tx *gorm.DB) error {
		if hooks.beforeStarted != nil {
			if err := hooks.beforeStarted(tx); err != nil {
				return err
			}
		}
		var err error
		operation, err = auditService.BeginMaintenanceTx(tx, audit.MaintenanceKindProviderSecretMigration)
		return err
	}); err != nil {
		return nil, fmt.Errorf("migration: audit STARTED: %w", err)
	}
	res.Phases = append(res.Phases, "STARTED")

	// ---- Phase 0: BACKUP（VACUUM INTO 一致性快照 + config 原始字节副本 + manifest）----
	// STARTED 已经提交，所以 backup 同时保留当前 audit schema、chain-state、
	// integrity triggers 与本次 operation 的启动证据。backup 失败时保留这个
	// pending STARTED，后续重跑由 BeginMaintenanceTx 复用同一 TargetID。
	backupDir, err := takeBackup(db, sqlDB, cfg, configPath, rawCfg, opts.BackupDir, mgr.KeyID(), encryptedColumnReady, userVersion, now())
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
		if hooks.beforePrepare != nil {
			if err := hooks.beforePrepare(tx); err != nil {
				return err
			}
		}
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
	prepareReplace, err := replaceMigrationConfig(hooks, "prepare", &cfgCandidate, configPath, configSnapshot.Mode)
	if err != nil {
		if prepareReplace.Renamed {
			if restoreErr := restoreMigrationConfig(hooks, configPath, configSnapshot); restoreErr != nil {
				return nil, restoreErr
			}
		}
		return nil, fmt.Errorf("migration: PREPARE (config): %w", err)
	}
	prepareSnapshot, err := configstore.ReadSnapshot(configPath)
	if err != nil {
		if restoreErr := restoreMigrationConfig(hooks, configPath, configSnapshot); restoreErr != nil {
			return nil, restoreErr
		}
		return nil, fmt.Errorf("migration: PREPARE (config) snapshot: %w", err)
	}
	res.Phases = append(res.Phases, "PREPARE")
	if hooks.beforeVerify != nil {
		if err := hooks.beforeVerify(db); err != nil {
			return nil, fmt.Errorf("migration: VERIFY preflight: %w", err)
		}
	}

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

	// ---- PHASE 3: FINALIZE（DB mutation + audit SUCCESS + config replace）----
	// SQLite 的最终提交与配置文件 rename 不可能组成一个跨存储事务：先把
	// SUCCESS 与 legacy 清理放入同一个 DB tx，再以 PREPARE snapshot 做配置
	// 失败/DB commit 失败的补偿。任何不可补偿的情况都返回稳定 rollback 错误。
	finalTx := db.Begin()
	if finalTx.Error != nil {
		return nil, fmt.Errorf("migration: FINALIZE (db begin): %w", finalTx.Error)
	}
	finalizedClients := 0
	for _, rr := range dbRows2 {
		if rr.Encrypted == "" || rr.Legacy == "" {
			continue
		}
		if err := finalTx.Exec("UPDATE clients SET backend_api_key = '' WHERE id = ?", rr.ID).Error; err != nil {
			_ = finalTx.Rollback()
			return nil, fmt.Errorf("migration: FINALIZE (db): clear client:%s: %w", rr.ID, err)
		}
		finalizedClients++
	}
	if err := auditService.CompleteMaintenanceTx(finalTx, operation); err != nil {
		_ = finalTx.Rollback()
		return nil, fmt.Errorf("migration: FINALIZE (audit): %w", err)
	}

	cfgFinal := *cfgVerify
	finalizedGlobal := 0
	for name, p := range cfgFinal.Providers {
		if p.APIKeyEncrypted != "" && p.APIKey != "" {
			p.APIKey = "" // legacy 明文清空；encrypted 保留
			cfgFinal.Providers[name] = p
			finalizedGlobal++
		}
	}
	finalReplace, err := replaceMigrationConfig(hooks, "finalize", &cfgFinal, configPath, prepareSnapshot.Mode)
	if err != nil {
		_ = finalTx.Rollback()
		if finalReplace.Renamed {
			if restoreErr := restoreMigrationConfig(hooks, configPath, prepareSnapshot); restoreErr != nil {
				return nil, restoreErr
			}
		}
		return nil, fmt.Errorf("migration: FINALIZE (config): %w", err)
	}

	commitErr := error(nil)
	if hooks.commitFinal != nil {
		commitErr = hooks.commitFinal(finalTx)
	} else {
		commitErr = finalTx.Commit().Error
	}
	if commitErr != nil {
		_ = finalTx.Rollback()
		if restoreErr := restoreMigrationConfig(hooks, configPath, prepareSnapshot); restoreErr != nil {
			return nil, restoreErr
		}
		return nil, fmt.Errorf("migration: FINALIZE (db commit): %w", commitErr)
	}
	res.FinalizedClients = finalizedClients
	res.FinalizedGlobal = finalizedGlobal
	res.Phases = append(res.Phases, "FINALIZE")

	return res, nil
}

func replaceMigrationConfig(hooks migrationHooks, kind string, cfg *config.Config, path string, mode fs.FileMode) (configstore.ReplaceResult, error) {
	data, err := config.MarshalYAML(cfg)
	if err != nil {
		return configstore.ReplaceResult{}, err
	}
	replace := hooks.replaceConfig
	if replace == nil {
		replace = func(_ string, _ *config.Config, path string, mode fs.FileMode) (configstore.ReplaceResult, error) {
			return configstore.AtomicReplace(path, data, mode)
		}
	}
	result, err := replace(kind, cfg, path, mode)
	if err == nil && (!result.Renamed || !result.DirectorySynced) {
		return result, errConfigReplaceIncomplete
	}
	return result, err
}

func restoreMigrationConfig(hooks migrationHooks, path string, snapshot configstore.Snapshot) error {
	restore := hooks.restoreConfig
	if restore == nil {
		restore = func(path string, snapshot configstore.Snapshot) (configstore.ReplaceResult, error) {
			return configstore.AtomicReplace(path, snapshot.Bytes, snapshot.Mode)
		}
	}
	result, err := restore(path, snapshot)
	if err != nil || !result.Renamed || !result.DirectorySynced {
		if err != nil {
			return fmt.Errorf("%w: %v", configaudit.ErrConfigAuditRollbackFailed, err)
		}
		return fmt.Errorf("%w: restore durability incomplete", configaudit.ErrConfigAuditRollbackFailed)
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
		_, err := os.Stat(backupDir)
		if os.IsNotExist(err) {
			break
		}
		if err != nil {
			return "", err
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
