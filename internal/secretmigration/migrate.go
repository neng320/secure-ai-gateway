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
	"strings"
	"time"

	"ai-gateway/internal/config"
	"ai-gateway/internal/models"
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

	cfg, err := config.Load(opts.ConfigPath)
	if err != nil {
		return nil, fmt.Errorf("migration: load config: %w", err)
	}

	db, err := gorm.Open(sqlite.Open(cfg.Database.Path), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		return nil, fmt.Errorf("migration: open db %s: %w", cfg.Database.Path, err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		return nil, err
	}
	defer func() { _ = sqlDB.Close() }()

	res := &Result{Phases: []string{}}

	// ---- Phase 0: BACKUP（VACUUM INTO 一致性快照 + config 副本 + manifest）----
	backupDir, err := takeBackup(db, sqlDB, cfg, opts.ConfigPath, opts.BackupDir, mgr.KeyID(), now())
	if err != nil {
		return nil, fmt.Errorf("migration: backup: %w", err)
	}
	res.BackupDir = backupDir
	res.Phases = append(res.Phases, "BACKUP")

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
	err = db.Transaction(func(tx *gorm.DB) error {
		for _, c := range clients {
			if c.state != secrets.SecretLegacyOnly {
				continue
			}
			env, err := mgr.EncryptClientBackendKey(c.id, []byte(c.legacy))
			if err != nil {
				return fmt.Errorf("prepare client:%s: %w", c.id, err)
			}
			if err := tx.Model(&models.Client{}).Where("id = ?", c.id).
				Update("backend_api_key_encrypted", env).Error; err != nil {
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
	cfgVerify, err := config.Load(opts.ConfigPath)
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
			if err := tx.Model(&models.Client{}).Where("id = ?", rr.ID).
				Update("backend_api_key", "").Error; err != nil {
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

// takeBackup: 迁移专用 recovery snapshot。
//   - DB：VACUUM INTO（SQLite 一致性快照；离线模式无并发写者）
//   - config：字节级副本
//   - manifest.json：时间/路径/key_id/SHA-256；绝不包含 Master Key 或 plaintext key
func takeBackup(db *gorm.DB, sqlDB *sql.DB, cfg *config.Config, configPath, backupRoot, keyID string, now time.Time) (string, error) {
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

	// config 副本
	srcCfg, err := os.ReadFile(configPath)
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(filepath.Join(backupDir, "config.yaml"), srcCfg, 0600); err != nil {
		return "", err
	}

	cfgSum := sha256.Sum256(srcCfg)
	dbSum, err := fileSHA256(snapshotPath)
	if err != nil {
		return "", err
	}

	manifest := map[string]string{
		"timestamp":          now.UTC().Format(time.RFC3339),
		"source_config_path": configPath,
		"source_db_path":     cfg.Database.Path,
		"master_key_id":      keyID,
		"config_sha256":      hex.EncodeToString(cfgSum[:]),
		"db_snapshot_sha256": dbSum,
		"sensitivity":        "contains legacy plaintext provider keys - SENSITIVE, encrypt or offline-store, never push",
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
