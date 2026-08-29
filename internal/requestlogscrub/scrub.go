// Package requestlogscrub 实现 SEC-003/P1-04D 的显式离线 scrub：
// 清除 request_logs 中 legacy 的 request_body / error_message 明文残留。
//
// 纪律（fail-closed）：
//   - 必须显式调用（CLI -scrub-request-log-content）且带第二个确认 flag
//   - config 纯读取（不创建/不写回）；DB 必须已存在且为 regular file（绝不创建空库）
//   - schema 显式检查（request_logs 表 + 两列存在），无 "no such column" 半途失败
//   - 不 AutoMigrate 未知数据库
//   - 不自动生成任何 plaintext backup（目标就是删除敏感正文；不可逆）
//   - 输出只含数量与文件名，绝不包含正文/错误文本
//
// 物理清理序列（仅 UPDATE=” 不足以消灭旧页字节）：
//
//	独占/离线检查 → WAL checkpoint(TRUNCATE)（如 WAL）→ secure_delete=ON（best-effort）
//	→ UPDATE 置空 → 再次 checkpoint → VACUUM 重写整库 → 关闭 → sidecar raw 扫描报告
package requestlogscrub

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"strings"
	"time"

	"ai-gateway/internal/config"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// Options: scrub 输入
type Options struct {
	ConfigPath string
	Now        func() time.Time
}

// Result: 结果（只含数量与文件名，不含任何正文材料）
type Result struct {
	ScrubbedRows   int
	RemainNonEmpty int
	DBPath         string
	Sidecars       []string // 存在的 sidecar 文件名（-wal/-shm/-journal）
	Phases         []string
}

// Run: 执行离线 scrub。任何前置失败 → 错误返回，文件零改动。
func Run(opts Options) (*Result, error) {
	if opts.ConfigPath == "" {
		return nil, fmt.Errorf("scrub: config path is required")
	}

	// config 纯读取：缺失/解析失败 → STOP，绝不创建
	rawCfg, err := os.ReadFile(opts.ConfigPath)
	if err != nil {
		return nil, fmt.Errorf("scrub: config %s: %w", opts.ConfigPath, err)
	}
	_ = rawCfg
	cfg, err := config.LoadExistingForMigration(opts.ConfigPath)
	if err != nil {
		return nil, fmt.Errorf("scrub: load config: %w", err)
	}
	if cfg.Database.Path == "" {
		return nil, fmt.Errorf("scrub: database.path is empty in config — stop")
	}

	// DB fail-closed：存在 + regular file，绝不创建
	dbPath := cfg.Database.Path
	st, err := os.Stat(dbPath)
	if err != nil {
		return nil, fmt.Errorf("scrub: database %s: %w (refusing to create)", dbPath, err)
	}
	if !st.Mode().IsRegular() {
		return nil, fmt.Errorf("scrub: database %s is not a regular file — stop", dbPath)
	}

	db, err := gorm.Open(sqlite.Open(dbPath), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	if err != nil {
		return nil, fmt.Errorf("scrub: open db %s: %w", dbPath, err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		return nil, err
	}
	defer func() { _ = sqlDB.Close() }()

	// 显式 schema 检查
	if !tableExists(db, "request_logs") {
		return nil, fmt.Errorf("scrub: schema check failed: table 'request_logs' not found in %s — stop", dbPath)
	}
	for _, col := range []string{"request_body", "error_message"} {
		if !columnExists(db, "request_logs", col) {
			return nil, fmt.Errorf("scrub: schema check failed: column 'request_logs.%s' not found — stop", col)
		}
	}

	res := &Result{DBPath: dbPath, Phases: []string{}}

	// 独占/offline 预检（P1-04.1）：WAL 模式先做 TRUNCATE checkpoint——
	// 首列 Busy!=0 即有其他连接（含活跃 reader）→ 任何 mutation 之前 STOP。
	var journalMode string
	if err := db.Raw("PRAGMA journal_mode").Scan(&journalMode).Error; err != nil {
		return nil, fmt.Errorf("scrub: read journal_mode: %w", err)
	}
	isWAL := strings.EqualFold(journalMode, "wal")
	if isWAL {
		if err := walCheckpointTruncate(db); err != nil {
			return nil, err // 含 OFFLINE_REQUIRED 语义
		}
		res.Phases = append(res.Phases, "WAL-CHECKPOINT")
	}

	// P1-04.2：持有式独占（消除 probe→mutation 的 TOCTOU）。
	// 单一 dedicated connection：
	//   busy_timeout=0 → locking_mode=EXCLUSIVE → BEGIN EXCLUSIVE
	// locking_mode=EXCLUSIVE 使独占锁在 COMMIT 之后仍由本连接持有，
	// 之后的 checkpoint/VACUUM/verify 期间任何并发连接都被 SQLITE_BUSY 拒绝，
	// 直到全部完成、conn.Close() 释放。杜绝“UPDATE 已提交但 VACUUM 被新并发者打断”。
	ctx := context.Background()
	conn, err := sqlDB.Conn(ctx)
	if err != nil {
		return nil, fmt.Errorf("scrub: acquire dedicated connection: %w", err)
	}
	defer func() { _ = conn.Close() }()
	// 关闭 gorm 连接池（本进程内的其他连接同样不得干扰独占期）
	if err := sqlDB.Close(); err != nil {
		return nil, fmt.Errorf("scrub: close pool: %w", err)
	}

	if _, err := conn.ExecContext(ctx, "PRAGMA busy_timeout = 0"); err != nil {
		return nil, fmt.Errorf("scrub: busy_timeout: %w", err)
	}
	if _, err := conn.ExecContext(ctx, "PRAGMA locking_mode = EXCLUSIVE"); err != nil {
		return nil, fmt.Errorf("scrub: locking_mode: %w", err)
	}
	if _, err := conn.ExecContext(ctx, "BEGIN EXCLUSIVE"); err != nil {
		return nil, fmt.Errorf("scrub: database is in use (exclusive lock unavailable) — "+
			"stop the gateway / close other connections and retry: %w (REQUEST_LOG_SCRUB_OFFLINE_REQUIRED)", err)
	}
	res.Phases = append(res.Phases, "EXCLUSIVE")

	exec := func(q string) error {
		if _, err := conn.ExecContext(ctx, q); err != nil {
			return fmt.Errorf("scrub: %s: %w", strings.Fields(q)[0], err)
		}
		return nil
	}
	queryCount := func(q string) (int64, error) {
		var n int64
		if err := conn.QueryRowContext(ctx, q).Scan(&n); err != nil {
			return 0, err
		}
		return n, nil
	}

	// secure_delete=ON（best-effort：driver 不支持时跳过，VACUUM 仍会重写整库）
	if _, err := conn.ExecContext(ctx, "PRAGMA secure_delete = ON"); err == nil {
		res.Phases = append(res.Phases, "SECURE-DELETE-ON")
	}

	// 清点（只输出数量）
	dirty, err := queryCount("SELECT count(*) FROM request_logs WHERE request_body != '' OR error_message != ''")
	if err != nil {
		return nil, fmt.Errorf("scrub: count legacy rows: %w", err)
	}

	// UPDATE 置空（在持有式独占事务内；保留 metadata 行）
	if err := exec("UPDATE request_logs SET request_body = '', error_message = '' WHERE request_body != '' OR error_message != ''"); err != nil {
		return nil, err
	}
	res.ScrubbedRows = int(dirty)
	res.Phases = append(res.Phases, "UPDATE")

	// COMMIT——locking_mode=EXCLUSIVE 使锁继续由本连接持有
	if err := exec("COMMIT"); err != nil {
		return nil, err
	}

	// WAL → DELETE 切换（持有独占时执行：把 WAL 拍平回主库并消除 -wal 旧帧；
	// 切换后 VACUUM 在 rollback-journal 模式下重写整库）。已在 DELETE 模式则跳过。
	if isWAL {
		var newMode string
		if err := conn.QueryRowContext(ctx, "PRAGMA journal_mode = DELETE").Scan(&newMode); err != nil {
			return nil, fmt.Errorf("scrub: journal switch: %w", err)
		}
		if !strings.EqualFold(newMode, "delete") {
			return nil, fmt.Errorf("scrub: journal switch failed (mode=%s) — stop", newMode)
		}
		res.Phases = append(res.Phases, "JOURNAL-SWITCH")
	}

	// VACUUM 重写整库（仍持有独占锁：并发者无法使其失败）
	if err := exec("VACUUM"); err != nil {
		return nil, err
	}
	res.Phases = append(res.Phases, "VACUUM")

	// 逻辑复核
	remain, err := queryCount("SELECT count(*) FROM request_logs WHERE request_body != '' OR error_message != ''")
	if err != nil {
		return nil, fmt.Errorf("scrub: verify: %w", err)
	}
	res.RemainNonEmpty = int(remain)
	if remain != 0 {
		return nil, fmt.Errorf("scrub: verification failed: %d rows still non-empty — stop", remain)
	}

	// 释放独占（conn.Close）
	_ = conn.Close()
	res.Phases = append(res.Phases, "CLOSE")

	// sidecar 清点（仅文件名；内容 raw-scan 由 fixture gate 以 canary 验证）
	for _, suffix := range []string{"-wal", "-shm", "-journal"} {
		if _, err := os.Stat(dbPath + suffix); err == nil {
			res.Sidecars = append(res.Sidecars, "gateway.db"+suffix)
		}
	}
	return res, nil
}

// walCheckpointTruncate: TRUNCATE checkpoint 并遵守 SQLite 契约——
// 首列 Busy!=0 表示 checkpoint 被其他连接阻塞、未完成 → 显式 STOP（fail-closed）。
func walCheckpointTruncate(db *gorm.DB) error {
	rows, err := db.Raw("PRAGMA wal_checkpoint(TRUNCATE)").Rows()
	if err != nil {
		return fmt.Errorf("scrub: wal checkpoint: %w", err)
	}
	defer rows.Close()
	var busy, logPages, checkpointed int64
	if rows.Next() {
		if err := rows.Scan(&busy, &logPages, &checkpointed); err != nil {
			return fmt.Errorf("scrub: wal checkpoint scan: %w", err)
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("scrub: wal checkpoint rows: %w", err)
	}
	if busy != 0 {
		return fmt.Errorf("scrub: WAL checkpoint blocked (busy=%d) — another connection is using the database; "+
			"stop the gateway / close other connections and retry (REQUEST_LOG_SCRUB_OFFLINE_REQUIRED)", busy)
	}
	return nil
}

// acquireExclusiveProbe: 以 busy_timeout=0 的独立连接尝试 BEGIN EXCLUSIVE。
// 任何并发占用（journal 模式下的读/写锁）都会立即 SQLITE_BUSY → STOP。
// 成功后立即 ROLLBACK（探测不持有锁、不做任何修改）。
func acquireExclusiveProbe(sqlDB *sql.DB) error {
	ctx := context.Background()
	conn, err := sqlDB.Conn(ctx)
	if err != nil {
		return fmt.Errorf("scrub: acquire connection: %w", err)
	}
	defer func() { _ = conn.Close() }()
	if _, err := conn.ExecContext(ctx, "PRAGMA busy_timeout = 0"); err != nil {
		return fmt.Errorf("scrub: busy_timeout: %w", err)
	}
	if _, err := conn.ExecContext(ctx, "BEGIN EXCLUSIVE"); err != nil {
		return fmt.Errorf("scrub: database is in use (exclusive lock unavailable) — "+
			"stop the gateway / close other connections and retry: %w (REQUEST_LOG_SCRUB_OFFLINE_REQUIRED)", err)
	}
	if _, err := conn.ExecContext(ctx, "ROLLBACK"); err != nil {
		return fmt.Errorf("scrub: exclusive probe rollback: %w", err)
	}
	return nil
}

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
