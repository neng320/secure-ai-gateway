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
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"ai-gateway/internal/audit"
	"ai-gateway/internal/config"
	gatewaydb "ai-gateway/internal/database"

	"gorm.io/gorm"
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

type scrubHooks struct {
	afterExclusive    func(*sql.Conn) error
	beforeMaintenance func(*sql.Conn) error
	vacuum            func(*sql.Conn) error
	verify            func(*sql.Conn) error
	beforeCompletion  func(*sql.Conn) error
}

// Run: 执行离线 scrub。任何前置失败 → 错误返回，文件零改动。
func Run(opts Options) (*Result, error) {
	return runWithHooks(opts, scrubHooks{})
}

func runWithHooks(opts Options, hooks scrubHooks) (*Result, error) {
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

	pinned, err := gatewaydb.OpenPinned(dbPath)
	if err != nil {
		return nil, fmt.Errorf("scrub: open db %s: %w", dbPath, err)
	}
	closed := false
	defer func() {
		if !closed {
			_ = pinned.Close()
		}
	}()

	res := &Result{DBPath: dbPath, Phases: []string{}}

	// 独占/offline 预检（P1-04.1）必须使用将承载整个 invocation 的 pinned conn。
	var journalMode string
	if err := pinned.Conn.QueryRowContext(context.Background(), "PRAGMA journal_mode").Scan(&journalMode); err != nil {
		return nil, fmt.Errorf("scrub: read journal_mode: %w", err)
	}
	isWAL := strings.EqualFold(journalMode, "wal")
	if err := pinned.AcquireExclusive(); err != nil {
		return nil, fmt.Errorf("scrub: database is in use (exclusive lock unavailable) — "+
			"stop the gateway / close other connections and retry: %w (REQUEST_LOG_SCRUB_OFFLINE_REQUIRED)", err)
	}
	res.Phases = append(res.Phases, "EXCLUSIVE")
	if hooks.afterExclusive != nil {
		if err := hooks.afterExclusive(pinned.Conn); err != nil {
			return nil, err
		}
	}
	if isWAL {
		if err := walCheckpointTruncate(pinned.Conn); err != nil {
			return nil, err // 含 OFFLINE_REQUIRED 语义
		}
		res.Phases = append(res.Phases, "WAL-CHECKPOINT")
	}

	// schema checks are read-only, but happen after ownership is established so
	// no unlocked DB handle exists in the maintenance path.
	if exists, err := tableExistsConn(pinned.Conn, "request_logs"); err != nil || !exists {
		if err != nil {
			return nil, fmt.Errorf("scrub: schema check failed: %w", err)
		}
		return nil, fmt.Errorf("scrub: schema check failed: table 'request_logs' not found in %s — stop", dbPath)
	}
	for _, col := range []string{"request_body", "error_message"} {
		exists, err := columnExistsConn(pinned.Conn, "request_logs", col)
		if err != nil || !exists {
			if err != nil {
				return nil, fmt.Errorf("scrub: schema check failed: %w", err)
			}
			return nil, fmt.Errorf("scrub: schema check failed: column 'request_logs.%s' not found — stop", col)
		}
	}

	// The audit prerequisite is bound to the same pinned connection. Its own
	// GORM transactions therefore cannot open a competing pool connection.
	if err := audit.MigrateIntegrity(pinned.DB); err != nil {
		return nil, fmt.Errorf("scrub: audit prerequisite migration: %w", err)
	}
	res.Phases = append(res.Phases, "AUDIT-MIGRATION")
	if _, err := audit.VerifyIntegrityReadOnly(pinned.DB); err != nil {
		return nil, fmt.Errorf("scrub: audit prerequisite verification: %w", err)
	}
	res.Phases = append(res.Phases, "AUDIT-VERIFIED")

	// secure_delete=ON（best-effort：driver 不支持时跳过，VACUUM 仍会重写整库）
	if _, err := pinned.Conn.ExecContext(context.Background(), "PRAGMA secure_delete = ON"); err == nil {
		res.Phases = append(res.Phases, "SECURE-DELETE-ON")
	}

	if hooks.beforeMaintenance != nil {
		if err := hooks.beforeMaintenance(pinned.Conn); err != nil {
			return nil, fmt.Errorf("scrub: test maintenance setup: %w", err)
		}
	}

	maintenanceTx, err := pinned.BeginExclusive()
	if err != nil {
		return nil, fmt.Errorf("scrub: begin exclusive maintenance transaction: %w", err)
	}
	rollbackMaintenance := func() {
		_ = maintenanceTx.Rollback().Error
	}
	auditService := audit.NewService(pinned.DB)
	operation, err := auditService.BeginMaintenanceTx(maintenanceTx, audit.MaintenanceKindRequestLogScrub)
	if err != nil {
		rollbackMaintenance()
		return nil, fmt.Errorf("scrub: begin maintenance audit: %w", err)
	}
	dirty, err := queryCountTx(maintenanceTx, "SELECT count(*) FROM request_logs WHERE request_body != '' OR error_message != ''")
	if err != nil {
		rollbackMaintenance()
		return nil, fmt.Errorf("scrub: count legacy rows: %w", err)
	}
	if err := maintenanceTx.Exec("UPDATE request_logs SET request_body = '', error_message = '' WHERE request_body != '' OR error_message != ''").Error; err != nil {
		rollbackMaintenance()
		return nil, fmt.Errorf("scrub: update: %w", err)
	}
	res.ScrubbedRows = int(dirty)
	res.Phases = append(res.Phases, "STARTED", "UPDATE")
	if err := maintenanceTx.Commit().Error; err != nil {
		rollbackMaintenance()
		return nil, fmt.Errorf("scrub: commit logical scrub: %w", err)
	}

	// WAL → DELETE 切换（持有独占时执行：把 WAL 拍平回主库并消除 -wal 旧帧；
	// 切换后 VACUUM 在 rollback-journal 模式下重写整库）。已在 DELETE 模式则跳过。
	if isWAL {
		var newMode string
		if err := pinned.Conn.QueryRowContext(context.Background(), "PRAGMA journal_mode = DELETE").Scan(&newMode); err != nil {
			return nil, fmt.Errorf("scrub: journal switch: %w", err)
		}
		if !strings.EqualFold(newMode, "delete") {
			return nil, fmt.Errorf("scrub: journal switch failed (mode=%s) — stop", newMode)
		}
		res.Phases = append(res.Phases, "JOURNAL-SWITCH")
	}

	// VACUUM 重写整库（仍持有独占锁：并发者无法使其失败）
	if hooks.vacuum != nil {
		err = hooks.vacuum(pinned.Conn)
	} else {
		_, err = pinned.Conn.ExecContext(context.Background(), "VACUUM")
	}
	if err != nil {
		return nil, err
	}
	res.Phases = append(res.Phases, "VACUUM")

	if err := verifyPhysicalScrubState(pinned.Conn, dbPath); err != nil {
		return nil, err
	}
	if hooks.verify != nil {
		if err := hooks.verify(pinned.Conn); err != nil {
			return nil, err
		}
	}
	res.Phases = append(res.Phases, "PHYSICAL-VERIFIED")
	remain, err := queryCountConn(pinned.Conn, "SELECT count(*) FROM request_logs WHERE request_body != '' OR error_message != ''")
	if err != nil {
		return nil, fmt.Errorf("scrub: verify: %w", err)
	}
	res.RemainNonEmpty = int(remain)
	if remain != 0 {
		return nil, fmt.Errorf("scrub: verification failed: %d rows still non-empty — stop", remain)
	}

	if hooks.beforeCompletion != nil {
		if err := hooks.beforeCompletion(pinned.Conn); err != nil {
			return nil, fmt.Errorf("scrub: test completion setup: %w", err)
		}
	}
	completionTx, err := pinned.BeginExclusive()
	if err != nil {
		return nil, fmt.Errorf("scrub: begin completion transaction: %w", err)
	}
	if err := auditService.CompleteMaintenanceTx(completionTx, operation); err != nil {
		_ = completionTx.Rollback().Error
		return nil, fmt.Errorf("scrub: complete maintenance audit: %w", err)
	}
	if err := completionTx.Commit().Error; err != nil {
		_ = completionTx.Rollback().Error
		return nil, fmt.Errorf("scrub: commit completion audit: %w", err)
	}
	res.Phases = append(res.Phases, "SUCCESS")

	if err := pinned.Close(); err != nil {
		closed = true
		return nil, fmt.Errorf("scrub: close pinned database: %w", err)
	}
	closed = true
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
func walCheckpointTruncate(conn *sql.Conn) error {
	rows, err := conn.QueryContext(context.Background(), "PRAGMA wal_checkpoint(TRUNCATE)")
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

func queryCountConn(conn *sql.Conn, query string) (int64, error) {
	var count int64
	if err := conn.QueryRowContext(context.Background(), query).Scan(&count); err != nil {
		return 0, err
	}
	return count, nil
}

func queryCountTx(tx *gorm.DB, query string) (int64, error) {
	var count int64
	if err := tx.Raw(query).Scan(&count).Error; err != nil {
		return 0, err
	}
	return count, nil
}

func verifyPhysicalScrubState(conn *sql.Conn, dbPath string) error {
	var journalMode string
	if err := conn.QueryRowContext(context.Background(), "PRAGMA journal_mode").Scan(&journalMode); err != nil {
		return fmt.Errorf("scrub: physical verify journal mode: %w", err)
	}
	if !strings.EqualFold(journalMode, "delete") {
		return fmt.Errorf("scrub: physical verify requires DELETE journal mode, got %q", journalMode)
	}
	for _, suffix := range []string{"-wal", "-shm"} {
		if _, err := os.Stat(dbPath + suffix); err == nil {
			return fmt.Errorf("scrub: physical verify found residual %s sidecar", suffix)
		} else if !os.IsNotExist(err) {
			return fmt.Errorf("scrub: physical verify sidecar check: %w", err)
		}
	}
	if err := verifyInactiveJournal(dbPath + "-journal"); err != nil {
		return err
	}
	var integrity string
	if err := conn.QueryRowContext(context.Background(), "PRAGMA integrity_check").Scan(&integrity); err != nil {
		return fmt.Errorf("scrub: physical verify integrity check: %w", err)
	}
	if !strings.EqualFold(strings.TrimSpace(integrity), "ok") {
		return fmt.Errorf("scrub: physical verify integrity check failed")
	}
	return nil
}

func verifyInactiveJournal(path string) error {
	file, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("scrub: physical verify sidecar check: %w", err)
	}
	defer file.Close()
	header := make([]byte, 8)
	read, err := io.ReadFull(file, header)
	if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
		return fmt.Errorf("scrub: physical verify journal header: %w", err)
	}
	if read > 0 && !bytes.Equal(header[:read], make([]byte, read)) {
		return fmt.Errorf("scrub: physical verify found active -journal sidecar")
	}
	return nil
}

func tableExistsConn(conn *sql.Conn, table string) (bool, error) {
	var count int64
	if err := conn.QueryRowContext(context.Background(), "SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name = ?", table).Scan(&count); err != nil {
		return false, err
	}
	return count == 1, nil
}

func columnExistsConn(conn *sql.Conn, table, column string) (bool, error) {
	var count int64
	query := "SELECT count(*) FROM pragma_table_info(?) WHERE name = ?"
	if err := conn.QueryRowContext(context.Background(), query, table, column).Scan(&count); err != nil {
		return false, err
	}
	return count == 1, nil
}
