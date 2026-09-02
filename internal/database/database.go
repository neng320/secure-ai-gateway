package database

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"strings"
)

// P1-05B · 生产 SQLite 打开器
//
// SQLite 的 PRAGMA foreign_keys 是 connection-scoped：只在某一连接上
// db.Exec("PRAGMA foreign_keys=ON") 不算数——连接池新建的连接默认仍是 OFF。
// 这里用 mattn DSN 参数 _foreign_keys=on，database/sql 为连接池创建的
// 每一个新连接都会携带该 PRAGMA（无需逐连接手动执行）。
//
// 生命周期一致性（ORPHAN-DATA / in-flight late-write）依赖外键约束参与判定：
//   - DELETE clients 缺失时任何 INSERT request_logs/daily_usages 都会失败
//   - RequestLog/DailyUsage 的 FK ON DELETE CASCADE 作为二次防线

import (
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"
)

// PinnedSQLite owns one database/sql connection for the full offline
// maintenance invocation. Its GORM handle is bound to that same connection;
// no pool-backed handle is used for audit or maintenance operations.
type PinnedSQLite struct {
	DB   *gorm.DB
	Conn *sql.Conn
	pool *sql.DB
}

// OpenPinned opens an existing SQLite database and binds a GORM handle to one
// pinned connection. The pool is retained only so the underlying connection
// can be closed deterministically after the maintenance operation.
func OpenPinned(path string) (*PinnedSQLite, error) {
	if path == "" {
		return nil, os.ErrInvalid
	}
	st, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() {
		return nil, os.ErrInvalid
	}

	pool, err := sql.Open(sqlite.DriverName, path+"?_foreign_keys=on&_busy_timeout=0")
	if err != nil {
		return nil, err
	}
	pool.SetMaxOpenConns(1)
	pool.SetMaxIdleConns(1)
	conn, err := pool.Conn(context.Background())
	if err != nil {
		_ = pool.Close()
		return nil, err
	}
	db, err := gorm.Open(sqlite.Dialector{DriverName: sqlite.DriverName, Conn: conn}, &gorm.Config{
		Logger:                 gormlogger.Default.LogMode(gormlogger.Silent),
		SkipDefaultTransaction: true,
	})
	if err != nil {
		_ = conn.Close()
		_ = pool.Close()
		return nil, err
	}
	return &PinnedSQLite{DB: db, Conn: conn, pool: pool}, nil
}

// AcquireExclusive obtains and retains SQLite EXCLUSIVE ownership before any
// audit schema migration or maintenance lookup. The empty transaction makes
// acquisition observable while locking_mode=EXCLUSIVE retains ownership over
// the subsequent commit boundaries on this connection.
func (p *PinnedSQLite) AcquireExclusive() error {
	if p == nil || p.Conn == nil {
		return os.ErrInvalid
	}
	ctx := context.Background()
	if _, err := p.Conn.ExecContext(ctx, "PRAGMA busy_timeout = 0"); err != nil {
		return err
	}
	var mode string
	if err := p.Conn.QueryRowContext(ctx, "PRAGMA locking_mode = EXCLUSIVE").Scan(&mode); err != nil {
		return err
	}
	if !strings.EqualFold(mode, "exclusive") {
		return fmt.Errorf("sqlite exclusive locking mode unavailable")
	}
	if _, err := p.Conn.ExecContext(ctx, "BEGIN EXCLUSIVE"); err != nil {
		return err
	}
	if _, err := p.Conn.ExecContext(ctx, "COMMIT"); err != nil {
		return err
	}
	return nil
}

// BeginExclusive starts a caller-owned exclusive transaction on the pinned
// connection and returns a GORM handle whose ConnPool is that active
// transaction. The adapter intentionally exposes only Commit/Rollback in
// addition to the embedded sql.Conn methods required by GORM.
func (p *PinnedSQLite) BeginExclusive() (*gorm.DB, error) {
	if p == nil || p.Conn == nil || p.DB == nil {
		return nil, os.ErrInvalid
	}
	if _, err := p.Conn.ExecContext(context.Background(), "BEGIN EXCLUSIVE"); err != nil {
		return nil, err
	}
	tx := p.DB.Session(&gorm.Session{NewDB: true, SkipDefaultTransaction: true})
	tx.Statement.ConnPool = &pinnedTransaction{Conn: p.Conn}
	return tx, nil
}

type pinnedTransaction struct {
	*sql.Conn
}

func (tx *pinnedTransaction) Commit() error {
	_, err := tx.ExecContext(context.Background(), "COMMIT")
	return err
}

func (tx *pinnedTransaction) Rollback() error {
	_, err := tx.ExecContext(context.Background(), "ROLLBACK")
	return err
}

func (p *PinnedSQLite) Close() error {
	if p == nil {
		return nil
	}
	var firstErr error
	if p.Conn != nil {
		if err := p.Conn.Close(); err != nil {
			firstErr = err
		}
		p.Conn = nil
	}
	if p.pool != nil {
		if err := p.pool.Close(); firstErr == nil && err != nil {
			firstErr = err
		}
		p.pool = nil
	}
	return firstErr
}

func Open(path string) (*gorm.DB, error) {
	return gorm.Open(sqlite.Open(path+"?_foreign_keys=on&_busy_timeout=5000"), &gorm.Config{
		Logger: gormlogger.Default.LogMode(gormlogger.Silent),
	})
}

// OpenReadOnly opens an existing SQLite database in read-only mode. The
// connection-scoped query_only pragma is a second defense against accidental
// writes by the offline verifier.
func OpenReadOnly(path string) (*gorm.DB, error) {
	if path == "" {
		return nil, os.ErrInvalid
	}
	st, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() {
		return nil, os.ErrInvalid
	}

	db, err := gorm.Open(sqlite.Open(path+"?mode=ro&_foreign_keys=on&_busy_timeout=5000"), &gorm.Config{
		Logger: gormlogger.Default.LogMode(gormlogger.Silent),
	})
	if err != nil {
		return nil, err
	}
	sqlDB, err := db.DB()
	if err != nil {
		return nil, err
	}
	sqlDB.SetMaxOpenConns(1)
	sqlDB.SetMaxIdleConns(1)
	if err := db.Exec("PRAGMA query_only = ON").Error; err != nil {
		_ = sqlDB.Close()
		return nil, err
	}
	return db, nil
}
