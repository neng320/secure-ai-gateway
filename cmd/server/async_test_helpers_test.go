package main

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"sync"
	"testing"

	"ai-gateway/internal/audit"

	"gorm.io/gorm"
)

func migrateTestAudit(t *testing.T, db *gorm.DB) {
	t.Helper()
	if err := audit.MigrateIntegrity(db); err != nil {
		t.Fatal(err)
	}
}

func migrateTestSchema(t *testing.T, db *gorm.DB, modelsToMigrate ...interface{}) {
	t.Helper()
	if err := db.AutoMigrate(modelsToMigrate...); err != nil {
		t.Fatal(err)
	}
	if err := audit.MigrateIntegrity(db); err != nil {
		t.Fatal(err)
	}
}

// testLastSeenPool is a test-only ConnPool wrapper. The real AuthMiddleware
// launches ClientService.UpdateLastSeen asynchronously, so fixtures must wait
// for the corresponding SQL transaction before closing temporary SQLite.
type testLastSeenPool struct {
	gorm.ConnPool
	mu        sync.Mutex
	completed uint64
	consumed  uint64
	inFlight  uint64
	notify    chan struct{}
}

func attachTestLastSeenPool(db *gorm.DB) *testLastSeenPool {
	pool := &testLastSeenPool{ConnPool: db.ConnPool, notify: make(chan struct{}, 1)}
	db.ConnPool = pool
	db.Statement.ConnPool = pool
	return pool
}

func (p *testLastSeenPool) ExecContext(ctx context.Context, query string, args ...interface{}) (sql.Result, error) {
	isLastSeen := isTestLastSeenUpdate(query)
	if isLastSeen {
		p.startLastSeen()
	}
	result, err := p.ConnPool.ExecContext(ctx, query, args...)
	if isLastSeen {
		p.finishLastSeen(1)
	}
	return result, err
}

func (p *testLastSeenPool) GetDBConn() (*sql.DB, error) {
	if sqlDB, ok := p.ConnPool.(*sql.DB); ok {
		return sqlDB, nil
	}
	return nil, errors.New("test LastSeen pool has no underlying database connection")
}

func (p *testLastSeenPool) startLastSeen() {
	p.mu.Lock()
	p.inFlight++
	p.mu.Unlock()
}

func (p *testLastSeenPool) finishLastSeen(count uint64) {
	p.mu.Lock()
	p.inFlight -= count
	p.completed += count
	p.mu.Unlock()
	select {
	case p.notify <- struct{}{}:
	default:
	}
}

func (p *testLastSeenPool) BeginTx(ctx context.Context, opts *sql.TxOptions) (gorm.ConnPool, error) {
	beginner, ok := p.ConnPool.(gorm.TxBeginner)
	if !ok {
		return nil, errors.New("test LastSeen pool cannot begin transaction")
	}
	tx, err := beginner.BeginTx(ctx, opts)
	if err != nil {
		return nil, err
	}
	return &testLastSeenTx{Tx: tx, pool: p}, nil
}

type testLastSeenTx struct {
	*sql.Tx
	pool          *testLastSeenPool
	lastSeenWrite int
}

func (tx *testLastSeenTx) ExecContext(ctx context.Context, query string, args ...interface{}) (sql.Result, error) {
	result, err := tx.Tx.ExecContext(ctx, query, args...)
	if isTestLastSeenUpdate(query) {
		tx.pool.startLastSeen()
		tx.lastSeenWrite++
	}
	return result, err
}

func (tx *testLastSeenTx) Commit() error {
	err := tx.Tx.Commit()
	tx.completeLastSeen()
	return err
}

func (tx *testLastSeenTx) Rollback() error {
	err := tx.Tx.Rollback()
	tx.completeLastSeen()
	return err
}

func (tx *testLastSeenTx) completeLastSeen() {
	if tx.lastSeenWrite == 0 {
		return
	}
	count := tx.lastSeenWrite
	tx.lastSeenWrite = 0
	tx.pool.finishLastSeen(uint64(count))
}

func isTestLastSeenUpdate(query string) bool {
	query = strings.ToLower(strings.ReplaceAll(query, "`", ""))
	return strings.Contains(query, "update clients set last_seen")
}

func (p *testLastSeenPool) waitForCompletion(t *testing.T) {
	t.Helper()
	for {
		p.mu.Lock()
		if p.consumed < p.completed {
			p.consumed++
			p.mu.Unlock()
			return
		}
		p.mu.Unlock()
		select {
		case <-p.notify:
		case <-t.Context().Done():
			t.Fatal("test context canceled before UpdateLastSeen completed")
		}
	}
}

func (p *testLastSeenPool) pending() (inFlight, unconsumed uint64) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.inFlight, p.completed - p.consumed
}

func closeTestLastSeenDB(db *gorm.DB, pool *testLastSeenPool) error {
	if pool != nil {
		inFlight, unconsumed := pool.pending()
		if inFlight != 0 || unconsumed != 0 {
			return errors.New("test LastSeen work remains before database close")
		}
		sqlDB, err := pool.GetDBConn()
		if err != nil {
			return err
		}
		return sqlDB.Close()
	}
	if db == nil {
		return nil
	}
	sqlDB, err := db.DB()
	if err != nil {
		return nil
	}
	return sqlDB.Close()
}
