package requestlogscrub

// P1-04D · Legacy Prompt Eradication Fixture Gate（SEC-003）
//
// 仅 t.TempDir() fixture + canary。覆盖：
//   - scrub 后逻辑清零（request_body/error_message 非空计数 = 0）
//   - raw scan：gateway.db + 全部 sidecar（-wal/-shm/-journal 若存在）canary 命中 = 0
//   - 缺确认/缺 config/缺 DB/schema 缺失 → 拒绝且零改动
//   - WAL 模式 DB 的 checkpoint 处理
//
// Canary：P104_LEGACY_PROMPT_ERADICATION_CANARY / P104_LEGACY_ERRORTEXT_ERADICATION_CANARY

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"ai-gateway/internal/audit"
	gatewaydb "ai-gateway/internal/database"
	"ai-gateway/internal/models"

	"github.com/google/uuid"
	_ "github.com/mattn/go-sqlite3"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

const (
	legacyPromptCanary = "P104_LEGACY_PROMPT_ERADICATION_CANARY"
	legacyErrorCanary  = "P104_LEGACY_ERRORTEXT_ERADICATION_CANARY"
)

type scrubFixture struct {
	dir     string
	cfgPath string
	dbPath  string
}

func newScrubFixture(t *testing.T) *scrubFixture {
	t.Helper()
	dir := t.TempDir()
	f := &scrubFixture{
		dir:     dir,
		cfgPath: filepath.Join(dir, "config.yaml"),
		dbPath:  filepath.Join(dir, "gateway.db"),
	}
	if err := os.WriteFile(f.cfgPath, []byte("server:\n  host: 127.0.0.1\ndatabase:\n  path: "+f.dbPath+"\nadmin:\n  username: admin\nproviders: {}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *scrubFixture) migrateAudit(t *testing.T) {
	t.Helper()
	db, err := gatewaydb.Open(f.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := audit.MigrateIntegrity(db); err != nil {
		t.Fatal(err)
	}
	closeGormTestDB(t, db)
}

func closeGormTestDB(t *testing.T, db *gorm.DB) {
	t.Helper()
	if sqlDB, err := db.DB(); err == nil {
		if err := sqlDB.Close(); err != nil {
			t.Fatal(err)
		}
	}
}

func (f *scrubFixture) maintenanceEvents(t *testing.T) []models.AuditEvent {
	t.Helper()
	db, err := gatewaydb.Open(f.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	var events []models.AuditEvent
	if err := db.Where("action IN ?", []string{audit.ActionRequestLogScrubStarted, audit.ActionRequestLogScrub}).Order("id ASC").Find(&events).Error; err != nil {
		t.Fatal(err)
	}
	closeGormTestDB(t, db)
	return events
}

func (f *scrubFixture) requestLogBytes(t *testing.T) []byte {
	t.Helper()
	db, err := gatewaydb.Open(f.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	var rows []models.RequestLog
	if err := db.Select("request_body", "error_message").Order("id ASC").Find(&rows).Error; err != nil {
		t.Fatal(err)
	}
	closeGormTestDB(t, db)
	var result []byte
	for _, row := range rows {
		result = append(result, row.RequestBody...)
		result = append(result, 0)
		result = append(result, row.ErrorMessage...)
		result = append(result, 0)
	}
	return result
}

func (f *scrubFixture) seedCurrentAudit(t *testing.T) {
	t.Helper()
	f.migrateAudit(t)
	db, err := gatewaydb.Open(f.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := audit.NewService(db).Record(models.AuditEvent{
		Action:     audit.ActionServerToolsUpdated,
		ActorType:  "admin",
		ActorID:    "test-admin",
		TargetType: "server",
		TargetID:   "server-tools",
	}); err != nil {
		t.Fatal(err)
	}
	closeGormTestDB(t, db)
}

func (f *scrubFixture) seedLegacyAudit(t *testing.T) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(f.dbPath), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Exec(`CREATE TABLE audit_events (
                id integer PRIMARY KEY AUTOINCREMENT,
                event_id varchar(64),
                action varchar(64),
                actor_type varchar(32),
                actor_id varchar(255),
                target_type varchar(32),
                target_id varchar(36),
                reason varchar(256),
                created_at datetime
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
		if err := db.Exec(statement).Error; err != nil {
			t.Fatal(err)
		}
	}
	if err := db.Exec(`INSERT INTO audit_events
                (id, event_id, action, actor_type, actor_id, target_type, target_id, reason, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		1, "legacy-event-1", audit.ActionServerToolsUpdated, "admin", "legacy-admin", "server", "server-tools", "", time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)).Error; err != nil {
		t.Fatal(err)
	}
	closeGormTestDB(t, db)
}

func (f *scrubFixture) corruptAuditEventHash(t *testing.T) {
	t.Helper()
	db, err := gatewaydb.Open(f.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Exec("DROP TRIGGER audit_events_no_update").Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Exec("UPDATE audit_events SET event_hash = ? WHERE id = 1", strings.Repeat("a", 64)).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Exec("CREATE TRIGGER audit_events_no_update BEFORE UPDATE ON audit_events BEGIN SELECT RAISE(ABORT, 'AUDIT_EVENT_IMMUTABLE'); END").Error; err != nil {
		t.Fatal(err)
	}
	closeGormTestDB(t, db)
}

func (f *scrubFixture) corruptAuditHead(t *testing.T) {
	t.Helper()
	db, err := gatewaydb.Open(f.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Exec("UPDATE audit_chain_states SET head_hash = ? WHERE id = 1", strings.Repeat("b", 64)).Error; err != nil {
		t.Fatal(err)
	}
	closeGormTestDB(t, db)
}

func (f *scrubFixture) corruptAuditTrigger(t *testing.T) {
	t.Helper()
	db, err := gatewaydb.Open(f.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Exec("DROP TRIGGER audit_events_no_update").Error; err != nil {
		t.Fatal(err)
	}
	closeGormTestDB(t, db)
}

func (f *scrubFixture) appendPending(t *testing.T, kind audit.MaintenanceKind) audit.MaintenanceOperation {
	t.Helper()
	db, err := gatewaydb.Open(f.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	var operation audit.MaintenanceOperation
	if err := db.Transaction(func(tx *gorm.DB) error {
		var beginErr error
		operation, beginErr = audit.NewService(db).BeginMaintenanceTx(tx, kind)
		return beginErr
	}); err != nil {
		t.Fatal(err)
	}
	closeGormTestDB(t, db)
	return operation
}

func (f *scrubFixture) appendMultiplePending(t *testing.T) {
	t.Helper()
	db, err := gatewaydb.Open(f.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Transaction(func(tx *gorm.DB) error {
		svc := audit.NewService(db)
		if err := svc.RecordTx(tx, models.AuditEvent{
			Action:     audit.ActionProviderSecretMigrationStarted,
			ActorType:  "cli",
			ActorID:    "migrate-provider-secrets",
			TargetType: "maintenance-operation",
			TargetID:   uuid.NewString(),
		}); err != nil {
			return err
		}
		return svc.RecordTx(tx, models.AuditEvent{
			Action:     audit.ActionRequestLogScrubStarted,
			ActorType:  "cli",
			ActorID:    "scrub-request-log-content",
			TargetType: "maintenance-operation",
			TargetID:   uuid.NewString(),
		})
	}); err != nil {
		t.Fatal(err)
	}
	closeGormTestDB(t, db)
}

func assertAuditCount(t *testing.T, f *scrubFixture, want int) {
	t.Helper()
	events := f.maintenanceEvents(t)
	if len(events) != want {
		t.Fatalf("maintenance event count=%d want=%d events=%+v", len(events), want, events)
	}
}

func assertRequestLogBytes(t *testing.T, f *scrubFixture, want []byte) {
	t.Helper()
	if got := f.requestLogBytes(t); !bytes.Equal(got, want) {
		t.Fatalf("request-log bytes changed: got=%q want=%q", got, want)
	}
}

func TestP108B_S7_LegacyAuditPrerequisiteAndCompletion(t *testing.T) {
	f := newScrubFixture(t)
	f.seedLegacyRows(t, false)
	f.seedLegacyAudit(t)
	res, err := Run(Options{ConfigPath: f.cfgPath})
	if err != nil {
		t.Fatal(err)
	}
	if res.RemainNonEmpty != 0 {
		t.Fatalf("scrub left non-empty rows: %+v", res)
	}
	events := f.maintenanceEvents(t)
	if len(events) != 2 || events[0].Action != audit.ActionRequestLogScrubStarted || events[1].Action != audit.ActionRequestLogScrub {
		t.Fatalf("unexpected maintenance audit pair: %+v", events)
	}
	if events[0].TargetID == "" || events[0].TargetID != events[1].TargetID {
		t.Fatalf("maintenance pair correlation mismatch: %+v", events)
	}
	for _, event := range events {
		if event.ActorType != "cli" || event.ActorID != "scrub-request-log-content" || event.TargetType != "maintenance-operation" || event.Reason != "" {
			t.Fatalf("unexpected trusted maintenance identity: %+v", event)
		}
		if strings.Contains(event.TargetID, legacyPromptCanary) || strings.Contains(event.TargetID, legacyErrorCanary) {
			t.Fatalf("request-log canary entered audit target: %+v", event)
		}
	}

	db, err := gatewaydb.Open(f.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := audit.NewService(db).VerifyAuditChain(); err != nil {
		t.Fatalf("completed scrub left invalid audit chain: %v", err)
	}
	closeGormTestDB(t, db)
}

func TestP108B_S7_CurrentAuditEventCorruptionFailsBeforeScrub(t *testing.T) {
	f := newScrubFixture(t)
	f.seedLegacyRows(t, false)
	f.seedCurrentAudit(t)
	f.corruptAuditEventHash(t)
	before := f.requestLogBytes(t)
	vacuumCalled := false
	_, err := runWithHooks(Options{ConfigPath: f.cfgPath}, scrubHooks{
		vacuum: func(*sql.Conn) error {
			vacuumCalled = true
			return nil
		},
	})
	if !errors.Is(err, audit.ErrAuditIntegrity) {
		t.Fatalf("event corruption must fail closed, got %v", err)
	}
	if vacuumCalled {
		t.Fatal("event corruption reached VACUUM")
	}
	assertRequestLogBytes(t, f, before)
	assertAuditCount(t, f, 0)
}

func TestP108B_S7_CurrentAuditHeadCorruptionFailsBeforeScrub(t *testing.T) {
	f := newScrubFixture(t)
	f.seedLegacyRows(t, false)
	f.seedCurrentAudit(t)
	f.corruptAuditHead(t)
	before := f.requestLogBytes(t)
	vacuumCalled := false
	_, err := runWithHooks(Options{ConfigPath: f.cfgPath}, scrubHooks{
		vacuum: func(*sql.Conn) error {
			vacuumCalled = true
			return nil
		},
	})
	if !errors.Is(err, audit.ErrAuditIntegrity) {
		t.Fatalf("audit head corruption must fail closed, got %v", err)
	}
	if vacuumCalled {
		t.Fatal("audit head corruption reached VACUUM")
	}
	assertRequestLogBytes(t, f, before)
	assertAuditCount(t, f, 0)
}

func TestP108B_S7_CurrentAuditTriggerCorruptionFailsBeforeScrub(t *testing.T) {
	f := newScrubFixture(t)
	f.seedLegacyRows(t, false)
	f.seedCurrentAudit(t)
	f.corruptAuditTrigger(t)
	before := f.requestLogBytes(t)
	vacuumCalled := false
	_, err := runWithHooks(Options{ConfigPath: f.cfgPath}, scrubHooks{
		vacuum: func(*sql.Conn) error {
			vacuumCalled = true
			return nil
		},
	})
	if !errors.Is(err, audit.ErrAuditIntegrity) {
		t.Fatalf("audit trigger corruption must fail closed, got %v", err)
	}
	if vacuumCalled {
		t.Fatal("audit trigger corruption reached VACUUM")
	}
	assertRequestLogBytes(t, f, before)
	assertAuditCount(t, f, 0)
}

func TestP108B_S7_StartedFailureRollsBackLogicalClear(t *testing.T) {
	f := newScrubFixture(t)
	f.seedLegacyRows(t, false)
	f.seedCurrentAudit(t)
	before := f.requestLogBytes(t)
	vacuumCalled := false
	_, err := runWithHooks(Options{ConfigPath: f.cfgPath}, scrubHooks{
		beforeMaintenance: func(conn *sql.Conn) error {
			_, err := conn.ExecContext(context.Background(), "CREATE TRIGGER reject_scrub_started BEFORE INSERT ON audit_events WHEN NEW.action = 'REQUEST_LOG_SCRUB_STARTED' BEGIN SELECT RAISE(ABORT, 'TEST_STARTED_INSERT_FAILED'); END")
			return err
		},
		vacuum: func(*sql.Conn) error {
			vacuumCalled = true
			return nil
		},
	})
	if err == nil {
		t.Fatal("STARTED failure must fail")
	}
	if vacuumCalled {
		t.Fatal("STARTED failure reached VACUUM")
	}
	assertRequestLogBytes(t, f, before)
	assertAuditCount(t, f, 0)
}

func TestP108B_S7_UpdateFailureRollsBackStartedAndClear(t *testing.T) {
	f := newScrubFixture(t)
	f.seedLegacyRows(t, false)
	f.seedCurrentAudit(t)
	before := f.requestLogBytes(t)
	_, err := runWithHooks(Options{ConfigPath: f.cfgPath}, scrubHooks{
		beforeMaintenance: func(conn *sql.Conn) error {
			_, err := conn.ExecContext(context.Background(), "CREATE TRIGGER reject_scrub_update BEFORE UPDATE OF request_body, error_message ON request_logs BEGIN SELECT RAISE(ABORT, 'TEST_UPDATE_FAILED'); END")
			return err
		},
	})
	if err == nil {
		t.Fatal("logical update failure must fail")
	}
	assertRequestLogBytes(t, f, before)
	assertAuditCount(t, f, 0)
}

func TestP108B_S7_VacuumFailureLeavesPendingStarted(t *testing.T) {
	f := newScrubFixture(t)
	f.seedLegacyRows(t, false)
	vacuumErr := errors.New("injected vacuum failure")
	_, err := runWithHooks(Options{ConfigPath: f.cfgPath}, scrubHooks{
		vacuum: func(*sql.Conn) error { return vacuumErr },
	})
	if !errors.Is(err, vacuumErr) {
		t.Fatalf("expected vacuum failure, got %v", err)
	}
	events := f.maintenanceEvents(t)
	if len(events) != 1 || events[0].Action != audit.ActionRequestLogScrubStarted {
		t.Fatalf("vacuum failure must leave exactly one pending STARTED: %+v", events)
	}
	if got := f.requestLogBytes(t); len(got) == 0 {
		t.Fatal("request-log fixture unexpectedly disappeared")
	}
	res, err := Run(Options{ConfigPath: f.cfgPath})
	if err != nil {
		t.Fatalf("pending scrub rerun failed: %v", err)
	}
	if res.RemainNonEmpty != 0 {
		t.Fatalf("pending scrub rerun left rows: %+v", res)
	}
	events = f.maintenanceEvents(t)
	if len(events) != 2 || events[0].TargetID != events[1].TargetID {
		t.Fatalf("rerun did not reuse pending target: %+v", events)
	}
}

func TestP108B_S7_VerificationFailureLeavesPendingStarted(t *testing.T) {
	f := newScrubFixture(t)
	f.seedLegacyRows(t, false)
	verifyErr := errors.New("injected physical verification failure")
	_, err := runWithHooks(Options{ConfigPath: f.cfgPath}, scrubHooks{
		verify: func(*sql.Conn) error { return verifyErr },
	})
	if !errors.Is(err, verifyErr) {
		t.Fatalf("expected verification failure, got %v", err)
	}
	events := f.maintenanceEvents(t)
	if len(events) != 1 || events[0].Action != audit.ActionRequestLogScrubStarted {
		t.Fatalf("verification failure must leave pending STARTED: %+v", events)
	}
}

func TestP108B_S7_CompletionFailureLeavesPendingStarted(t *testing.T) {
	f := newScrubFixture(t)
	f.seedLegacyRows(t, false)
	_, err := runWithHooks(Options{ConfigPath: f.cfgPath}, scrubHooks{
		beforeCompletion: func(conn *sql.Conn) error {
			_, err := conn.ExecContext(context.Background(), "CREATE TRIGGER reject_scrub_success BEFORE INSERT ON audit_events WHEN NEW.action = 'REQUEST_LOG_SCRUB' BEGIN SELECT RAISE(ABORT, 'TEST_COMPLETION_FAILED'); END")
			return err
		},
	})
	if err == nil {
		t.Fatal("completion failure must fail")
	}
	events := f.maintenanceEvents(t)
	if len(events) != 1 || events[0].Action != audit.ActionRequestLogScrubStarted {
		t.Fatalf("completion failure must leave exactly one pending STARTED: %+v", events)
	}
}

func TestP108B_S7_GlobalProviderPendingFailsBeforeScrub(t *testing.T) {
	f := newScrubFixture(t)
	f.seedLegacyRows(t, false)
	f.migrateAudit(t)
	f.appendPending(t, audit.MaintenanceKindProviderSecretMigration)
	before := f.requestLogBytes(t)
	vacuumCalled := false
	_, err := runWithHooks(Options{ConfigPath: f.cfgPath}, scrubHooks{
		vacuum: func(*sql.Conn) error {
			vacuumCalled = true
			return nil
		},
	})
	if !errors.Is(err, audit.ErrAuditIntegrity) {
		t.Fatalf("provider pending must fail closed, got %v", err)
	}
	if vacuumCalled {
		t.Fatal("provider pending reached VACUUM")
	}
	assertRequestLogBytes(t, f, before)
	providerEvents := f.maintenanceEvents(t)
	if len(providerEvents) != 0 {
		t.Fatalf("request scrub event filter unexpectedly included provider event: %+v", providerEvents)
	}
}

func TestP108B_S7_MultiplePendingFailsBeforeScrub(t *testing.T) {
	f := newScrubFixture(t)
	f.seedLegacyRows(t, false)
	f.migrateAudit(t)
	f.appendMultiplePending(t)
	before := f.requestLogBytes(t)
	vacuumCalled := false
	_, err := runWithHooks(Options{ConfigPath: f.cfgPath}, scrubHooks{
		vacuum: func(*sql.Conn) error {
			vacuumCalled = true
			return nil
		},
	})
	if !errors.Is(err, audit.ErrAuditIntegrity) {
		t.Fatalf("multiple pending operations must fail closed, got %v", err)
	}
	if vacuumCalled {
		t.Fatal("multiple pending operations reached VACUUM")
	}
	assertRequestLogBytes(t, f, before)
}

func TestP108B_S7_PinnedOwnershipContinuousAcrossScrubPhases(t *testing.T) {
	f := newScrubFixture(t)
	f.seedLegacyRows(t, false)
	competitor, err := sql.Open("sqlite3", f.dbPath+"?_busy_timeout=0")
	if err != nil {
		t.Fatal(err)
	}
	defer competitor.Close()

	assertBlocked := func() error {
		conn, err := competitor.Conn(context.Background())
		if err != nil {
			return nil
		}
		defer conn.Close()
		if _, err := conn.ExecContext(context.Background(), "BEGIN IMMEDIATE"); err == nil {
			_, _ = conn.ExecContext(context.Background(), "ROLLBACK")
			return errors.New("competitor acquired scrub ownership")
		}
		return nil
	}
	check := func(*sql.Conn) error { return assertBlocked() }
	res, err := runWithHooks(Options{ConfigPath: f.cfgPath}, scrubHooks{
		beforeMaintenance: check,
		vacuum: func(conn *sql.Conn) error {
			if err := assertBlocked(); err != nil {
				return err
			}
			_, err := conn.ExecContext(context.Background(), "VACUUM")
			return err
		},
		verify:           check,
		beforeCompletion: check,
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.RemainNonEmpty != 0 {
		t.Fatalf("continuous ownership test left rows: %+v", res)
	}
}

// seedLegacyRows: 用完整 schema 建库并写入 legacy 正文/错误文本行
func (f *scrubFixture) seedLegacyRows(t *testing.T, walMode bool) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(f.dbPath), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if walMode {
		if err := db.Exec("PRAGMA journal_mode=WAL").Error; err != nil {
			t.Fatal(err)
		}
	}
	if err := db.AutoMigrate(&models.RequestLog{}); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if err := db.Create(&models.RequestLog{
			ClientID:     "legacy-client",
			Model:        "old-model",
			StatusCode:   200,
			RequestBody:  legacyPromptCanary,
			ErrorMessage: legacyErrorCanary,
		}).Error; err != nil {
			t.Fatal(err)
		}
	}
	if err := db.Exec("PRAGMA wal_checkpoint(TRUNCATE)").Error; err != nil {
		t.Fatal(err)
	}
	if sqlDB, e := db.DB(); e == nil {
		_ = sqlDB.Close()
	}
}

func (f *scrubFixture) rawScanCanaryHits(t *testing.T) (int, []string) {
	t.Helper()
	total := 0
	var scanned []string
	for _, name := range []string{"gateway.db", "gateway.db-wal", "gateway.db-shm", "gateway.db-journal"} {
		p := filepath.Join(f.dir, name)
		raw, err := os.ReadFile(p)
		if err != nil {
			continue // 文件不存在 → 跳过
		}
		scanned = append(scanned, name)
		total += strings.Count(string(raw), legacyPromptCanary)
		total += strings.Count(string(raw), legacyErrorCanary)
	}
	return total, scanned
}

// happy path：逻辑清零 + raw scan 0（含 WAL 模式）
func TestScrub_Fixture_EradicationLogicalAndRaw(t *testing.T) {
	for _, wal := range []bool{false, true} {
		t.Run(map[bool]string{false: "delete-journal", true: "wal"}[wal], func(t *testing.T) {
			f := newScrubFixture(t)
			f.seedLegacyRows(t, wal)

			res, err := Run(Options{ConfigPath: f.cfgPath, Now: func() time.Time { return time.Now().UTC() }})
			if err != nil {
				t.Fatalf("scrub 失败: %v", err)
			}
			if res.ScrubbedRows != 3 || res.RemainNonEmpty != 0 {
				t.Fatalf("结果不符: %+v", res)
			}

			// 逻辑复核（独立连接）
			db, err := gorm.Open(sqlite.Open(f.dbPath), &gorm.Config{})
			if err != nil {
				t.Fatal(err)
			}
			var n int64
			if err := db.Raw("SELECT count(*) FROM request_logs WHERE request_body != '' OR error_message != ''").Scan(&n).Error; err != nil {
				t.Fatal(err)
			}
			var total int64
			_ = db.Raw("SELECT count(*) FROM request_logs").Scan(&total).Error
			if sqlDB, e := db.DB(); e == nil {
				_ = sqlDB.Close()
			}
			if n != 0 {
				t.Fatalf("[安全回归失败] 逻辑残留 %d 行", n)
			}
			if total != 3 {
				t.Fatalf("metadata 行应保留，实际 %d", total)
			}

			// raw scan：所有落盘文件 canary = 0
			hits, scanned := f.rawScanCanaryHits(t)
			if len(scanned) == 0 {
				t.Fatal("没有任何 DB 文件可扫描——fixture 异常")
			}
			if hits != 0 {
				t.Fatalf("[安全回归失败] 落盘文件仍含 canary（%d 处，扫描 %v）", hits, scanned)
			}
		})
	}
}

// 缺确认 → 由 CLI 层拒绝（此处验证 Run 本身与确认解耦：Run 不负责确认语义）
func TestScrub_MissingConfig_StopNoCreate(t *testing.T) {
	dir := t.TempDir()
	_, err := Run(Options{ConfigPath: filepath.Join(dir, "absent.yaml")})
	if err == nil {
		t.Fatal("[安全回归失败] config 缺失应 STOP")
	}
	if _, err := os.Stat(filepath.Join(dir, "absent.yaml")); !os.IsNotExist(err) {
		t.Fatal("[安全回归失败] scrub 创建了缺失的 config")
	}
}

func TestScrub_MissingDB_StopNoCreate(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	dbPath := filepath.Join(dir, "gateway.db")
	if err := os.WriteFile(cfgPath, []byte("database:\n  path: "+dbPath+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Run(Options{ConfigPath: cfgPath}); err == nil {
		t.Fatal("[安全回归失败] DB 缺失应 STOP")
	}
	if _, err := os.Stat(dbPath); !os.IsNotExist(err) {
		t.Fatal("[安全回归失败] scrub 为缺失路径创建了 DB")
	}
}

// schema 缺失（无 request_logs 表）→ 显式 STOP
func TestScrub_SchemaMissing_ExplicitStop(t *testing.T) {
	f := newScrubFixture(t)
	// 建一个没有 request_logs 表的 DB
	db, err := gorm.Open(sqlite.Open(f.dbPath), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Exec("CREATE TABLE other (id integer primary key)").Error; err != nil {
		t.Fatal(err)
	}
	if sqlDB, e := db.DB(); e == nil {
		_ = sqlDB.Close()
	}
	if _, err := Run(Options{ConfigPath: f.cfgPath}); err == nil || !strings.Contains(err.Error(), "request_logs") {
		t.Fatalf("[安全回归失败] schema 缺失应显式 STOP，实际 err=%v", err)
	}
}

// 目录式 DB → STOP
func TestScrub_DirectoryDB_Stop(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	dbPath := filepath.Join(dir, "gateway.db")
	if err := os.MkdirAll(dbPath, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfgPath, []byte("database:\n  path: "+dbPath+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Run(Options{ConfigPath: cfgPath}); err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("[安全回归失败] 目录式 DB 应 STOP，实际 err=%v", err)
	}
}

// ---------------------------------------------------------------------------
// P1-04.1 · Exclusive / Busy Gate（并发连接 → 任何 mutation 之前 STOP）
// ---------------------------------------------------------------------------

// holdLock: 在独立连接上以 BEGIN IMMEDIATE 占用写锁（足以阻塞 TRUNCATE checkpoint
// 与 BEGIN EXCLUSIVE 探测），并保持打开直到调用返回的 release。
func holdLock(t *testing.T, dbPath string) (release func()) {
	t.Helper()
	ctx := context.Background()
	raw, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := raw.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.ExecContext(ctx, "PRAGMA busy_timeout = 0"); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
		t.Fatalf("fixture: 占用写锁失败: %v", err)
	}
	if _, err := conn.ExecContext(ctx, "SELECT count(*) FROM request_logs"); err != nil {
		t.Fatal(err)
	}
	return func() {
		_, _ = conn.ExecContext(ctx, "ROLLBACK")
		_ = conn.Close()
		_ = raw.Close()
	}
}

// assertLegacyIntact: legacy 行原值仍在（未发生任何 mutation）
func assertLegacyIntact(t *testing.T, f *scrubFixture) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(f.dbPath), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	var n int64
	if err := db.Raw("SELECT count(*) FROM request_logs WHERE request_body = ?", legacyPromptCanary).Scan(&n).Error; err != nil {
		t.Fatal(err)
	}
	if n != 3 {
		t.Fatalf("[安全回归失败] legacy 正文应在 STOP 后保持原值（3 行），实际 %d", n)
	}
	if sqlDB, e := db.DB(); e == nil {
		_ = sqlDB.Close()
	}
}

// G. WAL 模式 + 并发写锁占用 → STOP 于任何 mutation 之前
func TestScrub_WALBusy_StopBeforeMutation(t *testing.T) {
	f := newScrubFixture(t)
	f.seedLegacyRows(t, true) // WAL 模式

	release := holdLock(t, f.dbPath)

	_, err := Run(Options{ConfigPath: f.cfgPath})
	if err == nil {
		release()
		t.Fatal("[安全回归失败] 并发占用下 scrub 应 STOP")
	}
	if !strings.Contains(err.Error(), "REQUEST_LOG_SCRUB_OFFLINE_REQUIRED") {
		t.Fatalf("[安全回归失败] 应报 OFFLINE_REQUIRED，实际 %v", err)
	}
	assertLegacyIntact(t, f)
	release()

	// 释放后重跑 → 成功：逻辑 0 + raw bytes 0
	res, err := Run(Options{ConfigPath: f.cfgPath})
	if err != nil {
		t.Fatalf("释放独占后 scrub 应成功: %v", err)
	}
	if res.RemainNonEmpty != 0 {
		t.Fatalf("[安全回归失败] scrub 后仍有残留: %+v", res)
	}
	hits, scanned := f.rawScanCanaryHits(t)
	if hits != 0 || len(scanned) == 0 {
		t.Fatalf("[安全回归失败] raw bytes 未清零: hits=%d scanned=%v", hits, scanned)
	}
}

// 反向：delete-journal 模式 + 并发写锁占用 → exclusive 探测 STOP
func TestScrub_JournalBusy_StopBeforeMutation(t *testing.T) {
	f := newScrubFixture(t)
	f.seedLegacyRows(t, false)

	release := holdLock(t, f.dbPath)

	_, err := Run(Options{ConfigPath: f.cfgPath})
	if err == nil {
		release()
		t.Fatal("[安全回归失败] journal 模式并发占用下 scrub 应 STOP")
	}
	if !strings.Contains(err.Error(), "REQUEST_LOG_SCRUB_OFFLINE_REQUIRED") {
		t.Fatalf("[安全回归失败] 应报 OFFLINE_REQUIRED，实际 %v", err)
	}
	assertLegacyIntact(t, f)
	release()
}

// ---------------------------------------------------------------------------
// P1-04.2 · 持有式独占的所有权保留属性（Gate B 的机制证明）
//
// locking_mode=EXCLUSIVE + BEGIN EXCLUSIVE + COMMIT 之后，独占锁由该连接
// 持续保留——另一个【已打开】连接的 BEGIN IMMEDIATE（busy_timeout=0）必须被
// SQLITE_BUSY 拒绝，直到持有连接关闭；关闭后并发者恢复可写。
// 这正是 scrub 在 UPDATE→VACUUM 期间赖以防干扰的机制。
// 两条连接都在上锁前打开（与真实 scrub 场景一致：连接预先存在）。
// ---------------------------------------------------------------------------
func TestScrub_ExclusiveOwnership_RetainedAcrossCommit(t *testing.T) {
	f := newScrubFixture(t)
	f.seedLegacyRows(t, false)

	ctx := context.Background()
	// open: 返回 (专用连接, 彻底销毁函数)——销毁 = conn.Close + raw.Close（释放底层句柄）
	open := func() (*sql.Conn, func()) {
		raw, err := sql.Open("sqlite3", f.dbPath)
		if err != nil {
			t.Fatal(err)
		}
		conn, err := raw.Conn(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := conn.ExecContext(ctx, "PRAGMA busy_timeout = 0"); err != nil {
			t.Fatal(err)
		}
		return conn, func() {
			_ = conn.Close()
			_ = raw.Close()
		}
	}

	owner, destroyOwner := open()
	intruder, destroyIntruder := open()
	defer destroyIntruder()

	// owner 取得独占并提交（locking_mode=EXCLUSIVE → 锁跨 COMMIT 保持）
	if _, err := owner.ExecContext(ctx, "PRAGMA locking_mode = EXCLUSIVE"); err != nil {
		t.Fatal(err)
	}
	if _, err := owner.ExecContext(ctx, "BEGIN EXCLUSIVE"); err != nil {
		t.Fatal(err)
	}
	if _, err := owner.ExecContext(ctx, "COMMIT"); err != nil {
		t.Fatal(err)
	}

	// 持有期内：intruder 写事务必须被拒
	if _, err := intruder.ExecContext(ctx, "BEGIN IMMEDIATE"); err == nil {
		_, _ = intruder.ExecContext(ctx, "ROLLBACK")
		t.Fatal("[安全回归失败] 持有式独占未生效——并发者可以干扰 scrub")
	}

	// owner 释放：conn.Close 只归还连接池——必须销毁底层 pool
	// 才真正关闭持有 locking_mode=EXCLUSIVE 锁的 sqlite 句柄
	if err := owner.Close(); err != nil {
		t.Fatal(err)
	}
	destroyOwner()

	// 释放后：intruder 恢复可写（因果性证明）
	if _, err := intruder.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
		t.Fatalf("[安全回归失败] owner 释放后并发者仍被拒: %v", err)
	}
	_, _ = intruder.ExecContext(ctx, "ROLLBACK")
	t.Log("[SEC-003 FIXED] 持有式独占：COMMIT 后锁保留，释放后恢复")
}

// P1-04.2.1 · WAL ownership 实际分支覆盖：
// journal_mode=WAL 的 legacy DB → Run 取得持有式独占 → WAL→DELETE 拍平 → VACUUM
// → 成功；logica l/raw 双清零，且 WAL sidecar 不再存在、journal_mode 已切到 delete。
// （持有期内并发者被拒的机制证明见 TestScrub_ExclusiveOwnership_RetainedAcrossCommit；
//
//	并发占用下 Run 提前 STOP 见 TestScrub_WALBusy_StopBeforeMutation。）
func TestScrub_WALOwnership_BranchEradication(t *testing.T) {
	f := newScrubFixture(t)
	f.seedLegacyRows(t, true) // WAL 模式 + legacy canary

	// 注：WAL 模式下【任何】其他打开的连接（即使空闲）都会合法阻止
	// BEGIN EXCLUSIVE 获取——这正是离线 Gate 的正确语义（必须关闭一切连接）。
	// 该前置阻断由 TestScrub_WALBusy_StopBeforeMutation 覆盖；
	// 持有期内干扰被拒由 TestScrub_ExclusiveOwnership_RetainedAcrossCommit 覆盖；
	// 本测试覆盖生产 Run 的 WAL→exclusive ownership→WAL→DELETE→VACUUM 实际分支。
	res, err := Run(Options{ConfigPath: f.cfgPath})
	if err != nil {
		t.Fatalf("WAL ownership 分支 scrub 应成功: %v", err)
	}
	if res.RemainNonEmpty != 0 {
		t.Fatalf("[安全回归失败] 残留: %+v", res)
	}

	// WAL→DELETE 分支确实执行：journal_mode 已切换
	db, err := gorm.Open(sqlite.Open(f.dbPath), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	var mode string
	if err := db.Raw("PRAGMA journal_mode").Scan(&mode).Error; err != nil {
		t.Fatal(err)
	}
	if sqlDB, e := db.DB(); e == nil {
		_ = sqlDB.Close()
	}
	if !strings.EqualFold(mode, "delete") {
		t.Fatalf("[安全回归失败] WAL→DELETE 分支未生效，journal_mode=%q", mode)
	}

	// 逻辑 + raw bytes 双清零（raw scan 覆盖 -wal/-shm 残留文件）
	hits, scanned := f.rawScanCanaryHits(t)
	if hits != 0 {
		t.Fatalf("[安全回归失败] raw bytes 含 canary（%d 处，扫描 %v）", hits, scanned)
	}
	for _, name := range scanned {
		if strings.HasSuffix(name, "-wal") {
			t.Fatalf("[安全回归失败] WAL sidecar 在 journal 切换后仍存在: %s", name)
		}
	}
	t.Log("[SEC-003 FIXED] WAL ownership 分支：独占持有 → 拍平 → VACUUM → 双清零")
}
