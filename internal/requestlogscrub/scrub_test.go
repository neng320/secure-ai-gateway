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
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"ai-gateway/internal/models"

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
