package database

import "os"

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
