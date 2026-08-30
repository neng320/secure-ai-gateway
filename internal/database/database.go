package database

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
