# ADR-003: SQLite 作为 V1 唯一持久化存储

- 状态：Accepted
- 日期：2026-08-28
- 关联：主方案 P2；ADR-004

## 背景

V1 是单机自托管网关：数据规模（Client 数、请求日志）小、并发有限、运维要极简。baseline-audit 确认现状为 gorm + mattn/go-sqlite3（CGO），AutoMigrate 启动即跑。

## 决策

1. V1 保持 SQLite 单文件存储，不引入 Redis/Kafka/PostgreSQL（scope-v1 Won't）。
2. 备份必须走**一致性在线快照**（SQLite Online Backup API 或驱动等价机制），禁止 cp 热库（P2-02）；快照写 staging 后原子 rename。
3. 审计确认当前**未显式启用 WAL**：P2-02 任务中评估开启 WAL 与 Online Backup 的兼容性，结论写入 backup-scope.md。
4. CGO 依赖（mattn/go-sqlite3）保留：CI 使用 ubuntu runner（P0-05 已配置 CGO_ENABLED=1）；若未来需要交叉编译，再评估 modernc.org/sqlite 纯 Go 驱动，属独立 ADR。

## 备选方案

1. **PostgreSQL**：强一致与并发更好，但 V1 用户是单机个人/小团队，引入数据库服务违背"极简运维"与备份一等能力目标（备份变成 DBA 问题）。
2. **纯文件（JSON）**：无法支撑请求日志的并发写与查询。
3. **BoltDB/Pebble 等嵌入式 KV**：缺 SQL 查询层，现有 gorm 代码全部重写。

## 后果

- 正面：备份=拷贝一个一致文件（加密后归档即可），恢复演练可在空目录完成；运维零依赖。
- 负面：单写者并发上限；WAL 模式下备份需在线 API 而非直接拷贝；文件级加密需靠备份包加密（P2-04）与磁盘层配合。
