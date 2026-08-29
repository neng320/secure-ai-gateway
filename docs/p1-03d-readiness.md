# P1-03D0 · Real Migration Readiness / Read-Only Preflight Report

> 生成时间：2026-08-29（本机时区）
> 性质：**只读预检**——未对任何真实 config / SQLite 执行迁移、写入、AutoMigrate、VACUUM、checkpoint；未生成 Master Key。
> 纪律：本文件面向 public 仓库，一切本机路径以占位符表示；真实路径仅存在于执行会话记录中。
> SEC-002 状态：🟠 **MIGRATION IMPLEMENTED / REAL EXECUTION PENDING**（不 CLOSED）。

---

## 0. Baseline

| 项 | 值 |
|---|---|
| develop | `e34f614`（merge: P1-03C3.1 Final Staging Corrections） |
| 恢复点 tag | `secure-gateway-p1-secret-migration-staging.1`（annotated，指向 e34f614；进入 P1-03D 的正式基线） |
| 前一 recovery point | `secure-gateway-p1-secret-migration-staging`（保留，修正前状态） |
| CI | run `33235469943` success（Format/Vet、Build/Test、Secret Scan） |
| 验证 | 本机 + fresh clone 全量 `go vet ./...` + `go test ./... -count=1` 全绿 |

## 1. 结论（TL;DR）

**本机当前不存在任何已部署的 gateway 实例，也不存在任何 `gateway.db`。**

- 无 gateway 相关进程、无 8090/8091/9090（及任何 API/Admin/Metrics 形态）监听者。
- 全机候选排查（H 盘 workspace 全量 + D 盘 maxdepth=4 + 仓库全树，排除 node_modules）：**0 个 `gateway.db` / `-wal` / `-shm` / `-journal` 文件**。
- 唯一与本项目相关的 config.yaml 候选是仓库内 gitignored 的测试残留（见 §3），其中 **Provider Secret 数量为 0**。
- 与 scope-v1.md 的部署状态声明一致：本网关尚未部署，无运营者真实凭证入库。

因此按任务卡规则（"如果无法唯一确定实际配置：STOP，不要猜"）：
**CONFIG_PATH / DB_PATH 尚无法唯一确定——迁移目标尚不存在。P1-03D1 = NOT READY（blocker 见 §9）。**

## 2. 配置/DB 路径语义（供 D1 前人工确认目标）

| 场景 | CONFIG_PATH（占位） | DB_PATH（占位） | 依据 |
|---|---|---|---|
| 开发机运行（默认行为） | `<REPO_ROOT>/config.yaml` | `<REPO_ROOT>/data/gateway.db`（相对 `database.path: ./data/gateway.db` 按进程 CWD 解析） | `Makefile run` / `go run ./cmd/server` 默认 `-config config.yaml`；`config.Load` 对缺失路径会进入 setup wizard 并创建 |
| VPS 生产（现有部署规范） | `<CONFIG_PATH>`（`-config` 显式参数） | `<DB_PATH>`（`database.path` 解析，相对路径按 `WorkingDirectory`） | `contrib/ai-gateway.service`：systemd、非 root `ai-gateway` 用户、`WorkingDirectory=/opt/ai-gateway` |

**当前两者均不存在实例。** D1 执行前必须由人工指定真实目标（或先完成部署）。

## 3. 候选文件分类结果（只读，无材料输出）

| 候选 | 判定 | Provider Secret 状态 | 备注 |
|---|---|---|---|
| `<TEST_ARTIFACT_CONFIG>`（仓库内，gitignored，927 B） | 测试残留（pre-P1-01F 字段形态：admin/metrics 端口为 0） | **global: 0 个（全 EMPTY）**；无 DB 指向 | 含测试生成的 password hash + session secret；非迁移目标；建议人工删除（D0 不动） |
| `<UPSTREAM_DOWNLOAD_CONFIG>`（D 盘 Downloads，965 B） | **上游作者 config 的下载副本**（host 0.0.0.0、gemini provider 存在但 key 为空） | gemini：EMPTY；无 DB | 含上游作者 password hash/session secret——SEC-005 已按"已泄漏"原则处理过 Git 历史；此本地副本建议人工删除或隔离（D0 不动） |
| `<UNRELATED_PROJECT_CONFIG>`（sub2api-deploy，597 B） | 无关项目（端口 8080、无 admin 段、无 provider） | global: 0 个 | 排除 |

三份文件的 SHA-256 已在执行会话中记录（真实值见会话报告，不入公共文档）。

## 4. Pre-migration 基线 hash

- 真实 config：**N/A（不存在）**
- 真实 DB：**N/A（不存在）**；`-wal`/`-shm`/`-journal`：均不存在
- 候选文件的 hash：见会话记录（占位：<TEST_ARTIFACT_CONFIG_SHA256> 等）

## 5. Read-only Provider Secret Inventory

- 使用 `config.LoadExistingForMigration`（side-effect-free）；SQLite 副本只读打开。
- 结果：**全部候选的 Global/Client 五态计数均为 EMPTY（0 个 legacy / 0 mixed / 0 encrypted / 0 invalid）**。
- 无 MIXED、无 INVALID → 不触发 inventory STOP（但迁移目标本身不存在，见 §1）。

## 6. SQLite Read-only Health

**N/A——无任何 SQLite 文件可检查。**（未创建、未打开不存在的路径。）

D1 时必须在真实目标上重新执行：`PRAGMA integrity_check`（非 ok 即 STOP）、`user_version`、`journal_mode`、`clients.id/backend_api_key/backend_api_key_encrypted` 列存在性。

## 7. 运行状态 / 活跃写入风险

- gateway / aigateway / secure-ai-gateway 进程：**无**
- API/Admin/Metrics 端口监听者：**无**
- 活跃 WAL：**无**（无任何 DB 文件）
- `D1_REQUIRES_SERVICE_STOP`：**N/A（当前无服务在跑）**；D1 执行时必须重新复查并取得独占窗口

## 8. Master Key 状态与计划

- 当前环境：`AIGATEWAY_MASTER_KEY` / `AIGATEWAY_MASTER_KEY_FILE` **均未设置** → `MASTER_KEY_ACTION=GENERATE_AT_D1`（本阶段未生成）。
- key_id：N/A（无 key）。
- 候选存储位置（**需人工确认**，D0 未创建）：
  - VPS（优先遵循现有部署规范，与 `<CONFIG_PATH>` 同域）：`<MASTER_KEY_FILE>`（`/etc/ai-gateway/master.key` 形态），属主 `ai-gateway:ai-gateway`，`chmod 0600`，systemd `Environment=AIGATEWAY_MASTER_KEY_FILE=...` 注入
  - 开发机：`<MASTER_KEY_FILE>`（数据分区、repo 外、Git 不可追踪的专用 secrets 目录），ACL 收敛到当前用户
- 硬性要求复述：不放 config.yaml、不放 SQLite、不放 migration backup；ENV 与 FILE 恰好其一。

## 9. Blockers（P1-03D1 前必须由人工解决）

1. **迁移目标不存在**：本机无已部署实例、无 `gateway.db`、无含真实 Provider Key 的 config。人工必须先确认目标（先部署 dev/VPS 实例，或指定既有真实路径后重跑 D0 预检）。
2. **Master Key 未生成**、存储位置候选（§8）需人工确认。
3. **Plaintext migration backup 处置**：`PLAINTEXT_BACKUP_DISPOSITION=NEEDS_HUMAN_DECISION`（PLAN A 转移加密/离线受控存储 vs PLAN B 等人工明确授权后删除）。AI 不得自行选择或删除。
4. （次要）两份本地遗留候选文件（§3）建议人工删除/隔离；其中上游作者配置副本属敏感遗留物。

## 10. P1-03D1 执行序列（计划，未执行）

```
人工 APPROVE P1-03D1 + 确认 CONFIG_PATH/DB_PATH/BACKUP_ROOT/MASTER_KEY_FILE
↓
重跑本预检确认状态未漂移（目标 hash 对比）
↓
Gateway 停止 + 进程/端口复查为空（独占 DB）
↓
Master Key 生成（一次性输出 base64 供配置，绝不入 repo/config/DB）+ 存储就位（0600）
↓
migration CLI: -migrate-provider-secrets -migration-backup-dir <BACKUP_ROOT>
  （BACKUP → [SCHEMA-ADD 仅 ADD COLUMN] → PREPARE → VERIFY → FINALIZE，引擎自带 fail-closed）
↓
逻辑字段验证（SELECT 确认 legacy='' 且 encrypted 为 enc:v1 信封；条数与 inventory 一致）
↓
WAL/SHM/journal 处理（确认 journal_mode；残留则 wal_checkpoint(TRUNCATE) 后复核）
↓
VACUUM 重写 active DB（消灭旧页/journal 残留字节；UPDATE ...='' 不足以证明擦除）
↓
再次关闭/检查 WAL/SHM 不复活
↓
active DB raw-byte scan（比对值在内存中取自迁移前 inventory；只输出 match count / record ID，绝不回显明文）
↓
active config raw-byte scan（同上纪律）
↓
post-migration encrypted-only snapshot（新 baseline hash 存档）
↓
STOP → 人工确认 plaintext backup 处置（PLAN A / B）→ P1-03D2
```

**回滚点**：迁移引擎的 `migration-backup-<ts>/`（gateway.db 一致性快照 + config.yaml 原始字节 + manifest，含 `migration_format_version`/schema 前置状态/`user_version`）。回滚 = 停服 → 用快照覆盖 DB 与 config → 重启（回到迁移前明文态）。

## 11. 资源预估

| 项 | 值 |
|---|---|
| GLOBAL_LEGACY_COUNT | **0（已知候选）**；真实目标待确认 |
| CLIENT_LEGACY_COUNT | **0（已知候选）**；真实目标待确认 |
| TOTAL_SECRET_COUNT | **0（已知候选）** |
| SCHEMA_ADD_REQUIRED | **N/A**（无 DB；D1 在真实目标上按 manifest/schema 检查判定） |
| BACKUP_SIZE_ESTIMATE | 极小（当前无 DB；若目标为全新部署实例，DB 通常 < 1 MB，含 config 副本 < 2 MB） |
| ESTIMATED_DOWNTIME | 迁移引擎本身秒级；含 VACUUM 重写 + 双 raw scan + WAL 复核，单实例小库 **< 5 分钟**（以 D1 实测为准） |
| 磁盘可用空间 | 开发机数据分区 868 GB free（远大于 DB+config 的 3 倍要求） |

## 12. 建议 Backup Root（需人工确认，D0 未创建）

- 开发机：`<BACKUP_ROOT>`（数据分区、repo 外、与 config/DB 不同目录；符合"数据产出不放系统盘"的既有规则）
- VPS：`<BACKUP_ROOT>`（repo 外、与 `/opt/ai-gateway/data` 与 `<CONFIG_PATH>` 不同目录；建议 `/var/backups/secure-ai-gateway`，属主 `ai-gateway`，0700）

> 提醒（P1-03D2 硬 Gate）：迁移 backup **故意保留迁移前明文**。SEC-002 最终 CLOSED 的条件之一是 active storage 无明文 **且** plaintext backup 已按 PLAN A/B 处置完毕。
