# 存储布局与权限规范（storage-layout）

**版本：** P0-04 · 2026-08-28
**效力：** 运行时文件布局基线。任何任务不得把下列 runtime 路径纳入 Git 跟踪；CI 有大文件与 secret 检查兜底（P0-05）。

## 1. 目录职责

| 路径 | 内容 | Git | 权限（Linux 生产） | 说明 |
|---|---|---|---|---|
| `config.yaml` | **运行时真实配置**（含 Provider Key、session_secret） | ❌ 永不 | `0600`，仅服务账号可读 | 由首次启动自动生成或从 example 手工复制 |
| `config.example.yaml` | 模板（无真实密钥） | ✅ | 0644 | 根目录与 `docker/` 各一份，保持原位 |
| `data/` | SQLite `gateway.db` 及 journal/WAL/SHM | ❌ 永不 | `0700` | 默认 `./data/gateway.db`（config.database.path 可改） |
| `backups/` | 备份归档 + manifest（P2 产物） | ❌ 永不 | `0700` | **P2-06：必须与 data/ 不同物理卷**，启动时检测并告警 |
| `secrets/` | 主密钥文件（P1-03 引入 `MASTER_KEY` 等） | ❌ 永不 | `0700`，文件 `0600` | 优先环境变量注入；文件方式仅限无法用 env 的场景 |
| `logs/` | 运行日志（当前 zap 仅 stdout，字段为既有占位） | ❌ 永不 | `0750` | P1-08 重构日志时一并处理 |
| `deploy/` | systemd / Caddy / Windows Service 部署资产 | ✅ | — | P6 创建 |
| `docs/` | 审计、范围、ADR、runbook | ✅ | — | — |

## 2. 权限基线（Linux 生产，P6-02 验收依据）

1. 服务以专用非 root 账号运行（P6-01），对 `data/ backups/ secrets/ config.yaml` 拥有读写，对其余只读。
2. `config.yaml`、`secrets/` 下文件 `0600`；目录 `0700`。
3. 启动时自检：权限过宽 → 生产模式拒绝启动或高级别告警（P6-02 任务实现）。
4. Web/静态服务**禁止**暴露 `backups/ data/ secrets/ logs/`——Edge 反代仅转发 API 必需路径（P6-03）。

## 3. 已执行的止血（本任务）

- `git rm --cached`：`aigateway`（39MB 二进制）、`config.yaml`（含上游实例的 session_secret/prometheus 密码）、`node_modules/*`（10 个文件）
- `.gitignore` 扩展：`.env*`、`secrets/`、`data/`、`backups/`、`*.db*`、`aigateway`
- ⚠️ **历史仍在**：`git filter-repo` 历史清洗列为独立 backlog（SEC-005 遗留项）。在此之前，从历史检出的一切凭证视为已泄漏。

## 4. 密钥轮换要求（SEC-005 关联）

| 凭证 | 状态 | 要求 |
|---|---|---|
| 上游实例 session_secret / prometheus 密码（config.yaml，已入历史） | 视为已泄漏 | 任何实例部署前必须通过 setup 向导重新生成，禁止复用 |
| admin bcrypt hash（同上） | 视为已泄漏 | 同上，首次部署走 `/setup` 设置新密码 |
| 运营者自有凭证 | 不存在 | 尚无部署；未来凭证仅经环境变量/secret 文件注入，不入 Git |
