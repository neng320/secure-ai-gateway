# 轻量安全 LLM API Gateway · P0 执行设计

**日期：** 2026-08-28
**依据：** 《轻量安全LLM_API_Gateway_完整执行方案_v1.0.md》
**范围：** 本设计固化 P0 阶段的本地执行决策；P1+ 沿用原方案，不再重复。

## 1. 已确认的环境决策

| 决策项 | 结论 |
|---|---|
| 仓库位置 | `H:/zcode workspace/secure-ai-gateway` |
| Fork 方式 | GitHub Fork（保留 upstream 关系）+ rename 为 `secure-ai-gateway` |
| 基线 commit | `2e192f174e97523b725d402fe7110273b95ef46d`（上游 main，2026-03-04） |
| Go 版本 | 1.27.0（winget 安装），go.mod 要求 1.24+ |
| Go 模块代理 | `GOPROXY=https://goproxy.cn,direct`（proxy.golang.org 不可达） |
| 开发环境 | Windows 10（本机），Git Bash |
| 生产环境 | Linux VPS 为唯一生产验收平台：systemd / Caddy / ufw|nftables / 非 root 专用账号 / SQLite 本地 / systemd timer 备份 / 第二盘或 NAS / Admin 仅 loopback+SSH 隧道或 Tailscale |
| Windows 定位 | 仅本地开发、调试、功能验证；不复制 Linux 生产安全实现；保留 Windows Service / PowerShell / Task Scheduler / Defender 防火墙脚本 |

## 2. 分支与发布流程

```text
upstream/main ──fetch──> main（基线与发布 tag，禁直接开发）
                            │
                            ├── develop（集成主干）
                            │      ▲
task/P0-02-audit ───────────┘      │（--no-ff 合入，PR 可选）
task/P1-05-provider-key ───────────┘

阶段完成：develop ──> main（--no-ff）──> tag secure-gateway-p0
```

- 一个 Task ID 一个分支：`task/<TASK-ID-kebab>`。
- 每任务固定产出五项：变更摘要 / 文件清单 / 测试命令与结果 / 风险 / 回滚方法。
- 验收失败即停，不降低标准，不顺手实现后续任务。

## 3. 测试策略（TDD）

上游基线**零测试**（27 个 Go 文件全部无测试文件），因此：

1. **P0 阶段**：不补历史测试（属于 P1 范围）；但 CI 必须验证"能失败"——注入语法错误/测试失败确认流水线拦截后再恢复（P0-05）。
2. **P1+ 阶段**：所有安全功能先写失败测试再实现；改动到的既有关键路径（auth、quota、key 生命周期）必须同步补 characterization test。
3. **回归底线**：`gofmt`、`go vet`、`go test ./...` 三绿才能合并。

## 4. 基线审计已发现的既有问题（P0-02 正式确认）

| # | 发现 | 影响 | 计划处理 |
|---|---|---|---|
| 1 | `go vet` 报 2 处 IPv6 地址格式错误（`internal/services/tools.go:189,217`） | CI 无法三绿 | P0-05 前修复（最小改动，仅地址格式化） |
| 2 | 39MB 预编译二进制 `aigateway` 提交进了 Git | 仓库膨胀、二进制不可审计 | P0-04 目录规范中移除跟踪并加 .gitignore |
| 3 | `node_modules/` 提交进了 Git | 同上 | 同上 |
| 4 | `config.yaml`（非 example）被提交 | 可能含真实密钥泄漏风险 | P0-02 审计内容，P0-04 规范化 |

## 5. P0 完成定义（DoD）

- [ ] 干净克隆 + `go build ./...` + `go test ./...` 通过
- [ ] `docs/baseline-audit.md` 完成，每项标注已验证/仅声明/缺失
- [ ] `docs/scope-v1.md` 冻结 Must/Should/Won't
- [ ] `config.example.yaml` 无真实密钥；`docs/storage-layout.md` 完成
- [ ] CI 生效且验证过"能拦截坏提交"
- [ ] 4 份 ADR 合入
- [ ] `develop` → `main`，打 tag `secure-gateway-p0`
- [ ] **暂停，等用户验收后再进入 P1**

## 6. 风险与回滚

- 风险：上游后续更新与安全增强冲突 → 每阶段打 tag，rebase 策略在 P1 开工前单独决定。
- 回滚：任意任务分支可 `git branch -D`；阶段级回滚 `git reset --hard <tag>`；仓库级回滚删除 fork 重新执行 P0-01（成本 ≈ 10 分钟）。
