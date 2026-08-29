# Development Workflow（DW-01 起强制执行）

> 本文档是所有 AI Agent 与维护者的**流程契约**。分支保护由 GitHub 强制（见 §7），
> 本文档解释规则、理由与历史失败模式。恢复点基线：`secure-gateway-p1-secret-at-rest`（develop `9d0bdf3`）。

## 1. 分支模型（MERGE-BASED HISTORY）

```text
task/<TASK-ID>-<slug>      ← 一切开发工作发生在这里（每任务独立分支）
   │  scripts/verify.sh 全绿 → commit
   ▼
Pull Request → develop     ← GitHub 强制：PR 必需、三项 CI required、enforce_admins=TRUE
   │  远程 CI 全绿 → merge commit（--no-ff 语义，禁止 squash/rebase 改写任务历史）
   ▼
develop                    ← 集成分支；禁止直接 push（保护规则对管理员同样生效）
   │  阶段完成时打 annotated tag 作为恢复点
   ▼
main                       ← release-only，当前冻结（MAIN_RELEASE_FROZEN=true）
```

- **merge policy = MERGE-BASED**：`Require linear history` 已关闭（与 `--no-ff` 任务合并语义冲突，
  二者不可同时成立，本项目正式选择 merge-based）。
- `main` 在 **SEC-003 CLOSED 且 Production Security Gate 通过**之前不同步 develop
  （详见 `docs/main-develop-reconciliation.md`）。

## 2. Local Verification Contract（提交前必做）

**每次 commit 之前必须单独执行：**

```bash
bash scripts/verify.sh
```

脚本内容（任何一步失败立即非 0 退出）：

1. gofmt（仅检查 Git 跟踪的 Go 文件）
2. `go vet ./...`
3. `go build ./...`（CGO_ENABLED=1）
4. `go test ./... -count=1`（禁用 test cache）
5. secret scan（`scripts/secret-scan.sh`）
6. large file check（`scripts/check-large-files.sh`）
7. repo hygiene（`*.provisioning` / `*.migrating` 等临时文件与运行时配置不得被跟踪）

## 3. 明令禁止（对 Agent 与维护者同等生效）

- ❌ 直接在 `develop` / `main` 上开发或 push（enforce_admins=TRUE 下会被 GitHub 拒绝）
- ❌ admin bypass（`gh pr merge --admin`、保护规则临时降级等）
- ❌ 测试失败后继续 commit / CI 红灯后进入下一个 Task
- ❌ 用 `go test ... | grep ...` 等 pipeline 过滤后以管道退出码决定提交
  （除非显式 `set -o pipefail`——本项目直接禁用该模式，用 verify.sh 取代）
- ❌ 分支上存在未 tracked / 被 gitignore 吞掉的源码却宣称完成（交付必须经 fresh-clone 验证）
- ❌ 为让测试通过而删除/弱化安全回归测试
- ❌ 在未跑 verify.sh 的情况下 commit

## 4. PR 流程

```text
Agent
→ git checkout -b task/<TASK-ID>-<slug>（自当前 develop HEAD）
→ 实现 + bash scripts/verify.sh（全绿）
→ commit（任务粒度；不夹带无关变更）
→ git push -u origin task/...
→ gh pr create --base develop（标题/正文写清变更摘要、测试证据、风险与回滚）
→ 等待三项 required checks 全绿（Format & Vet / Build & Test / Secret Scan & Repo Hygiene）
→ gh pr merge --merge（merge commit；禁 --admin）
→ 确认 develop 上合并后的 CI 再次全绿
→ 阶段恢复点：git tag -a <checkpoint> && git push origin <checkpoint>
```

单人仓库不强制人工 approval（required_approving_review_count=0），但 **PR + 三项 CI checks + enforce_admins 为强制**——
即"提交进入 develop"这个动作永远经过远程 CI，且管理员无法绕过。

## 5. CI 与本地 Gate 对齐

- `Build & Test` 执行 `go test ./... -count=1`（与 verify.sh 相同；禁 test cache）。
- 三个 required context 名称固定，**不得改名**（改名会使 branch protection 的 required context 失效）：
  - `Format & Vet`
  - `Build & Test`
  - `Secret Scan & Repo Hygiene`

## 6. 真实失败模式记录（工程经验，无个人归责）

以下两类事故在本仓库历史上真实发生过，是本 Gate 存在的直接原因：

### 模式 A：pipeline exit-code masking（管道退出码掩蔽）

```bash
# 危险模式（曾导致带病提交两次）：
go test ./... | grep -E "^(ok|FAIL)" && git commit ...
```

`grep` 的退出码覆盖了 `go test` 的退出码：测试实际失败时管道整体仍返回 0，
Agent 据"命令成功"继续 commit，把红灯带进 develop。
**根治**：禁止以 pipeline 输出过滤决定提交；测试与 commit 分开执行；统一走 `scripts/verify.sh`（`set -euo pipefail`）。

### 模式 B：gitignore-created CI coverage illusion（交付幻觉）

`.gitignore` 中的 `secrets/` 规则把 `internal/secrets/` 整个包吞掉：
本地 `go test` 全绿（文件在磁盘上），GitHub 上根本没有该包（CI 在残缺树上跑出另一种"绿"），
首个安全基础设施任务以"DELIVERY FAIL"收场，靠人工复验才发现。
**根治**：`.gitignore` 根锚定（`/secrets/`）、CI 增加 `Critical package delivery guard`、
重要交付强制 fresh-clone 拉取验证 + 关键文件 SHA-256 对比。

**共同教训**：本地绿 ≠ 远程交付；退出码 ≠ 事实；交付验证必须以 GitHub 上的真实树为准。

## 7. 分支保护配置（GitHub 强制层）

两个受保护分支（`develop`、`main`）统一为：

| 规则 | 值 |
|---|---|
| Require pull request before merging | ✅（required_approving_review_count=0，单人仓库不强制他人 approve） |
| Require status checks | ✅ `Format & Vet` + `Build & Test` + `Secret Scan & Repo Hygiene` |
| Require branches up to date（strict） | ✅ |
| Enforce Admins | ✅（管理员与 Agent 同样受约束） |
| Require linear history | ❌（MERGE-BASED） |
| Allow force pushes | ❌ |
| Allow deletions | ❌ |

变更前的配置快照（DW-01 采集）：develop/main 均为 `enforce_admins=false`、`strict=false`、
`required_linear_history=true`（与 no-ff 合并冲突）、未要求 PR——即管理员可直接 push 绕过全部检查。
本 Gate 之后上述缺口全部闭合。

## 8. main 冻结声明

```text
MAIN_RELEASE_FROZEN=true
```

`main` 的保护规则同步收紧（同样 enforce_admins / PR / 三 checks / 禁 force-push / 禁删除），
但其内容保持不动。解冻与 reconciliation 条件：

1. SEC-003 CLOSED
2. Production Security Gate 通过（SEC-001~005 全 CLOSED）

届时按 `docs/main-develop-reconciliation.md` 的计划执行，本任务不做任何 main 变更。
