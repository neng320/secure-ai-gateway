# main / develop Divergence & Reconciliation Plan

> DW-01 §8 交付物：**只调查，不解决**。本任务不做 merge/rebase/force-push/history rewrite。
> 采集时间：2026-08-29，基于 `git fetch origin` 后的远端状态。

## 1. 现状快照

| 项 | 值 |
|---|---|
| main HEAD | `1dbc8bb` — merge: P1-01F Listener Isolation（API/Admin/Metrics 三面隔离） |
| develop HEAD（DW-01 采集时） | `9d0bdf3` — merge: SEC-002 Closure Review |
| merge-base | `cc8d652` — merge: P1-01F Listener Isolation |
| develop ahead（origin/main..origin/develop） | **58 commits** |
| develop behind（origin/develop..origin/main） | **2 commits** |

## 2. main-only commits（2 个）

```text
1dbc8bb merge: P1-01F Listener Isolation（API/Admin/Metrics 三面隔离）
d9ca403 merge: secure-gateway P0 基线与治理（P0-01~P0-06）
```

**成因**：这两个 commit 是 **P1-00 历史清洗（git filter-repo 移除 config.yaml/aigateway/node_modules 全历史）之前**
的原始 merge commit。develop 在 P1-00 被整体重写（旧→新 SHA 映射见 `docs/p1-00-sha-mapping.md`），
main 未跟随重写，因此保留了一批"内容已被 develop 重写版覆盖、但 SHA 不同"的祖先 commit。

**内容等价性判断**：main-only 两个 commit 均为 merge commit，其树内容 ⊆ merge-base 之后的既有工作；
develop 侧的重写版本包含相同内容的清洗版（且额外删除了历史中的敏感文件）。**预计无独有业务内容。**
（Reconciliation 执行时仍须以 `git diff` 最终树校验为准，见 §4。）

## 3. 分叉风险

1. **main 落后 58 个 commit**：SEC-001/002/004 修复、迁移引擎、监听面收敛等全部只在 develop。
   main 当前不可部署、不可发布——这与 Production Gate（SEC-003 OPEN → FAIL）一致，属预期冻结状态。
2. **`MAIN_RELEASE_FROZEN=true`**：main 保护规则已收紧（enforce_admins/PR/三 checks/禁 force-push/禁删除），
   内容冻结至 reconciliation 窗口。
3. **重写历史与原历史并存**：merge 时 Git 会把 pre-rewrite 的 main-only commit 并入历史——
   这意味着 **config.yaml 等已被 P1-00 从 develop 历史清除的敏感文件会经由 main 侧祖先关系重新出现在
   main 的历史图中**（作为旧祖先 commit 的 blob，而非当前树内容）。这是不可回避的历史事实
   （SEC-005 已按"已泄漏"原则处理），但必须在 reconciliation 时明确知晓并记录。

## 4. Reconciliation Plan（SEC-003 CLOSED + Production Gate 通过后执行）

```text
前置条件（全部满足才启动）：
  ① SEC-003 CLOSED（P1-04 完成）
  ② SEC-001~005 全部 CLOSED → Production Security Gate PASS
  ③ 本计划经人工批准

步骤（全部走 PR，禁 force-push/禁 history rewrite）：
  1. git fetch origin && git checkout -b task/main-reconciliation origin/main
  2. git merge --no-ff origin/develop
     - 预期冲突点：两侧在 merge-base 后对同名文件的改动（develop 侧为权威清洗版）
     - 冲突解决原则：以 develop 的树内容为准
  3. 树等价校验（硬性）：
       git diff --stat origin/develop <merge-result>   必须为空
     若非空 → 禁止 merge，回人工审查
  4. bash scripts/verify.sh 全绿
  5. PR → main（三项 required checks 全绿）→ merge commit
  6. 校验 main HEAD 树 == develop 树；打 release tag
  7. 在 docs/p1-00-sha-mapping.md 追加 main 侧 pre-rewrite commit 的最终去向说明

禁止事项：
  - force push main（保护规则层面也已禁止）
  - rebase main 或任何 history rewrite
  - 跳过树等价校验直接 merge
  - 在 Production Gate 未 PASS 前执行本计划
```

## 5. DW-01 的边界

本文件仅为调查与计划。DW-01 执行期间 main 内容零变更（唯一触碰 main 的是其分支保护规则的收紧，
非代码变更）。
