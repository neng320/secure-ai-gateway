# P1-05A · Client Key Lifecycle Characterization

> 审计对象：tag `secure-gateway-p1-request-log-privacy.5`（develop `55f258e`）时点。
> 本阶段**生产行为 0 修改**；仅审计 + characterization tests + 本文档。
> 测试：`internal/handlers/p1_05a_lifecycle_test.go`（10 用例，全部 PASS）。
> **P1-05B 已修正全部 4 项 [KNOWN-GAP]（见 §7 Correction Results）；P1-05C 已完成 REVOKED/Reason/Audit foundation（见 §8），P1-05 整体 COMPLETE。**

## 1. 生命周期数据流（ISSUE → STORE → AUTHENTICATE → SUSPEND → RE-ENABLE → ROTATE → REVOKE → DELETE → CLEANUP → AUDIT）

```text
ISSUE        services/client.go CreateClient: GenerateAPIKeyWithPrefix(prefix+UUIDv4) → 明文仅本次返回
STORE        clients.api_key_hash = SHA-256(plaintext)；无明文列（BackendAPIKey 属 provider key，独立域）
AUTHENTICATE middleware/auth.go Handler: GetClientByAPIKey(哈希查库 + is_active=true 过滤) → 500ms 内完成
             ↑ 缓存死代码：AuthMiddleware.cache / getClientFromCacheOrDB / InvalidateCache 均零调用方
SUSPEND      admin ToggleClient(IsActive=false) → 下一次请求表现为 401 invalid-key（非 403）
RE-ENABLE    ToggleClient(IsActive=true) → 原 key 原样恢复（= SUSPEND/RESUME，不是吊销）
ROTATE       RegenerateAPIKey: UPDATE api_key_hash 覆盖 → 旧 key 立即永久失效（旧 hash 无残留）
REVOKE       不存在独立语义/字段（revocation_reason/revoked_at/revoked_by 均无）
DELETE       DeleteClient: 仅删 clients 行；request_logs / daily_usages 孤儿残留
CLEANUP      无级联、无孤儿清理、无审计事件（AUDIT_EVENT_COUNT = 0）
AUDIT        CLIENT_CREATED/KEY_ROTATED/DISABLED/ENABLED/KEY_REVOKED/DELETED 均无持久化事件
```

## 2. 逐项事实（11 个 acceptance 的精确答案）

| # | 问题 | 精确答案（测试证据） |
|---|---|---|
| 1 | Regenerate 不存在 client 是否 false-success | **是**：`RegenerateAPIKey("nonexistent")` 返回 `err==nil + 非空新 key`，但 `RowsAffected==0`，key 未存库即不可用 → `[KNOWN-GAP: P1-05 ROTATE-NOTFOUND]`。UI 侧更糟：POST `/admin/clients/nonexistent/regenerate` → **HTTP 200 + 截断页面 + 尾部 `Template error: nil pointer evaluating *models.Client.Name`**（模板在 nil Client 字段访问处失败；头部已发出故状态码滞留 200；管理员无错误提示） |
| 2 | Disabled client 实际 401 还是 403 | **401**（`{"error": "Invalid API key"}`）。`GetClientByAPIKey` 查询即含 `is_active=true` 过滤 → disabled client 命中 nil → middleware 的 `if !client.IsActive { 403 }` 分支**不可达**（死代码） |
| 3 | Re-enable 是否恢复原 key | **是**：原 key 原样恢复可用 → 当前语义 = SUSPEND/RESUME（无吊销状态） |
| 4 | Delete 后孤儿行 | **request_logs 与 daily_usages 全部残留**（clients 0，logs 2，usage 1）→ `[KNOWN-GAP: P1-05 ORPHAN-DATA]`；prometheus 内存 label 系列亦残留（进程生命周期内无 TTL） |
| 5 | Rotation 是否立即生效 | **是**：rotate 后下一请求（零 sleep）旧 key 401、新 key 200；旧 hash 从库中被覆盖移除 |
| 6 | Delete 是否立即失效 | **是**：删行后 key 自然无法命中（无缓存介入） |
| 7 | Auth cache 是否真的参与请求 | **否**：`AuthMiddleware.cache`、`getClientFromCacheOrDB`、`InvalidateCache` 均为死代码（零调用方）；每次请求直接 DB 哈希查找 |
| 8 | RateLimiter cache 是否有 residue | **是（bounded）**：`limits:<clientID>` 桶存于 go-cache，TTL 24h；`ResetClient` 零调用方；被删 client 的桶在 TTL 内残留（内存态，无安全可利用性，属 bounded residue） |
| 9 | Lifecycle audit 当前 | **0**（`AUDIT_EVENT_COUNT = 0`；无任何持久化生命周期事件） |
| 10 | Revocation reason 当前 | **不存在**：模型无 `revoked_at/revoked_by/revocation_reason/Status` 字段（反射断言） |
| 11 | Metrics compare | **仍是普通字符串比较**：`username != h.username || password != h.password`（非 constant-time）→ `[KNOWN-GAP: P1-05 METRICS-COMPARE]` |

## 3. Key 生成（固化，P1-05B 不擅自更换）

```text
格式：prefix（sk- / sk-ant- / gm_ / 自定义）+ uuid.New()（UUIDv4）
熵：122-bit（RFC 4122 v4 随机位）——未发现可预测/熵不足/collision 证据，保持兼容
存储：仅 clients.api_key_hash（SHA-256）；明文生命周期 = Create/Regenerate 调用的一次性返回 + Admin 结果页一次性展示
```

## 4. Delete Cascade Inventory（全部 client_id / ClientID 引用）

| RESOURCE | OWNER | ON_DISABLE | ON_ROTATE | ON_DELETE | TARGET_POLICY（P1-05B 建议） |
|---|---|---|---|---|---|
| `clients` | client | 保留 | 保留 | 删除（现状 ✓） | — |
| `request_logs`（SQLite） | client | 保留 | 保留 | **孤儿残留（gap）** | 按策略清理（物理删除或孤儿 scrub；审计要求见下） |
| `daily_usages`（SQLite，gorm 复数表 `daily_usages`） | client | 保留 | 保留 | **孤儿残留（gap）** | 同上 |
| Prometheus label 系列（进程内存，`requestsTotal` 等 × client_id） | client | 保留 | 保留 | 无限期残留（内存） | 接受（bounded by 进程生命周期）或按 client 过滤 |
| `RateLimiter.cache` `limits:<clientID>` | client | 保留 | 保留 | 24h TTL 残留 | 触发 `ResetClient`（当前零调用方） |
| `AuthMiddleware.cache` `client:*<id>` | client | — | — | — | 死代码，P1-05B 可删除或真正启用 |
| `AdminSession` | admin | N/A | N/A | N/A | 与 client 生命周期无关 |
| Dashboard/WS clientStats | 派生 | 无持久化 | 无持久化 | 下次广播自然消失 | — |

## 5. 其他固化

- **ToggleClient 错误吞掉**：`client.IsActive = !client.IsActive; h.clientService.UpdateClient(client)` 忽略返回值 → `[KNOWN-GAP: P1-05 TOGGLE-ERR-SWALLOW]`（一致性 gap，本阶段不修）
- **RegenerateKey handler**：对 `GetClientByID` 的 nil 未防护（见 acceptance #1 UI 症状）；`RegenerateAPIKey` 服务层同样未防护
- **CreateClient 服务层不设 Backend**（DB 默认 gemini）——既定行为（P1-03 测试已固化的优先级语义依赖此点）

## 6. Target Semantics Proposal（只提方案，P1-05A 不实现）

```text
状态          语义
ACTIVE        可用（现状）
SUSPENDED     Toggle 停用，原 key 可恢复（现状已是；补显式 Status 字段与事件）
REVOKED       独立于 suspend 的永久吊销态（当前不存在；须新状态+吊销时间/原因/操作者）
ROTATED       旧 key 永久失效、新 key 立即生效（现状已满足；补 ROTATED 事件）
DELETED       client 本体删除；request_logs/daily_usages 按明确策略清理；
              安全审计事件必须保留（不得随行删除）
Reason        所有 destructive 动作须带 bounded reason（字段+UI+校验）
Audit         需要持久化 append-only 事件（P1-05 专表 vs P1-08 AuditEvent foundation——
              本阶段仅提出，不编码）
```

**P1-05B 建议修复顺序**：① `RegenerateAPIKey`/`DeleteClient` 的 RowsAffected 检查与 false-success 根除（含 UI nil-防护）；② 显式 SUSPENDED/REVOKED 状态 + 吊销元数据；③ 级联清理策略（request_logs/daily_usages + RateLimiter 重置）；④ 生命周期审计事件；⑤ Metrics constant-time 比较；⑥ auth cache 死代码处置。
**执行结果见 §7 —— ①③⑤⑥ 及"Delete 后 in-flight late-write"已在 P1-05B 完成；②④ 留待 P1-05C。**

---

## 7. P1-05B Correction Results（lifecycle consistency foundation，tag `secure-gateway-p1-client-lifecycle-consistency`）

### 7.1 关闭清单（原 [KNOWN-GAP] / 新发现 → 修复 → 证据）

| 项 | P1-05A 固化现状 | P1-05B 修复 | 证据 |
|---|---|---|---|
| ROTATE-NOTFOUND | `RegenerateAPIKey` nil error + 生成无主 key；UI 200 + 截断模板 | service 返回 `ErrClientNotFound` + `key==""`；Admin 404，无模板错误/无 key 渲染 | `TestP105A_Rotate_Nonexistent_FalseSuccess`（[P1-05B FIXED]）、`TestP105A_AdminRegenerate_NonexistentClient_404`、`TestP105B_Regenerate_Nonexistent_ErrAnd404` |
| ORPHAN-DATA | Delete 后 request_logs/daily_usages 孤儿残留 | DeleteClient 单事务（children 先删 → client 后删，RowsAffected 检查）+ FK ON DELETE CASCADE（双保险）；三表恒 0 | `TestP105A_Delete_OrphanData`（[P1-05B FIXED]）、`TestP105B_Delete_Existing_AllTablesZero`、`TestP105B_ForeignKeys_OnAllPooledConnections` |
| TOGGLE-ERR-SWALLOW | `ToggleClient` 忽略 `UpdateClient` 错误 | 新增 `SetClientActive(id, active)`（RowsAffected→ErrClientNotFound）；handler 检查错误：404/500 generic；表单支持显式 `active=true/false` | `TestP105B_Toggle_DbErrorNotSwallowed`（DROP TABLE 注入 → 500 且不泄露 raw error） |
| METRICS-COMPARE | `username != h.username \|\| password != h.password` 普通比较 | SHA-256 定长化 ×2 + `subtle.ConstantTimeCompare`，两比较均执行（位与合并，无 secret-dependent short-circuit） | `TestP105B_MetricsBasicAuth_ConstantTimeContract`（200/401×3）+ `TestP105B_StaticGate_MetricsConstantTime` |
| dead Auth cache | `AuthMiddleware.cache` / `getClientFromCacheOrDB` / `InvalidateCache` 零调用方 | 全部删除（含 auth.go 内 go-cache import）；认证始终直接 DB lookup | `TestP105B_StaticGate_DeadCacheRemoved`；行为证明：rotate/delete/suspend 下一请求零 sleep 即反映（既有 B/D/E/F 用例） |
| RateLimiter 死接线 | `ResetClient` 零调用方；limiter 为 buildAPIRouter 局部对象 | limiter 提升为 `gatewayDeps.rateLimiter` 共享实例（API+Admin 同一对象）；Delete 事务成功后才 `ResetClient(clientID)`；**ROTATE/SUSPEND/RESUME 一律不 reset**（防轮换刷额度） | `TestP105B_Rotate_InheritsRateLimitState`（rotate 后 remaining 继承为 0 → 429）、`TestP105B_Delete_ResetsRateLimitBucket`（delete 后同 ID 重建 → 200）、静态 Gate `TestP105B_StaticGate_RateLimiterSharedInstance`（NewRateLimiter 恰 1 处）+ `ResetClientOnlyOnDelete`（调用恰 1 处） |

### 7.2 新发现：IN_FLIGHT_DELETE_LATE_WRITE（本阶段核心 Acceptance）

**发现**：Delete cleanup 不能只做 `DELETE client → DELETE request_logs → DELETE daily_usages`——已通过认证的 **in-flight request** 在 Delete 返回后才完成时，`LogRequest()` 仍会无条件 Create `RequestLog` 并 upsert `DailyUsage`，重新制造孤儿数据（check-then-write TOCTOU 的持久化侧等价物）。

**最终解决（方案 A：DB-level referential integrity）**：

```text
1. models：RequestLog.ClientID / DailyUsage.ClientID 增加 FK → clients(id)
   ON UPDATE CASCADE ON DELETE CASCADE（gorm constraint tag，AutoMigrate 内联建表）
2. internal/database.Open：DSN 级 _foreign_keys=on——PRAGMA foreign_keys 是
   connection-scoped，DSN 参数保证连接池【每个新连接】都强制外键
   （测试用 SetMaxIdleConns(0) 逐个取新连接验证 PRAGMA==1）
3. DeleteClient：单事务 children-first 清理 + client 删除（RowsAffected 检查），
   任一步失败整体 ROLLBACK
4. LogRequest/updateDailyUsage：INSERT 命中 FK violation（client 已删）→ 静默跳过
   （isClientGoneForeignKey 双保险：gorm.ErrForeignKeyViolated + sqlite3 原生错误码）
   → 旧请求正常结束，零孤儿
```

**Gate（channel barrier，无 sleep）**：认证放行 → 旧请求阻塞在日志写入前 → Admin Delete 成功 → 放行旧请求完成 → 等全部写入结束 → `clients=0 / request_logs=0 / daily_usages=0`。
证据：`TestP105B_Delete_InFlightLateWrite_Barrier`；还有不经 barrier 的精简证明 `TestP105B_LogRequest_FKViolation_GracefulSkip` 与事务回滚注入 `TestP105B_Delete_TransactionFailure_Rollback`（AFTER DELETE 触发器 RAISE(ABORT) → 三表原值保留）。

**遗留边界**：既有旧库（AutoMigrate 之前创建、无法 ALTER ADD CONSTRAINT 的 SQLite）可能缺 FK——此时 late-write 防线退化为 DeleteClient 事务内显式清理（孤儿仍不可能产生于 Delete 路径本身），但 late-write INSERT 不报 FK 错；本仓库无运营者存量库（SEC-002：0 实例），新库全部内联 FK。

### 7.3 其余落实

- **Suspend/Resume 契约统一**：SUSPENDED / ROTATED-old / DELETED / random invalid 全部 401 `Invalid API key`（deliberate contract，不提供 credential-validity oracle）；middleware 的 `if !client.IsActive { 403 }` **死分支删除**（`GetClientByAPIKey` 查询已含 is_active 过滤）。
- **Prometheus residue 政策（正式记录）**：`client_id` label 系列属 private metrics listener 的 process-lifetime operational telemetry，不含 credential，进程重启即消失 → `ON_DELETE = retain until process restart`（本阶段不扩大重构范围）。
- **静态/交付 Gate**：`TestP105B_StaticGate_*` 6 项——死亡标识符、RowsAffected≥3、ResetClient 恰 1 调用、常量时间比较、共享实例、DSN 外键。
- **正确性注记**：P1-05B 不取消已开始的 upstream 请求；要求的是 Delete 后禁止新认证、并禁止旧 in-flight 请求重建 client-owned 持久行。

---

## 8. P1-05C Final Lifecycle Semantics

P1-05C 在 P1-05B 的 lifecycle consistency foundation 上增加永久吊销与通用审计底座。状态不新增持久化 `Status` 字段，始终由 `RevokedAt` 与 `IsActive` 推导：

| State | Derived condition | Key/auth behavior | Allowed transitions |
|---|---|---|---|
| `ACTIVE` | `RevokedAt IS NULL` and `IsActive = true` | current key authenticates | suspend, revoke, rotate, delete |
| `SUSPENDED` | `RevokedAt IS NULL` and `IsActive = false` | current key returns the same generic `401 Invalid API key` | resume, revoke, rotate, delete |
| `REVOKED` | `RevokedAt IS NOT NULL` | `APIKeyHash IS NULL`; all old keys permanently return generic `401` | delete only; ordinary metadata/settings edits remain allowed but cannot alter lifecycle columns |
| `DELETED` | client row absent | no client authentication; retained audit target ID | terminal absence |

`REVOKED` is terminal: suspend, resume, rotate, and repeat revoke return the stable invalid-transition error (`HTTP 409`). Revoke writes `IsActive=false`, `RevokedAt`, trusted `RevokedBy`, normalized bounded `RevocationReason`, and SQL `NULL` `APIKeyHash` in one transaction. Multiple revoked clients therefore do not collide on the unique hash index.

Lifecycle reasons are trimmed, valid UTF-8, non-empty for rotate/suspend/revoke/delete, at most 256 Unicode code points, and reject CR/LF and control characters. Resume accepts an empty reason but validates it when supplied. Admin actor identity is taken from the server-side configured admin username; submitted `actor`, `actor_id`, and `revoked_by` form fields are ignored.

The generic `AuditEvent` schema stores only fixed action, trusted actor, client target, bounded reason, timestamp, and server-generated event ID. Create, rotate, suspend, resume, revoke, and delete each append exactly one event in the same SQLite transaction as the mutation; an audit insert failure rolls back the mutation. Delete removes client-owned request logs and daily usage but leaves the `CLIENT_DELETED` event because `AuditEvent` has no client foreign key.

The application boundary is append/read-only (`RecordTx` and `List`); it is not a claim of database-level immutability, tamper evidence, hash chaining, retention, or complete audit coverage. Those controls remain P1-08 scope.

Evidence: `internal/handlers/p1_05c_lifecycle_test.go` A–Z acceptance suite, `internal/handlers/p1_05c_static_gate_test.go` source gates, and `docs/adr/ADR-008-client-lifecycle-audit-foundation.md`.
