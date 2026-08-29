# P1-05A · Client Key Lifecycle Characterization

> 审计对象：tag `secure-gateway-p1-request-log-privacy.5`（develop `55f258e`）时点。
> 本阶段**生产行为 0 修改**；仅审计 + characterization tests + 本文档。
> 测试：`internal/handlers/p1_05a_lifecycle_test.go`（10 用例，全部 PASS，其中 3 个标记 `[KNOWN-GAP: P1-05 ...]`）。

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