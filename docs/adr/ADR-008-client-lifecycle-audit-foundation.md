# ADR-008: Client Lifecycle and Audit Foundation

- 状态：ACCEPTED（2026-08-30，P1-05C）
- 关联：P1-05、`docs/p1-05-client-key-lifecycle-characterization.md`、SEC-001~005

## 背景

P1-05B 已收口 Client key rotation、suspend/resume、delete cleanup、连接池外键和 in-flight late-write 一致性。仍需要永久吊销语义、受约束的生命周期原因与操作者记录，以及与生命周期 mutation 原子绑定的审计事件。设计必须避免把生命周期状态复制到第二个持久化字段，也不能让普通 settings 更新重新激活已吊销 client。

## 决策

1. **不持久化 `Status`**：Client 只增加 nullable `RevokedAt`、`RevokedBy`、`RevocationReason`。`LifecycleState()` 按 `RevokedAt != nil` 优先、其次 `IsActive` 推导 `ACTIVE`、`SUSPENDED`、`REVOKED` 三态；Client 行删除表示 `DELETED`。
2. **REVOKED 是终态**：Revoke 必须把 `IsActive` 设为 false、写入服务端时间与可信 admin actor、保存规范化 reason，并把 `APIKeyHash` 写为 SQL `NULL`。之后 Resume、Rotate、Suspend 和再次 Revoke 均拒绝；Delete 仍允许。
3. **Reason policy**：Rotate、Suspend、Revoke、Delete 必须提供 reason；Resume 可选但若提供必须经过同一 validator。reason 必须是合法 UTF-8、TrimSpace 后非空（required action）、最多 256 个 Unicode code points，且不得含 CR/LF/control characters。错误响应不回显完整 reason。
4. **Trusted actor**：`RevokedBy` 与 AuditEvent actor 使用服务端可信身份（当前为 `cfg.Admin.Username`，`actor_type=admin`），不信任任何表单 `actor`、`actor_id` 或 `revoked_by` 字段。
5. **Mutation + audit 同事务**：Create、Rotate、Suspend、Resume、Revoke、Delete 的数据库 mutation 与一个对应 AuditEvent append 必须在同一 SQLite transaction 中提交。Admin Create 的 provider-key envelope 与 allowlisted settings 也通过 `CreateClientWithSettings` 纳入 create transaction。任何 audit/settings/encryption 失败都必须 rollback，失败路径不返回新 plaintext key。
6. **Generic AuditEvent**：使用通用 `AuditEvent`，而不是 ClientLifecycleEvent 专表。事件只包含 server-generated event ID、固定 action、actor、client target、bounded reason 和 timestamp；禁止 request/response body、Authorization、client plaintext key、APIKeyHash、provider secret 或任意 JSON payload。
7. **Application append-only boundary**：生产 audit service 只暴露 `RecordTx` append 与 `List` read，不提供 Update/Delete API。当前决策是 application append-only foundation，不宣称数据库级 immutable、tamper-proof、tamper-evident、hash-chain 或完整管理动作覆盖。
8. **Audit survives client delete**：AuditEvent 不建立指向 Client 的 foreign key 或 `ON DELETE CASCADE`。`CLIENT_DELETED` 的 target ID 在 Client 行删除后仍保留。
9. **Settings write boundary**：普通 settings 与 model 更新使用 allowlisted/bounded column updates，禁止触碰 `APIKeyHash`、`IsActive`、`RevokedAt`、`RevokedBy`、`RevocationReason`，并禁止对 Client 使用整行 `Save`。
10. **P1-08 后续边界**：数据库级 append-only triggers、canonical hash chain、启动/离线 integrity verification、完整 security-sensitive Admin audit coverage 与 viewer 属于 P1-08，不在 P1-05C 中提前实现或宣称完成。

## 后果

- 正面：永久吊销不会与暂停混淆；撤销后旧 key 无法命中且不可被 settings/rotation 复活；生命周期事实和审计记录原子一致；删除 client 不会删除审计证据。
- 代价：AuditEvent 当前仍依赖应用路径的 append-only 纪律；恶意 DB owner/root 可直接修改或删除数据库内容，完整防篡改能力需 P1-08。
- 兼容性：新增 revoked 列与 audit_events 表为 additive migration；旧 Client 行保留，既有 APIKeyHash 不变，Revoked* 默认为 NULL/空值。

## 验证

- `internal/handlers/p1_05c_lifecycle_test.go`：A–Z 生命周期、reason、actor、原子回滚、race、privacy 和 additive migration acceptance。
- `internal/handlers/p1_05c_static_gate_test.go`：AuditEvent 无 production Update/Delete、Admin actor 不取表单、Client settings/models 不走整行 Save、六个 lifecycle mutation 均调用 `RecordTx`。
- `internal/handlers/p1_05b_lifecycle_test.go` 与既有 P1-04 privacy/security gates：P1-05B late-write/FK、认证与 secret privacy 不回归。
