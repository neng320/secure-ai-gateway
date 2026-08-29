# ADR-007: Request Logging Privacy（SEC-003）

- 状态：ACCEPTED（2026-08-29，P1-04）
- 关联：SEC-003、docs/p1-04-request-log-characterization.md、ADR-006（密钥加密，独立域）

## 背景

baseline 审计确认：完整 prompt（inbound request body）被默认持久化到 `request_logs.request_body`，
raw 错误文本可进入 `error_message`，且 Dashboard 将正文 server-render 进 HTML/JS modal，
Client Detail 原样渲染 ErrorMessage——persistence 与 presentation 两层暴露。

## 决策

1. **Metadata-only by default**：`RequestLog` 仅持久化
   `request_id / client_id / provider / model / status_code / input_tokens / output_tokens /
   latency_ms / error_code / is_streaming / has_tools / tool_names / created_at`。
   **prompt / messages / tool arguments / tool result / request body / response body /
   raw upstream error text / Authorization / URL query secret 一律不落盘。**
2. **结构化日志 API**：持久层接口为 `services.RequestRecord`——调用点根本不存在
   body / raw error text 可传；`RequestBody`/`ErrorMessage` 新写恒空由持久层强制，
   不依赖调用者自觉。
3. **legacy 字段保留**：`request_body` / `error_message` 两列不 DROP/RENAME（additive 演进），
   降级为 LEGACY PRIVACY MIGRATION FIELD（`json:"-"`），仅作为 P1-04D scrub 落点。
4. **raw upstream error 永不入库**：错误以 bounded 稳定错误码记录
   （`UPSTREAM_NETWORK_ERROR / UPSTREAM_AUTH_ERROR / UPSTREAM_RATE_LIMIT / UPSTREAM_4XX /
   UPSTREAM_5XX / INVALID_REQUEST / INTERNAL_ERROR`）——无用户正文、无 URL、无 secret。
   向调用客户端返回适度错误文本属即时响应，不在本决策约束内。
5. **Request ID**：服务器生成（crypto/rand 128-bit → 32 hex），绝不信任客户端提供的
   `X-Request-ID`；同一请求全链一致：响应头 `X-Request-ID` == `RequestLog.RequestID`。
6. **Request/Response body 不属于持久化数据模型**。临时诊断正文不落 SQLite、不做 AEAD 加密存储
   （避免 retention/key 生命周期/备份清除的额外治理面），改为：
   `Request → bounded MEMORY-ONLY store → hard expiry → zero/clear → authenticated Admin on-demand`。
   - 显式 opt-in：`logging.request_body_capture.enabled`（默认 OFF）
   - `expires_at` 必填（RFC3339、未来、距校验时刻 ≤24h 硬窗口；超窗拒绝启动）
   - bounded：`max_bytes` 默认 16KiB / 硬上限 64KiB；`max_entries` 默认 100 / 硬上限 1000（超限拒绝启动）
   - 到期真实 timer 自动 disable + 清空；eviction/清空 best-effort 置零；重启自然消失
   - 读取仅经 `GET /admin/request-bodies/{requestID}`（RequireAuth、Admin 监听面、
     `Cache-Control: no-store`、缺失/关闭/过期 → 404）；正文绝不 server-render 进
     Dashboard HTML、绝不经 WS 广播
   - 捕获范围仅限已认证 LLM API 请求的原始 inbound payload（cap 改写之前）；
     admin/login/setup、表单、Authorization/Master Key 永不捕获
7. **legacy 存量 fail-closed**：启动 preflight 发现 `request_logs` 中任何非空
   request_body/error_message → 拒绝启动（哨兵 `REQUEST_LOG_PRIVACY_MIGRATION_REQUIRED`，
   仅报告行数）。清理走显式离线 CLI `-scrub-request-log-content` + `-confirm-destructive-scrub`
   （WAL checkpoint → secure_delete → UPDATE 置空 → VACUUM 重写 → sidecar 检查），
   **不可逆且不自动生成 plaintext backup**。
8. **runtime log 纪律**：不可信 upstream error body 不得回显进 runtime log；
   fallback 日志只输出 bounded 错误码。
9. **WS**：Dashboard WebSocket 只广播纯 metadata（无 request_body presence、无正文、无 raw error）。

## 后果

- 正面：prompt 正文从数据模型中消失；诊断需求有受控、自动过期的出口；旧实例升级有明确迁移路径。
- 代价：诊断正文重启即失（by design）；排障需显式开启 capture；错误排障从文本降级为错误码 + 客户端即时响应。
- Production Gate：SEC-003 关闭后 SEC-001~005 全部 CLOSED，但 **PRODUCTION_RELEASE_REVIEW = REQUIRED**（人工评审），`MAIN_RELEASE_FROZEN=true` 保持。

## 验证

- P1-04A 特征化（6 KNOWN-VULN）→ P1-04B 红转绿安全回归 + RequestID/ErrorCode 新增回归
- P1-04C：config fail-closed 7 用例、store 边界 6 用例（含 `-race`）、端到端 5 用例（含磁盘 raw scan=0）
- P1-04D：scrub fixture（delete-journal/WAL 双模式 逻辑+raw bytes 清零）+ preflight 3 用例
- Prompt Privacy Security Gate（cmd/server 全栈 5 用例）：DEFAULT MODE 三类请求
  磁盘/日志 0 canary、DIAGNOSTIC、BOUNDS、RUNTIME ERROR、静态 tripwire
