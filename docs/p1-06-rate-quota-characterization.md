# P1-06 · Rate / Quota Characterization and Enforcement

> P1-06A 基线：`origin/develop` `8b6559ef016cad3aaed586ec718036ae15a54136`（P1-05C complete）。
> 当前 P1-06B 分支：`task/p1-06b-rate-quota-enforcement`，起点为 P1-06A merge `a3f9008b2294c304c4dc8b31f8966a3eed677826`。
> P1-06A 阶段只做审计、characterization tests 与文档，生产行为修改数 = 0；
> P1-06B enforcement 结果记录在 §8。
> 测试：`internal/middleware/p1_06a_rate_characterization_test.go`、
> `internal/services/p1_06a_quota_characterization_test.go`、
> `internal/handlers/p1_06a_request_limits_characterization_test.go`。

## 1. 实际调用链

```text
公网 API
  → Recovery / SecurityHeaders / MaxRequestSize / RequestID
  → AuthMiddleware.GetClientByAPIKey（每次 DB lookup）
  → RateLimiter.Middleware
       → clientLimits.minute.tryConsume()
       → clientLimits.hour.tryConsume()
       → clientLimits.day.tryConsume()
  → Gemini proxy 或 OpenAI-compatible handler
       → 协议解析 / provider request
       → upstream
       → RequestLog metadata + DailyUsage read/modify/save
       → Stats / Prometheus
```

`cmd/server/server.go` 将同一个 `RateLimiter` 接到公网 API 面；Admin 只共享生命周期清理能力，不经过公网 rate middleware。当前没有独立的 quota preflight stage：`QuotaRequestsDay`、`QuotaInputTokensDay`、`QuotaOutputTokensDay` 由 Client/Stats/UI 保存或展示，但没有在 upstream 前阻止请求的执行 gate。

## 2. CURRENT：RateLimiter

| 事实 | 当前行为与证据 |
|---|---|
| 三个窗口 | 存在 minute/hour/day 三个 `tokenBucket`，每个有独立 capacity/token 计数；但 `tokenBucket.refill()` 对全部 bucket 都使用 `elapsed >= time.Minute` 后整桶补满。hour/day 并非真实 1h/24h 窗口。 |
| 算法 | 固定容量 token bucket 形态；不按比例 refill，也不是真正 rolling/fixed window。每次 refill 是 full reset。 |
| 缓存 | `RateLimiter` 使用进程内 go-cache，client bucket 设置为 24h；不持久化。 |
| 动态限额 | 相同 client ID 命中已有缓存后，Admin 修改 Client rate limit 不会更新 bucket capacity；除非显式 `ResetClient` 或进程重启。characterization 已复现。 |
| 生命周期 | P1-05C 语义保留：Rotate/Suspend/Resume 不 reset；成功 Revoke/Delete 才 reset。 |
| 重启 | 新 `RateLimiter` 没有旧 bucket，消费状态清零。 |
| 0/负数 | bucket 初始 token 不大于 0，首请求立即 429；没有独立的配置 fail-closed 校验或溢出校验。 |
| 并发 | 已初始化的 warm bucket 由 `tokenBucket.mu` 串行消费，128 并发、capacity=32 时通过数为 32。cold cache 的 `Get → create → Set` 不是原子 LoadOrStore；当前测试在 32 轮中观察到多轮通过数超过 capacity，存在初始化竞态。 |
| 消费顺序 | minute 成功后才尝试 hour，hour 成功后才尝试 day；后面的 bucket 失败不会返还前面已消费的 token。 |
| 成功 header | RateLimiter 写 `X-RateLimit-Remaining-Minute/Hour/Day`，不写对应 Limit header。Proxy 后续写 Limit header 时使用 `string(rune(limit))`，不是十进制格式，需后续修正。 |
| 429 header/body | 返回 HTTP 429；body 是 JSON-shaped 字符串但 `Content-Type` 为 `text/plain; charset=utf-8`；只有通用 `X-RateLimit-Remaining: 0` 与 `X-RateLimit-Reset`，没有 `Retry-After`，没有稳定 rate/quota error code。hour/day 失败的 reset 文案按 1h/24h 计算，但 bucket 实际一分钟后即可 refill。 |

## 3. CURRENT：Quota 与 usage accounting

| 事实 | 当前行为与证据 |
|---|---|
| Request quota | `QuotaRequestsDay` 不参与 proxy/OpenAI request preflight；即使配置为 1，当前 accounting path 仍可记录第二个请求。 |
| Input/output daily quota | `QuotaInputTokensDay` 与 `QuotaOutputTokensDay` 只保存/展示，不在 upstream 前阻止请求；测试使用 quota=0 仍通过当前 Gemini preflight。 |
| DailyUsage 创建 | `GeminiService.LogRequest` 先插入 `request_logs`，再查找当天 `DailyUsage`；缺失时创建。日期使用 `time.Now().Truncate(24*time.Hour)`，即以 UTC 绝对边界对齐（Asia/Shanghai 进程中显示为本地 08:00）。 |
| 计费时机 | `TotalRequests`、input/output tokens 在 `LogRequest` 的 upstream 后路径递增；Proxy 非流式路径会对 `ForwardRequest` 的返回结果调用 metadata logging，但 streaming 在建立 upstream response 前失败时直接返回；OpenAI handler 的部分早期/非 retryable error 分支在写响应后不进入同一 LogRequest 路径。具体协议路径需要 P1-06B/P1-07 统一。 |
| upstream error/429 | RateLimiter 拒绝发生在 handler 前，因此不会产生 upstream usage；进入 handler 后是否记录错误取决于 Proxy/OpenAI 分支。当前 `LogRequest` 本身会保存传入的 status code 并 charge tokens，不负责 quota 判定。 |
| 并发更新 | `DailyUsage` 使用 `SELECT → struct increment → Save`，不是原子 SQL increment；32 个并发成功更新在当前运行中只保留了 3 个 request，明确存在 lost update。SQLite 调度导致具体丢失数量可能变化。 |
| streaming | Proxy streaming 与 OpenAI streaming 在完成流后各调用一次 `LogRequest`；测试确认 `IsStreaming=true` 的记录与 usage charge 各一次。断流、client disconnect、tool/fallback 计费边界仍未形成统一 contract。 |
| Delete/Revoke | P1-05C Delete 清理 client-owned request logs/daily usage；Revoke 只改变 credential lifecycle 并 reset limiter，不清理历史 usage/logs。 |

## 4. CURRENT：Max token limits

- Gemini proxy 的 `MaxInputTokens` 在 upstream 前执行，但使用 `len(body)/4` 的启发式，不是可靠 tokenizer；超限返回 HTTP 400 `MAX_INPUT_TOKENS_EXCEEDED`。
- Gemini proxy 的 `MaxOutputTokens` 不拒绝请求，而是把 `generationConfig.maxOutputTokens` 改写为 client 上限；`0` 表示不限制。
- OpenAI-compatible ChatCompletions 当前没有调用同一 request-limit gate，用户 `max_tokens` 会按请求值传给 provider，即使超过 `Client.MaxOutputTokens`。
- 这些字段已经存在并在 UI/Stats 中可见，但“字段存在”不等于所有协议路径都 enforce。

## 5. KNOWN-GAP：P1-06A 基线发现

1. hour/day bucket 的时间语义错误：两者一分钟后整桶 refill。
2. cold-cache `getOrCreateLimits` 初始化竞态可造成 burst 超额。
3. Admin 动态限额修改不会作用于已有 24h bucket，且没有明确“降低/提高额度”的迁移语义。
4. 后续 bucket 失败不回滚前面已消费的 token。
5. 0/负数/overflow limit 没有独立配置校验契约。
6. 429 body/header 缺少统一 JSON、稳定 code、Retry-After 和准确的三个窗口 metadata；Proxy Limit header 目前是 rune 编码问题。
7. `QuotaRequestsDay`、`QuotaInputTokensDay`、`QuotaOutputTokensDay` 没有 upstream 前执行 gate。
8. DailyUsage read-modify-save 在并发下 lost update；request log 与 usage charge 也不是同一原子 accounting transaction。
9. token quota 的 reservation、in-flight overshoot、stream 断流/重试/tool loop charge 语义未定义。
10. MaxInput 使用 bytes/4 启发式；OpenAI-compatible path 没有与 Gemini path 对齐的 MaxInput/MaxOutput contract。

## 6. TARGET：P1-06B 输入约束

P1-06B 应先锁定明确的 fixed/rolling/token-bucket 语义，再实现最小统一执行层：

- minute/hour/day 使用真实独立窗口（或文档明确的等价 rolling 语义），以 injectable clock 做边界测试，不使用真实 sleep。
- bucket 初始化与消费具备并发原子性；同一 client 的 burst 不超过当前 capacity。
- Admin 改限额后下一请求使用新值，但不凭空重置已消费量；降低/提高额度与 restart 行为写入测试和 ADR。
- 无效 limit fail closed，拒绝 0/负数/overflow 的静默 unlimited 或整数 wrap。
- request quota 在 upstream 前检查；达到 `QuotaRequestsDay` 时稳定返回 HTTP 429 与 quota-specific code，且并发不超额。
- token quota 先定义可证明的 reservation/charge contract；不能用 bytes/4 冒充精确 token count。已知无法严格 reservation 的 overshoot 必须 bounded 且文档化。
- streaming/non-streaming/fallback/retry 共用 rate/request quota/usage contract，断流不得 double charge。
- 所有 429 使用统一 JSON error schema、稳定 code、Retry-After 与准确 window metadata；invalid request 不调用 upstream。
- 继续保持 P1-05 lifecycle cleanup、P1-04 privacy 与 P1-05C audit 回归全绿。

## 7. P1-06A Characterization Evidence

| Test | 结论 |
|---|---|
| A/B/C | A 阶段事实：minute 可限流；hour/day 有独立 capacity 但实际均一分钟 refill。 |
| D | A 阶段事实：warm bucket 并发消费不超过 capacity；cold-cache burst 观察到初始化超额。 |
| E/F | A 阶段事实：动态编辑不刷新现有 cache；新 limiter/重启清空内存消费。 |
| G/H/I | A 阶段事实：daily request/input/output quota 不参与当前 accounting/preflight；Gemini MaxInput 启发式拒绝、Gemini MaxOutput rewrite、OpenAI max_tokens passthrough。 |
| J | A 阶段事实：DailyUsage 并发 read-modify-save lost update。 |
| K | A 阶段事实：streaming metadata 与 usage 各记录/charge 一次。 |
| L | A 阶段事实：429 为 plain-text JSON-shaped body，缺 Retry-After/stable code/Limit metadata。 |

P1-06A 结论：以上是 enforcement 前的可复现事实与明确缺口；P1-06B 的关闭结果如下。

## 8. P1-06B Enforcement Results

### Rate

- minute/hour/day 使用独立 fixed windows：60s、1h、24h；`NewRateLimiterWithClock` 允许无长 sleep 的边界测试。
- 同一 client 的三窗口在一次 mutex 临界区内同步配置、refill、consume；任一窗口失败不会吞掉前面窗口的 token。
- `sync.Map.LoadOrStore` 消除 cold-cache 重复 bucket；动态限额按“新 capacity - 已消费量”调整，降额不会送额度，升额不会清空历史消费。
- 成功响应提供三个 Limit 与 Remaining header；429 使用 JSON `RATE_LIMIT_EXCEEDED`、失败窗口、准确 reset、Retry-After。0/负数 rate limit fail closed。

### Quota / usage

- `NewQuotaMiddleware` 只对 generative POST（chat completions、Gemini generateContent）生效，排除 count_tokens 与 GET models；reservation 发生在 downstream/upstream handler 前。
- Request quota 每个请求预留 1；input reservation 使用 request body 的 conservative byte upper bound（截到 Client MaxInputTokens），不宣称精确 tokenizer；output reservation 使用请求声明值或 Client MaxOutputTokens 上界。
- `DailyUsage` 新增 reservation counters。SQLite upsert 条件原子检查 total+reserved 不超过日 quota；并发 reservation 不超额。完成后 transaction 内将实际 usage 加入 totals 并释放 reservation，早期/传输失败由 middleware release。
- 无效负数 quota/max-token 配置返回稳定 `QUOTA_CONFIGURATION_INVALID`；达到 request/input/output 日 quota 返回 HTTP 429 与对应 stable code；历史 usage 不因动态 quota 编辑重置。
- `LogRequest` 将 request log insert 与 unreserved usage upsert 放入同一 transaction；reserved request 的 log 与实际 token charge 也同一 transaction。所有 stats 查询使用同一 UTC `UsageDate`。
- Gemini 与 OpenAI request paths 都执行 conservative MaxInput gate；OpenAI `max_tokens` 超过 Client MaxOutputTokens 返回 `MAX_OUTPUT_TOKENS_EXCEEDED`；Gemini output 请求继续受 client cap 限制。

### V1 charging boundary

完整 upstream response 并成功写入 metadata log 才 charge request/actual tokens；这包括 non-retryable upstream HTTP error（按请求计数、无实际 token 时按 0 charge）。invalid request、provider setup failure 和 transport failure 在没有可 charge response 时释放 reservation。后续若要求“所有 upstream attempt 均计费”，需在后续迭代中为各 fallback/retry/error path 增加统一 charge contract。

P1-06B 关闭 P1-06A 的 rate-window、cold-cache、dynamic-edit、atomic DailyUsage、stable-429 与 request/token quota enforcement gaps；P1-05 lifecycle、P1-04 privacy 与 audit 回归继续作为 required regression。
