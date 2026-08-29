# P1-04A · Request Logging Characterization（SEC-003）

> 审计对象：tag `secure-gateway-development-workflow-gate`（develop `2a4a363`）时点的生产行为。
> **本阶段生产行为 0 修改**；仅审计 + characterization tests + 本文档。
> 测试：`internal/handlers/p1_04a_characterization_test.go`（8 用例，全部 PASS，其中 6 个标记 `[KNOWN-VULN: SEC-003]`）。

## 1. 数据流总图（SOURCE → MEMORY → PERSISTENCE → PRESENTATION → LOG SINK）

```text
SOURCE（正文来源）
  ├─ OpenAI/兼容路由   handlers/openai.go ChatCompletions: io.ReadAll(r.Body) → string(body)
  ├─ Gemini 原生路由   handlers/proxy.go GenerateContent/StreamGenerateContent: io.ReadAll(r.Body) → body
  └─ providers/*       buildRequestBody（出站重写体，非持久化来源）
MEMORY
  ├─ capOutputTokens(client, body)（proxy 专用，可能改写 maxOutputTokens）
  └─ requestBody（openai 全路径透传）
PERSISTENCE
  ├─ services/gemini.go LogRequest(...) → models.RequestLog{RequestBody, ErrorMessage} → SQLite request_logs
  └─ models.RequestLog json tags: request_body / error_message（可序列化）
PRESENTATION
  ├─ Dashboard（admin.go Dashboard → dashboard.html :1332 showRequestBody('{{js .RequestBody}}')）
  └─ Client Detail（client_detail.html :2070 RequestBody presence badge；:2073 {{.ErrorMessage}} 原样渲染）
LOG/ERROR SINK
  ├─ openai.go fallback: log.Printf("[CHAT] Trying fallback: %s (error: %v)") ← extractErrorMessage(respBody)
  └─ WS（wshub.go:210）: "request_body": RequestBody != "" —— 仅 presence bool，无正文
```

## 2. 逐 Endpoint 矩阵

| # | Endpoint | Streaming | Body source | Body transformation | DB persistence | HTML exposure | JSON exposure | WS exposure | Runtime log | Error-text | 测试 |
|---|---|---|---|---|---|---|---|---|---|---|---|
| 1 | POST /v1/chat/completions（openai） | no | `io.ReadAll(r.Body)` 全量 | 无 | **全量 inbound JSON → request_body**（仅到达 :465 的路径；初始 4xx/5xx 提前 return 不落行） | Dashboard modal（全量） | json.Marshal 可序列化 | presence bool | 否 | **ErrorMessage 不写**（openai 传 ""）；raw upstream error 只进 runtime fallback log | A |
| 2 | POST /v1/chat/completions（openai） | yes（`"stream":true`） | 同上 | 无 | **全量 inbound JSON → request_body**（仅成功流） | 同上 | 同上 | presence bool | fallback log 同上 | 同上 | B |
| 3 | POST /v1/models/{m}:generateContent（gemini proxy） | no | `io.ReadAll(r.Body)` | **capOutputTokens 改写后**持久化 | **cap 后 body → request_body**（测试证实 `maxOutputTokens:5000→100`）；`err.Error()` 传输错误文本 → **ErrorMessage** | Dashboard modal | 可序列化 | presence bool | 否 | **ErrorMessage=传输错误文本**（url.Error 形态；当前 URL 无 key、无 prompt 回显，但属不可信文本入库） | C |
| 4 | POST /v1/models/{m}:streamGenerateContent（gemini proxy） | yes | `io.ReadAll(r.Body)` | 无 | **无任何 RequestLog 行**（元数据缺口；GetBaseURL 硬编码 googleapis 致无法 e2e，测试经 service 层驱动） | — | — | — | 否 | 无 | C2 |
| 5 | GET /admin/dashboard | — | — | — | 读侧 | **`showRequestBody('{{js .RequestBody}}')` 全量正文进 HTML/JS**（:1332） | — | — | — | — | E |
| 6 | GET /admin/clients/{id} | — | — | — | 读侧 | **RequestBody presence badge（:2070）+ `{{.ErrorMessage}}` 原样渲染（:2073）** | — | — | — | — | F |
| 7 | models.RequestLog | — | — | — | — | — | **`json:"request_body"` / `json:"error_message"` 可序列化** | — | — | — | D |
| 8 | Dashboard WS（buildPayload） | — | — | — | — | — | `"request_body": l.RequestBody != ""` | **仅 presence bool，无正文** ✓ | — | — | （代码审计固化） |

## 3. 现有 Retention 与配置

- `request_logs` 无任何 TTL/清理机制；正文随行数无限期保留在 SQLite。
- `logging:` 配置段仅有 `level` / `file`，**没有正文日志的 enable/expiry 控制**。
- DB `request_body`/`error_message` 均为 `TEXT`，无长度上限。

## 4. 错误文本路径明细（fact 9）

| 路径 | raw upstream error 文本去向 |
|---|---|
| openai 非流式/流式 4xx/5xx | `extractErrorMessage(respBody)` → 仅返回给调用客户端（writeOpenAIError）+ **fallback 分支 `log.Printf` 回显进 runtime log（KNOWN-VULN，测试 G 证实）**；不进 DB |
| openai tool-loop 重试失败 | break 后仍走 LogRequest（statusCode 记 4xx/5xx），ErrorMessage 仍为 "" |
| gemini proxy 传输错误 | `err.Error()`（url.Error 文本，含 upstream URL——P1-03C3 后无 key）→ **DB ErrorMessage 持久化** |
| gemini proxy 上游 4xx/5xx 响应 | 原样转发给客户端；不解析、不落 DB |
| Admin Test/Fetch client | provider error 文本即时 JSON 返回（on-demand，非持久化）——出 P1-04 范围 |

~~**运行时日志的"不可信 upstream body 回显"只有一处**~~（**P1-04.1 复勘修正：此结论错误**）：
P1-04 终验 review 发现 provider 层还存在正文 runtime log 通道——`openai_compat.go`/`ollama.go` 在
`DEBUG=1` 时输出完整 request body 与 response body（含完整 URL），`openai_compat.go` FetchModels 与
`vllm.go` ListModels 甚至无条件输出 response body。该通道无限期、非 bounded、非 expiry，
完全绕过 request_body_capture 的 memory-only 语义，是 Final Gate 0-canary 的覆盖缺口
（Gate 未在 DEBUG=1 下运行）。**已在 P1-04.1 全部根除**（provider 层日志仅剩 provider/model/
status/bytes metadata），并以 `internal/providers/p1_041_debug_log_gate_test.go`
（DEBUG=1 canary 双端 + 静态 tripwire）防回归。

**不可信文本持久化只有一处**：gemini proxy 传输错误的 `err.Error()` → DB ErrorMessage
（P1-04B 起改为 bounded ErrorCode）。

## 5. Target P1-04 行为（对照）

| 项 | 现状 | P1-04B/C/D 目标 |
|---|---|---|
| request_body / error_message 持久化 | 正文全量入库（1/2/3） | **新写恒为空**（legacy 列保留，json:"-"，注释 LEGACY PRIVACY MIGRATION FIELD） |
| Log API | `LogRequest(..., errMsg string, requestBody string, ...)` footgun | 结构化 `RequestRecord`（metadata-only），调用点无 body/error 可传 |
| Gemini stream 元数据缺口 | 无 RequestLog | 补 metadata-only 记录（RequestID/Provider/ErrorCode 等） |
| Request ID | 无（writeOpenAIError 另造随机 id） | 服务器 crypto/rand ≥128-bit，全链一致；响应 `X-Request-ID` == DB `RequestLog.RequestID` |
| ErrorMessage | 传输错误原文 | bounded `ErrorCode`（UPSTREAM_NETWORK_ERROR / UPSTREAM_AUTH_ERROR / UPSTREAM_RATE_LIMIT / UPSTREAM_4XX / UPSTREAM_5XX / INVALID_REQUEST / INTERNAL_ERROR） |
| Dashboard/Client Detail | 全量正文进 HTML/JS、ErrorMessage 原样渲染 | 全部移除；展示 RequestID/Provider/ErrorCode；无 `showRequestBody` 注入点 |
| WS | presence bool | 保持无正文；删除 `request_body` 字段 |
| 临时诊断正文 | 无 | MEMORY-ONLY bounded store，显式 opt-in，≤24h 硬过期（P1-04C） |
| legacy 正文存量 | 无清理路径 | startup preflight fail-closed + `-scrub-request-log-content`（P1-04D） |

## 6. 测试清单（P1-04A，全部 PASS）

| 测试 | 标记 | 固化内容 |
|---|---|---|
| TestP104A_OpenAI_NonStream_PersistsFullBody | KNOWN-VULN | A |
| TestP104A_OpenAI_Stream_PersistsFullBody | KNOWN-VULN | B |
| TestP104A_Gemini_Native_PersistsCappedBody | KNOWN-VULN | C + cap 语义 |
| TestP104A_Gemini_Stream_NoRequestLogAtAll | CURRENT | 4（无行事实） |
| TestP104A_RequestLog_JSON_SerializesBodyAndError | KNOWN-VULN | D |
| TestP104A_DashboardHTML_RendersFullBody | KNOWN-VULN | E |
| TestP104A_ClientDetail_RendersRawErrorMessage | KNOWN-VULN | F |
| TestP104A_RuntimeLog_UpstreamErrorEchoed | KNOWN-VULN | G（runtime log 回显；同时固化 openai 错误路径 DB error_message 为空） |

P1-04B 完成时上述 KNOWN-VULN 必须全部发生红→绿转换并改写为 `[SEC-003 FIXED]` 安全回归，禁止删除。
