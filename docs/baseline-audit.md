# 基线安全审计报告（baseline-audit）

**审计对象：** secure-ai-gateway @ 基线 `2e192f174e97523b725d402fe7110273b95ef46d`（上游 DatanoiseTV/aigateway main）
**审计日期：** 2026-08-28
**审计方法：** 逐文件阅读 27 个 Go 源文件中的全部安全相关代码 + 路由提取 + 配置文件核查。标注口径：✅ 已验证（读到实现代码） / ⚠️ 部分验证（结构存在、执行链未逐行核） / ❌ 缺失 / 📛 README 声明与代码不符。

---

## 0. 核心结论（TL;DR）

1. **🔴 CRITICAL：管理员认证可被完全绕过。** 会话 Cookie 的值就是字面量 `"authenticated"`，`RequireAuth` 只检查 Cookie 是否存在（admin.go:126-143、166-175）。任何人在公网发 `Cookie: admin_session=x` 即可获得全部管理功能（增删 Client、读取 Provider Key、读取完整请求日志）。`SessionSecret` 生成了但从未用于签名。
2. **🔴 CRITICAL：所有 Provider Key 明文存储。** SQLite `clients.backend_api_key`（models.go:18）与 config.yaml `providers.*.api_key`（config.go:32）均为明文。README 宣称 "Provider Key 静态加密" 📛 **与代码不符**。全库无任何 AEAD/加密代码。
3. **🔴 HIGH：完整 Prompt 默认入库。** 每次请求的完整请求体写入 `request_logs.request_body`（models.go:58；openai.go:443,633；proxy.go:87；gemini.go:192）。
4. **🔴 HIGH：CSRF 防护是假的。** 表单 token 是静态字符串 `"login-csrf-token"`（admin.go:146），无任何校验代码。
5. **🟠 MEDIUM：默认监听 `0.0.0.0:8090`，API / Admin / Setup / Metrics / Swagger / Static 全部同一端口**（main.go:118-178），与文档 P1-01/P1-02/P4-02 的要求全面冲突。

以下逐项给出证据与 V1 影响。

---

## 1. 安全功能逐项核对（对应方案 P0-02 第 1 条）

### 1.1 客户端 API Key 生命周期 — ✅ 已验证（本项质量较好）

| 子项 | 结论 | 证据 |
|---|---|---|
| Key 生成 | `prefix + uuid.New()`，UUIDv4 ≈ 122bit 熵，足够 | client.go:136-151 |
| 存储 | SHA-256 哈希，`uniqueIndex`，明文不落库 | models.go:11；client.go:157-160 |
| 比对 | 哈希后 DB 索引查询；辅助函数用 `subtle.ConstantTimeCompare` | client.go:56-72, 122-124 |
| 仅创建时显示一次 | ✅ `CreateClient` 返回明文 key，此后只有哈希 | client.go:26-54 |
| 重新签发 | ✅ `RegenerateAPIKey` | client.go:105-120 |
| 禁用/启用 | ✅ `IsActive` 开关（auth.go:73 拒绝禁用 client） | models.go:12 |
| 最后使用时间 | ✅ `LastSeen` 异步更新 | auth.go:80 |
| 注 | 哈希用 SHA-256 而非慢哈希；因 key 为高熵随机值可接受，不建议改 | — |

**缺口：** 无"吊销原因/审计事件"；`DeleteClient` 为硬删除且无级联清理 `request_logs`。

### 1.2 Provider Key 静态加密 — 📛 声明不实 + ❌ 缺失

- `Client.BackendAPIKey string` → SQLite 明文 varchar(500)（models.go:16-18）
- `ProviderConfig.APIKey` → config.yaml 明文（config.go:29-37）
- 全库 grep `aes|gcm|cipher|encrypt|nonce` 无任何加密实现；`x/crypto` 仅用于 bcrypt
- **无主密钥概念、无 key-id、无轮换能力**（详见第 2 节）

### 1.3 管理员认证与会话 — 🔴 见 TL;DR #1，细节：

| 子项 | 结论 | 证据 |
|---|---|---|
| 登录校验 | ✅ 用户名比对 + `bcrypt.CompareHashAndPassword` 正确 | admin.go:148-160 |
| 会话签发 | ❌ Cookie 值 = 静态 `"authenticated"`，24h 过期由浏览器侧执行 | admin.go:162-175 |
| 会话校验 | ❌ `RequireAuth` 仅检查 Cookie 存在且非空 → **可伪造** | admin.go:126-143 |
| 会话吊销 | ❌ 无服务端会话表；登出仅清浏览器 Cookie | admin.go:177-188 |
| `AdminSession` 模型 | **死代码**：定义了但未纳入 AutoMigrate、全库无引用 | models.go:74-79；main.go:239-243 |
| Session rotation | ❌ 登录后无新 session 标识 | — |
| Cookie 属性 | HttpOnly ✅ / SameSite=Strict ✅ / Secure 仅 HTTPS 时 ⚠️ | admin.go:166-171 |

### 1.4 CSRF — 🔴 见 TL;DR #4。所有管理写操作（创建/删除 Client、更新配置）均无有效 CSRF 防护，SameSite=Strict 是唯一实际屏障（自托管场景尚可，但不可依赖）。

### 1.5 管理登录防爆破 — ❌ 缺失（`HandleLogin` 无失败计数、无退避、无锁定；方案 P1-03 需从零建）。

### 1.6 限流 — ✅ 已验证（实现存在）

- 内存 token bucket（分钟/小时/天三级），per-client（ratelimit.go 全文件）
- **限制：** 重启即清零、仅单实例有效、无持久化——V1 单机可接受，需写入文档
- Client 级字段 `RateLimitMinute/Hour/Day`（models.go:35-37）✅

### 1.7 配额 — ⚠️ 部分验证

- 数据结构与默认值完整：client 字段 + config defaults（models.go:38-42；config.go:76-82）
- `QuotaInfo` 模型与统计服务存在；**token 级扣减执行链未逐行核对**（stats.go 383 行未全读）→ 不作为安全前提

### 1.8 模型白名单 — ⚠️ 部分验证

- 结构存在：`ProviderConfig.AllowedModels`（config.go:35）+ client 级 `BackendModels`（models.go:24）
- 管理端有 update-models 路由；**请求路径上的强制拦截点未逐行验证** → 不作为安全前提

### 1.9 日志与脱敏 — 🔴 见 TL;DR #3，附加发现：

- `auth.go:57` / `client.go:58,64`：日志输出 API Key 前 8 字符 → 低危泄漏（可关联但不可还原）
- `config.Logging.File` 字段**从未被使用**：zap 仅输出 stdout（main.go:79、logger.go 全文），配置项具有误导性
- 无脱敏中间件、无 secret pattern 遮盖 → P1-08 从零建

### 1.10 数据库 — ✅ 已验证

- SQLite via gorm + `mattn/go-sqlite3`（**CGO 依赖**，影响 CI 与交叉编译，P0-05 需配置）
- 默认路径 `./data/gateway.db`，目录 0755，连接池 100
- 启动即 `AutoMigrate(Client, RequestLog, DailyUsage)`（main.go:239-243）——**无迁移前备份**（P2-10 针对此）
- 未显式启用 WAL（默认 journal 模式），P2-02 在线快照需一并评估

### 1.11 Setup 向导 — ⚠️ 已验证，行为危险

- 密码未设时 `/setup` **无认证公开**（main.go:146-151），叠加默认 `0.0.0.0` 监听 → 部署瞬间可被抢注管理员
- setup.go:81 硬编码写 `"config.yaml"`，**忽略 `-config` 参数** → 多配置文件部署会写错文件
- 完成设置后强制启用 Prometheus 并把自动生成密码打印到 stdout（setup.go:77-79）

### 1.12 监听面 — ✅ 已验证：单端口 8090，默认 host `0.0.0.0`（config.go:202-204）；`-port` 可覆盖；HTTPS 可选。Admin 与 API 无法分离绑定 → P1-01 核心工作。

---

## 2. 加密密钥专项（对应方案 P0-02 第 2 条）

| 问题 | 答案 |
|---|---|
| 加密密钥来源 | **不存在。** 无主密钥、无 KMS、无环境变量注入（配置只读 YAML 文件，无 env override） |
| 算法 | 仅 bcrypt（admin 密码）+ SHA-256（client key 哈希）；Provider Key 无任何加密 |
| nonce/IV 管理 | 不适用（无对称加密实现） |
| 密钥轮换 | Client Key 可重签（唯一存在的轮换能力）；Provider Key 可更新但无 key-id/版本；无 master key 轮换流程 |
| 密钥泄漏面 | config.yaml **已被提交进 Git**：含 admin bcrypt hash、`session_secret`、prometheus 明文密码（见第 4 节） |

---

## 3. HTTP 路由与监听全清单（对应方案 P0-02 第 3 条）

监听：`cfg.Server.Host:Port`（默认 `0.0.0.0:8090`），全部路由同一 listener。

| 分组 | 路由 | 认证 |
|---|---|---|
| 系统根 | `/`（跳转） | 无 |
| 健康 | `/health`、`/health/live`、`/health/ready` | 无 |
| **Setup 向导** | `GET/POST /setup`（仅当密码未设时注册） | **无（危险）** |
| Admin 公开 | `/admin`、`GET/POST /admin/login`、`POST /admin/logout` | 无 |
| **Admin 受保护** | `/admin/dashboard`、`/admin/clients`、`/admin/clients/{id}`、`/admin/clients/{id}/delete|regenerate|toggle|test|fetch-models|update|update-models`、`/admin/stats`、`/admin/stats/api`、`/admin/server-tools`、`/admin/ws` | 仅 Cookie 存在性检查（可绕过） |
| API（需 Client Key） | `/v1/chat/completions`、`/v1/messages`、`/v1/messages/count_tokens`、`/chat/completions`、`/v1/models`、`/v1/models/{model}` | Bearer Client Key ✅ |
| API（Gemini 原生，需 Client Key） | `/models/{model}:generateContent`、`/models/{model}:streamGenerateContent`、`/models`、`/models/{model}` | Bearer Client Key ✅ |
| 指标 | `/metrics`（Basic Auth，非常量时间比较 metrics.go:118-121） | 弱 |
| 静态/Swagger | `/static/*`、`/swagger`、`/swagger/`、`/swagger/doc.json` | **无（信息泄露面）** |

中间件栈：Recovery → SecurityHeaders（✅ 安全响应头齐全 security.go:12-22）→ MaxRequestSize(10MB) ✅；API 组加 Auth + RateLimit；Admin 组加 60s Timeout。

---

## 4. 仓库卫生与工程基线问题

| # | 问题 | 处理计划 |
|---|---|---|
| 1 | `config.yaml`（真实运行配置）已提交：bcrypt hash、session_secret、prometheus 密码入库 | P0-04 移出跟踪；建议历史中视为已泄漏、上线前全部轮换 |
| 2 | 39MB 预编译二进制 `aigateway` 提交入库 | P0-04 移除跟踪 + .gitignore |
| 3 | `node_modules/` 提交入库 | 同上 |
| 4 | `go vet` 既有失败 ×2：`internal/services/tools.go:189,217`（`fmt.Sprintf("%s:%d")` 传给 net.Dial，IPv6 不兼容） | P0-05 前修复（最小格式修复） |
| 5 | **27 个 Go 文件零测试** | P1 起按 TDD 补；关键路径 characterization test 优先 |
| 6 | metrics 密码比较非常量时间（metrics.go:118-121） | P1-05 一并修 |
| 7 | `-reset-password` 将新密码回显 stdout（main.go:75） | P1-08 一并修 |

---

## 5. 未验证项清单（不得作为安全前提）

以下在本次审计中**未逐行核实**，后续任务不得直接引用为"已具备"：

1. Token 配额的实际扣减执行链（stats.go 383 行未全读）
2. 模型白名单在请求路径上的强制拦截点
3. 流式（SSE）转发路径的资源释放与错误处理（P4-06 时专项验证）
4. 各 Provider 实现（openai_compat/anthropic/gemini/ollama/azure/vllm 共 2000+ 行）的 header 透传是否泄漏内部信息
5. WebSocket `/admin/ws` 的认证（继承 RequireAuth 的可绕过问题，但未单独验证）

---

## 6. 对 P1+ 的直接影响

| V1 任务 | 本审计的加重/新增输入 |
|---|---|
| P1-01 监听面分离 | 默认 0.0.0.0 + 全路由单端口，需重排全部路由组 |
| P1-02 管理会话 | 不是"加固"而是"从零重建"：当前会话体系无服务端状态、可伪造 |
| P1-03 防爆破 | 从零建 |
| P1-04 Client Key | 现有实现质量好，主要补审计事件与级联清理 |
| P1-05 Provider Key 加密 | 从零建（含主密钥、AEAD、key-id）；metrics 比较一并修 |
| P1-08 日志脱敏 | 需先关停 RequestBody 入库默认行为（行为变更，注意兼容） |
| P2-02 SQLite 快照 | 确认 CGO 驱动 + 非 WAL 模式下的快照方案 |
| P0-04 目录规范 | 处理第 4 节 #1-3 |
| P0-05 CI | 先修 #4 vet 失败；CI 需 CGO 环境 |

---

*审计人：ZCode（AI）· 逐文件代码阅读 · 证据均给出 file:line，可复核。*
