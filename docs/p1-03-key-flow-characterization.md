# P1-03A · Provider Key Flow Characterization（密钥流特征地图）

**日期：** 2026-08-29
**基线：** tag `secure-gateway-p1-admin-security.3` 之后的 develop（本任务 commit）
**性质：** 只审计 + 特征化测试（`internal/handlers/p1_03a_key_flow_test.go`，9 用例），**零生产代码改动**。
**Canary：** `P103A_CANARY_GLOBAL_PROVIDER_SECRET` / `P103A_CANARY_CLIENT_PROVIDER_SECRET` / `P103A_CANARY_GEMINI_PROVIDER_SECRET`（刻意非真实 Key 形态，防 scanner 误报）

---

## 1. Secret A：全局 Provider Key（`providers.<name>.api_key`，含 legacy `gemini.api_key`）

| 维度 | 事实（file:line 证据） |
|---|---|
| Source | 运营者写入 config.yaml；或首次启动自动生成的默认配置（无 key） |
| At-rest location | **明文** config.yaml `providers.<name>.api_key`（config.go:32 ProviderConfig.APIKey yaml tag） |
| Write path | 手工编辑 / Setup 不涉及；`config.SaveConfig`/`Save` 直接 yaml.Marshal 整个 cfg |
| Read path | `config.Load` → `cfg.Providers` → `providers.BuildRegistry(cfg)`（provider.go:158）为每个 provider 构造实例 |
| Runtime plaintext boundary | Registry 内 provider 实例持有明文 `cfg.APIKey`（如 openai_compat.go:201-203 用于 Authorization header） |
| Upstream sink | `Authorization: Bearer <key>`（openai 兼容系）；Gemini 系：URL query `?key=<key>`（gemini.go:58,89,199,215） |
| Log exposure | ⚠️ **Gemini URL 含 key**：`ChatCompletion`/`ChatCompletionStream` 构造的 URL 进入 `*url.Error`；`TestConnection`（gemini.go:202 `"Failed to connect: " + err.Error()`）同样。见 KNOWN-VULN 测试 `TestP103A_Gemini_URLContainsKey_InErrorPath` |
| UI exposure | 无直接 UI（全局 key 不经模板渲染）；Admin "settings" 无修改入口（当前仅 config 文件） |
| Error exposure | 见 Log exposure——错误串带完整 URL |
| Current tests | `TestP103A_GlobalKey_PlaintextInSavedYAML`、`TestP103A_GlobalKey_SaveRoundTrip_PlaintextOut`、`TestP103A_Gemini_URLContainsKey_InErrorPath`、`TestP103A_Gemini_TestConnection_EmptyKeyClearMessage` |
| Future migration contact point | ① config.go Load/Save（解密读 + 禁止明文回写）② BuildRegistry/buildProvider ③ gemini.go URL 构造改 header 传 key |

### 已固化行为（测试断言）

- [KNOWN-VULN: SEC-002] Save 后 YAML **可找到明文 canary**；Load 回读运行态为明文（往返明文进明文出）
- **设计硬约束**：只要运行态 cfg 持明文，`SaveConfig` 必然把明文写回磁盘（`TestP103A_GlobalKey_SaveRoundTrip_PlaintextOut`）→ AEAD 迁移必须改造"运行态字段 = 明文"这一前提，而非只改读入口
- Gemini TestConnection/FetchModels 使用**硬编码 googleapis URL**（不可注入 base URL），空 key 时明确返回 "API key not configured"

## 2. Secret B：每 Client Provider Key（`Client.BackendAPIKey`）

| 维度 | 事实（file:line 证据） |
|---|---|
| Source | Admin 表单 `backend_api_key`（admin.go:452 create / :524 update） |
| At-rest location | **明文** SQLite `clients.backend_api_key` varchar(500)（models.go:18，`json:"-"`） |
| Write path | CreateClient（:468 无条件赋值）；UpdateClient（:551 **无条件覆盖——blank = 清空**）；`RegenerateAPIKey` 不触碰 |
| Read path | `AuthMiddleware`（每请求 fresh 读取 client）→ `OpenAIHandler.resolveProvider`（openai.go:114-142） |
| Runtime plaintext boundary | resolveProvider：`client.BackendAPIKey != "" \|\| BackendBaseURL != ""` → BuildSingleProvider（明文 key 进 provider 实例）；`TestClientConnection`/`FetchClientModels`（admin.go:818,854）同样构造 |
| Upstream sink | 同 Secret A（Bearer header / Gemini query） |
| Log exposure | `json:"-"` 使 API JSON 不含（`TestP103A_ClientKey_NotInJSONMarshaling` 确认）；但 Template **HTML 回显**（见 UI exposure）；日志路径与 Secret A 的 Gemini URL 问题相同（client key 可进入 gemini URL） |
| UI exposure | ⚠️ **编辑表单明文回填**：admin.go:1872 `<input type="password" name="backend_api_key" value="{{...BackendAPIKey}}">`——type=password 只遮显示，HTML 源码含完整明文（`TestP103A_ClientKey_ReDisplayedInEditFormHTML`） |
| Error exposure | TestClientConnection（/admin/clients/{id}/test）返回 provider message；openai_compat TestConnection 错误串含 URL（BaseURL 无 key，风险低）；Gemini 同 Secret A |
| Current tests | `TestP103A_ClientKey_PlaintextInSQLite`、`TestP103A_KeyPrecedence_ClientKeyWins_ThenGlobalFallback`、`TestP103A_UpdateClient_BlankKeyClears`、`TestP103A_ClientKey_ReDisplayedInEditFormHTML`、`TestP103A_ClientKey_NotInJSONMarshaling` |
| Future migration contact point | ① models.Client.BackendAPIKey（字段改密文/新增列）② UpdateClient blank 语义（迁移后必须显式决定"blank=保留/清空"）③ admin.go:1872 模板回填（改遮罩）④ resolveProvider/TestConnection/FetchClientModels 解密点 ⑤ 迁移需 data migration（本批禁止） |

### 已固化行为（测试断言）

- **Key 优先级**（`TestP103A_KeyPrecedence_ClientKeyWins_ThenGlobalFallback`，本地 upstream 捕获 Authorization）：
  1. client key 非空 → **client key 胜出**
  2. client key 空 + BackendBaseURL 非空 → **回退全局 key**（openai.go:128-132）
  3. client key 与 BaseURL 均空 → **registry 全局 provider**（openai.go:141）
- **blank key 语义**：UpdateClient 无条件覆盖 → **blank = 清空**（`TestP103A_UpdateClient_BlankKeyClears`）。UI "保留"效果来自编辑表单 value 预填回传，非服务端语义。⚠️ 迁移设计注意：AEAD 后若模板改遮罩（不再回填），现有"提交即清空"语义会把 key 清掉——必须同步改造
- **已知事实（额外发现）**：service 层 `CreateClient` 不设置 `Backend` 字段（DB 默认 `gemini`）——此前未记录的隐患（测试已显式设置以绕开）

## 3. 日志/错误暴露面清单（代码走读）

| 位置 | 内容 | 风险 | 测试 |
|---|---|---|---|
| providers/gemini.go:58 | `?key=` 进入 ChatCompletion URL | *url.Error 时泄漏 | `TestP103A_Gemini_URLContainsKey_InErrorPath` ✅ |
| providers/gemini.go:89 | 同上（stream） | 同上 | 代码走读（与 :58 同构） |
| providers/gemini.go:202 | TestConnection `"Failed to connect: " + err.Error()`（URL 含 key） | UI/错误串泄漏（硬编码 googleapis，需真实网络错误触发） | 代码走读（不可注入，未自动化） |
| providers/gemini.go:216 | FetchModels 同 URL 模式 | 同上 | 代码走读 |
| handlers/proxy.go:84-87 | `errMsg = err.Error()` → LogRequest → `request_logs.error_message`（SQLite + Admin UI） | **Gemini URL key 可持久化进 DB** | 间接（依赖 Gemini URL 问题） |
| handlers/openai.go:386 | `extractErrorMessage(respBody)` 上游响应体入错误/日志 | 上游可控内容入库 | P1-04 范围 |
| internal/handlers/admin.go:1872 | 明文 key 回填 HTML | UI 源码泄漏 | `TestP103A_ClientKey_ReDisplayedInEditFormHTML` ✅ |
| openai_compat.go:409 | TestConnection `"Failed to connect: " + err.Error()`（URL 不含 key，key 在 header） | 低 | — |

## 4. P1-03B/C 设计约束（由本特征化固化的硬前提）

1. **不能只加密读入口**：运行态 cfg 字段为明文时 SaveConfig 必然明文回写——加密方案必须让"运行态持有的就是密文 envelope"，或彻底替换保存路径。
2. **blank key 语义必须显式迁移**：现 UI 依赖 value 回填保留 key；遮罩后需服务端"空 = 保留"语义。
3. **Gemini key 传输方式需一并改造**（URL query → `x-goog-api-key` header），否则加密后错误路径依旧泄 key。
4. **resolveProvider / TestConnection / FetchClientModels 是解密接触面**（三处构造 provider）。
5. `json:"-"` 已防 API JSON 泄露——迁移时保持。
6. 迁移阶段必须存在 data migration（加密存量行），**本批禁止执行**。
