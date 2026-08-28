# V1 范围冻结（scope-v1）

**冻结日期：** 2026-08-28
**依据：** 《轻量安全LLM_API_Gateway_完整执行方案》v1.0 + `docs/baseline-audit.md` 审计结论
**效力：** 合入 develop 后生效。后续任何 PR 不得无审批扩展 Won't 项；SEC 项未全部关闭前，Production Gate 一票否决。

---

## 1. Production Blocking 安全项（SEC Register）

> 规则：**任意一项未关闭 ⇒ Production Gate = FAIL，禁止公网发布。** 与其他功能完成度无关，不接受"先发布再修"。

| ID | 状态 | 描述 | 审计证据 | 关闭标准 | 承接任务 |
|---|---|---|---|---|---|
| SEC-001 | 🔴 OPEN | Admin 认证可绕过：会话 Cookie 值为静态 `"authenticated"`，服务端仅检查存在性 | baseline-audit §1.3 | 服务端会话（随机 ID + 有效期校验）或签名/加密 Cookie；Cookie 内容 ≠ 权限；有吊销能力 | P1-01/02（重建） |
| SEC-002 | 🔴 OPEN | Provider Key 明文存储（SQLite `backend_api_key` + config.yaml） | baseline-audit §1.2 | AEAD（AES-256-GCM 或 XChaCha20-Poly1305）加密落库，主密钥来自环境变量/secret 文件；库内仅 ciphertext+nonce+key_id | P1-03 |
| SEC-003 | 🔴 OPEN | 完整 Prompt 默认持久化到 `request_logs.request_body` | baseline-audit §1.9 | 默认仅记录元数据（request_id/client/model/tokens/latency/status/error）；正文日志默认 OFF、需显式临时开启、有过期时间 | P1-04 |
| SEC-004 | 🔴 OPEN | CSRF 防护无效（静态假 token，无校验） | baseline-audit §1.4 | 真实随机 token + 服务端校验，或等效 same-origin 严格校验；覆盖全部管理写操作 | P1-02 |
| SEC-005 | 🟠 P0 处理中 | Secret 进入 Git 历史（上游作者的 config.yaml：session_secret、prometheus 密码） | baseline-audit §4-1 | config.yaml 移出跟踪 + .gitignore（P0-04）；跟踪文件 secret 扫描进 CI（P0-05）；**任何复用该配置的部署视为凭证已泄漏，上线前必须重新生成**；历史清洗（filter-repo）作为独立任务另行评估 | P0-04/P0-05 + 历史清洗（backlog） |

**当前部署状态声明：** 本网关尚未在任何服务器部署，无真实流量、无属于运营者的真实凭证入库。入库凭证属于上游作者实例，按"已泄漏"原则处理（见 SEC-005 关闭标准）。在 SEC-001~005 全部关闭前，**禁止在公网环境运行任何实例**，开发实例仅允许绑定 loopback。

---

## 2. V1 MUST（发布必需）

1. **网关核心**：Client CRUD、Bearer 鉴权、Provider 路由（OpenAI 兼容 + Anthropic + Gemini 原生 + 本地模型）、流式转发
2. **管理面安全**：重建的认证/会话/CSRF（SEC-001/004）、登录防爆破、Admin 仅 loopback/隧道
3. **密钥安全**：Provider Key AEAD 静态加密 + 主密钥管理（SEC-002）、Client Key 仅哈希存储（已具备，补审计事件）
4. **隐私默认**：Prompt/Response 正文默认不落盘、日志 secret 遮盖（SEC-003）、不可变管理审计事件
5. **监听面**：API / Admin / Metrics 独立绑定，生产默认 Admin/Metrics 仅 loopback（原 P1-01，与 P1-01 Admin 重建绑定执行）
6. **备份恢复**：一致性在线快照、manifest+SHA-256、加密归档、保留策略、恢复预检与演练（P2）
7. **安全阀门**：Guard 独立进程、fail-closed、限时旁路（P3/P4）
8. **主机边界**：Linux VPS 为生产验收平台——systemd / Caddy / ufw / 非 root / loopback Admin（P6）；Windows 仅开发调试
9. **可证明性**：核心回归、绕过、Secret 泄漏、备份一致性、灾难恢复全部有可重复测试（P7）
10. **运维**：版本标识、健康检查、升级先快照、轮换、事件响应 runbook（P8）

## 3. V1 SHOULD

- RTK 上下文压缩（客户端侧可选，不入网关数据链）
- 客户端接入模板（OpenAI/Anthropic/环境变量三类）
- 恢复演练季度化、延迟基线报告（P7-10）
- 依赖漏洞扫描进 CI（secret 扫描 P0-05 先行）

## 4. V1 WON'T（非目标，与主方案 §3 一致）

- API 售卖、支付、余额、计费商城
- 企业组织 / 复杂 RBAC / SSO 平台
- Redis / Kafka / PostgreSQL 强依赖
- 把特定 AI 客户端的工具权限策略写进网关核心
- 把 RTK 当安全产品

## 5. P1 执行顺序修订（覆盖主方案 §7 的 P1 内部顺序）

> 审计确认底座安全声明不实，P1 按"先止血后加固"重排。原编号在括号中保留以便对照。

| 新顺序 | 任务 | 原编号 | 说明 |
|---|---|---|---|
| 1 | Admin Authentication 重建 | 原 P1-02 主体 | 服务端会话或签名 Cookie，杜绝 Cookie=权限；**监听面分离（原 P1-01）随之落地：Admin/Metrics 仅 loopback** |
| 2 | Session / Cookie / CSRF | 原 P1-02 余项+P1-03 | rotation、过期、防爆破、真 CSRF |
| 3 | Provider Key AEAD 加密 | 原 P1-05 | 主密钥 env/secret 文件；库内 ciphertext+nonce+key_id |
| 4 | Prompt/Response 日志隐私重构 | 原 P1-08 前半 | SEC-003；默认元数据、正文 opt-in 临时开 |
| 5 | Client Key 生命周期 | 原 P1-04 | 补审计事件、吊销原因、级联清理 |
| 6 | Rate Limit / Quota | 原 P1-06 | 补安全默认与超额错误码契约 |
| 7 | Request validation | 原 P1-07 | 协议/体积/深度校验 |
| 8 | Audit logging | 原 P1-08 后半 | 不可变管理审计事件 |

**对后续 AI 执行者的强制提示：** 不要基于 README 假设 Provider Key 加密、会话安全、CSRF 已存在——以 `docs/baseline-audit.md` 为唯一事实来源，一切从代码出发。

## 6. P0 完成门（本阶段）

见 `docs/superpowers/specs/2026-08-28-secure-gateway-p0-design.md` §5。P0-06 合入后打 tag `secure-gateway-p0` 并**暂停等验收**，不进入 P1。
