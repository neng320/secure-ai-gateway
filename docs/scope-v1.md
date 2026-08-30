# V1 范围冻结（scope-v1）

**冻结日期：** 2026-08-28
**依据：** 《轻量安全LLM_API_Gateway_完整执行方案》v1.0 + `docs/baseline-audit.md` 审计结论
**效力：** 合入 develop 后生效。后续任何 PR 不得无审批扩展 Won't 项；SEC 项未全部关闭前，Production Gate 一票否决。

---

## 1. Production Blocking 安全项（SEC Register）

> 规则：**任意一项未关闭 ⇒ Production Gate = FAIL，禁止公网发布。** 与其他功能完成度无关，不接受"先发布再修"。

| ID | 状态 | 描述 | 审计证据 | 关闭标准 | 承接任务 |
|---|---|---|---|---|---|
| SEC-001 | ✅ **CLOSED**（2026-08-29） | Admin 认证可绕过：会话 Cookie 值为静态 `"authenticated"`，服务端仅检查存在性 | baseline-audit §1.3 | 服务端会话（随机 ID + 有效期校验）或签名/加密 Cookie；Cookie 内容 ≠ 权限；有吊销能力 | **已实现**：P1-01B(Session Store) + P1-01C(随机 256-bit 签发) + P1-01D(RequireAuth 服务端校验) + P1-01E(Logout 吊销)；证据：Auth Security Regression Gate @ develop `f34c8e4`（伪造/过期/吊销/改1字符全拒 + 合法对照 + HTML/JSON/WS 三面覆盖） |
| SEC-002 | ✅ **CLOSED**（2026-08-29）。**AEAD at-rest implementation verified. No operator legacy Provider Secret data existed, therefore real migration was N/A. Fresh-install Global + Client secret provisioning stores encrypted-only. Legacy plaintext states fail closed and migration path remains available for future upgrades.** 关闭链：P1-03A 特征化 → P1-03B/B.1 AES-256-GCM 基础（ADR-006）→ P1-03C0~C3+C2.1 迁移实现/Runtime-UI 切换/模拟 Gate（staging.1 基线）→ P1-03D0/D0.1 只读预检确认无运营者 legacy secret 存量（0 实例/0 DB/0 明文，Windows+WSL 全排查）→ Real Legacy Migration 判定 **N/A**（迁移引擎保留为未来旧实例升级能力）→ P1-03D1A `-set-provider-key` 安全 provisioning（key 不进 argv/TTY no-echo/candidate 原子写）→ P1-03D1B Fresh-Install Secret-at-Rest Gate（隔离 staging+canary：Global 经安全 CLI/Client 经 Admin 双 canary 全链路功能验证、YAML 无明文键、SQLite legacy 非空=0、全部落盘文件 raw scan canary 命中=0、错误/缺失 Master Key 启动拒绝、正确 key 重启成功）。证据 @ develop `d0a9828`，恢复点 tag `secure-gateway-p1-secret-at-rest` | Provider Key 明文存储（SQLite `backend_api_key` + config.yaml） | baseline-audit §1.2 + docs/p1-03-key-flow-characterization.md + docs/p1-03d-readiness.md | 已满足：AEAD 加密落库（AAD 领域隔离）、主密钥 ENV/FILE 恰一 fail-closed、fresh install 全程无明文落盘、明文/混合/损坏态 fail-closed 且迁移路径可用 | P1-03A~D1B ✅ |
| SEC-003 | ✅ **CLOSED**（2026-08-29，P1-04 + P1-04.1 + P1-04.2 + P1-04.2.1 + **P1-04.3 auth credential log closure**）。Request logging defaults to metadata-only. Prompt/request/response bodies and raw upstream errors are not persisted. Optional diagnostic request-body capture is explicit, bounded, memory-only and hard-expiring. Legacy persisted request content is rejected at startup and has an explicit offline scrub path. **证据链**：P1-04A 特征化（6 KNOWN-VULN 红转绿）→ P1-04B metadata-only（RequestRecord 恒空强制/RequestID 128-bit 全链一致/bounded ErrorCode/HTML+WS 正文移除）→ P1-04C MEMORY-ONLY 诊断捕获（≤24h/64KiB/1000 硬上限/真实 timer）→ P1-04D legacy fail-closed + 双确认不可逆 scrub（持有式独占：locking_mode=EXCLUSIVE 锁保持至 VACUUM/verify 后释放，WAL→DELETE 拍平+所有权保留属性测试）→ **P1-04.1**（provider DEBUG 正文 sink 6 处根除）→ **P1-04.2**（FetchModels URL+headers 含 Authorization Bearer Provider Key、vLLM URL/proxy 凭据值/url.Error、client.go key 前缀根除）→ **P1-04.2.1**（zero-file static tripwire false-green 修复：runtime.Caller+go.mod 显式 root、coverage sentinel、AST sink 检查）→ **P1-04.3**：removed reachable client-auth credential fragment logging from middleware（malformed authHeader[:20]/apiKey[:8]×2）and expanded the AST runtime-log gate from three hand-selected directories to all production runtime Go sources（internal/ 递归+cmd/server，RUNTIME_PRODUCTION_FILES_SCANNED=40，required 15/15），including middleware and cmd/server；credential 层规则（apiKey/authHeader/token/password/secret 标识符+SliceExpr 捕捉+hash 精确 allow）+ auth middleware DEBUG/Bearer/malformed/短 token canary 5 用例 + `secretlog:allow` 精确豁免机制（bootstrap 一次性凭证显示 3 处，带 reason 可审计）。→ **P1-04.4**：removed the final explicit bootstrap raw-password stdout exceptions（createDefaultConfig 不再生成/打印明文 Admin 密码，fresh install 走既有私有 /setup 流程；Prometheus bootstrap 仅提示 generated and saved to config，stdout 零材料；`secretlog:allow` 注释豁免机制整体废除——生产源码 marker 计数清零由 Gate 断言，synthetic fixture 证明带 marker 的密码打印仍 FAIL）。恢复点 tag `secure-gateway-p1-request-log-privacy.5`（.0~.4 保留）。 | 完整 Prompt 默认持久化到 `request_logs.request_body` | baseline-audit §1.9 + docs/p1-04-request-log-characterization.md | 已满足 | P1-04A~D + P1-04.1/04.2/04.2.1/04.3/04.4 ✅ |
| SEC-004 | ✅ **CLOSED**（2026-08-29，P1-02.2 同步受保护身份 + P1-02.3 Setup 配置提交原子性/candidate 模式/显式 config path） | CSRF 防护无效（静态假 token，无校验）；wsUpgrader.CheckOrigin 恒 true；登录无防爆破 | baseline-audit §1.4 | **已实现（P1-02A~D）**：① 受保护组 POST 强制会话绑定 HMAC CSRF（constant-time）；② login/setup pre-auth double-submit；③ 全部管理表单布线；④ WS Origin 严格同源（缺失 Origin 拒绝、不信任 X-Forwarded-*）；⑤ 登录防爆破（5 次失败锁 15min，429+Retry-After，username 维度不泄露存在性）。证据：P1-02 Security Gate（CSRF 全路由矩阵/跨会话拒绝/爆破 HTTP 层）@ develop | P1-02A~D ✅ |
| SEC-005 | ✅ **CLOSED (fork-side)**（2026-08-29） | Secret 进入 Git 历史（上游作者的 config.yaml：session_secret、prometheus 密码） | baseline-audit §4-1 | fork 侧：filter-repo 全历史清洗 + 重打恢复点 `secure-gateway-p0.1`（见 docs/p1-00-sha-mapping.md）。**边界：upstream 仓库公开历史与 GitHub 服务端缓存不在本仓库控制范围**；pre-P1-00 bundle 备份含旧 Secret，属敏感备份须加密离线保存或人工确认后删除 | P0-04/P0-05 + P1-00 ✅ |

**SEC Register 汇总状态（2026-08-29）：**

```text
SECURITY_REGISTER_001_005 = CLOSED
PRODUCTION_RELEASE_REVIEW = REQUIRED   ← 不因 Register 全 CLOSED 自动宣布 Production Gate PASS
MAIN_RELEASE_FROZEN=true               ← main 保持冻结，reconciliation 计划见 docs/main-develop-reconciliation.md
```

**当前部署状态声明：** 本网关尚未在任何服务器部署，无真实流量、无属于运营者的真实凭证入库。入库凭证属于上游作者实例，按"已泄漏"原则处理（见 SEC-005 关闭标准）。在 SEC-001~005 全部关闭前，**禁止在公网环境运行任何实例**，开发实例仅允许绑定 loopback。

### P1-05 Client Key Lifecycle 执行状态（2026-08-30）

```text
P1-05A 特征化 ✅（develop 870e584，PR #14）——零生产修改审计 + 10 个 characterization 用例
P1-05B lifecycle consistency foundation ✅（tag secure-gateway-p1-client-lifecycle-consistency）
  关闭：ROTATE-NOTFOUND / ORPHAN-DATA / TOGGLE-ERR-SWALLOW / METRICS-COMPARE /
        dead Auth cache / IN_FLIGHT_DELETE_LATE_WRITE（Delete 后 late-write orphan race）
P1-05C Permanent Revocation & Audit Foundation ✅（本分支；A–Z acceptance + static gates）
  完成：三态派生 lifecycle / terminal REVOKED / SQL NULL APIKeyHash /
        bounded reason / trusted actor / same-transaction AuditEvent /
        delete 后 audit 保留 / allowlisted settings update
P1-05 Client Key Lifecycle：✅ COMPLETE
  说明：AuditEvent 为 application append-only foundation；P1-08 负责数据库级
        append-only、tamper-evident chain、完整管理动作覆盖与 viewer。
```

SEC-001~005：本块不改变 Register 状态——**全部保持 CLOSED**。

### P1-06 Rate Limit / Quota 执行状态（2026-08-30）

```text
P1-06A Rate / Quota Characterization ✅（PR #17；merge a3f9008b）
  仅 tests/docs；固化三级 rate window、quota 未执行、DailyUsage lost update 等真实缺口。
P1-06B Rate / Quota Enforcement ✅（PR #18；merge 34b4b919）
  完成：60s/1h/24h 独立窗口、cold-cache 原子初始化、动态限额保留已消费量、
        stable rate/quota error contract、并发 reservation、原子 usage charge、
        OpenAI/Gemini MaxInput/MaxOutput gate、stream/non-stream 统一 reservation。
P1-06B.1 Route & Streaming Closure ✅（PR #19；correction commit 30264f4）
  关闭：显式 generative route matrix、/v1/messages 与 Gemini stream quota gate、
        bounded usageMetadata accounting、missing-metadata conservative charge、no double charge。
P1-06 overall：✅ COMPLETE
  说明：token 计数使用 conservative byte upper bound，不冒充精确 tokenizer；
        P1-07 继续负责更完整的 request-structure validation。
```

### P1-07 Request Validation 执行状态（2026-08-30）

```text
P1-07A Request Validation Characterization ✅（PR #20；merge dc2db17c）
  仅 tests/docs；固化 10 MiB body cap、JSON/media/schema 缺口与 upstream bypass 事实。
P1-07B Request Validation Enforcement ✅（本分支；PR #21）
  完成：Auth→Rate→Validation→Quota 顺序、一次 bounded body read/context 复用、
        stable 413/415 JSON errors、JSON depth 64、protocol minimums、
        model/token/collection bounds、invalid input upstream=0 canaries。
P1-07 overall：✅ COMPLETE
  P1-08 不在本任务范围内。
```

### P1-08 Audit Logging 执行状态（2026-08-30）

```text
P1-08A Audit Logging Characterization ✅（当前分支；tests/docs only）
  固化 P1-05C 六个 lifecycle action、同事务 rollback、无 FK 保留、
  application-only append-only 边界，以及登录/配置/诊断/离线操作的审计缺口。
P1-08B Audit Logging Enforcement ⛔ NOT STARTED
P1-08 overall：🟡 VERIFYING（不得视为 COMPLETE）
```

### Hardening Backlog（非阻塞，SEC-002 保持 CLOSED）

| ID | 描述 | 来源 | 状态 |
|---|---|---|---|
| P1-03D1A.1 | **Master-Key Coherence Hardening**：`-replace-provider-key` 覆盖既有 encrypted key 前，current envelope 必须能被当前 Master Key 验证/解密；若系统已有其他 encrypted secrets，新 provisioning 的 key_id 必须与现有 secret set 一致；wrong master key → 拒绝写 config（原文件 byte-for-byte 不变）。该问题不造成明文泄漏（SEC-002 关闭标准不受影响），属 Master-Key 一致性/可用性加固 | SEC-002 复验发现 | 📋 BACKLOG |

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
> P0 验收（2026-08-28）补充：新增 **P1-00**；安全工程强化项并入 P1-03/P7；供应链项并入 P8。

| 新顺序 | 任务 | 原编号 | 说明 |
|---|---|---|---|
| 0 | **P1-00 Repository History Sanitation** ✅ 已完成（2026-08-28，filter-repo 清洗 config.yaml/aigateway/node_modules 全历史，force push 全分支，重打 secure-gateway-p0.1 → main，bundle 备份存 H:/zcode workspace/backup/） | （P0 验收新增） | 本仓库是 Public Fork，历史中的上游 config.yaml（session_secret/prometheus 密码）仍可从旧 commit 取出。用 `git filter-repo` 清洗本 fork 历史 + force push；**注意：上游仓库的公开历史无法由本 fork 清除，若上游凭证真实，最终处置是上游轮换**。清洗后重新打 P0 恢复 tag（secure-gateway-p0.1）。历史清洗完成后才允许进入 P1-01 正式编码。 |
| 1 | Admin Authentication 重建 | 原 P1-02 主体 | 服务端会话或签名 Cookie，杜绝 Cookie=权限；**监听面分离（原 P1-01）随之落地：Admin/Metrics 仅 loopback** |
| 2 | Session / Cookie / CSRF | 原 P1-02 余项+P1-03 | rotation、过期、防爆破、真 CSRF |
| 3 | Provider Key AEAD 加密 | 原 P1-05 | 主密钥 env/secret 文件；库内 ciphertext+nonce+key_id |
| 4 | Prompt/Response 日志隐私重构 | 原 P1-08 前半 | SEC-003；默认元数据、正文 opt-in 临时开 |
| 5 | Client Key 生命周期 | 原 P1-04 | 补审计事件、吊销原因、级联清理 |
| 6 | Rate Limit / Quota | 原 P1-06 | 补安全默认与超额错误码契约 |
| 7 | Request validation | 原 P1-07 | 协议/体积/深度校验 |
| 8 | Audit logging | 原 P1-08 后半 | 不可变管理审计事件 |

### 安全工程强化（验收补充，随对应阶段落地）

- **P1-03 起**：`scripts/secret-scan.sh` 基础版继续保留；P7 前引入 **gitleaks 或 trufflehog**（历史扫描 + 通用熵检测，弥补正则无法覆盖 `session_secret`/`password` 类通用 Secret 的短板），与本仓库的 forbidden-file 检查叠加使用。
- **P8-01**：正式 release 采用 **signed tag**（GPG）+ artifact checksum，补供应链可信度（当前 `secure-gateway-p0` 为未签名 tag，开发期可接受）。

**对后续 AI 执行者的强制提示：** 不要基于 README 假设 Provider Key 加密、会话安全、CSRF 已存在——以 `docs/baseline-audit.md` 为唯一事实来源，一切从代码出发。

## 6. P0 完成门（本阶段）

见 `docs/superpowers/specs/2026-08-28-secure-gateway-p0-design.md` §5。P0-06 合入后打 tag `secure-gateway-p0` 并**暂停等验收**，不进入 P1。
