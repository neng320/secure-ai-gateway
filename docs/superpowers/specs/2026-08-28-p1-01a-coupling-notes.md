# P1-01A 产出：Admin 认证耦合点清单（供 P1-01B~G 使用）

**日期：** 2026-08-28
**来源：** task/P1-01A-auth-characterization（characterization tests + 代码走读）
**基线：** tag `secure-gateway-p0`
**测试文件：** `internal/handlers/admin_auth_characterization_test.go`（14 用例，[NORMAL]×8 / [KNOWN-VULN]×6）

---

## 1. 测试与 SEC 项的映射（P1-01B~D 完成时必须反转的断言）

| 测试 | 固化的现状 | 对应 SEC | 重构后应变为 |
|---|---|---|---|
| `TestAuthChar_VULN_SessionValueIsStaticLiteral` | Cookie 值 = 静态 `"authenticated"`，SessionSecret 不参与 | SEC-001 | 每次登录生成随机 session ID；不同实例/密码值不同 |
| `TestSEC001_VULN_ForgedCookieValue_GrantsAdminAccess` | 任意非空 Cookie → 200（/admin/clients） | SEC-001 | 302 → /admin/login |
| `TestSEC001_VULN_ForgedCookie_AccessStatsAPI` | 伪造 Cookie → 200（/admin/stats/api JSON 泄露面） | SEC-001 | 302/401 |
| `TestSEC001_VULN_ExpiredCookieAttribute_StillAccepted` | 过期 72h 的 Cookie 仍放行（服务端从不校验） | SEC-001 | 拒绝 |
| `TestAuthChar_VULN_Logout_DoesNotRevokeServerSide` | 登出仅清浏览器 Cookie，无服务端吊销 | SEC-001 | 登出吊销服务端会话 |
| `TestSEC004_VULN_LoginIgnoresCSRFToken` | 登录完全不做 CSRF 校验（缺/伪造 token 均放行） | SEC-004 | 校验失败 → 403 |

保持不变的 [NORMAL] 断言（回归底线）：登录成功 302→dashboard、Cookie HttpOnly+SameSite=Strict+24h、错误凭据 401、无/空 Cookie 302→login、setup 开关行为、setup 后新凭据可登录。

## 2. 代码耦合点清单（重构时的接触面）

### 2.1 `internal/handlers/admin.go`

| 位置 | 现状 | P1-01 动作 |
|---|---|---|
| `RequireAuth`（L126-143） | 仅检查 Cookie 存在+非空 | **重写为服务端会话校验**；签名/查找/过期判断都在这里 |
| `HandleLogin`（L148-175） | bcrypt 校验正确；签发静态 Cookie | 保留 bcrypt；改为创建服务端会话 + 随机 ID；**加登录防爆破**（P1-02） |
| `HandleLogout`（L177-188） | 仅下发清空 Cookie | 增加服务端吊销 |
| Cookie 名 `"admin_session"` | 硬编码 3 处（login/logout/RequireAuth） | 收敛为单一常量 |
| `NewAdminHandler`（L64-90） | `gob.Register(time.Time{})` —— 疑似旧版服务端会话残留 | P1-01B 落地会话存储后删除 |
| `ShowLogin`（L144-149） | `CSRFToken: "login-csrf-token"` 静态 | P1-02 接管（本阶段不动） |
| 管理写操作路由组（L110-122） | 无 CSRF 校验 | P1-02 接管 |

### 2.2 `internal/models/models.go`

- `AdminSession`（L74-79）：**死代码**——未被 AutoMigrate、无任何引用。P1-01B 二选一：复活为会话表（推荐，加 `TokenHash`/`RevokedAt`/`LastSeenAt` 字段）或删除。

### 2.3 `cmd/server/main.go`

- L139-158：admin/setup 路由挂载顺序与条件；setup 关闭判断 `IsSetupRequired()` 依赖 `cfg.Admin.PasswordHash == "__SETUP_REQUIRED__"`。
- 全部路由单端口单 listener（`cfg.Server.Host:Port`）——P1-01F 拆分 API/Admin/Metrics 绑定地址时的改造面。
- `logger.Init(false)` 无文件输出；审计事件落地时（P1-08）需要新通道。

### 2.4 `internal/config/config.go`

- `AdminConfig{Username, PasswordHash, SessionSecret}`：SessionSecret 已生成但无人消费——P1-01B 若用签名 Cookie 方案则启用之；若用服务端会话表则仍需它防篡改（建议保留并消费）。
- `ResetAdminPassword` / `SaveConfig`：`-reset-password` 密码回显 stdout（审计 §4-7）——P1-08 一并处理。
- **配置无环境变量覆盖能力**：P1-03 主密钥注入（`MASTER_KEY`）前必须先给 config 加 env override 钩子。

### 2.5 `internal/handlers/setup.go`

- L81：`config.SaveConfig(h.cfg, "config.yaml")` **硬编码相对路径**，忽略 `-config` 参数——修复窗口：P1-01B（会话存储落地时顺手，属 setup 域）或独立微任务。
- setup 完成即强制开启 Prometheus 并打印密码到 stdout（L77-79）——同上记录。

### 2.6 相邻面（本阶段只记录，不改动）

| 面 | 现状 | 归属 |
|---|---|---|
| `/metrics` Basic Auth | 用户名/密码**非常量时间**比较（metrics.go:118-121） | P1-01F 一起改（监听面隔离时顺带） |
| `/admin/ws` WebSocket | 继承 RequireAuth（当前可伪造） | P1-01D 自动修复，需补一条 WS 升级场景测试 |
| 管理模板表单 | 均带静态 `csrf_token` 隐藏域 | P1-02 接管（真 token + 全写操作校验） |
| `middleware.Timeout(60s)` | 包裹受保护 admin 组 | 无需动，但注意会话存储查询也要在此超时内 |

## 3. P1-01B~G 建议的接口草案（P1-01B 实现时可修订）

```go
// internal/auth/session.go（建议新包，避免 handlers 膨胀）
type Store interface {
    Create(ctx context.Context, tokenHash []byte, expiresAt time.Time) error
    Get(ctx context.Context, tokenHash []byte) (Session, error) // ErrNotFound/ErrExpired
    Revoke(ctx context.Context, tokenHash []byte) error
    RevokeAllForUser(ctx context.Context, username string) error
}
// token 生成：crypto/rand 32B；存储前 SHA-256（与 Client Key 同策略，防库泄漏直接拿到可用会话）
// Cookie：HttpOnly + Secure(按 HTTPS 配置) + SameSite=Lax/Strict + Path=/
// 过期：滑动或固定 24h，服务端权威；登出吊销；登录 rotation（新 ID）
```

## 4. 攻击回归底线（P1-01G 验收）

1. 伪造/过期/登出后的 Cookie → 一律拒绝（本文件 [KNOWN-VULN] 用例反转）。
2. 无 Cookie / 空 Cookie → 302 login（不变）。
3. 并发会话与吊销：改密/登出全部会话（可选 stretch）。
4. 会话固定：登录前后 Cookie 值必须变化（rotation 断言）。
