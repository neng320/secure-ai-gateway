# ADR-005: 废弃网关内建 TLS，由反向代理终止

- 状态：Accepted
- 日期：2026-08-29
- 关联：P1-01F（监听面隔离）、P1-01F.1（本决策的实施任务）、ADR-002/P6-03

## 背景

P1-01F 将单端口"全家桶"拆分为 Public API / Private Admin / Private Metrics 三个监听面。拆分前上游代码在 `server.https.enabled=true` 时调用 `ListenAndServeTLS`；拆分后的统一 `net.Listen + http.Server.Serve` 路径**没有** TLS 分支，导致 `server.https` 成为"看起来有效、实际无效"的静默回归——用户配置了 HTTPS 却以明文 HTTP 运行。

生产架构已确定为 `Internet HTTPS → Caddy → Gateway loopback HTTP`，网关自身不再需要 TLS 终止能力。

## 决策（方案 A：废弃，而非恢复三面 TLS）

1. 网关所有监听面只提供**明文 HTTP**，部署假设为 loopback / 私网，TLS 一律由反向代理（Caddy/Nginx）终止。
2. `server.https` **正式废弃**：
   - 字段保留（旧配置可解析，`enabled=false` 照常工作）；
   - `enabled=true` 时 **Load 拒绝启动**并给出明确错误与迁移说明——绝不静默以 HTTP 启动让用户误以为流量已加密。
3. ~~Admin 会话 Cookie 的 `Secure` 属性暂维持 `cfg.Server.HTTPS.Enabled`~~ **已于 P1-02A 解除耦合**：引入显式 `admin.cookie_secure` 配置（默认 false 支持 loopback/SSH 隧道 HTTP 开发；生产经 HTTPS 访问 Admin 面时显式置 true），登录/登出 Cookie 属性保持一致。
4. Swagger 与管理静态资源已归属私有 Admin 监听面（P1-01F），生产不经公网暴露。

## 备选方案

**方案 B：为三个 listener 各自恢复 TLS**——3 监听 × HTTP/TLS × 证书行为组合，复杂度显著增加；有 Caddy 终止后毫无必要；且内部 Admin/Metrics 本应仅 loopback，加 TLS 属于重复防护。已否决。

## 后果与迁移说明

- 现有配置迁移：从 `config.yaml` **删除 `server.https` 段**（或保持 `enabled: false`）；TLS 改在 Caddy 配置中终止（`reverse_proxy 127.0.0.1:8090`）。
- 若升级后启动报 "server.https is DEPRECATED and unsupported"，即为本次变更的预期行为，按错误信息迁移即可。
- 部署文档（P6-03）将以 `Caddy HTTPS → 127.0.0.1:8090 HTTP` 为唯一生产拓扑。
