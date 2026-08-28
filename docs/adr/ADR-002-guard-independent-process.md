# ADR-002: Security Guard 作为独立进程（fail-closed）

- 状态：Accepted
- 日期：2026-08-28
- 关联：主方案 P3/P4；scope-v1.md SEC Register

## 背景

公网请求必须在进入核心网关前完成内容安全审查（Secret 检测、PII 策略、Prompt Injection 检测）。扫描器涉及模型加载与第三方服务（如 Trylon /safeguard），生命周期与稳定性不同于网关本体。

## 决策

1. Guard 为**独立二进制**（`cmd/guard/`），默认仅监听 loopback/私网。
2. Guard 对外保持原协议（透明反代，支持 SSE 流式），安全判定结果通过内部 header/metadata 传递。
3. Gateway API 模式增加 `INTERNAL_GATEWAY_TOKEN` 校验（P4-01），外部请求不能绕过 Guard 直连 Gateway；Edge 只把 API 路由指向 Guard。
4. 扫描器以 adapter 接入（P3-06），可替换为 mock 或其他实现；**扫描器超时/异常一律 fail-closed**（P3-09），仅允许管理员开启限时、审计、自动过期的 emergency bypass。

## 备选方案

1. **网关内置中间件做扫描**：进程内耦合，扫描器崩溃 = 网关崩溃；替换扫描器需改核心代码；违背"核心不依赖具体扫描器 SDK"要求。
2. **旁路异步扫描（只告警不阻断）**：无法满足 Secret=block 的安全边界（V1 §2），Secret 泄漏后果不可逆。

## 后果

- 正面：扫描器可独立升级/重启/替换；故障域隔离；协议解耦使 Gateway 保持轻量。
- 负面：增加一跳延迟（P7-10 建立基线，超阈值不发布）；部署单元多一个（P6 提供 systemd 单元）。
