# ADR-001: 以 DatanoiseTV/aigateway 为核心网关底座（Fork 增强）

- 状态：Accepted
- 日期：2026-08-28
- 关联：docs/baseline-audit.md、docs/scope-v1.md

## 背景

需要一个自托管、轻量、支持多 LLM Provider 的 API 网关，作为"Edge → Security Guard → Gateway → Providers"主链的核心。要求 per-client Key、配额、模型白名单、管理界面，且不引入重型依赖。

## 决策

Fork DatanoiseTV/aigateway（基线 `2e192f17`，MIT）作为底座，在其上做安全增强，而非从零自研。

理由（已逐行验证的加分项）：
- Client API Key 全链路正确：SHA-256 哈希存储、仅创建时显示、可重签、可禁用（client.go）
- 内置 per-client 限流（三级 token bucket）与配额模型
- 多 Provider 抽象已覆盖 OpenAI 兼容 / Anthropic / Gemini 原生 / Ollama / LM Studio / Azure / vLLM
- 依赖极轻：chi + gorm/sqlite + zap，单体二进制
- 安全响应头、请求体积上限、优雅停机等基础中间件齐备

## 已知代价（审计确认，不允许基于 README 假设）

- Admin 会话可伪造（SEC-001）、CSRF 无效（SEC-004）——P1-01/02 从零重建
- Provider Key 全部明文（SEC-002）——P1-03 从零实现 AEAD
- 完整 Prompt 默认入库（SEC-003）——P1-04 重构
- 零测试、CGO SQLite 依赖、上游可能停止维护（最近推送 2026-03）

## 备选方案

1. **从零自研**：可控性最高，但重复造轮子，无法在 V1 时间盒内达到 P2/P7 的验收深度。
2. **LiteLLM / one-api / new-api 等成熟项目**：功能更全但体积大、Python/PHP 栈与运维模型不符，且同样存在模型映射等可信问题。
3. **Higress / APISIX 等通用网关 + 插件**：过重，运维成本高。

## 后果

- 正面：以最小代价获得正确的 Key 管理骨架与多 Provider 路由，安全增强有清晰落点。
- 负面：承担上游同步成本；必须在 P1 重建三项核心安全能力后，README 声明才可信。
