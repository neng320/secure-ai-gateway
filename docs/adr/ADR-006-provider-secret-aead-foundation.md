# ADR-006: Provider Secret AEAD 基础设施（Master Key + 版本化信封）

- 状态：Accepted
- 日期：2026-08-29
- 关联：P1-03A（密钥流特征化 docs/p1-03-key-flow-characterization.md）、SEC-002、ADR-001

## 背景

密钥流特征化确认两类 Provider Secret 当前全部明文：

- 全局：`providers.<name>.api_key` 明文存 config.yaml，Save 往返明文进明文出
- 每 Client：`Client.BackendAPIKey` 明文存 SQLite `backend_api_key` 列；编辑表单把明文 key 回填进 HTML value；Gemini provider 把 `?key=<secret>` 拼进 URL 并在错误路径泄漏进 error 字符串（可持久化到 `request_logs`）

本 ADR 只建立密码学基础设施；**不接入任何业务字段、不做数据迁移**。

## 决策

1. **算法**：AES-256-GCM（Go 标准库 `crypto/aes` + `cipher.NewGCM`），每次加密使用 `crypto/rand` 随机 96-bit nonce。不自行设计算法；不使用 ECB/CBC；不把 base64 当加密；不使用单向 hash 替代可恢复加密。
2. **信封格式**（版本化）：
   ```
   enc:v1:<key_id>:<base64url(nonce | ciphertext + GCM tag)>
   ```
   - `key_id` = SHA-256(masterKey) 前 8 字节 hex——仅作标识，稳定且可检测密钥不匹配
   - 解析严格：前缀/分段数/版本/key_id/base64/最小长度任一非法即拒绝，绝不 panic
3. **AAD**：Encrypt/Decrypt 必须显式传上下文字符串（未来如 `provider-config:<name>`、`client-backend:<client-id>`），参与 GCM 认证——密文不可跨上下文复制。
4. **Master Key 来源**（fail-closed，恰好其一）：
   - `AIGATEWAY_MASTER_KEY`：base64(32 字节随机)
   - `AIGATEWAY_MASTER_KEY_FILE`：含同格式的文件路径
   - 同时设置 → 拒绝；都不设置 → `ErrMasterKeyUnavailable`；base64/长度非法 → 拒绝
   - **禁止自动生成后静默保存**：提供显式 `GenerateMasterKey()`（内存返回），持久化由运维完成
5. **错误纪律**：所有错误不包含明文、密钥、完整密文；本包零日志输出。
6. **接口隔离**：业务层只依赖 `secrets.Cipher`（Encrypt/Decrypt/KeyID），不接触 AES/GCM 细节。

## 备选方案

1. **方案 B：三个 listener 各自原生 TLS 式地为每字段做独立加密栈** —— 复杂度无谓增长（同 ADR-005 逻辑：基础设施集中一处）。
2. **age/libsodium 外部工具**：引入外部依赖与子进程边界，V1 目标是轻量单二进制。
3. **仅 hash 不解密**：Provider Key 需要原文调用上游，不可行。

## 后果与边界

- 本阶段（P1-03B）完成后 **SEC-002 保持 OPEN**：`ProviderConfig.APIKey` 与 `Client.BackendAPIKey` 仍为明文，characterization 测试（P1-03A）继续 PASS。
- 后续迁移（P1-03C，需单独人工验收）必须：数据迁移脚本 + `UpdateClient` blank 语义显式化 + admin.go:1872 模板遮罩改造 + Gemini key 传输改 header + SaveConfig 明文回写路径改造（见特征化文档 §4 设计约束）。
- Master Key 丢失 = 密文不可恢复；runbook（P8）必须写明备份/轮换流程。Key 轮换用 key_id 识别旧信封，双 key 重加密窗口期实现。
- Master Key File 的文件权限强化（0600/属主）记录给 P6-02 执行，本阶段不因 Windows/WSL 权限差异扩范围。
