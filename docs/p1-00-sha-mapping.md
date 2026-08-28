# P1-00 产物：Git 历史清洗 SHA 映射与执行记录

**执行日期：** 2026-08-28
**工具：** git-filter-repo（`--invert-paths --path config.yaml --path aigateway --path node_modules`）
**清洗前完整备份：** `H:/zcode workspace/backup/secure-ai-gateway-pre-P100-20260828.bundle`（18MB，`git clone` 该 bundle 可恢复旧历史）

## 1. 旧 SHA → 新 SHA 映射

| 引用 | 旧 SHA（清洗前，仅存于备份 bundle） | 新 SHA（清洗后） |
|---|---|---|
| 上游基线 commit | `2e192f174e97523b725d402fe7110273b95ef46d` | **不存在对应物**——该提交树中含 `config.yaml`，被重写；清洗后新历史根为 `c080ae4`（Initial commit 重写版）。原对象在 upstream 仓库仍可获取 |
| P0 阶段 tag（旧 `secure-gateway-p0`） | `6dc78a78` → tag 对象 `043862a` | 已删除（远程+本地），由 `secure-gateway-p0.1` 替代 |
| **P0 恢复点（新）`secure-gateway-p0.1`** | — | `20d7f16`（tag 对象）→ `d9ca403`（main 合并提交） |
| main | `6dc78a7` | `d9ca403` |
| develop（P1-01A 合并后头） | `69ab0ef` | `dc1077d` |
| P1-01A tests 提交 | `2c7eb66` | `893b610` |
| P1-01A 断言收紧提交 | `c3fd80c` | `da1c3d0` |
| P0-06 ADR 提交 | `54fa1a3` | `a86bf45` |
| P0-05 CI 提交 | `ea7c321` | （重写版，见 `git log --all --oneline | grep P0-05`） |
| 上游历史 tag v0.1.0~v0.6.1 | 旧对象 | 全部重写为无密钥树 |

## 2. 执行方式说明（与 scope 的偏差记录）

scope 建议在隔离 clone 中执行；实际在**本地工作仓**以 `--force` 执行（等价安全性，理由：执行前已生成完整 bundle 备份，且远程在 force push 前始终保留旧历史作为第二恢复源）。任务分支 P0-01~P0-06、P1-01A 均已合并后删除，缩小重写面。

## 3. 验证结论

- `git log --all -- config.yaml|aigateway|node_modules` → 全空
- 遍历全部 commit 树逐文件比对 → **0 残留**
- 清洗后 `go build ./...` + 全部测试通过；force push 后 main/develop CI 双绿
- 远程残留的旧 tag `secure-gateway-p0` 已显式删除（否则旧历史经 tag 保持可达）

## 4. 边界（不可声称的事项）

1. **上游仓库 DatanoiseTV/aigateway 的公开历史不受影响**，其中同样的 config.yaml 凭证依旧公开；若上游凭证真实，唯一处置是上游轮换。
2. GitHub 服务端可能按 SHA 缓存旧 commit 一段时间；彻底清除需联系 GitHub Support。
3. 本 fork 的旧 SHA 仅可从备份 bundle / GitHub 缓存恢复；bundle 含旧密钥，**不要推送到任何远端**。

## 5. ⚠️ 敏感备份处置（P1-00 验收补充，2026-08-29）

`H:/zcode workspace/backup/secure-ai-gateway-pre-P100-20260828.bundle` **包含被清洗掉的旧历史与旧凭证（session_secret、prometheus 密码、上游 config.yaml），属敏感备份**：

- **不得**推送到任何远端/网盘/仓库
- **必须**二选一：① 加密后离线保存（如 `gpg -c` 或 age 加密）② 在人工确认 `secure-gateway-p0.1` 可从当前历史恢复所需内容后，由**人工**删除
- **AI/自动化不得自行删除该 bundle**（含未来会话）
