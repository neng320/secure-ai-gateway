#!/usr/bin/env bash
# Secret 泄漏扫描：检查 Git 跟踪文件中的高置信 secret 模式 + 禁止跟踪 runtime 配置
# 用法: bash scripts/secret-scan.sh   （退出码 0=干净, 1=发现泄漏）
set -uo pipefail

patterns=(
  'AKIA[0-9A-Z]{16}'                          # AWS Access Key ID
  '-----BEGIN [A-Z ]*PRIVATE KEY-----'        # 私钥块
  'sk-ant-[A-Za-z0-9_-]{20,}'                 # Anthropic API Key
  'sk-proj-[A-Za-z0-9_-]{20,}'                # OpenAI Project Key
  'ghp_[A-Za-z0-9]{36}'                       # GitHub PAT (classic)
  'github_pat_[A-Za-z0-9_]{20,}'              # GitHub PAT (fine-grained)
  'xox[abprs]-[A-Za-z0-9-]{10,}'              # Slack token
  'AIza[0-9A-Za-z_-]{35}'                     # Google API Key
)

# runtime 配置/产物绝不允许被跟踪（与 docs/storage-layout.md 对应）
forbidden=(config.yaml config.local.yaml aigateway)
violations=0

for f in "${forbidden[@]}"; do
  if git ls-files --error-unmatch "$f" >/dev/null 2>&1; then
    echo "❌ FORBIDDEN TRACKED FILE: $f 不允许进入版本控制（见 docs/storage-layout.md）"
    violations=1
  fi
done

while IFS= read -r f; do
  for p in "${patterns[@]}"; do
    hits=$(grep -InE "$p" -- "$f" 2>/dev/null || true)
    if [ -n "$hits" ]; then
      echo "❌ SECRET LEAK in $f (pattern: $p):"
      echo "$hits" | sed 's/^/    /'
      violations=1
    fi
  done
done < <(git ls-files)

if [ "$violations" -eq 0 ]; then
  echo "✅ secret-scan: 未发现泄漏，无违规跟踪文件"
fi
exit "$violations"
