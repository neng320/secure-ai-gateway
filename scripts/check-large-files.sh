#!/usr/bin/env bash
# 大文件检查：任何 Git 跟踪文件超过 5MB 即失败（防止二进制/数据文件再次入库）
# 用法: bash scripts/check-large-files.sh   （退出码 0=通过, 1=超标）
set -uo pipefail

LIMIT_BYTES=$((5 * 1024 * 1024))
violations=0

while IFS= read -r f; do
  size=$(wc -c < "$f" 2>/dev/null || echo 0)
  if [ "$size" -gt "$LIMIT_BYTES" ]; then
    echo "❌ LARGE FILE: $f (${size} bytes > ${LIMIT_BYTES})"
    violations=1
  fi
done < <(git ls-files)

if [ "$violations" -eq 0 ]; then
  echo "✅ large-files: 所有跟踪文件均 < 5MB"
fi
exit "$violations"
