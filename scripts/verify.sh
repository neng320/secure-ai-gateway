#!/usr/bin/env bash
# DW-01 · Local Verification Contract
#
# 纪律：任何 Agent 在每次 commit 之前必须【单独执行】本脚本并确认退出码为 0。
# 任何一步失败立即非 0 退出；严禁用 grep/pipeline 过滤测试输出后以管道退出码
# 决定是否提交（退出码掩蔽事故的根治措施，见 docs/development-workflow.md §失败模式）。
#
# 用法: bash scripts/verify.sh
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

fail() {
  echo "❌ verify.sh FAILED: $1"
  exit 1
}

echo "==> [1/7] gofmt（仅检查 Git 跟踪且实际存在的 Go 文件）"
# 过滤已 staged 删除但尚未提交的文件（避免 gofmt 报 missing file）
tracked_go=""
for f in $(git ls-files '*.go'); do
  [ -f "$f" ] && tracked_go="$tracked_go $f"
done
unformatted=$(gofmt -l $tracked_go)
if [ -n "$unformatted" ]; then
  fail "以下文件需要 gofmt:
$unformatted"
fi

echo "==> [2/7] go vet ./..."
go vet ./...

echo "==> [3/7] go build ./...（CGO_ENABLED=1，与 CI 对齐）"
CGO_ENABLED=1 go build ./...

echo "==> [4/7] go test ./... -count=1（禁用 test cache，防安全 Gate 被缓存掩盖）"
CGO_ENABLED=1 go test ./... -count=1

echo "==> [5/7] secret scan"
bash scripts/secret-scan.sh

echo "==> [6/7] large file check"
bash scripts/check-large-files.sh

echo "==> [7/7] repo hygiene（运行时产物/临时文件绝不允许被跟踪）"
for pat in '*.provisioning' '*.migrating'; do
  if git ls-files -- "$pat" | grep -q .; then
    fail "tracked temp artifact matches $pat（candidate/迁移临时文件不得入库）"
  fi
done
for f in config.yaml config.local.yaml aigateway; do
  if git ls-files --error-unmatch "$f" >/dev/null 2>&1; then
    fail "forbidden tracked runtime file: $f（见 docs/storage-layout.md）"
  fi
done

echo "✅ verify.sh: 全部本地 Gate 通过（gofmt / vet / build / test -count=1 / secret scan / large files / hygiene）"
