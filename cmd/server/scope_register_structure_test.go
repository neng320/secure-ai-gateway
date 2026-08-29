package main

// P1-04.2 · SEC Register 文档结构 Gate
//
// 背景：P1-04.1 的 scope 更新曾把新旧两套 SEC-003 证据拼接在同一行（Markdown
// table 行畸形，同时存在两套关闭措辞）。本 Gate 固化结构不变量：
//   - 每个 SEC-0xx 恰好出现一行 table row
//   - SEC-003 的关闭措辞（closure phrase）恰好出现一次
//   - 各行均为合法 table 行（以 | 开头、以 | 结尾）

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestScopeRegister_Structure(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "docs", "scope-v1.md"))
	if err != nil {
		t.Fatal(err)
	}
	s := string(raw)

	for _, sid := range []string{"SEC-001", "SEC-002", "SEC-003", "SEC-004", "SEC-005"} {
		if n := strings.Count(s, "| "+sid+" |"); n != 1 {
			t.Fatalf("[文档结构失败] %s table row 应恰出现 1 次，实际 %d 次", sid, n)
		}
	}

	// SEC-003 行合法性与唯一措辞
	for _, line := range strings.Split(s, "\n") {
		if strings.HasPrefix(line, "| SEC-003 |") {
			if !strings.HasSuffix(strings.TrimSpace(line), "|") {
				t.Fatal("[文档结构失败] SEC-003 行不是合法 table 行（未以 | 结尾）")
			}
			if n := strings.Count(line, "Request logging defaults to metadata-only"); n != 1 {
				t.Fatalf("[文档结构失败] SEC-003 closure 措辞应恰出现 1 次，实际 %d（旧行拼接回归）", n)
			}
		}
	}

	if n := strings.Count(s, "Request logging defaults to metadata-only"); n != 1 {
		t.Fatalf("[文档结构失败] 全文 closure 措辞应恰 1 次，实际 %d", n)
	}
	t.Log("[SEC-003] scope register 结构 Gate 通过")
}
