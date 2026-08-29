package providers

// P1-04.2.1 · Privacy Static Gate（AST 版）——修复 P1-04.1 静态 tripwire 的 false-green
//
// 事故：旧实现用 filepath.Glob("../internal/<dir>/*.go")，而 go test 的 cwd 是
// package 源码目录（internal/providers），路径解析到 internal/internal/...（不存在），
// 扫描文件数=0、循环零次、静默 PASS——与 P1-03B delivery illusion 同类。
//
// 本 Gate：
//   1. runtime.Caller(0) → 向上找 go.mod → 显式 repo root（绝不 cwd 猜测）
//   2. 扫描 internal/{providers,services,handlers} 生产 *.go（排除 _test.go）
//   3. coverage sentinel：扫描数 > 0 且必须包含 7 个关键文件，否则 TEST FAIL
//   4. go/parser + go/ast 识别 log.Printf/Println/Print/Fatalf/Errorf 与
//      fmt.Printf/Fprintln/Print/Fprintf(stdout|stderr) 的 CallExpr，
//      检查参数是否引用敏感值（完整 URL / proxy 凭据 / Header / APIKey /
//      body / respBody 等）——支持多行 CallExpr（line-grep 的绕过面已封死）
//   5. 合成 fixture 自测：三个违规形态必须 FAIL，安全 metadata 必须 PASS
//
// runtime canary（p1_041/p1_042 各用例）仍是主证明；本 Gate 是第二层。

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

// findModuleRoot: 从当前测试文件位置向上寻找 go.mod（绝不依赖进程 cwd）
func findModuleRoot(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller(0) failed")
	}
	dir := filepath.Dir(thisFile)
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("go.mod not found — cannot locate module root")
		}
		dir = parent
	}
}

// exprSrc: 把 AST 表达式渲染回源码文本（用于精确判断）
func exprSrc(fset *token.FileSet, expr ast.Expr) string {
	var b strings.Builder
	if err := printer.Fprint(&b, fset, expr); err != nil {
		return ""
	}
	return b.String()
}

var stringBodyRe = regexp.MustCompile(`^string\((body|respBody|rawBody|u)\)$`)

// sensitiveSelector: 出现在日志参数中即违规的 selector 字段
func sensitiveSelector(name string) bool {
	switch name {
	case "Header", "Authorization", "APIKey", "BaseURL",
		"RequestBody", "ErrorMessage", "BackendAPIKey":
		return true
	}
	return false
}

// sensitiveValueIdent: 作为【值】直接透传即违规的标识符
// （len(body)/len(respBody) 属字节数 metadata，由调用侧显式放行）
func sensitiveValueIdent(name string) bool {
	switch name {
	case "body", "respBody", "rawBody", "url", "requestURL":
		return true
	}
	return false
}

// scanLogSinks: 解析单个 Go 源文件，返回日志 sink 违规描述（空 = 干净）
func scanLogSinks(t *testing.T, fset *token.FileSet, filename string, src any) []string {
	t.Helper()
	file, err := parser.ParseFile(fset, filename, src, 0)
	if err != nil {
		t.Fatalf("static gate: parse %s: %v", filename, err)
	}
	var findings []string
	add := func(line int, kind, detail string) {
		findings = append(findings, fmt.Sprintf("%s:%d %s: %s", filename, line, kind, detail))
	}

	ast.Inspect(file, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		pkgIdent, _ := sel.X.(*ast.Ident)
		if pkgIdent == nil {
			return true
		}
		fn := sel.Sel.Name
		isLog := pkgIdent.Name == "log" &&
			(fn == "Printf" || fn == "Println" || fn == "Print" || fn == "Fatalf" || fn == "Fatal" || fn == "Errorf")
		if !isLog && pkgIdent.Name == "fmt" {
			if fn == "Printf" || fn == "Println" || fn == "Print" {
				isLog = true
			}
			if fn == "Fprintf" && len(call.Args) > 0 {
				t0 := exprSrc(fset, call.Args[0])
				if strings.Contains(t0, "Stdout") || strings.Contains(t0, "Stderr") {
					isLog = true
				}
			}
		}
		if !isLog {
			return true
		}

		line := fset.Position(call.Pos()).Line
		for _, arg := range call.Args[skipFormatString(call):] {
			// len(...) = 字节数 metadata，显式放行
			if isLenCall(arg) {
				continue
			}
			src := exprSrc(fset, arg)

			if src == "url" || strings.HasSuffix(src, ".URL") {
				add(line, "full-URL value", src)
				continue
			}
			if strings.Contains(src, "proxyURL") ||
				strings.Contains(src, `Getenv("HTTP_PROXY`) ||
				strings.Contains(src, `Getenv("HTTPS_PROXY`) {
				add(line, "proxy credential value", src)
				continue
			}
			flagged := false
			for _, bad := range []string{".Header", ".Authorization", ".APIKey", ".BaseURL",
				".RequestBody", ".ErrorMessage", ".BackendAPIKey"} {
				if strings.Contains(src, bad) {
					add(line, "sensitive field", src)
					flagged = true
					break
				}
			}
			if flagged {
				continue
			}
			if stringBodyRe.MatchString(src) {
				add(line, "body via string()", src)
				continue
			}
			if sensitiveValueIdent(src) {
				add(line, "body/URL identifier passthrough", src)
			}
		}
		return true
	})
	return findings
}

// skipFormatString: 日志调用的第一个参数是格式串，跳过
func skipFormatString(call *ast.CallExpr) int {
	if len(call.Args) > 0 {
		if _, ok := call.Args[0].(*ast.BasicLit); ok {
			return 1
		}
	}
	return 0
}

func isLenCall(expr ast.Expr) bool {
	call, ok := expr.(*ast.CallExpr)
	if !ok {
		return false
	}
	ident, ok := call.Fun.(*ast.Ident)
	return ok && ident.Name == "len" && len(call.Args) == 1
}

// 仓库扫描 + coverage sentinel
func TestP10421_StaticGate_ScanProductionSources(t *testing.T) {
	root := findModuleRoot(t)
	dirs := []string{"providers", "services", "handlers"}

	scanned := map[string]bool{}
	totalFindings := []string{}
	scannedFiles := 0

	for _, d := range dirs {
		dirPath := filepath.Join(root, "internal", d)
		entries, err := os.ReadDir(dirPath)
		if err != nil {
			t.Fatalf("static gate: read %s: %v", dirPath, err)
		}
		for _, e := range entries {
			name := e.Name()
			if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
				continue
			}
			path := filepath.Join(dirPath, name)
			src, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			fset := token.NewFileSet()
			findings := scanLogSinks(t, fset, name, string(src))
			scanned[name] = true
			scannedFiles++
			totalFindings = append(totalFindings, findings...)
		}
	}

	// Coverage sentinel（P1-04.1 false-green 的根治）：必须真的扫到文件与关键文件
	t.Logf("PRODUCTION_FILES_SCANNED=%d", scannedFiles)
	if scannedFiles == 0 {
		t.Fatal("[gate delivery 失败] 静态扫描文件数为 0——覆盖幻觉")
	}
	required := []string{
		filepath.Join("providers", "openai_compat.go"),
		filepath.Join("providers", "vllm.go"),
		filepath.Join("services", "client.go"),
		filepath.Join("services", "gemini.go"),
		filepath.Join("handlers", "admin.go"),
		filepath.Join("handlers", "openai.go"),
		filepath.Join("handlers", "proxy.go"),
	}
	for _, rel := range required {
		base := filepath.Base(rel)
		if !scanned[base] {
			t.Fatalf("[gate delivery 失败] 预期文件未参与扫描: %s", rel)
		}
	}
	t.Logf("required-file coverage: %d/%d present", len(required), len(required))

	if len(totalFindings) > 0 {
		t.Fatalf("[安全回归失败] 生产源码存在 %d 个 runtime secret log sink:\n%s",
			len(totalFindings), strings.Join(totalFindings, "\n"))
	}
	t.Log("[SEC-003] 静态 AST Gate：生产源码无 body/URL/credential/header/proxy 日志 sink")
}

// 合成 fixture 自测：scanner 必须抓到三种违规形态、放行安全 metadata
func TestP10421_StaticGate_SyntheticFixtures(t *testing.T) {
	violations := []struct {
		name string
		src  string
	}{
		{"A: single-line header leak", "package p\nimport \"log\"\nfunc f() { httpReq := newReq(); log.Printf(\"headers=%v\", httpReq.Header) }\n"},
		{"B: multiline APIKey leak", "package p\nimport \"log\"\nfunc f(cfg *C) {\n\tlog.Printf(\n\t\t\"secret=%s\",\n\t\tcfg.APIKey,\n\t)\n}\n"},
		{"C: body via string()", "package p\nimport \"log\"\nfunc f(body []byte) {\n\tlog.Printf(\"body=%s\", string(body))\n}\n"},
		{"D: full URL value", "package p\nimport \"log\"\nfunc f(url string) {\n\tlog.Printf(\"GET %s\", url)\n}\n"},
		{"E: body identifier passthrough", "package p\nimport \"log\"\nfunc f(respBody []byte) {\n\tlog.Printf(\"resp=%s\", respBody)\n}\n"},
	}
	for _, tc := range violations {
		t.Run(tc.name, func(t *testing.T) {
			fset := token.NewFileSet()
			findings := scanLogSinks(t, fset, "fixture.go", tc.src)
			if len(findings) == 0 {
				t.Fatalf("[gate 失效] 合成违规未被检测: %s", tc.name)
			}
		})
	}

	safe := []struct {
		name string
		src  string
	}{
		{"safe: multiline metadata", "package p\nimport \"log\"\nfunc f(provider string, status, size int) {\n\tlog.Printf(\n\t\t\"provider=%s status=%d bytes=%d\",\n\t\tprovider, status, size,\n\t)\n}\n"},
		{"safe: len(body) byte count", "package p\nimport \"log\"\nfunc f(body []byte) {\n\tlog.Printf(\"bytes=%d\", len(body))\n}\n"},
		{"safe: URL.Path (path-only)", "package p\nimport \"log\"\nfunc f(r *R) {\n\tlog.Printf(\"rejected %s\", r.URL.Path)\n}\n"},
		{"safe: hash fragment", "package p\nimport \"log\"\nfunc f(apiKeyHash []byte) {\n\tlog.Printf(\"lookup (hash: %x)\", apiKeyHash[:8])\n}\n"},
	}
	for _, tc := range safe {
		t.Run(tc.name, func(t *testing.T) {
			fset := token.NewFileSet()
			findings := scanLogSinks(t, fset, "fixture.go", tc.src)
			if len(findings) != 0 {
				t.Fatalf("[误报] 安全 metadata 被判违规: %v", findings)
			}
		})
	}
}
