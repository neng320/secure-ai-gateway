package middleware

// P1-04.3 · Runtime-Wide Secret Log Static Gate（SEC-003）
//
// 取代 P1-04.2.1 的三目录 allowlist 版本（该版本漏掉了 internal/middleware——
// 所有公网 API 认证入口所在，正是 credential sink 事故现场）。
//
// 扫描范围（card 规定）：
//   - internal/**/*.go 递归（排除 _test.go）
//   - cmd/server/*.go
//
// 规则（在 P1-04.2.1 基础上新增 credential 层）：
//   - 值透传标识符：apiKey / authHeader / authorizationHeader / token /
//     password / secret / body / respBody / rawBody / url / requestURL / proxyURL
//     —— SliceExpr（apiKey[:8]、authHeader[:20]）经标识符走查天然覆盖
//   - selector 字段：.Header / .Authorization / .APIKey / .BaseURL /
//     .RequestBody / .ErrorMessage / .BackendAPIKey / .Password / .Token / .Secret
//   - string(body...) 转换、proxy 环境变量值
//   - len(...) 字节计数、URL.Path（path-only）、apiKeyHash[:N]（哈希片段）
//     显式放行；P1-04.4 起注释型豁免机制整体废除（生产源码 marker 计数必须为 0）
//
// runtime canary（auth_canary_test.go 及 p1_041/p1_042 各用例）仍是主证明。

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"io/fs"
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
		"RequestBody", "ErrorMessage", "BackendAPIKey",
		"Password", "Token", "Secret", "APIToken":
		return true
	}
	return false
}

// sensitiveValueIdent: 作为【值】直接透传即违规的标识符（精确名匹配——
// apiKeyHash / hashAPIKey 哈希材料不在其列，实现"精确 allow"）
func sensitiveValueIdent(name string) bool {
	switch name {
	case "apiKey", "authHeader", "authorizationHeader", "token", "password", "secret",
		"body", "respBody", "rawBody", "url", "requestURL", "proxyURL":
		return true
	}
	return false
}

// scanLogSinks: 解析单个 Go 源文件，返回日志 sink 违规描述（空 = 干净）
func scanLogSinks(t *testing.T, fset *token.FileSet, filename string, src string) []string {
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

		for _, arg := range call.Args[skipFormatString(call):] {
			// len(...) = 字节数 metadata，显式放行
			if isLenCall(arg) {
				continue
			}
			src := exprSrc(fset, arg)
			line := fset.Position(arg.Pos()).Line

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
				".RequestBody", ".ErrorMessage", ".BackendAPIKey",
				".Password", ".Token", ".Secret"} {
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
			// 标识符走查（SliceExpr apiKey[:8] / authHeader[:20] 经此天然覆盖）
			leak := false
			ast.Inspect(arg, func(a ast.Node) bool {
				if id, ok := a.(*ast.Ident); ok && sensitiveValueIdent(id.Name) {
					leak = true
					return false
				}
				return true
			})
			if leak {
				add(line, "credential/body identifier passthrough", src)
			}
		}
		return true
	})
	return findings
}

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

// collectRuntimeSources: internal/**/*.go 递归 + cmd/server/*.go，排除 _test.go
func collectRuntimeSources(t *testing.T, root string) map[string]string {
	t.Helper()
	out := map[string]string{}
	err := filepath.WalkDir(filepath.Join(root, "internal"), func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		name := d.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			return nil
		}
		src, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, path)
		out[filepath.ToSlash(rel)] = string(src)
		return nil
	})
	if err != nil {
		t.Fatalf("static gate: walk internal: %v", err)
	}
	serverFiles, err := filepath.Glob(filepath.Join(root, "cmd", "server", "*.go"))
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range serverFiles {
		name := filepath.Base(path)
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		src, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		out[filepath.ToSlash(filepath.Join("cmd", "server", name))] = string(src)
	}
	return out
}

// Runtime-wide 仓库扫描 + coverage sentinel
func TestP1043_StaticGate_RuntimeWide(t *testing.T) {
	root := findModuleRoot(t)
	sources := collectRuntimeSources(t, root)

	t.Logf("RUNTIME_PRODUCTION_FILES_SCANNED=%d", len(sources))
	if len(sources) == 0 {
		t.Fatal("[gate delivery 失败] 静态扫描文件数为 0——覆盖幻觉")
	}

	// coverage sentinel：关键生产文件必须全部实际参与扫描
	required := []string{
		"internal/middleware/auth.go",
		"internal/middleware/security.go",
		"internal/services/client.go",
		"internal/services/gemini.go",
		"internal/providers/openai_compat.go",
		"internal/providers/vllm.go",
		"internal/handlers/admin.go",
		"internal/handlers/openai.go",
		"internal/handlers/proxy.go",
		"internal/auth/session.go",
		"internal/auth/csrf.go",
		"internal/secrets/cipher.go",
		"internal/secrets/masterkey.go",
		"cmd/server/main.go",
		"cmd/server/server.go",
	}
	for _, rel := range required {
		if _, ok := sources[rel]; !ok {
			t.Fatalf("[gate delivery 失败] 预期文件未参与扫描: %s", rel)
		}
	}
	t.Logf("required-file coverage: %d/%d present", len(required), len(required))

	// P1-04.4：注释型豁免机制已整体废除——生产源码不得存在任何 marker 残留
	for name, src := range sources {
		if strings.Contains(src, "secretlog:allow") {
			t.Fatalf("[安全回归失败] 生产源码存在 secretlog:allow 豁免残留: %s", name)
		}
	}

	var allFindings []string
	scannedWithSinks := map[string]bool{}
	for name, src := range sources {
		fset := token.NewFileSet()
		findings := scanLogSinks(t, fset, name, src)
		if len(findings) > 0 {
			allFindings = append(allFindings, findings...)
			scannedWithSinks[name] = true
		}
	}
	if len(allFindings) > 0 {
		for name := range scannedWithSinks {
			t.Logf("violations in: %s", name)
		}
		t.Fatalf("[安全回归失败] runtime 生产源码存在 %d 个 secret log sink:\n%s",
			len(allFindings), strings.Join(allFindings, "\n"))
	}
	t.Log("[SEC-003] Runtime-wide AST Gate：全部生产源码无 credential/body/URL/proxy 日志 sink")
}

// 合成 fixture 自测：credential 层新增形态必须抓到、哈希与方法 metadata 必须放行
func TestP1043_StaticGate_SyntheticFixtures(t *testing.T) {
	violations := []struct {
		name string
		src  string
	}{
		{"A: single-line header leak", "package p\nimport \"log\"\nfunc f() { httpReq := newReq(); log.Printf(\"headers=%v\", httpReq.Header) }\n"},
		{"B: multiline APIKey leak", "package p\nimport \"log\"\nfunc f(cfg *C) {\n\tlog.Printf(\n\t\t\"secret=%s\",\n\t\tcfg.APIKey,\n\t)\n}\n"},
		{"C: body via string()", "package p\nimport \"log\"\nfunc f(body []byte) {\n\tlog.Printf(\"body=%s\", string(body))\n}\n"},
		{"D: full URL value", "package p\nimport \"log\"\nfunc f(url string) {\n\tlog.Printf(\"GET %s\", url)\n}\n"},
		{"E: body identifier passthrough", "package p\nimport \"log\"\nfunc f(respBody []byte) {\n\tlog.Printf(\"resp=%s\", respBody)\n}\n"},
		{"F: apiKey slice [:8]", "package p\nimport \"log\"\nfunc f(apiKey string) {\n\tlog.Printf(\"key: %s\", apiKey[:8])\n}\n"},
		{"G: authHeader slice [:20] multiline", "package p\nimport \"log\"\nfunc f(authHeader string) {\n\tlog.Printf(\n\t\t\"auth: %s\",\n\t\tauthHeader[:20],\n\t)\n}\n"},
		{"H: token passthrough", "package p\nimport \"log\"\nfunc f(token string) {\n\tlog.Printf(\"token=%s\", token)\n}\n"},
		{"I: password field selector", "package p\nimport \"log\"\nfunc f(cfg *C) {\n\tlog.Printf(\"pw=%s\", cfg.Password)\n}\n"},
		{"J: password stdout with allow-marker comment still FAIL", "package p\nimport \"log\"\nfunc f(password string) {\n	fmt.Printf(\"Password: %s\\n\", password) // secretlog:allow bootstrap\n}\n"},
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
		{"safe: hash fragment (precise allow)", "package p\nimport \"log\"\nfunc f(apiKeyHash []byte) {\n\tlog.Printf(\"lookup (hash: %x)\", apiKeyHash[:8])\n}\n"},
		{"safe: method/path per card", "package p\nimport \"log\"\nfunc f(r *R) {\n\tlog.Printf(\"invalid api key method=%s path=%s\", r.Method, r.URL.Path)\n}\n"},
	}
	for _, tc := range safe {
		t.Run(tc.name, func(t *testing.T) {
			fset := token.NewFileSet()
			findings := scanLogSinks(t, fset, "fixture.go", tc.src)
			if len(findings) != 0 {
				t.Fatalf("[误报] 安全形态被判违规: %v", findings)
			}
		})
	}
}
