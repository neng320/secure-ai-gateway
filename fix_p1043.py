import io

NL = chr(10)

def patch(path, pairs):
    s = io.open(path, encoding="utf-8").read()
    for old, new in pairs:
        assert old in s, f"{path}: anchor missing: {old[:70]!r}"
        s = s.replace(old, new, 1)
    io.open(path, "w", encoding="utf-8", newline=NL).write(s)
    print(path, "ok")

# ---------- auth.go：根除 credential fragment 日志 ----------
patch("internal/middleware/auth.go", [
    (
        '\t\t\tlog.Printf("[AUTH] Invalid Authorization header format for %s %s: %s", r.Method, r.URL.Path, authHeader[:min(20, len(authHeader))])\n',
        "\t\t\t// P1-04.3：Authorization 内容（哪怕前 20 字符，短 token 可能整段）是凭证材料——绝不入日志\n"
        '\t\t\tlog.Printf("[AUTH] invalid authorization format for %s %s", r.Method, r.URL.Path)\n',
    ),
    (
        '\t\tlog.Printf("[AUTH] Trying to authenticate API key: %s... for %s %s", apiKey[:min(8, len(apiKey))], r.Method, r.URL.Path)\n',
        "\t\t// P1-04.3：key 前缀也是凭证——认证尝试只记录 method/path\n"
        '\t\tlog.Printf("[AUTH] authentication attempt for %s %s", r.Method, r.URL.Path)\n',
    ),
    (
        '\t\t\tlog.Printf("[AUTH] Invalid API key: %s... for %s %s", apiKey[:min(8, len(apiKey))], r.Method, r.URL.Path)\n',
        '\t\t\tlog.Printf("[AUTH] invalid api key for %s %s", r.Method, r.URL.Path)\n',
    ),
    (
        '\t\tlog.Printf("[AUTH] Authenticated client %s (%s) for %s %s", client.Name, client.ID, r.Method, r.URL.Path)\n',
        '\t\tlog.Printf("[AUTH] authenticated client_id=%s for %s %s", client.ID, r.Method, r.URL.Path)\n',
    ),
])
print("auth.go fixed")

# ---------- config.go：bootstrap 一次性凭证显示 → 精确 allow 标记 ----------
patch("internal/config/config.go", [
    (
        '\tfmt.Printf("  Password: %s\\n", defaultPassword)\n',
        '\tfmt.Printf("  Password: %s\\n", defaultPassword) // secretlog:allow bootstrap-onetime-credential（初始化向导一次性显示，操作者必须借此完成首次登录）\n',
    ),
    (
        '\t\t\tfmt.Printf("  Password: %s\\n", cfg.Prometheus.Password)\n'
        '\t\t\tfmt.Printf("  ===========================================\\n\\n")\n'
        "\t\t}\n",
        "\t\t\tfmt.Printf(\"  Password: %s\\n\", cfg.Prometheus.Password) // secretlog:allow bootstrap-onetime-credential\n"
        '\t\t\tfmt.Printf("  ===========================================\\n\\n")\n'
        "\t\t}\n",
    ),
    (
        '\t\t\tfmt.Printf("  Password: %s\\n", cfg.Prometheus.Password)\n'
        '\t\t\tfmt.Printf("===========================================\\n\\n")\n'
        "\t\t}\n",
        "\t\t\tfmt.Printf(\"  Password: %s\\n\", cfg.Prometheus.Password) // secretlog:allow bootstrap-onetime-credential\n"
        '\t\t\tfmt.Printf("===========================================\\n\\n")\n'
        "\t\t}\n",
    ),
])
print("config.go markers ok")
