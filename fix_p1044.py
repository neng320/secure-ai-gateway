import io

p = r"internal/config/config.go"
s = io.open(p, encoding="utf-8").read()
BSN = chr(92) + "n"  # literal backslash-n as it appears in Go source

def sub(old, new):
    global s
    assert old in s, "anchor missing: " + repr(old[:60])
    s = s.replace(old, new, 1)

# ① createDefaultConfig：不再生成/打印明文 admin 密码——走既有 __SETUP_REQUIRED__ /setup 流程
sub(
    "func createDefaultConfig(path string) (*Config, error) {\n"
    "\tsecret := generateRandomString(32)\n"
    "\tdefaultPassword := generateRandomString(16)\n"
    "\thash, err := bcrypt.GenerateFromPassword([]byte(defaultPassword), bcrypt.DefaultCost)\n"
    "\tif err != nil {\n"
    "\t\treturn nil, fmt.Errorf(\"failed to hash password: %w\", err)\n"
    "\t}\n"
    "\n"
    "\tcfg := &Config{",
    "func createDefaultConfig(path string) (*Config, error) {\n"
    "\tsecret := generateRandomString(32)\n"
    "\n"
    "\tcfg := &Config{",
)

sub(
    "\t\tAdmin: AdminConfig{\n"
    "\t\t\tUsername:      \"admin\",\n"
    "\t\t\tPasswordHash:  string(hash),\n"
    "\t\t\tSessionSecret: secret,\n"
    "\t\t\tCookieSecure:  false, // 默认支持 loopback/SSH 隧道 HTTP 开发；生产走 HTTPS 访问 Admin 面时显式置 true\n"
    "\t\t},",
    "\t\tAdmin: AdminConfig{\n"
    "\t\t\tUsername: \"admin\",\n"
    "\t\t\t// P1-04.4：首启不再生成/打印明文密码——走既有私有 /setup 流程\n"
    "\t\t\t//（用户自行设置密码；SetupHandler.IsSetupRequired 据此判定）\n"
    "\t\t\tPasswordHash:  \"__SETUP_REQUIRED__\",\n"
    "\t\t\tSessionSecret: secret,\n"
    "\t\t\tCookieSecure:  false, // 默认支持 loopback/SSH 隧道 HTTP 开发；生产走 HTTPS 访问 Admin 面时显式置 true\n"
    "\t\t},",
)

# ② banner（注意 Password 行尾还挂着 P1-04.3 的 allow 注释——一并删除）
old_b1 = (
    "\tfmt.Printf(\"" + BSN + "===========================================\" + BSN + \")".replace(BSN + BSN + "\")", BSN + "\")") + "\n"
)
# 直接逐行构造，避免歧义：
old_b1_lines = [
    "\tfmt.Printf(\"" + BSN + "===========================================" + BSN + "\")",
    "\tfmt.Printf(\"  Default credentials generated!" + BSN + "\")",
    "\tfmt.Printf(\"===========================================" + BSN + "\")",
    "\tfmt.Printf(\"  Username: admin" + BSN + "\")",
    "\tfmt.Printf(\"  Password: %s" + BSN + "\", defaultPassword) // secretlog:allow bootstrap-onetime-credential",
    "\tfmt.Printf(\"  (Save this - it will not be shown again)" + BSN + "\")",
    "\tfmt.Printf(\"===========================================" + BSN + BSN + "\")",
]
new_b1_lines = [
    "\t// P1-04.4：stdout 绝不出现任何生成密码材料（secretlog:allow 机制一并废除）",
    "\tfmt.Printf(\"" + BSN + "===========================================" + BSN + "\")",
    "\tfmt.Printf(\"  Initial setup required!" + BSN + "\")",
    "\tfmt.Printf(\"  Set the admin password via the private admin listener:" + BSN + "\")",
    "\tfmt.Printf(\"    http://127.0.0.1:8091/setup" + BSN + "\")",
    "\tfmt.Printf(\"  (loopback-only by default; see server.admin in config.yaml)" + BSN + "\")",
    "\tfmt.Printf(\"===========================================" + BSN + BSN + "\")",
]
sub(chr(10).join(old_b1_lines), chr(10).join(new_b1_lines))

# ③ ensureDefaults Prometheus：保留自动生成（写配置），stdout 零材料（含行尾 allow 注释删除）
old_p1 = (
    "\t\tfmt.Printf(\"  Prometheus credentials generated!" + BSN + "\")\n"
    "\t\tfmt.Printf(\"  Username: %s" + BSN + "\", cfg.Prometheus.Username)\n"
    "\t\tfmt.Printf(\"  Password: %s" + BSN + "\", cfg.Prometheus.Password) // secretlog:allow bootstrap-onetime-credential\n"
)
new_p1 = (
    "\t\tfmt.Printf(\"  Prometheus credentials generated and saved to config." + BSN + "\")\n"
)
sub(old_p1, new_p1)

old_p2 = (
    "\t\tfmt.Printf(\"  Prometheus password generated!" + BSN + "\")\n"
    "\t\tfmt.Printf(\"  Username: %s" + BSN + "\", cfg.Prometheus.Username)\n"
    "\t\tfmt.Printf(\"  Password: %s" + BSN + "\", cfg.Prometheus.Password) // secretlog:allow bootstrap-onetime-credential\n"
)
new_p2 = (
    "\t\tfmt.Printf(\"  Prometheus password generated and saved to config." + BSN + "\")\n"
)
sub(old_p2, new_p2)

io.open(p, "w", encoding="utf-8", newline="\n").write(s)
print("config.go fixed")
assert "secretlog:allow" not in s, "marker residue"
assert "defaultPassword" not in s, "defaultPassword residue"
print("residue clean")
