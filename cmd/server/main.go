// @title AI Gateway API
// @version 1.0
// @description Self-hosted API gateway for LLM providers with rate limiting, quotas, and analytics
// @termsOfService https://github.com/DatanoiseTV/aigateway

// @contact.name Support
// @contact.url https://github.com/DatanoiseTV/aigateway/issues
// @license.name MIT
// @license.url https://github.com/DatanoiseTV/aigateway/blob/main/LICENSE

// @host localhost:8090
// @BasePath /
// @schemes http https
// @securityDefinitions.apikey ApiKeyAuth
// @in header
// @name Authorization
// @description API key authentication. Use format: "Bearer <client-api-key>"
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"ai-gateway/internal/audit"
	"ai-gateway/internal/capture"
	"ai-gateway/internal/config"
	"ai-gateway/internal/database"
	"ai-gateway/internal/logger"
	"ai-gateway/internal/models"
	"ai-gateway/internal/requestlogscrub"
	"ai-gateway/internal/secretmigration"
	"ai-gateway/internal/secrets"

	_ "ai-gateway/docs"
	"gorm.io/gorm"
)

var (
	version      = "dev"
	commit       = "unknown"
	buildTime    = "unknown"
	setupMode    = flag.Bool("setup", false, "Run setup wizard")
	resetPw      = flag.Bool("reset-password", false, "Offline operation: gateway must be stopped; restart required after reset (hidden TTY or explicit stdin mode)")
	resetPwStdin = flag.Bool("reset-password-stdin", false, "Read the reset password from stdin (requires -reset-password)")
	migrateSec   = flag.Bool("migrate-provider-secrets", false, "Offline migration: encrypt provider secrets (PREPARE/VERIFY/FINALIZE), then exit")
	// P1-04D：显式离线 scrub——清除 request_logs legacy 正文/错误文本（不可逆，需二次确认）
	scrubReqLog  = flag.Bool("scrub-request-log-content", false, "Offline scrub: clear legacy request_body/error_message in request_logs, then exit (IRREVERSIBLE)")
	confirmScrub = flag.Bool("confirm-destructive-scrub", false, "Required second confirmation flag for -scrub-request-log-content")
	backupDirFl  = flag.String("migration-backup-dir", "", "Backup root dir for provider secret migration (required with -migrate-provider-secrets)")
	// P1-03D1A：安全 Global Provider Key provisioning。
	// Key 绝不允许作为 CLI 参数（防 shell history / argv 泄露）——只能 TTY 隐藏输入或显式 stdin。
	setProvKeyFl   = flag.String("set-provider-key", "", "Provider name whose API key to provision securely (hidden TTY input + confirm; or -provider-key-stdin). Never pass the key as an argument.")
	provKeyStdin   = flag.Bool("provider-key-stdin", false, "Read the provider key from stdin instead of the TTY (explicit non-interactive mode; input is never echoed)")
	replacePKey    = flag.Bool("replace-provider-key", false, "Allow overwriting an existing encrypted provider key (deliberate replacement)")
	verifyAuditLog = flag.Bool("verify-audit-log", false, "Offline: verify the existing tamper-evident audit log, then exit")
)

func main() {
	configPath := flag.String("config", "config.yaml", "Path to config file")
	port := flag.Int("port", 0, "Port to listen on (overrides API port from config)")
	flag.Parse()

	if *verifyAuditLog {
		os.Exit(runVerifyAuditLog(*configPath, os.Stdout, os.Stderr))
	}

	// Handle password reset flag
	if *resetPw || *resetPwStdin {
		if flag.NArg() != 0 {
			fmt.Fprintln(os.Stderr, "error: -reset-password does not accept a password argument")
			os.Exit(2)
		}
		if !*resetPw {
			fmt.Fprintln(os.Stderr, "error: -reset-password-stdin requires -reset-password")
			os.Exit(2)
		}
		reader := newAdminPasswordReader(os.Stdin, *resetPwStdin)
		if err := runResetAdminPassword(*configPath, reader, os.Stdout); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
		return
	}

	printBanner()

	// P1-03C2：显式离线迁移模式——不启动任何 HTTP listener
	if *migrateSec {
		runProviderSecretMigration(*configPath, *backupDirFl)
		return
	}

	// P1-04D：显式离线 scrub 模式——不启动任何 HTTP listener；不可逆，需二次确认
	if *scrubReqLog {
		runRequestLogScrub(*configPath, *confirmScrub)
		return
	}

	// P1-03D1A：安全 Global Provider Key provisioning——不启动任何 HTTP listener
	if *setProvKeyFl != "" {
		reader := newProviderKeyReader(os.Stdin, *provKeyStdin)
		if _, err := runSetProviderKey(*configPath, *setProvKeyFl, *replacePKey, reader, os.Stdout); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
		return
	}

	if err := logger.Init(false); err != nil {
		log.Printf("Failed to init logger, using silent: %v", err)
		logger.InitSilent()
	}
	defer logger.Sync()

	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	if err := os.MkdirAll("./data", 0755); err != nil {
		log.Fatalf("Failed to create data directory: %v", err)
	}
	if err := os.MkdirAll("./logs", 0755); err != nil {
		log.Fatalf("Failed to create logs directory: %v", err)
	}

	db, err := initDatabase(cfg)
	if err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}
	if err := autoMigrate(db); err != nil {
		log.Fatalf("Failed to migrate database: %v", err)
	}
	if err := runAuditPreflightThen(db, func() error { return nil }); err != nil {
		log.Fatalf("%v", err)
	}

	// P1-04D 启动 preflight：legacy prompt/error 正文残留 → 拒绝启动（须离线 scrub）
	if err := ensureRequestLogPrivacyRunnable(db); err != nil {
		log.Fatalf("%v", err)
	}

	// P1-03C1 启动 preflight：明文/混合/损坏 Provider Secret → 拒绝启动
	secretMgr, err := ensureProviderSecretsRunnable(cfg, db)
	if err != nil {
		log.Fatalf("%v", err)
	}

	// P1-04C：诊断正文捕获（默认 OFF；显式 opt-in、bounded、≤24h 硬过期、MEMORY-ONLY）
	captureSettings, err := cfg.Logging.ResolveRequestBodyCapture(time.Now())
	if err != nil {
		log.Fatalf("request_body_capture: %v", err)
	}
	captureStore := capture.NewStore(captureSettings.Enabled, captureSettings.ExpiresAt, captureSettings.MaxBytes, captureSettings.MaxEntries)
	if cfg.Logging.RequestBodyCapture.Enabled && !captureSettings.Enabled {
		// 非敏感 warning：请求过启用但已失效（过期）——正文不会被捕获
		log.Printf("request_body_capture requested but stays disabled (expired); no request bodies are captured")
	}

	// P1-03C3 运行时视图：持久化 cfg 保持 envelope-only，解密明文只进入 runtimeCfg
	runtimeCfg, err := buildRuntimeConfig(cfg, secretMgr)
	if err != nil {
		log.Fatalf("runtime provider config: %v", err)
	}

	deps := newGatewayDeps(cfg, runtimeCfg, db, *setupMode, secretMgr, captureStore)
	apiMux := buildAPIRouter(deps)
	adminMux, err := buildAdminRouter(deps)
	if err != nil {
		log.Fatalf("Failed to build admin router: %v", err)
	}
	metricsMux := buildMetricsRouter(deps)

	if *port > 0 {
		cfg.Server.Port = *port
	}

	// 同步绑定全部端口：任一失败即整体失败，不留半启动状态
	servers, err := startListeners(cfg, apiMux, adminMux, metricsMux)
	if err != nil {
		log.Fatalf("Failed to start listeners: %v", err)
	}
	for _, s := range servers {
		log.Printf("%s listening on %s", s.name, s.ln.Addr())
	}

	errCh := make(chan error, 1)
	serveAll(servers, errCh)

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	select {
	case sig := <-quit:
		log.Printf("Received %s, shutting down...", sig)
	case err := <-errCh:
		log.Printf("Listener error: %v — shutting down remaining listeners", err)
	}

	if err := shutdownAll(servers, 10*time.Second); err != nil && !errors.Is(err, context.DeadlineExceeded) {
		log.Printf("Shutdown completed with error: %v", err)
	}
	log.Println("Server exited")
}

func runAuditStartupPreflight(db *gorm.DB) error {
	if err := audit.MigrateIntegrity(db); err != nil {
		return errors.New("AUDIT_INTEGRITY_CHECK_FAILED")
	}
	return nil
}

func runAuditPreflightThen(db *gorm.DB, next func() error) error {
	if err := runAuditStartupPreflight(db); err != nil {
		return err
	}
	return next()
}

func runVerifyAuditLog(configPath string, stdout, stderr io.Writer) int {
	cfg, err := config.LoadExistingForMigration(configPath)
	if err != nil || cfg.Database.Path == "" {
		fmt.Fprintln(stderr, "AUDIT_VERIFY_FAILED")
		return 1
	}
	db, err := database.OpenReadOnly(cfg.Database.Path)
	if err != nil {
		fmt.Fprintln(stderr, "AUDIT_VERIFY_FAILED")
		return 1
	}
	summary, verifyErr := audit.VerifyIntegrityReadOnly(db)
	closeErr := error(nil)
	if sqlDB, dbErr := db.DB(); dbErr != nil {
		closeErr = dbErr
	} else {
		closeErr = sqlDB.Close()
	}
	if closeErr != nil && verifyErr == nil {
		verifyErr = closeErr
	}
	if errors.Is(verifyErr, audit.ErrAuditMigrationRequired) {
		fmt.Fprintln(stderr, "AUDIT_SCHEMA_MIGRATION_REQUIRED")
		return 2
	}
	if errors.Is(verifyErr, audit.ErrAuditIntegrity) {
		fmt.Fprintln(stderr, "AUDIT_INTEGRITY_CHECK_FAILED")
		return 1
	}
	if verifyErr != nil {
		fmt.Fprintln(stderr, "AUDIT_VERIFY_FAILED")
		return 1
	}
	head := summary.HeadHash
	if head == "" {
		head = "GENESIS"
	}
	fmt.Fprintf(stdout, "AUDIT_VERIFY_OK\nevents=%d\nhead_sha256=%s\n", summary.EventCount, head)
	return 0
}

// runRequestLogScrub: 显式离线 scrub 入口（P1-04D）。
// 无确认 flag → 拒绝执行；输出只含数量与文件名，绝不包含正文材料。
func runRequestLogScrub(configPath string, confirmed bool) {
	if !confirmed {
		fmt.Println("error: -scrub-request-log-content is IRREVERSIBLE and requires -confirm-destructive-scrub")
		fmt.Println("note: no plaintext backup is created by this tool; make a controlled encrypted copy first if legally required")
		os.Exit(2)
	}
	res, err := requestlogscrub.Run(requestlogscrub.Options{ConfigPath: configPath})
	if err != nil {
		fmt.Printf("error: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("scrub complete\n")
	fmt.Printf("  db path        : %s\n", res.DBPath)
	fmt.Printf("  rows scrubbed  : %d\n", res.ScrubbedRows)
	fmt.Printf("  remain non-empty: %d\n", res.RemainNonEmpty)
	fmt.Printf("  sidecars        : %s\n", strings.Join(res.Sidecars, ", "))
	fmt.Printf("  phases          : %s\n", strings.Join(res.Phases, " -> "))
}

// runProviderSecretMigration: 离线迁移入口（P1-03C2）。
// Master Key 从环境加载（fail-closed）；输出只含数量/位置，不含 secret 材料。
func runProviderSecretMigration(configPath, backupDir string) {
	if backupDir == "" {
		fmt.Println("error: -migration-backup-dir is required with -migrate-provider-secrets")
		os.Exit(2)
	}
	key, err := secrets.LoadMasterKey(os.Getenv)
	if err != nil {
		fmt.Printf("error: %v\n", err)
		os.Exit(2)
	}
	res, err := secretmigration.Run(secretmigration.Options{
		ConfigPath: configPath,
		BackupDir:  backupDir,
		MasterKey:  key,
	})
	if err != nil {
		fmt.Printf("error: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("migration complete\n")
	fmt.Printf("  backup dir       : %s\n", res.BackupDir)
	fmt.Printf("  global prepared  : %d (legacy-only)\n", res.GlobalLegacyOnly)
	fmt.Printf("  client prepared  : %d (legacy-only)\n", res.ClientLegacyOnly)
	fmt.Printf("  already encrypted: global=%d clients=%d\n", res.GlobalEncrypted, res.ClientEncrypted)
	fmt.Printf("  finalized        : global=%d clients=%d\n", res.FinalizedGlobal, res.FinalizedClients)
	fmt.Printf("  phases           : %s\n", strings.Join(res.Phases, " -> "))
	fmt.Println("next: restart gateway (preflight now requires AIGATEWAY_MASTER_KEY)")
}

func initDatabase(cfg *config.Config) (*gorm.DB, error) {
	// P1-05B：统一经 internal/database.Open —— DSN 级 _foreign_keys=on，
	// 连接池新建连接也强制执行外键（late-write / ORPHAN-DATA 防线）。
	db, err := database.Open(cfg.Database.Path)
	if err != nil {
		return nil, err
	}

	sqlDB, err := db.DB()
	if err != nil {
		return nil, err
	}

	sqlDB.SetMaxIdleConns(10)
	sqlDB.SetMaxOpenConns(100)
	sqlDB.SetConnMaxLifetime(time.Hour)

	return db, nil
}

func autoMigrate(db *gorm.DB) error {
	return db.AutoMigrate(
		&models.Client{},
		&models.RequestLog{},
		&models.DailyUsage{},
		&models.AdminSession{},
	)
}

func printBanner() {
	fmt.Println("AI Gateway v" + version + " (" + commit + ")")
}
