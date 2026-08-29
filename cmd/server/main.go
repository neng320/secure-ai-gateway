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
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"ai-gateway/internal/capture"
	"ai-gateway/internal/config"
	"ai-gateway/internal/logger"
	"ai-gateway/internal/models"
	"ai-gateway/internal/secretmigration"
	"ai-gateway/internal/secrets"

	_ "ai-gateway/docs"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"
)

var (
	version     = "dev"
	commit      = "unknown"
	buildTime   = "unknown"
	setupMode   = flag.Bool("setup", false, "Run setup wizard")
	resetPw     = flag.String("reset-password", "", "Reset admin password to the specified value")
	migrateSec  = flag.Bool("migrate-provider-secrets", false, "Offline migration: encrypt provider secrets (PREPARE/VERIFY/FINALIZE), then exit")
	backupDirFl = flag.String("migration-backup-dir", "", "Backup root dir for provider secret migration (required with -migrate-provider-secrets)")
	// P1-03D1A：安全 Global Provider Key provisioning。
	// Key 绝不允许作为 CLI 参数（防 shell history / argv 泄露）——只能 TTY 隐藏输入或显式 stdin。
	setProvKeyFl = flag.String("set-provider-key", "", "Provider name whose API key to provision securely (hidden TTY input + confirm; or -provider-key-stdin). Never pass the key as an argument.")
	provKeyStdin = flag.Bool("provider-key-stdin", false, "Read the provider key from stdin instead of the TTY (explicit non-interactive mode; input is never echoed)")
	replacePKey  = flag.Bool("replace-provider-key", false, "Allow overwriting an existing encrypted provider key (deliberate replacement)")
)

func main() {
	configPath := flag.String("config", "config.yaml", "Path to config file")
	port := flag.Int("port", 0, "Port to listen on (overrides API port from config)")
	flag.Parse()

	printBanner()

	// Handle password reset flag
	if *resetPw != "" {
		cfg, err := config.Load(*configPath)
		if err != nil {
			log.Fatalf("Failed to load config: %v", err)
		}
		if err := config.ResetAdminPassword(cfg, *resetPw); err != nil {
			log.Fatalf("Failed to reset password: %v", err)
		}
		if err := config.SaveConfig(cfg, *configPath); err != nil {
			log.Fatalf("Failed to save config: %v", err)
		}
		fmt.Printf("Admin password has been reset\n")
		return
	}

	// P1-03C2：显式离线迁移模式——不启动任何 HTTP listener
	if *migrateSec {
		runProviderSecretMigration(*configPath, *backupDirFl)
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
	db, err := gorm.Open(sqlite.Open(cfg.Database.Path), &gorm.Config{
		Logger: gormlogger.Default.LogMode(gormlogger.Silent),
	})
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
