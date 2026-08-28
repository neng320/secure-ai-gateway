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
	"syscall"
	"time"

	"ai-gateway/internal/config"
	"ai-gateway/internal/logger"
	"ai-gateway/internal/models"

	_ "ai-gateway/docs"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"
)

var (
	version   = "dev"
	commit    = "unknown"
	buildTime = "unknown"
	setupMode = flag.Bool("setup", false, "Run setup wizard")
	resetPw   = flag.String("reset-password", "", "Reset admin password to the specified value")
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

	deps := newGatewayDeps(cfg, db, *setupMode)
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
