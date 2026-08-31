package main

// P1-01F · Listener Isolation
//
// 单端口"全家桶"拆分为三个独立监听面：
//
//	Public API   server.host:port        仅 API + 必需 health（公网唯一入口，生产置于反代之后）
//	Private Admin server.admin.host:port /admin /setup /static /swagger（默认 127.0.0.1）
//	Private Metrics server.metrics.host:port /metrics（默认 127.0.0.1，仅 prometheus.enabled 时启动）
//
// 原则：不改变认证/限流/Provider 路由行为；只收敛网络暴露面。

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"ai-gateway/internal/auth"
	"ai-gateway/internal/capture"
	"ai-gateway/internal/config"
	"ai-gateway/internal/handlers"
	mw "ai-gateway/internal/middleware"
	"ai-gateway/internal/providers"
	"ai-gateway/internal/secrets"
	"ai-gateway/internal/services"
	"ai-gateway/internal/templates"

	"github.com/go-chi/chi/v5"
	"github.com/swaggo/http-swagger/v2"
	"gorm.io/gorm"
)

// gatewayDeps 汇集三个监听面共享的构造依赖。
// cfg 与 runtimeCfg 必须区分（P1-03C3）：cfg 是持久化视图（Provider Key 只含信封，
// 供 Admin/Setup/SaveConfig 使用）；runtimeCfg 是运行时视图（已解密明文，仅供上游调用）。
type gatewayDeps struct {
	cfg           *config.Config
	runtimeCfg    *config.Config
	db            *gorm.DB
	setupMode     bool
	clientService *services.ClientService
	statsService  *services.StatsService
	geminiService *services.GeminiService
	dashboardHub  *services.DashboardHub
	toolService   *services.ToolService
	sessionStore  auth.Store
	loginLimiter  *auth.LoginRateLimiter
	registry      *providers.Registry
	secretManager *secrets.Manager
	captureStore  *capture.Store
	health        *handlers.HealthHandler
	// P1-05B：RateLimiter 提升为 gateway lifecycle 共享实例——
	// DeleteClient 事务成功后可 ResetClient(clientID)；ROTATE/SUSPEND/RESUME 不重置。
	rateLimiter *mw.RateLimiter
}

func newGatewayDeps(cfg, runtimeCfg *config.Config, db *gorm.DB, setupMode bool, secretMgr *secrets.Manager, captureStore *capture.Store) gatewayDeps {
	clientService := services.NewClientService(db)
	geminiService := services.NewGeminiService(db, runtimeCfg)
	statsService := services.NewStatsService(db)
	toolService := services.NewToolService(cfg.ServerTools.Tools)
	dashboardHub := services.NewDashboardHub(statsService)
	geminiService.SetOnRequestLogged(dashboardHub.NotifyUpdate)
	loginLimiter := auth.NewLoginRateLimiter()
	loginLimiter.Configure(cfg.Admin.LoginMaxFailures, time.Duration(cfg.Admin.LoginLockoutMinutes)*time.Minute, cfg.Admin.Username)
	rateLimiter := mw.NewRateLimiter()
	return gatewayDeps{
		cfg:           cfg,
		runtimeCfg:    runtimeCfg,
		db:            db,
		setupMode:     setupMode,
		clientService: clientService,
		statsService:  statsService,
		geminiService: geminiService,
		dashboardHub:  dashboardHub,
		toolService:   toolService,
		sessionStore:  auth.NewSQLiteStore(db),
		loginLimiter:  loginLimiter,
		registry:      providers.BuildRegistry(runtimeCfg),
		secretManager: secretMgr,
		captureStore:  captureStore,
		health:        handlers.NewHealthHandler(db),
		rateLimiter:   rateLimiter,
	}
}

// buildRuntimeConfig: 从持久化 cfg 派生运行时视图（P1-03C3）。
// 逐 provider 解密 APIKeyEncrypted → 明文仅写入副本；持久化 cfg 永不被触碰
// （对副本的一切修改都不会回流，SaveConfig 序列化的仍是 envelope-only 视图）。
// 禁止把解密结果写回 cfg.Providers[name].APIKey。
func buildRuntimeConfig(persistent *config.Config, mgr *secrets.Manager) (*config.Config, error) {
	rc := *persistent
	rc.Providers = make(map[string]config.ProviderConfig, len(persistent.Providers))
	for name, p := range persistent.Providers {
		if p.APIKeyEncrypted != "" {
			if mgr == nil {
				return nil, fmt.Errorf("provider %q has an encrypted key but no master key is configured", name)
			}
			pt, err := mgr.DecryptGlobalProviderKey(name, p.APIKeyEncrypted)
			if err != nil {
				return nil, fmt.Errorf("provider %q key unavailable: %w", name, err)
			}
			p.APIKey = string(pt)
			p.APIKeyEncrypted = ""
		}
		rc.Providers[name] = p
	}
	return &rc, nil
}

// ensureProviderSecretsRunnable: 启动 preflight（P1-03C1）。
// 检测明文/混合/损坏 Provider Secret → 拒绝启动（PROVIDER_SECRET_MIGRATION_REQUIRED）；
// 检测密文 → 要求 Master Key 并逐项试解密（错误 key/key_id 不符/篡改 → 拒绝）；
// 全部为空 → 允许无 Master Key 启动（Ollama/LM Studio 场景）。
// 存在密文时返回已验证的 Manager（C3 runtime 解密将复用）。
func ensureProviderSecretsRunnable(cfg *config.Config, db *gorm.DB) (*secrets.Manager, error) {
	var items []secrets.SecretItem
	for name, p := range cfg.Providers {
		items = append(items, secrets.SecretItem{Kind: secrets.KindGlobal, Ref: name, Legacy: p.APIKey, Encrypted: p.APIKeyEncrypted})
	}
	var rows []struct {
		ID                     string
		Legacy                 string
		BackendAPIKeyEncrypted string
	}
	if err := db.Raw("SELECT id, backend_api_key AS legacy, backend_api_key_encrypted FROM clients").Scan(&rows).Error; err != nil {
		return nil, fmt.Errorf("secrets preflight: %w", err)
	}
	for _, rr := range rows {
		items = append(items, secrets.SecretItem{Kind: secrets.KindClient, Ref: rr.ID, Legacy: rr.Legacy, Encrypted: rr.BackendAPIKeyEncrypted})
	}

	res := secrets.ScanPreflight(items)
	if res.MigrationRequired {
		return nil, fmt.Errorf("%w (locations: %s)", secrets.ErrProviderSecretMigrationRequired, strings.Join(res.Offenders, ", "))
	}
	if !res.NeedMasterKey {
		// 全部为空：无 Master Key 配置 → 无需 Manager，合法启动（Ollama/LM Studio 场景）。
		// 恰好配置一个合法 Master Key → 仍构造 Manager（P1-03C3）：
		// 空系统也要能安全新增第一个 Provider Secret（明文保存被禁止）。
		// 双源冲突 / 格式错误 → fail-closed（运营者明确配置了 Secret 基础设施但配置错误）。
		if os.Getenv(secrets.EnvMasterKey) == "" && os.Getenv(secrets.EnvMasterKeyFile) == "" {
			return nil, nil
		}
		key, err := secrets.LoadMasterKey(os.Getenv)
		if err != nil {
			return nil, err
		}
		cipher, err := secrets.NewAESGCMCipher(key)
		if err != nil {
			return nil, err
		}
		return secrets.NewManager(cipher), nil
	}
	key, err := secrets.LoadMasterKey(os.Getenv)
	if err != nil {
		return nil, err
	}
	cipher, err := secrets.NewAESGCMCipher(key)
	if err != nil {
		return nil, err
	}
	mgr := secrets.NewManager(cipher)
	if err := secrets.VerifyEncryptedItems(mgr, res.EncryptedItems); err != nil {
		return nil, err
	}
	return mgr, nil
}

// ensureRequestLogPrivacyRunnable: SEC-003/P1-04D 启动 preflight。
// request_logs 中存在任何 legacy request_body/error_message 非空行 → 拒绝正常启动，
// 错误含稳定哨兵 REQUEST_LOG_PRIVACY_MIGRATION_REQUIRED（仅报告行数，绝不输出内容）。
// 清理路径：显式 -scrub-request-log-content（不可逆）。
func ensureRequestLogPrivacyRunnable(db *gorm.DB) error {
	var dirty int64
	if err := db.Raw("SELECT count(*) FROM request_logs WHERE request_body != '' OR error_message != ''").Scan(&dirty).Error; err != nil {
		// 表/列缺失由 AutoMigrate 保证；到达此处仍失败属异常 → fail-closed
		return fmt.Errorf("request log privacy preflight: %w", err)
	}
	if dirty > 0 {
		return fmt.Errorf("REQUEST_LOG_PRIVACY_MIGRATION_REQUIRED: %d request_logs rows still contain legacy prompt/error content; "+
			"run -scrub-request-log-content -confirm-destructive-scrub offline (irreversible)", dirty)
	}
	return nil
}

// buildAPIRouter: 公网入口。仅 API 端点与必需 health；
// 禁止挂载 /admin /setup /metrics /static /swagger 及任何管理面路由。
func buildAPIRouter(d gatewayDeps) *chi.Mux {
	r := chi.NewRouter()
	r.Use(mw.Recovery)
	r.Use(mw.SecurityHeaders)
	r.Use(mw.MaxRequestSize(mw.DefaultRequestBodyMaxBytes))
	// SEC-003（P1-04B）：全 API 面 request ID——响应头 X-Request-ID == DB RequestLog.RequestID
	r.Use(mw.RequestID())

	d.health.RegisterRoutes(r)

	authMiddleware := mw.NewAuthMiddleware(d.clientService)
	// P1-05B：与 Admin 面共享同一 RateLimiter 实例（gatewayDeps.rateLimiter），
	// Delete 成功后 handler 才能 ResetClient 运行时 bucket。
	rateLimiter := d.rateLimiter
	proxyHandler := handlers.NewProxyHandler(d.geminiService, d.statsService, d.captureStore)
	openaiHandler := handlers.NewOpenAIHandler(d.geminiService, d.clientService, d.statsService, d.registry, d.toolService, d.secretManager, d.captureStore)

	r.Group(func(r chi.Router) {
		r.Use(authMiddleware.Handler)
		r.Use(rateLimiter.Middleware)
		r.Use(mw.RequestValidation(mw.DefaultRequestBodyMaxBytes))
		r.Use(mw.NewQuotaMiddleware(d.db))
		proxyHandler.RegisterRoutes(r)
		openaiHandler.RegisterRoutes(r)
	})
	return r
}

// buildAdminRouter: 私有管理面。Swagger/静态资源归属此处——随 Admin 监听面默认 loopback，
// 不再默认暴露公网（生产管理员经 SSH 隧道/Tailscale 访问）。
func buildAdminRouter(d gatewayDeps) (*chi.Mux, error) {
	r := chi.NewRouter()
	r.Use(mw.Recovery)
	r.Use(mw.SecurityHeaders)
	// P1-02.1：Admin 面恢复请求体上限（与原单端口行为一致；更细粒度校验属 P1-07）
	r.Use(mw.MaxRequestSize(10 << 20))

	configPath := config.SourcePath()
	if configPath == "" {
		return nil, fmt.Errorf("config source path unknown; cannot wire admin persistence or setup")
	}
	adminHandler, err := handlers.NewAdminHandler(d.cfg, d.clientService, d.statsService, d.geminiService, d.dashboardHub, d.toolService, d.sessionStore, d.loginLimiter, d.secretManager, configPath, d.captureStore, d.rateLimiter)
	if err != nil {
		return nil, fmt.Errorf("admin handler: %w", err)
	}

	setupHandler := handlers.NewSetupHandler(d.cfg, d.setupMode, d.loginLimiter, configPath, d.db)
	if setupHandler.IsSetupRequired() {
		setupHandler.RegisterRoutes(r)
		r.Get("/", func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "/setup", http.StatusFound)
		})
	} else {
		r.Get("/", func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "/admin/dashboard", http.StatusFound)
		})
	}
	adminHandler.RegisterRoutes(r)

	r.Handle("/static/*", http.FileServer(http.FS(templates.Static)))
	r.Get("/swagger", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/swagger/", http.StatusMovedPermanently)
	})
	r.Get("/swagger/", httpSwagger.Handler(httpSwagger.URL("/swagger/doc.json")))
	r.Get("/swagger/doc.json", httpSwagger.Handler(httpSwagger.URL("/swagger/doc.json")))
	return r, nil
}

// buildMetricsRouter: /metrics 独立监听面；未启用时返回 nil（不启动监听）。
func buildMetricsRouter(d gatewayDeps) chi.Router {
	if !d.cfg.Prometheus.Enabled {
		return nil
	}
	r := chi.NewRouter()
	metricsHandler := handlers.NewMetricsHandler(d.statsService, d.cfg.Prometheus.Username, d.cfg.Prometheus.Password)
	metricsHandler.RegisterRoutes(r)
	return r
}

// listenerServer: 一个已绑定端口的 HTTP 服务
type listenerServer struct {
	name string
	srv  *http.Server
	ln   net.Listener
}

// startListeners: 先同步绑定全部端口——任一 bind 失败立即返回错误并关闭已建立的监听，绝不静默假成功。
func startListeners(cfg *config.Config, apiMux, adminMux, metricsMux chi.Router) ([]listenerServer, error) {
	type spec struct {
		name string
		host string
		port int
		h    chi.Router
	}
	specs := []spec{
		{"api", cfg.Server.Host, cfg.Server.Port, apiMux},
		{"admin", cfg.Server.Admin.Host, cfg.Server.Admin.Port, adminMux},
	}
	if metricsMux != nil {
		specs = append(specs, spec{"metrics", cfg.Server.Metrics.Host, cfg.Server.Metrics.Port, metricsMux})
	}

	var out []listenerServer
	for _, sp := range specs {
		addr := net.JoinHostPort(sp.host, strconv.Itoa(sp.port))
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			for _, s := range out {
				_ = s.ln.Close()
			}
			return nil, fmt.Errorf("%s listener bind %s: %w", sp.name, addr, err)
		}
		out = append(out, listenerServer{
			name: sp.name,
			ln:   ln,
			srv: &http.Server{
				Handler:      sp.h,
				ReadTimeout:  30 * time.Second,
				WriteTimeout: 120 * time.Second,
				IdleTimeout:  60 * time.Second,
			},
		})
	}
	return out, nil
}

// serveAll: 并发 Serve 全部监听面；任一非预期错误立即上报（ErrServerClosed 除外）。
func serveAll(servers []listenerServer, errCh chan<- error) {
	for _, s := range servers {
		s := s
		go func() {
			if err := s.srv.Serve(s.ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
				select {
				case errCh <- fmt.Errorf("%s listener: %w", s.name, err):
				default:
				}
			}
		}()
	}
}

// shutdownAll: 统一优雅关停，聚合各监听面的关停错误。
func shutdownAll(servers []listenerServer, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	var firstErr error
	for _, s := range servers {
		if err := s.srv.Shutdown(ctx); err != nil && firstErr == nil {
			firstErr = fmt.Errorf("%s shutdown: %w", s.name, err)
		}
	}
	return firstErr
}
