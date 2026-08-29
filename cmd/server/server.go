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
	"strconv"
	"time"

	"ai-gateway/internal/auth"
	"ai-gateway/internal/config"
	"ai-gateway/internal/handlers"
	mw "ai-gateway/internal/middleware"
	"ai-gateway/internal/providers"
	"ai-gateway/internal/services"
	"ai-gateway/internal/templates"

	"github.com/go-chi/chi/v5"
	"github.com/swaggo/http-swagger/v2"
	"gorm.io/gorm"
)

// gatewayDeps 汇集三个监听面共享的构造依赖。
type gatewayDeps struct {
	cfg           *config.Config
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
	health        *handlers.HealthHandler
}

func newGatewayDeps(cfg *config.Config, db *gorm.DB, setupMode bool) gatewayDeps {
	clientService := services.NewClientService(db)
	geminiService := services.NewGeminiService(db, cfg)
	statsService := services.NewStatsService(db)
	toolService := services.NewToolService(cfg.ServerTools.Tools)
	dashboardHub := services.NewDashboardHub(statsService)
	geminiService.SetOnRequestLogged(dashboardHub.NotifyUpdate)
	loginLimiter := auth.NewLoginRateLimiter()
	loginLimiter.Configure(cfg.Admin.LoginMaxFailures, time.Duration(cfg.Admin.LoginLockoutMinutes)*time.Minute, cfg.Admin.Username)
	return gatewayDeps{
		cfg:           cfg,
		db:            db,
		setupMode:     setupMode,
		clientService: clientService,
		statsService:  statsService,
		geminiService: geminiService,
		dashboardHub:  dashboardHub,
		toolService:   toolService,
		sessionStore:  auth.NewSQLiteStore(db),
		loginLimiter:  loginLimiter,
		registry:      providers.BuildRegistry(cfg),
		health:        handlers.NewHealthHandler(db),
	}
}

// buildAPIRouter: 公网入口。仅 API 端点与必需 health；
// 禁止挂载 /admin /setup /metrics /static /swagger 及任何管理面路由。
func buildAPIRouter(d gatewayDeps) *chi.Mux {
	r := chi.NewRouter()
	r.Use(mw.Recovery)
	r.Use(mw.SecurityHeaders)
	r.Use(mw.MaxRequestSize(10 << 20))

	d.health.RegisterRoutes(r)

	authMiddleware := mw.NewAuthMiddleware(d.clientService)
	rateLimiter := mw.NewRateLimiter()
	proxyHandler := handlers.NewProxyHandler(d.geminiService, d.statsService)
	openaiHandler := handlers.NewOpenAIHandler(d.geminiService, d.clientService, d.statsService, d.registry, d.toolService)

	r.Group(func(r chi.Router) {
		r.Use(authMiddleware.Handler)
		r.Use(rateLimiter.Middleware)
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

	adminHandler, err := handlers.NewAdminHandler(d.cfg, d.clientService, d.statsService, d.geminiService, d.dashboardHub, d.toolService, d.sessionStore, d.loginLimiter)
	if err != nil {
		return nil, fmt.Errorf("admin handler: %w", err)
	}

	configPath := config.SourcePath()
	if configPath == "" {
		return nil, fmt.Errorf("config source path unknown; cannot wire setup persistence")
	}
	setupHandler := handlers.NewSetupHandler(d.cfg, d.setupMode, d.loginLimiter, configPath)
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
