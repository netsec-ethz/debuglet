// Copyright 2025 ETH Zurich
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"context"
	"crypto/tls"
	"database/sql"
	"flag"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/soheilhy/cmux"
	"go.uber.org/zap"
	"golang.org/x/sync/errgroup"

	"debuglet/internal/dispatcher"
	"debuglet/internal/dispatcher/config"
	"debuglet/internal/dispatcher/payments"
	"debuglet/internal/dispatcher/transport/api"

	_ "modernc.org/sqlite"
)

func main() {
	cfgPath := flag.String("config", "/etc/debuglet/dispatcher/dispatcher.toml", "Path to dispatcher configuration file")
	flag.Parse()

	cfg, err := config.LoadConfig(*cfgPath)
	if err != nil {
		panic(fmt.Sprintf("Failed to load dispatcher config: %v", err))
	}

	logLevel, err := zap.ParseAtomicLevel(cfg.Logging.LogLevel)
	if err != nil {
		logLevel = zap.NewAtomicLevelAt(zap.InfoLevel)
	}
	logCfg := zap.NewDevelopmentConfig()
	if cfg.Logging.JSONLogs {
		logCfg = zap.NewProductionConfig()
	}
	logCfg.Level = logLevel
	logCfg.OutputPaths = []string{"stdout"}
	logger, _ := logCfg.Build()
	defer logger.Sync()

	// ---- Database init ----
	db, err := sql.Open("sqlite", cfg.Database.Path)
	if err != nil {
		logger.Fatal("Failed to open database", zap.Error(err))
	}
	// NOTE: limiting to a single connection could be a source of bottleneck with a lot of DB reads/writes
	db.SetMaxOpenConns(1)
	defer db.Close()

	paymentHandler := payments.NewPaymentHandler(db, cfg, logger)

	// ---- Dispatcher init ----
	d := dispatcher.New(logger, db, cfg.Server.Version, time.Duration(cfg.Scheduler.ExecutorTimeout)*time.Second, time.Duration(cfg.Scheduler.SchedulerGranularityMs)*time.Millisecond, paymentHandler)
	defer d.Close()
	if err := d.RestoreScheduler(context.Background()); err != nil {
		logger.Fatal("Failed to restore scheduler from database", zap.Error(err))
	}

	g, subCtx := errgroup.WithContext(context.Background())

	// ---- Start gRPC Server ----
	g.Go(func() error {
		addr := fmt.Sprintf(":%d", cfg.Server.GRPCPort)
		return d.Bidi.ServeGRPC(subCtx, addr)
	})

	// ---- Start combined HTTP + Yamux on cmux ----
	g.Go(func() error {
		g2, ctx2 := errgroup.WithContext(subCtx)

		addr := fmt.Sprintf(":%d", cfg.Server.HTTPPort)
		var lc net.ListenConfig
		lis, err := lc.Listen(ctx2, "tcp", addr)
		if err != nil {
			return fmt.Errorf("cmux listen: %w", err)
		}

		m := cmux.New(lis)
		httpL := m.Match(cmux.HTTP2(), cmux.HTTP1Fast())
		yamuxL := m.Match(cmux.Any())

		go func() {
			<-ctx2.Done()
			m.Close()
			lis.Close()
		}()

		logger.Info("Combined HTTP+Yamux listener started", zap.Int("port", cfg.Server.HTTPPort))

		g2.Go(func() error { return m.Serve() })
		g2.Go(func() error { return startHTTPServer(httpL, d, cfg, db, logger) })
		g2.Go(func() error { return d.Bidi.ServeYamux(ctx2, yamuxL) })
		return g2.Wait()
	})
	// ---- Start payment handler ----
	if cfg.Sui.GRPCEndpoint != "" {
		g.Go(func() error { return paymentHandler.Start(subCtx) })
	}

	if err := g.Wait(); err != nil {
		logger.Fatal("dispatcher exited with error", zap.Error(err))
	}
}

// startHTTPServer runs the Echo-based HTTP API on the given listener.
func startHTTPServer(lis net.Listener, manager *dispatcher.Dispatcher, cfg *config.DispatcherConfig, db *sql.DB, logger *zap.Logger) error {
	handler := api.NewHandler(manager, logger)

	e := echo.New()
	e.HideBanner = true
	e.HidePort = true
	e.Use(middleware.Recover())
	logFormat := `{"level":"info","ts":${time_unix},"msg":"request","method":"${method}","uri":"${uri}","status":${status},"latency":${latency},"remote_ip":"${remote_ip}","host":"${host}","error":"${error}"}` + "\n"
	if !cfg.Logging.JSONLogs {
		logFormat = "${time_rfc3339}\t${method}\t${uri} ${status} ${latency_human} ${remote_ip}\n"
	}
	e.Use(middleware.LoggerWithConfig(middleware.LoggerConfig{
		Format: logFormat,
	}))
	e.Use(middleware.CORS())

	handler.RegisterRoutes(e, db)

	logger.Info("Dispatcher HTTP API started", zap.String("address", lis.Addr().String()))

	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}

	server := &http.Server{
		Handler:   e,
		TLSConfig: tlsConfig,
	}
	if cfg.TLS.Disable {
		return server.Serve(lis)
	} else {
		return server.Serve(tls.NewListener(lis, tlsConfig))
	}
}
