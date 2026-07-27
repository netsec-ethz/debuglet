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
	"flag"
	"fmt"
	"net/http"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"go.uber.org/zap"
	"golang.org/x/sync/errgroup"

	"debuglet/internal/dispatcher"
	"debuglet/internal/dispatcher/config"
	"debuglet/internal/dispatcher/transport/api"
	//"debuglet/internal/dispatcher/transport/rpc"
	"debuglet/internal/dispatcher/db"
	"debuglet/internal/dispatcher/sui"
	//pb "debuglet/protocol"
)

func main() {
	cfgPath := flag.String("config", "/etc/debuglet/dispatcher/dispatcher.toml", "Path to dispatcher configuration file")
	flag.Parse()

	cfg, err := config.LoadConfig(*cfgPath)
	if err != nil {
		panic(fmt.Sprintf("Failed to load dispatcher config: %v", err))
	}

	logLevel, err := zap.ParseAtomicLevel(cfg.LogLevel)
	if err != nil {
		logLevel = zap.NewAtomicLevelAt(zap.InfoLevel)
	}
	logCfg := zap.NewDevelopmentConfig()
	if cfg.JSONLogs {
		logCfg = zap.NewProductionConfig()
	}
	logCfg.Level = logLevel
	logCfg.OutputPaths = []string{"stdout"}
	logger, _ := logCfg.Build()
	defer logger.Sync()
	userDB, err := db.NewUserDB(cfg.Database.Path)
	if err != nil {
		logger.Fatal("failed to open user database", zap.Error(err))
	}
	defer userDB.Close()

	d := dispatcher.New(logger, cfg.Version, time.Duration(cfg.ExecutorTimeout)*time.Second)
	defer d.Close()

	g, subCtx := errgroup.WithContext(context.Background())

	yamuxPort := cfg.YamuxPort
	if yamuxPort == 0 {
		yamuxPort = cfg.GRPCPort + 1
	}

	// ---- Start gRPC Server ----
	g.Go(func() error {
		addr := fmt.Sprintf(":%d", cfg.GRPCPort)
		return d.Bidi.ServeGRPC(subCtx, addr)
	})

	// ---- Start Yamux Listener ----
	g.Go(func() error {
		addr := fmt.Sprintf(":%d", yamuxPort)
		return d.Bidi.ServeYamux(subCtx, addr)
	})

	// ---- Start HTTP Server ----
	g.Go(func() error { return startHTTPServer(d, userDB, cfg, logger) })

	// ---- Start Sui Event Listener ----
	if cfg.Sui.RPCURL != "" {
		g.Go(func() error { return startSuiListener(userDB,cfg,logger)})
	}

	if err := g.Wait(); err != nil {
		logger.Fatal("dispatcher exited with error", zap.Error(err))
	}

}

// startSuiListener subscribes to Sui PaymentReceipt events via gRPC and credits user balances.
func startSuiListener(userDB *db.UserDB, cfg *config.DispatcherConfig, logger *zap.Logger) error {
	l := sui.NewListener(cfg.Sui.RPCURL, cfg.Sui.GRPCEndpoint, cfg.Sui.Address, userDB, logger)
	return l.Start(context.Background())
}

// startHTTPServer runs the Echo-based HTTP API
func startHTTPServer(manager *dispatcher.Dispatcher, userDB *db.UserDB, cfg *config.DispatcherConfig, logger *zap.Logger) error {
	port := cfg.HTTPPort

	handler := api.NewHandler(manager, userDB, logger)

	e := echo.New()
	e.HideBanner = true
	e.HidePort = true
	e.Use(middleware.Recover())
	e.Use(middleware.LoggerWithConfig(middleware.LoggerConfig{
		Format: `{"level":"info","ts":${time_unix},"msg":"request","method":"${method}","uri":"${uri}","status":${status},"latency":${latency},"remote_ip":"${remote_ip}","host":"${host}","error":"${error}"}` + "\n",
	}))
	e.Use(middleware.CORS())

	handler.RegisterRoutes(e)

	addr := fmt.Sprintf(":%d", port)
	logger.Info("Dispatcher HTTP API started", zap.Int("port", port))

	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12, // More compatible than forcing 1.3
	}

	server := &http.Server{
		Addr:      addr,
		Handler:   e,
		TLSConfig: tlsConfig,
	}
	if cfg.DisableTLS {
		return server.ListenAndServe()
	} else {
		return server.ListenAndServeTLS(cfg.TLS.CertFile, cfg.TLS.KeyFile)
	}
}
