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
	"crypto/x509"
	"flag"
	"fmt"
	"net/http"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"go.uber.org/zap"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc/credentials"

	"debuglet/internal/dispatcher"
	"debuglet/internal/dispatcher/config"
	"debuglet/internal/dispatcher/transport/api"
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
	logCfg := zap.NewProductionConfig()
	logCfg.Level = logLevel
	logCfg.OutputPaths = []string{"stdout"}
	logger, _ := logCfg.Build()
	defer logger.Sync()

	d := dispatcher.New(logger, cfg.Version, time.Duration(cfg.ExecutorTimeout)*time.Second)
	defer d.Close()

	g, subCtx := errgroup.WithContext(context.Background())

	// ---- Start gRPC Server ----
	g.Go(func() error {
		addr := fmt.Sprintf(":%d", cfg.GRPCPort)
		return d.Bidi.ListenAndServe(subCtx, addr)
	})
	// ---- Start HTTP Server ----
	g.Go(func() error { return startHTTPServer(d, cfg, logger) })

	if err := g.Wait(); err != nil {
		logger.Fatal("dispatcher exited with error", zap.Error(err))
	}
}

func getServerCredentials(cfg *config.DispatcherConfig, logger *zap.Logger) (credentials.TransportCredentials, error) {
	// Load the server's certificate and key
	serverCert, err := tls.LoadX509KeyPair(
		cfg.TLS.CertFile,
		cfg.TLS.KeyFile,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to load server certificate: %w", err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.RequireAnyClientCert, // 👈 Require cert but skip CA validation
		// ClientCAs: caCertPool, // optional if you want to enforce CA later
		MinVersion: tls.VersionTLS13,
		VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			// Custom verification logic
			if len(rawCerts) == 0 {
				return fmt.Errorf("no client certificate provided")
			}
			cert, err := x509.ParseCertificate(rawCerts[0])
			if err != nil {
				return fmt.Errorf("invalid client certificate: %w", err)
			}

			// Example: extract Common Name (executor ID)
			logger.Info("Client connected",
				zap.String("CN", cert.Subject.CommonName),
				zap.String("Subject", cert.Subject.String()),
			)

			// You could check against a known list of executor IDs:
			// if !isKnownExecutor(cert.Subject.CommonName) {
			//     return fmt.Errorf("unauthorized executor: %s", cert.Subject.CommonName)
			// }

			return nil // Allow connection
		},
	}

	creds := credentials.NewTLS(tlsConfig)
	return creds, nil
}

// startHTTPServer runs the Echo-based HTTP API
func startHTTPServer(manager *dispatcher.Dispatcher, cfg *config.DispatcherConfig, logger *zap.Logger) error {
	port := cfg.HTTPPort

	handler := api.NewHandler(manager, logger)

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

	// Explicit TLS configuration for the HTTP server
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
