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
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"net"
	"sync"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"debuglet/internal/dispatcher"
	"debuglet/internal/dispatcher/api"
	"debuglet/internal/dispatcher/db"
	pb "debuglet/protocol"
)

func main() {
	cfgPath := flag.String("config", "/etc/debuglet/dispatcher/dispatcher.toml", "Path to dispatcher configuration file")
	flag.Parse()

	logger, _ := zap.NewProduction()
	defer logger.Sync()

	cfg, err := dispatcher.LoadConfig(*cfgPath)
	if err != nil {
		logger.Fatal("Failed to load dispatcher config: %v", zap.Error(err))
	}

	userDB, err := db.NewUserDB(cfg.Database.Path)
	if err != nil {
		logger.Fatal("failed to open user database", zap.Error(err))
	}
	defer userDB.Close()

	manager := dispatcher.NewDispatcher()

	var wg sync.WaitGroup
	wg.Add(2)

	// ---- Start gRPC Server ----
	go func() {
		defer wg.Done()
		if err := startGRPCServer(manager, cfg, logger); err != nil {
			logger.Fatal("failed to start gRPC server", zap.Error(err))
		}
	}()

	// ---- Start HTTP Server ----
	go func() {
		defer wg.Done()
		if err := startHTTPServer(manager, userDB, cfg, logger); err != nil {
			logger.Fatal("failed to start HTTP server", zap.Error(err))
		}
	}()

	wg.Wait()
}

func getServerCredentials(cfg *dispatcher.DispatcherConfig) (credentials.TransportCredentials, error) {
	// Load the server's certificate and key
	serverCert, err := tls.LoadX509KeyPair(
		cfg.TLS.CertFile,
		cfg.TLS.KeyFile,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to load server certificate: %w", err)
	}

	// Optionally, load CA if you want to check later
	// caCert, _ := os.ReadFile("/etc/debuglet/dispatcher/ca.crt")
	// caCertPool := x509.NewCertPool()
	// caCertPool.AppendCertsFromPEM(caCert)

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
			fmt.Printf("Client connected with CN=%s, Subject=%s\n", cert.Subject.CommonName, cert.Subject)

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

// startGRPCServer runs the dispatcher’s gRPC interface
func startGRPCServer(manager *dispatcher.Dispatcher, cfg *dispatcher.DispatcherConfig, logger *zap.Logger) error {
	port := cfg.GRPCPort
	addr := fmt.Sprintf(":%d", port)
	lis, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", addr, err)
	}

	creds, err := getServerCredentials(cfg)
	if err != nil {
		return fmt.Errorf("failed to get server credentials: %w", err)
	}
	srv := grpc.NewServer(grpc.Creds(creds))
	pb.RegisterDebugletDispatcherServer(srv, dispatcher.NewDispatcherServer(manager))

	logger.Info("Dispatcher gRPC server started", zap.Int("port", port))
	if err := srv.Serve(lis); err != nil {
		return fmt.Errorf("gRPC server failed: %w", err)
	}

	return nil
}

// startHTTPServer runs the Echo-based HTTP API
func startHTTPServer(manager *dispatcher.Dispatcher, userDB *db.UserDB, cfg *dispatcher.DispatcherConfig, logger *zap.Logger) error {
	port := cfg.HTTPPort
	handler := api.NewHandler(manager, userDB, logger)

	e := echo.New()
	e.HideBanner = true
	e.Use(middleware.Recover())
	e.Use(middleware.Logger())
	e.Use(middleware.CORS()) // TODO: specify CORS origin

	handler.RegisterRoutes(e)

	addr := fmt.Sprintf(":%d", port)
	logger.Info("Dispatcher HTTP API started", zap.Int("port", port))
	return e.StartTLS(addr, cfg.TLS.CertFile, cfg.TLS.KeyFile)
}
