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
	"flag"
	"fmt"
	"os"

	"go.uber.org/zap"

	"debuglet/internal/executor"
	"debuglet/internal/executor/config"
	"debuglet/internal/executor/storage/memory"

	scionFlag "github.com/scionproto/scion/private/app/flag"
)

func main() {
	cfgPath := flag.String("config", "/etc/debuglet/executor/executor.toml", "Path to executor configuration file")
	flag.Parse()

	cfg, err := config.LoadConfig(*cfgPath)
	if err != nil {
		panic(fmt.Sprintf("Failed to load executor config: %v", err))
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

	var envFlags scionFlag.SCIONEnvironment
	if err := envFlags.LoadExternalVars(); err != nil {
		logger.Fatal("Failed to load SCION environment variables", zap.Error(err))
		return
	}
	os.Setenv("SCION_DAEMON_ADDRESS", envFlags.Daemon())

	storage := memory.NewStorage()

	logger.Info("Starting executor:", zap.String("executor_id", cfg.ExecutorID), zap.String("dispatcher_addr", cfg.DispatcherAddr))

	exec, err := executor.New(cfg, logger, storage)
	if err != nil {
		logger.Fatal("Failed to create executor", zap.Error(err))
		return
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		if err := storage.StartLoop(ctx); err != nil {
			logger.Fatal("Failed to start storage loop", zap.Error(err))
			return
		}
	}()

	if err := exec.Start(ctx); err != nil {
		logger.Fatal("Failed to start executor", zap.Error(err))
	}
}
