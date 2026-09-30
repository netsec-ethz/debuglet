// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package daemonlog

import (
	"strings"
	"testing"

	"github.com/hashicorp/yamux"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
)

func TestYamuxDiagnosticsStayPrivateAndBounded(t *testing.T) {
	for _, level := range []zapcore.Level{zapcore.InfoLevel, zapcore.DebugLevel} {
		t.Run(level.String(), func(t *testing.T) {
			core, logs := observer.New(level)
			config := YamuxConfig(zap.New(core))
			if err := yamux.VerifyConfig(config); err != nil {
				t.Fatal(err)
			}
			if config.LogOutput != nil {
				t.Fatal("transport diagnostics have a second output")
			}
			config.Logger.Printf("read failed: %s", "private-transport-sentinel\n"+strings.Repeat("x", 4096))
			if level == zapcore.InfoLevel {
				if logs.Len() != 0 {
					t.Fatal("private transport detail reached routine logs")
				}
				return
			}
			entries := logs.FilterMessage("Private yamux diagnostic").All()
			if len(entries) != 1 {
				t.Fatal("private operator diagnostic missing")
			}
			text := entries[0].ContextMap()["error"].(string)
			if !strings.Contains(text, "private-transport-sentinel") || strings.Contains(text, "\n") || len(text) > 2051 {
				t.Fatal("private transport diagnostic lost context or exceeded its bound")
			}
		})
	}
}
