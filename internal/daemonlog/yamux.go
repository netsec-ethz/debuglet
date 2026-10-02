// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package daemonlog

import (
	"fmt"

	"github.com/hashicorp/yamux"
	"go.uber.org/zap"
)

// YamuxConfig retains the transport defaults while sending its internal
// diagnostics to the operator's bounded, opt-in Debug sink instead of stderr.
// Yamux logs transport errors and frame metadata, never stream payloads.
func YamuxConfig(logger *zap.Logger) *yamux.Config {
	config := yamux.DefaultConfig()
	config.LogOutput = nil
	config.Logger = privateYamuxLogger{logger: logger}
	return config
}

type privateYamuxLogger struct{ logger *zap.Logger }

func (l privateYamuxLogger) Print(values ...interface{}) {
	l.Printf("%s", fmt.Sprint(values...))
}

func (l privateYamuxLogger) Println(values ...interface{}) {
	l.Printf("%s", fmt.Sprintln(values...))
}

func (l privateYamuxLogger) Printf(format string, values ...interface{}) {
	if l.logger == nil {
		return
	}
	if entry := l.logger.Check(zap.DebugLevel, "Private yamux diagnostic"); entry != nil {
		entry.Write(zap.String("error", Diagnostic(fmt.Errorf(format, values...))))
	}
}
