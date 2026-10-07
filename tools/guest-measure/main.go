//go:build linux

// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

// guest-measure measures one WASI hello module with the executor's interpreter
// and memory settings. It deliberately provides no networking host imports.
package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"syscall"
	"time"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/imports/wasi_snapshot_preview1"
)

type capture struct {
	bytes.Buffer
	start time.Time
	first *float64
}

func (w *capture) Write(p []byte) (int, error) {
	if w.Len()+len(p) > 64<<10 {
		return 0, errors.New("measurement output exceeds 64 KiB")
	}
	if len(p) > 0 && w.first == nil {
		elapsed := float64(time.Since(w.start)) / float64(time.Millisecond)
		w.first = &elapsed
	}
	return w.Buffer.Write(p)
}

func main() {
	stdlib := flag.String("stdlib-root", "", "optional read-only filesystem root; unavailable in the real executor")
	flag.Parse()
	if flag.NArg() == 0 {
		fmt.Fprintln(os.Stderr, "usage: guest-measure [-stdlib-root DIR] module.wasm [guest arguments...]")
		os.Exit(2)
	}
	wasm, err := os.ReadFile(flag.Arg(0))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	rt := wazero.NewRuntimeWithConfig(ctx, wazero.NewRuntimeConfigInterpreter().WithMemoryLimitPages(4096).WithCloseOnContextDone(true))
	defer rt.Close(context.Background())
	start := time.Now()
	compiled, err := rt.CompileModule(ctx, wasm)
	compileMS := float64(time.Since(start)) / float64(time.Millisecond)
	var imports []string
	out, stderr := &capture{}, &capture{}
	var runMS float64
	if err == nil {
		for _, fn := range compiled.ImportedFunctions() {
			module, name, _ := fn.Import()
			if module != "wasi_snapshot_preview1" {
				imports = append(imports, module+"."+name)
			}
		}
		_, err = wasi_snapshot_preview1.Instantiate(ctx, rt)
	}
	if err == nil {
		config := wazero.NewModuleConfig().WithStdout(out).WithStderr(stderr).
			WithSysWalltime().WithSysNanotime().WithSysNanosleep().WithRandSource(rand.Reader).
			WithArgs(flag.Args()[1:]...)
		if *stdlib != "" {
			config = config.WithFSConfig(wazero.NewFSConfig().WithReadOnlyDirMount(*stdlib, "/"))
		}
		out.start = time.Now()
		stderr.start = out.start
		_, err = rt.InstantiateModule(ctx, compiled, config)
		runMS = float64(time.Since(out.start)) / float64(time.Millisecond)
	}
	var rss syscall.Rusage
	if usageErr := syscall.Getrusage(syscall.RUSAGE_SELF, &rss); usageErr != nil {
		err = errors.Join(err, usageErr)
	}
	sum := sha256.Sum256(wasm)
	message := ""
	if err != nil {
		message = err.Error()
	}
	if err := json.NewEncoder(os.Stdout).Encode(map[string]any{
		"module_sha256": hex.EncodeToString(sum[:]), "bytes": len(wasm),
		"compile_ms": compileMS, "first_stdout_ms": out.first, "first_stderr_ms": stderr.first,
		"run_ms": runMS, "maxrss_kib": rss.Maxrss, "filesystem_mounted": *stdlib != "",
		"non_wasi_imports": imports, "stdout": out.String(), "stderr": stderr.String(), "error": message,
	}); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	if message != "" {
		os.Exit(1)
	}
}
