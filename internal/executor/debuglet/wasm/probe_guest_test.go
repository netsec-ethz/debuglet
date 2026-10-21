// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package wasm

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"github.com/netsec-ethz/debuglet/internal/executor/debuglet/netpolicy"
	"github.com/netsec-ethz/debuglet/internal/guestio"
	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/imports/wasi_snapshot_preview1"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestTLSProbeGuest(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Minute)
	defer cancel()
	output := filepath.Join(t.TempDir(), "probe.wasm")
	build := exec.CommandContext(ctx, "go", "build", "-buildvcs=false", "-o", output, "./pkg/debuglet/testdata/probe_io")
	build.Dir = "../../../.."
	build.Env = append(os.Environ(), "GOOS=wasip1", "GOARCH=wasm", "CGO_ENABLED=0")
	if data, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build probe guest: %v %s", err, data)
	}
	module, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	cert, roots := smSelfSigned(t)
	listener, err := tls.Listen("tcp4", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		_ = conn.(*tls.Conn).Handshake()
	}()
	env := policyEnv(t, localSpec(), netpolicy.Run{Addresses: []string{"127.0.0.1"}})
	env.TlsCfg = &tls.Config{RootCAs: roots}
	runtime := wazero.NewRuntime(ctx)
	defer runtime.Close(ctx)
	if _, err := wasi_snapshot_preview1.Instantiate(ctx, runtime); err != nil {
		t.Fatal(err)
	}
	if _, err := RegisterIO(runtime.NewHostModuleBuilder(guestio.Module), env).Instantiate(ctx); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	_, err = runtime.InstantiateWithConfig(ctx, module, wazero.NewModuleConfig().WithArgs("probe", "tls", listener.Addr().String()).WithStdout(&stdout).WithStderr(&stderr))
	if err != nil {
		t.Fatalf("run probe guest: %v %s", err, &stderr)
	}
	var info guestio.TLSInfo
	if err := json.Unmarshal(stdout.Bytes(), &info); err != nil {
		t.Fatal(err)
	}
	if !info.Verified || len(info.Certificates) != 1 {
		t.Fatalf("guest result: %s", &stdout)
	}
	<-done
}
