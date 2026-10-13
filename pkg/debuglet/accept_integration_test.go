// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package debuglet_test

import (
	"context"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/netsec-ethz/debuglet/internal/guestio"
	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
)

func TestBoundedAcceptGuest(t *testing.T) {
	wasm := buildGuest(t, "./pkg/debuglet/testdata/bounded_accept")
	ctx := context.Background()
	runtime := wazero.NewRuntime(ctx)
	defer runtime.Close(ctx)
	compiled, err := runtime.CompileModule(ctx, wasm)
	if err != nil {
		t.Fatal(err)
	}
	defer compiled.Close(ctx)
	found := false
	for _, fn := range compiled.ImportedFunctions() {
		module, name, _ := fn.Import()
		if module == guestio.Module && name == "accept_tcp" {
			found = true
			if !sameTypes(fn.ParamTypes(), []api.ValueType{api.ValueTypeI64}) || !sameTypes(fn.ResultTypes(), []api.ValueType{api.ValueTypeI64}) {
				t.Fatal("bounded accept import signature changed")
			}
		}
	}
	if !found {
		t.Fatal("bounded accept import missing")
	}

	t.Run("no input terminates", func(t *testing.T) {
		g := startGuest(t, wasm, hostOptions{addresses: []string{loopback}, listenTCP: true, args: []string{"no-input"}})
		if !g.wait(5*time.Second) || g.err() != nil {
			t.Fatalf("guest did not finish normally: %v; %s", g.err(), g.output())
		}
		requireContains(t, g, "bounded no-input exit")
	})
	t.Run("timeout recovery and close", func(t *testing.T) {
		g := startGuest(t, wasm, hostOptions{addresses: []string{loopback}, listenTCP: true, args: []string{"recovery"}})
		address := strings.TrimPrefix(g.waitFor("ready ", 5*time.Second), "ready ")
		peer, err := net.DialTimeout("tcp", address, time.Second)
		if err != nil {
			t.Fatal(err)
		}
		defer peer.Close()
		_ = peer.SetDeadline(time.Now().Add(5 * time.Second))
		buf := make([]byte, 4)
		// Send no input until the accepted guest read has timed out and recovered.
		if _, err := io.ReadFull(peer, buf); err != nil || string(buf) != "PING" {
			t.Fatalf("accepted socket did not survive its accept context: %q %v; %s", buf, err, g.output())
		}
		if _, err := peer.Write([]byte("PONG")); err != nil {
			t.Fatal(err)
		}
		g.waitFor("legacy ", 5*time.Second)
		legacy, err := net.DialTimeout("tcp", address, time.Second)
		if err != nil {
			t.Fatal(err)
		}
		defer legacy.Close()
		_ = legacy.SetDeadline(time.Now().Add(5 * time.Second))
		if _, err := legacy.Write([]byte("PING")); err != nil {
			t.Fatal(err)
		}
		if _, err := io.ReadFull(legacy, buf); err != nil || string(buf) != "PONG" {
			t.Fatalf("legacy accept after timeout: %q %v; %s", buf, err, g.output())
		}
		if !g.wait(5*time.Second) || g.err() != nil {
			t.Fatalf("guest recovery failed: %v; %s", g.err(), g.output())
		}
		requireContains(t, g, "bounded accept recovered and closed")
	})
}
