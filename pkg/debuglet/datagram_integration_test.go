// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package debuglet_test

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/netsec-ethz/debuglet/internal/guestio"
	"github.com/tetratelabs/wazero"
)

func TestUDPListenerGuest(t *testing.T) {
	wasm := buildGuest(t, "./pkg/debuglet/testdata/udp_listener")
	ctx := context.Background()
	runtime := wazero.NewRuntime(ctx)
	defer runtime.Close(ctx)
	compiled, err := runtime.CompileModule(ctx, wasm)
	if err != nil {
		t.Fatal(err)
	}
	defer compiled.Close(ctx)
	imports := map[string]bool{}
	for _, fn := range compiled.ImportedFunctions() {
		module, name, _ := fn.Import()
		if module == guestio.Module {
			imports[name] = true
		}
	}
	if !imports["receive_udp"] || !imports["reply_udp"] {
		t.Fatalf("imports=%v", imports)
	}
	t.Run("timeout", func(t *testing.T) {
		g := startGuest(t, wasm, hostOptions{addresses: []string{loopback}, listenUDP: true, args: []string{"timeout"}})
		if !g.wait(5*time.Second) || g.err() != nil {
			t.Fatalf("timeout guest: %v %s", g.err(), g.output())
		}
		requireContains(t, g, "UDP timeout recovered")
	})
	t.Run("receive and reply", func(t *testing.T) {
		g := startGuest(t, wasm, hostOptions{addresses: []string{loopback}, listenUDP: true, args: []string{"reply"}})
		address := strings.TrimPrefix(g.waitFor("ready ", 5*time.Second), "ready ")
		peer, err := net.DialTimeout("udp", address, time.Second)
		if err != nil {
			t.Fatal(err)
		}
		defer peer.Close()
		for _, request := range []string{"LONG123456", "", "PING"} {
			peer.SetDeadline(time.Now().Add(5 * time.Second))
			if _, err := peer.Write([]byte(request)); err != nil {
				t.Fatal(err)
			}
			buf := make([]byte, 8)
			n, err := peer.Read(buf)
			want := "PONG"
			if request == "" {
				want = ""
			}
			if err != nil || string(buf[:n]) != want {
				t.Fatalf("reply=%q %v; %s", buf[:n], err, g.output())
			}
		}
		if !g.wait(5*time.Second) || g.err() != nil {
			t.Fatalf("reply guest: %v %s", g.err(), g.output())
		}
		requireContains(t, g, "UDP truncation, empty datagram and same-port replies passed")
	})
}
