// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package debuglet

import (
	"context"
	"errors"
	"net"
	"strconv"
	"testing"

	"github.com/netsec-ethz/debuglet/internal/executor/debuglet/netpolicy"
	"github.com/netsec-ethz/debuglet/internal/executor/debuglet/socket"
	"github.com/netsec-ethz/debuglet/internal/executor/debuglet/wasm"
	"go.uber.org/zap"
)

func TestListenerBudgetReservesBeforeListenAndReleasesOnFailure(t *testing.T) {
	for _, held := range []bool{false, true} {
		t.Run(map[bool]string{false: "quota", true: "listen_failure"}[held], func(t *testing.T) {
			occupied, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if err != nil {
				t.Fatal(err)
			}
			defer occupied.Close()
			port := occupied.Addr().(*net.TCPAddr).Port
			if !held {
				occupied.Close()
			}
			ports, err := socket.NewPortManager("127.0.0.1", strconv.Itoa(port))
			if err != nil {
				t.Fatal(err)
			}
			operator, err := netpolicy.Parse(netpolicy.Defaults())
			if err != nil {
				t.Fatal(err)
			}
			node := socket.NewDescriptorBudget(1)
			budget := socket.NewBudget(socket.DefaultLimits(), node)
			d := &Debuglet{env: &wasm.WasmEnv{Budget: budget, Registry: socket.NewSocketRegistry(budget), PortManager: ports, Logger: zap.NewNop().Sugar(), Net: netpolicy.New(operator, netpolicy.Run{ListenTCP: true, ListenUDP: true})}}
			t.Cleanup(func() { _ = d.Close(context.Background()) })
			if held {
				if err := d.StartServers(context.Background(), StartServersReq{TCP: true}); err == nil || errors.Is(err, socket.ErrQuota) {
					t.Fatalf("listen failure=%v", err)
				}
			} else {
				if err := d.StartServers(context.Background(), StartServersReq{TCP: true}); err != nil {
					t.Fatal(err)
				}
				if err := d.StartServers(context.Background(), StartServersReq{UDP: true}); !errors.Is(err, socket.ErrQuota) {
					t.Fatalf("listener did not reserve node capacity: %v", err)
				}
				if err := d.Close(context.Background()); err != nil {
					t.Fatal(err)
				}
			}
			// A failed bind returns capacity before run cleanup; a closed listener
			// returns it once, even when cleanup is called repeatedly.
			reservation, err := budget.ReserveSocket(1)
			if err != nil {
				t.Fatal(err)
			}
			reservation.Release()
		})
	}
}
