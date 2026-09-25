package executor

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/netsec-ethz/debuglet/internal/executor/debuglet/netpolicy"
	"github.com/netsec-ethz/debuglet/internal/executor/debuglet/wasm"
	"github.com/netsec-ethz/debuglet/internal/executor/ratelimit"
	"github.com/netsec-ethz/debuglet/internal/executor/ratelimit/app"
	"github.com/netsec-ethz/debuglet/internal/executor/scheduler"
	"github.com/tetratelabs/wazero"
)

func TestRegisteredListenerAccountsFirstDatagramAfterPublication(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	const addr = "127.0.0.1"
	cfg := fixtureConfig()
	localTargets := true
	cfg.Network.Policy.LocalTargets = &localTargets
	e := newFixtureExecutor(t, cfg, nil, newFixtureMemoryStorage(t))
	e.limiter.SetAddrCapacity(addr, app.Megabit)
	spec := scheduler.Spec{
		DebugletID: uuid.New(),
		Policy: scheduler.Policy{
			CeilBW: int64(app.Megabit), Addresses: []string{addr}, ListenUDP: true,
		},
	}
	op := newDebugletOperation(ctx)
	t.Cleanup(func() {
		if completion := op.finish(nil, nil); completion.CleanupErr != nil {
			t.Error(completion.CleanupErr)
		}
		e.unregisterDebuglet(spec.DebugletID, op)
		op.cancel(nil)
	})
	// Registration publishes both limits before a listener can account traffic.
	if _, err := e.registerDebuglet(spec, op); err != nil {
		t.Fatal(err)
	}

	server, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP(addr)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Close() })
	deadline, _ := ctx.Deadline()
	if err := server.SetReadDeadline(deadline); err != nil {
		t.Fatal(err)
	}
	peer, err := net.DialUDP("udp4", nil, server.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = peer.Close() })
	const payload = "first listener datagram"
	if _, err := peer.Write([]byte(payload)); err != nil {
		t.Fatal(err)
	}

	operator, err := cfg.Network.Policy.Compile()
	if err != nil {
		t.Fatal(err)
	}
	env := &wasm.WasmEnv{
		Net: netpolicy.New(operator, netpolicy.Run{
			Addresses: spec.Policy.Addresses, ListenUDP: true,
		}),
		Accountant: ratelimit.NewAccountant(e.limiter, spec.DebugletID),
		UdpServer:  server,
		Logger:     e.logger.Sugar(),
	}
	// A memory-only module gives the production host function a real guest buffer.
	runtime := wazero.NewRuntimeWithConfig(ctx, wazero.NewRuntimeConfigInterpreter())
	t.Cleanup(func() { _ = runtime.Close(context.Background()) })
	module, err := runtime.Instantiate(ctx, []byte{
		0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00,
		0x05, 0x03, 0x01, 0x00, 0x01,
		0x07, 0x0a, 0x01, 0x06, 'm', 'e', 'm', 'o', 'r', 'y', 0x02, 0x00,
	})
	if err != nil {
		t.Fatal(err)
	}
	n := wasm.HostReceiveUDPFrom(env)(ctx, module, 0, 128, 128, 128, 256)
	if n != int32(len(payload)) {
		t.Fatalf("received %d bytes, want %d", n, len(payload))
	}
	got, ok := module.Memory().Read(0, uint32(n))
	if !ok || string(got) != payload {
		t.Fatalf("guest received %q, want %q", got, payload)
	}
}
