// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package wasm

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/netsec-ethz/debuglet/internal/executor/debuglet/netpolicy"
	"github.com/netsec-ethz/debuglet/internal/guestio"
)

func meshUDPFixture(t *testing.T, count int) ([]*WasmEnv, []guestio.MeshPeer) {
	t.Helper()
	envs := make([]*WasmEnv, count)
	peers := make([]guestio.MeshPeer, count)
	for i := range envs {
		server, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatal(err)
		}
		env := policyEnv(t, localSpec(), netpolicy.Run{Addresses: []string{"127.0.0.1"}, ListenUDP: true})
		env.UdpServer = server
		envs[i] = env
		peers[i] = guestio.MeshPeer{Participant: fmt.Sprintf("peer-%d", i), RunID: env.DebugletID.String(), ExecutorID: fmt.Sprintf("executor-%d", i), UDPAddress: server.LocalAddr().String()}
	}
	return envs, peers
}

func meshUDPFixtureConfig(peers []guestio.MeshPeer, self string, start time.Time) guestio.MeshConfig {
	return guestio.MeshConfig{Kind: "udp", Group: "mesh-fixture", Fingerprint: "fixture-fingerprint", Self: self, Peers: peers, StartMS: start.UnixMilli(), DurationMS: 3000, IntervalMS: 1000, WindowMS: 2000}
}

// Three production services exchange probes using the normal listener policy,
// accounting and outbound socket registry. The final one-second window must
// survive the two-second receive grace without becoming a fabricated RTT.
func TestMeshUDPWindowsAndPartialFinal(t *testing.T) {
	envs, peers := meshUDPFixture(t, 3)
	ctx, cancel := context.WithTimeout(t.Context(), 7*time.Second)
	defer cancel()
	start := time.Now().Add(200 * time.Millisecond)
	services := make([]*meshUDP, len(envs))
	for i, env := range envs {
		service, err := startMeshUDP(ctx, env, meshUDPFixtureConfig(peers, peers[i].Participant, start))
		if err != nil {
			t.Fatal(err)
		}
		services[i] = service
		t.Cleanup(func() { _ = service.Close() })
	}
	for i, service := range services {
		select {
		case <-service.done:
		case <-ctx.Done():
			t.Fatal("mesh service did not finish within grace")
		}
		for window, expectedSent := range []int{2, 1} {
			snapshot := service.Snapshot()
			if !snapshot.OK || snapshot.Error != "" || snapshot.SkippedWindows != 0 || len(snapshot.Rows) != 2 {
				t.Fatalf("peer %d window %d: %+v", i, window, snapshot)
			}
			wantStart := start.UnixMilli() + int64(window)*2000
			wantEnd := start.UnixMilli() + int64(2000+window*1000)
			if snapshot.WindowStartMS != wantStart || snapshot.WindowEndMS != wantEnd {
				t.Fatalf("incorrect full/partial window bounds: %+v", snapshot)
			}
			for _, row := range snapshot.Rows {
				if row["self"] != peers[i].Participant || row["peer"] == peers[i].Participant || row["sent"] != expectedSent || row["received"] != expectedSent || row["echoes"] != expectedSent || row["remote_sent"] != expectedSent || row["delivered"] != expectedSent || row["loss_percent"] != float64(0) || row["loss_ok"] != true || row["write_errors"] != 0 || row["skipped"] != 0 {
					t.Errorf("peer %d window %d accounting: %+v", i, window, row)
				}
				if window == 0 {
					mean, ok := row["rtt_mean_ms"].(float64)
					if !ok || mean <= 0 || row["rtt_ok"] != true || row["rtt_variation_ms"] == nil {
						t.Errorf("missing measured RTT: %+v", row)
					}
				} else if row["rtt_ok"] != false || row["rtt_mean_ms"] != nil || row["rtt_variation_ms"] != nil {
					t.Errorf("one sample must not fabricate complete timing statistics: %+v", row)
				}
			}
		}
		if snapshot := service.Snapshot(); len(snapshot.Rows) != 0 {
			t.Fatalf("duplicate window returned: %+v", snapshot)
		}
	}
}

func TestMeshUDPCloseJoinsAndRestoresListener(t *testing.T) {
	envs, peers := meshUDPFixture(t, 2)
	service, err := startMeshUDP(t.Context(), envs[0], meshUDPFixtureConfig(peers, peers[0].Participant, time.Now().Add(time.Minute)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = service.Close() })
	handle := service.peers[peers[1].Participant].handle
	if err := service.Close(); err != nil {
		t.Fatal(err)
	}
	if err := service.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-service.done:
	default:
		t.Fatal("Close returned before service joined")
	}
	if _, err := envs[0].Registry.Get(handle); err == nil {
		t.Fatal("mesh outbound socket leaked after Close")
	}
	type readResult struct {
		payload string
		err     error
	}
	read := make(chan readResult, 1)
	go func() {
		data := make([]byte, 32)
		n, _, err := envs[0].UdpServer.ReadFromUDP(data)
		read <- readResult{string(data[:n]), err}
	}()
	// A stale cancellation deadline would make this read return immediately.
	select {
	case result := <-read:
		t.Fatalf("listener was not reusable after Close: %+v", result)
	case <-time.After(20 * time.Millisecond):
	}
	if _, err := envs[1].UdpServer.WriteToUDP([]byte("after-stop"), envs[0].UdpServer.LocalAddr().(*net.UDPAddr)); err != nil {
		t.Fatal(err)
	}
	select {
	case result := <-read:
		if result.err != nil || result.payload != "after-stop" {
			t.Fatalf("reused listener: %+v", result)
		}
	case <-time.After(time.Second):
		t.Fatal("listener remained blocked after mesh cancellation")
	}
}

func TestMeshUDPSnapshotBoundAndLossMath(t *testing.T) {
	service := &meshUDP{}
	for i := range 6 {
		service.publish(guestio.MeshSnapshot{WindowEndMS: int64(i)})
	}
	for i := 2; i < 6; i++ {
		snapshot := service.Snapshot()
		wantDropped := 0
		if i == 2 {
			wantDropped = 2
		}
		if snapshot.WindowEndMS != int64(i) || snapshot.SkippedWindows != wantDropped {
			t.Fatalf("bounded queue order/loss accounting: %+v", snapshot)
		}
	}
	if snapshot := service.Snapshot(); len(snapshot.Rows) != 0 || snapshot.SkippedWindows != 0 {
		t.Fatalf("empty queue: %+v", snapshot)
	}
	window := &meshUDPWindow{sent: []bool{true, true, false}, received: []bool{true, false, true}, echoed: []bool{true, false, false}, remote: []bool{true, true, false}, rtts: []float64{30, 10, 20}}
	row := meshUDPRow("a", "b", window, 2)
	if row["remote_sent"] != 2 || row["delivered"] != 1 || row["loss_percent"] != float64(50) || row["rtt_mean_ms"] != float64(20) || row["rtt_p95_ms"] != float64(30) || row["rtt_variation_ms"] != float64(15) || row["skipped"] != 2 || row["loss_series"] != "b → a" {
		t.Fatalf("bitmap intersection or unsorted RTT variation: %+v", row)
	}
	window.remote, window.rtts = nil, nil
	row = meshUDPRow("a", "b", window, 0)
	if row["loss_ok"] != false || row["loss_percent"] != nil || row["remote_sent"] != nil || row["rtt_ok"] != false || row["rtt_mean_ms"] != nil {
		t.Fatalf("missing evidence must remain unavailable: %+v", row)
	}
}
