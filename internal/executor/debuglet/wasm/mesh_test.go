// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package wasm

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/netsec-ethz/debuglet/internal/executor/debuglet/netpolicy"
	"github.com/netsec-ethz/debuglet/internal/guestio"
	"github.com/netsec-ethz/debuglet/pkg/wire"
	"testing"
	"time"
)

func meshAdmitFixture(t *testing.T, env *WasmEnv, c guestio.MeshConfig) {
	t.Helper()
	admitted := wire.Experiment{ID: c.Group, StartTimeNS: c.StartMS * int64(time.Millisecond)}
	for _, p := range c.Peers {
		metadata, err := json.Marshal(map[string]string{"participant": p.Participant, "fingerprint": c.Fingerprint, "address": p.TCPAddress, "udp_address": p.UDPAddress})
		if err != nil {
			t.Fatal(err)
		}
		admitted.Participants = append(admitted.Participants, wire.ExperimentParticipant{ID: p.RunID, ExecutorID: p.ExecutorID, Metadata: metadata})
	}
	env.meshGroup = &admitted
}
func TestMeshRequiresExactAdmittedMembership(t *testing.T) {
	env, _, config, _ := meshTCPFixture(t)
	if err := env.validateMesh(&config); !errors.Is(err, netpolicy.ErrDenied) {
		t.Fatalf("missing Ready result: %v", err)
	}
	meshAdmitFixture(t, env, config)
	if err := env.validateMesh(&config); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*guestio.MeshConfig){
		func(c *guestio.MeshConfig) { c.Group = "other" },
		func(c *guestio.MeshConfig) { c.Fingerprint = "other" },
		func(c *guestio.MeshConfig) { c.Self = "b" },
		func(c *guestio.MeshConfig) { c.StartMS++ },
		func(c *guestio.MeshConfig) { c.Peers[1].TCPAddress = "203.0.113.1:443" },
		func(c *guestio.MeshConfig) { c.Peers[1].ExecutorID = "other" },
		func(c *guestio.MeshConfig) { c.Peers[1].RunID = "other" },
		func(c *guestio.MeshConfig) { c.Peers[1].Participant = c.Peers[0].Participant },
	} {
		c := config
		c.Peers = append([]guestio.MeshPeer(nil), config.Peers...)
		change(&c)
		if err := env.validateMesh(&c); !errors.Is(err, netpolicy.ErrDenied) {
			t.Fatalf("tampered membership accepted: %+v %v", c, err)
		}
	}
}
func TestMeshClaimsListenersBeforeLegacyCalls(t *testing.T) {
	env := newReceiveEnv()
	mod := newGuestModule(t)
	env.meshTCPClaim = true
	env.meshUDPClaim = true
	ctx := context.Background()
	for _, result := range []uint64{
		HostIOAcceptTCP(env)(ctx, 1),
		HostIOReceiveUDP(env)(ctx, mod.Memory(), 0, 1, 0, 1, 0, 1),
		HostIOReplyUDP(env)(ctx, mod.Memory(), 0, 1, 0, 1, 1),
	} {
		if uint32(result>>32) != guestio.Denied {
			t.Fatalf("owned listener operation=%x", result)
		}
	}
	if hostTrap(func() { HostAcceptTCP(env)(ctx) }) == nil {
		t.Fatal("legacy TCP accept raced service")
	}
	// Validate buffers before even stopping a service, including bridge chunk bounds.
	env.meshUDPClaim = true
	data := []byte(`{"service":1}`)
	mod.Memory().Write(0, data)
	if hostTrap(func() { hostMesh(env, "stop")(ctx, mod.Memory(), 0, uint32(len(data)), wasmPageSize-9000, 32768) }) == nil {
		t.Fatal("short output memory accepted")
	}
	if !env.meshUDPClaim {
		t.Fatal("invalid buffer mutated service ownership")
	}
	result := hostMesh(env, "stop")(ctx, boundedExperimentMemory{mod.Memory()}, 0, uint32(len(data)), 16384, 32768)
	if uint32(result>>32) != 0 || env.meshUDPClaim {
		t.Fatalf("stop result=%x", result)
	}
}
