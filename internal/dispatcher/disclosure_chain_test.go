// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package dispatcher

import (
	"bytes"
	"context"
	"testing"

	pb "github.com/netsec-ethz/debuglet/protocol"
)

// TestDisclosuresFollowTheRegisteredChain registers one executor twice with
// different chains, as a restarted executor does, and checks that each chain's
// disclosure for the same epoch is kept under its own anchor.
func TestDisclosuresFollowTheRegisteredChain(t *testing.T) {
	d, _, _ := newRegistryFixture(t)
	const id = "restarted"
	anchorA, anchorB := bytes.Repeat([]byte{0xA}, 32), bytes.Repeat([]byte{0xB}, 32)
	keyA, keyB := bytes.Repeat([]byte{0x1A}, 32), bytes.Repeat([]byte{0x1B}, 32)

	register := func(anchor []byte) {
		t.Helper()
		owner := registryOwner(t, id)
		hello := registryHello(id)
		hello.TeslaAnchorKey = anchor
		if err := registryRegisterWithSetup(context.Background(), d, owner, hello, "127.0.0.1"); err != nil {
			t.Fatal(err)
		}
		if !owner.MarkRegistered() {
			t.Fatal("fresh registration was retired")
		}
		t.Cleanup(func() { owner.Retire() })
	}
	heartbeat := func(key []byte) {
		t.Helper()
		mutation := effectTestMutation(t, d, id)
		defer mutation.Finish()
		if _, err := d.OnHeartbeat(t.Context(), mutation, &pb.HeartbeatRequest{ExecutorId: id, TeslaKeyEpoch: 5, TeslaKey: key}); err != nil {
			t.Fatal(err)
		}
	}

	register(anchorA)
	heartbeat(keyA)
	d.mu.RLock()
	d.executors[id].owner.Retire()
	d.mu.RUnlock()
	register(anchorB)
	heartbeat(keyB)

	for _, want := range []struct {
		name        string
		anchor, key []byte
	}{{"B", anchorB, keyB}, {"A", anchorA, keyA}} {
		if epoch, key, ok := d.keystore.LatestDisclosed(id, want.anchor); !ok || epoch != 5 || !bytes.Equal(key, want.key) {
			t.Fatalf("latest disclosure for chain %s = (%d, %x, %v); want (5, %x, true)", want.name, epoch, key, ok, want.key)
		}
	}
}
