// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package dispatcher

import (
	"bytes"
	"context"
	"crypto/sha256"
	"testing"

	pb "github.com/netsec-ethz/debuglet/protocol"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
)

// chainKey returns k_epoch of a chain whose k_5 is tail, k_i = H(k_{i+1}).
func chainKey(tail []byte, epoch int) []byte {
	k := tail
	for range 5 - epoch {
		sum := sha256.Sum256(k)
		k = sum[:]
	}
	return k
}

// TestDisclosuresFollowTheRegisteredChain registers one executor twice with
// different chains, as a restarted executor does, and checks that each chain's
// disclosure for the same epoch is kept under its own anchor.
func TestDisclosuresFollowTheRegisteredChain(t *testing.T) {
	d, _, _ := newRegistryFixture(t)
	const id = "restarted"
	keyA, keyB := bytes.Repeat([]byte{0x1A}, 32), bytes.Repeat([]byte{0x1B}, 32)
	anchorA, anchorB := chainKey(keyA, 0), chainKey(keyB, 0)

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

// TestHeartbeatDropsForgedDisclosures checks that a key which does not hash to
// the registered anchor is not stored, that the heartbeat still succeeds, and
// that the chain is warned about once rather than on every heartbeat.
func TestHeartbeatDropsForgedDisclosures(t *testing.T) {
	d, _, _ := newRegistryFixture(t)
	core, logs := observer.New(zapcore.WarnLevel)
	d.logger = zap.New(core)
	const id = "forger"
	tail := bytes.Repeat([]byte{0x2C}, 32)
	owner := registryOwner(t, id)
	hello := registryHello(id)
	hello.TeslaAnchorKey = chainKey(tail, 0)
	if err := registryRegisterWithSetup(context.Background(), d, owner, hello, "127.0.0.1"); err != nil {
		t.Fatal(err)
	}
	if !owner.MarkRegistered() {
		t.Fatal("fresh registration was retired")
	}
	t.Cleanup(func() { owner.Retire() })
	heartbeat := func(epoch int64, key []byte) {
		t.Helper()
		mutation := effectTestMutation(t, d, id)
		defer mutation.Finish()
		if _, err := d.OnHeartbeat(t.Context(), mutation, &pb.HeartbeatRequest{ExecutorId: id, TeslaKeyEpoch: epoch, TeslaKey: key}); err != nil {
			t.Fatal(err)
		}
	}

	heartbeat(3, bytes.Repeat([]byte{0xEE}, 32))
	heartbeat(4, bytes.Repeat([]byte{0xEF}, 32))
	if _, _, ok := d.keystore.LatestDisclosed(id, hello.TeslaAnchorKey); ok {
		t.Fatal("a forged disclosure was stored")
	}
	if n := logs.FilterMessage("Rejected disclosed TESLA key").Len(); n != 1 {
		t.Fatalf("forged disclosures warned %d times; want once", n)
	}
	heartbeat(5, tail)
	if epoch, key, ok := d.keystore.LatestDisclosed(id, hello.TeslaAnchorKey); !ok || epoch != 5 || !bytes.Equal(key, tail) {
		t.Fatalf("latest disclosure = (%d, %x, %v); want the genuine k_5", epoch, key, ok)
	}
}
