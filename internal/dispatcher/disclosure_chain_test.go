// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package dispatcher

import (
	"bytes"
	"context"
	"crypto/sha256"
	"testing"
	"time"

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

// TestHeartbeatBoundsDisclosuresByRegisteredSchedule checks that the heartbeat
// handler applies the schedule the executor registered, disclosure delay
// included: a disclosure before its epoch plus d is dropped and reported once
// as an early disclosure, the one due now is stored.
func TestHeartbeatBoundsDisclosuresByRegisteredSchedule(t *testing.T) {
	d, _, _ := newRegistryFixture(t)
	core, logs := observer.New(zapcore.WarnLevel)
	d.logger = zap.New(core)
	start := time.Unix(1_700_000_000, 0)
	d.now = func() time.Time { return start.Add(105 * time.Second) }
	const id = "scheduled"
	tail := bytes.Repeat([]byte{0x3D}, 32)
	owner := registryOwner(t, id)
	hello := registryHello(id)
	hello.TeslaAnchorKey = chainKey(tail, 0)
	hello.TeslaAnchorTimestampNs = start.UnixNano()
	hello.TeslaDelaySec = 20
	hello.TeslaDisclosureDelayEpochs = 2
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

	// With 20s epochs, start+105s (110s with the skew allowance) is epoch 5
	// and d = 2 allows at most k_3: the genuine k_5 and k_4 are early.
	heartbeat(5, tail)
	heartbeat(4, chainKey(tail, 4))
	if _, _, ok := d.keystore.LatestDisclosed(id, hello.TeslaAnchorKey); ok {
		t.Fatal("a disclosure ahead of the registered schedule was stored")
	}
	if n := logs.FilterMessage("Executor disclosed a TESLA key early; it is misbehaving").FilterLevelExact(zapcore.ErrorLevel).Len(); n != 1 {
		t.Fatalf("early disclosures logged %d times; want once", n)
	}
	heartbeat(3, chainKey(tail, 3))
	if epoch, _, ok := d.keystore.LatestDisclosed(id, hello.TeslaAnchorKey); !ok || epoch != 3 {
		t.Fatalf("latest disclosure = (%d, %v); want epoch 3", epoch, ok)
	}
}

// TestHeartbeatExtraDisclosures checks the extra disclosures beside the
// current chain's key: one for an earlier recorded chain is stored under that
// chain together with the current key, repeated and reordered ones change
// nothing, one for an unrecorded anchor is dropped, and a heartbeat with more
// than maxExtraDisclosures of them has all of them refused.
func TestHeartbeatExtraDisclosures(t *testing.T) {
	d, _, _ := newRegistryFixture(t)
	core, logs := observer.New(zapcore.WarnLevel)
	d.logger = zap.New(core)
	const id = "restarted-tail"
	tailA, tailB := bytes.Repeat([]byte{0x6A}, 32), bytes.Repeat([]byte{0x6B}, 32)
	anchorA, anchorB := chainKey(tailA, 0), chainKey(tailB, 0)
	attributionRegister(t, d, id, anchorA)
	d.mu.RLock()
	d.executors[id].owner.Retire()
	d.mu.RUnlock()
	attributionRegister(t, d, id, anchorB)
	extraA := func(epochs ...int) []*pb.TeslaDisclosure {
		var out []*pb.TeslaDisclosure
		for _, epoch := range epochs {
			out = append(out, &pb.TeslaDisclosure{Anchor: anchorA, Epoch: int64(epoch), Key: chainKey(tailA, epoch)})
		}
		return out
	}

	attributionHeartbeat(t, d, id, &pb.HeartbeatRequest{ExtraDisclosures: extraA(1, 2, 3, 4, 5)})
	if _, _, ok := d.keystore.LatestDisclosed(id, anchorA); ok || attributionKeyRows(t, d) != 0 {
		t.Fatal("a heartbeat with more extra disclosures than allowed stored one")
	}
	if n := logs.FilterMessage("Refused a heartbeat's extra TESLA disclosures").Len(); n != 1 {
		t.Fatalf("refusal logged %d times; want once", n)
	}

	attributionHeartbeat(t, d, id, &pb.HeartbeatRequest{TeslaKeyEpoch: 5, TeslaKey: tailB, ExtraDisclosures: extraA(4)})
	for _, want := range []struct {
		name   string
		anchor []byte
		epoch  int64
		key    []byte
	}{{"current", anchorB, 5, tailB}, {"earlier", anchorA, 4, chainKey(tailA, 4)}} {
		if epoch, key, ok := d.keystore.LatestDisclosed(id, want.anchor); !ok || epoch != want.epoch || !bytes.Equal(key, want.key) {
			t.Fatalf("%s chain latest=(%d, %x, %v); want k_%d", want.name, epoch, key, ok, want.epoch)
		}
	}

	attributionHeartbeat(t, d, id, &pb.HeartbeatRequest{ExtraDisclosures: extraA(5, 3, 5, 4)})
	attributionHeartbeat(t, d, id, &pb.HeartbeatRequest{ExtraDisclosures: extraA(5)})
	if epoch, _, ok := d.keystore.LatestDisclosed(id, anchorA); !ok || epoch != 5 {
		t.Fatalf("earlier chain latest=(%d, %v) after repeated disclosures; want k_5", epoch, ok)
	}
	rows := attributionKeyRows(t, d)
	unknown := bytes.Repeat([]byte{0x6C}, 32)
	attributionHeartbeat(t, d, id, &pb.HeartbeatRequest{ExtraDisclosures: []*pb.TeslaDisclosure{{Anchor: chainKey(unknown, 0), Epoch: 5, Key: unknown}}})
	if n := attributionKeyRows(t, d); n != rows {
		t.Fatalf("%d keys on record after an unrecorded chain's disclosure; want %d", n, rows)
	}
	if n := logs.FilterMessage("Rejected disclosed TESLA key").Len() + logs.FilterMessage("Executor disclosed a TESLA key early; it is misbehaving").Len(); n != 0 {
		t.Fatalf("genuine disclosures were rejected %d times", n)
	}
}
