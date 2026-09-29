// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package dispatcher

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/netsec-ethz/debuglet/internal/dispatcher/config"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/database"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/payments"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/tag"
	pb "github.com/netsec-ethz/debuglet/protocol"
	"go.uber.org/zap"
)

// attributionRegister registers id with the given chain anchor on d.
func attributionRegister(t *testing.T, d *Dispatcher, id string, anchor []byte) {
	t.Helper()
	attributionRegisterWith(t, d, id, anchor, nil)
}

// attributionRegisterWith registers id with the given chain anchor and hello
// capability report on d.
func attributionRegisterWith(t *testing.T, d *Dispatcher, id string, anchor []byte, caps *pb.ExecutorCapabilities) {
	t.Helper()
	owner := registryOwner(t, id)
	hello := registryHello(id)
	hello.TeslaAnchorKey = anchor
	hello.TeslaChainLength = 5
	hello.Capabilities = caps
	if err := registryRegisterWithSetup(context.Background(), d, owner, hello, "127.0.0.1"); err != nil {
		t.Fatal(err)
	}
	if !owner.MarkRegistered() {
		t.Fatal("fresh registration was retired")
	}
	t.Cleanup(func() { owner.Retire() })
}

func attributionHeartbeat(t *testing.T, d *Dispatcher, id string, req *pb.HeartbeatRequest) {
	t.Helper()
	mutation := effectTestMutation(t, d, id)
	defer mutation.Finish()
	req.ExecutorId = id
	if _, err := d.OnHeartbeat(t.Context(), mutation, req); err != nil {
		t.Fatal(err)
	}
}

func attributionKeyRows(t *testing.T, d *Dispatcher) int {
	t.Helper()
	var n int
	if err := d.db.QueryRow(`SELECT count(*) FROM attribution_keys`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// TestDisclosedKeysSurviveADispatcherRestart records a verified disclosure
// once, and a dispatcher started on the same database answers it and keeps
// verifying the chain from it.
func TestDisclosedKeysSurviveADispatcherRestart(t *testing.T) {
	d, db, _ := newRegistryFixture(t)
	const id = "durable"
	tail := bytes.Repeat([]byte{0x4E}, 32)
	anchor := chainKey(tail, 0)
	attributionRegister(t, d, id, anchor)
	attributionHeartbeat(t, d, id, &pb.HeartbeatRequest{TeslaKeyEpoch: 3, TeslaKey: chainKey(tail, 3)})
	attributionHeartbeat(t, d, id, &pb.HeartbeatRequest{TeslaKeyEpoch: 3, TeslaKey: chainKey(tail, 3)})
	if n := attributionKeyRows(t, d); n != 1 {
		t.Fatalf("a repeated disclosure is on record %d times; want once", n)
	}
	chain, err := database.New(db).GetAttributionChain(t.Context(), database.GetAttributionChainParams{ExecutorID: id, ChainID: tag.ChainID(anchor)})
	if err != nil || chain.ChainLength != 5 || chain.IntervalNs != int64(2*time.Second) || chain.TagSpec != tag.TagSpecLegacy {
		t.Fatalf("recorded chain=%+v, %v", chain, err)
	}
	d.Close()

	cfg := &config.DispatcherConfig{}
	cfg.Sui.Disabled = true
	restarted, err := New(zap.NewNop(), db, "restarted", time.Minute, time.Second, payments.NewPaymentHandler(db, cfg, zap.NewNop()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(restarted.Close)
	if epoch, key, ok := restarted.keystore.LatestDisclosed(id, anchor); !ok || epoch != 3 || !bytes.Equal(key, chainKey(tail, 3)) {
		t.Fatalf("after restart latest=(%d, %x, %v); want k_3", epoch, key, ok)
	}
	// The next disclosure verifies against the key on record, not the anchor,
	// and a forged one is still dropped.
	attributionRegister(t, restarted, id, anchor)
	attributionHeartbeat(t, restarted, id, &pb.HeartbeatRequest{TeslaKeyEpoch: 4, TeslaKey: bytes.Repeat([]byte{0xEE}, 32)})
	attributionHeartbeat(t, restarted, id, &pb.HeartbeatRequest{TeslaKeyEpoch: 5, TeslaKey: tail})
	if epoch, _, ok := restarted.keystore.LatestDisclosed(id, anchor); !ok || epoch != 5 {
		t.Fatalf("after restart the chain continued to (%d, %v); want epoch 5", epoch, ok)
	}
	if key, ok := restarted.keystore.Get(id, anchor, 3); !ok || !bytes.Equal(key, chainKey(tail, 3)) {
		t.Fatalf("k_3 after restart=(%x, %v)", key, ok)
	}
	if n := attributionKeyRows(t, restarted); n != 2 {
		t.Fatalf("%d keys on record; want k_3 and k_5", n)
	}
}

// TestDisclosureForAnEarlierRecordedChain accepts the tail of a chain the
// executor announced before it restarted onto a new one, verified against the
// recorded schedule, and drops a key for a chain that is not on record.
func TestDisclosureForAnEarlierRecordedChain(t *testing.T) {
	d, _, _ := newRegistryFixture(t)
	const id = "rolled"
	tailA, tailB := bytes.Repeat([]byte{0x5A}, 32), bytes.Repeat([]byte{0x5B}, 32)
	anchorA, anchorB := chainKey(tailA, 0), chainKey(tailB, 0)
	attributionRegister(t, d, id, anchorA)
	d.mu.RLock()
	d.executors[id].owner.Retire()
	d.mu.RUnlock()
	attributionRegister(t, d, id, anchorB)

	attributionHeartbeat(t, d, id, &pb.HeartbeatRequest{TeslaKeyEpoch: 5, TeslaKey: tailA, TeslaKeyAnchor: anchorA})
	if epoch, key, ok := d.keystore.LatestDisclosed(id, anchorA); !ok || epoch != 5 || !bytes.Equal(key, tailA) {
		t.Fatalf("earlier chain latest=(%d, %x, %v); want its k_5", epoch, key, ok)
	}
	if _, _, ok := d.keystore.LatestDisclosed(id, anchorB); ok {
		t.Fatal("a key of the earlier chain was stored under the current one")
	}
	unknown := bytes.Repeat([]byte{0x5C}, 32)
	attributionHeartbeat(t, d, id, &pb.HeartbeatRequest{TeslaKeyEpoch: 5, TeslaKey: unknown, TeslaKeyAnchor: chainKey(unknown, 0)})
	if n := attributionKeyRows(t, d); n != 1 {
		t.Fatalf("%d keys on record; want only the earlier chain's k_5", n)
	}
	// A key of the current chain may still name it explicitly.
	attributionHeartbeat(t, d, id, &pb.HeartbeatRequest{TeslaKeyEpoch: 5, TeslaKey: tailB, TeslaKeyAnchor: anchorB})
	if epoch, _, ok := d.keystore.LatestDisclosed(id, anchorB); !ok || epoch != 5 {
		t.Fatalf("current chain latest=(%d, %v); want epoch 5", epoch, ok)
	}
}

// TestRecordedChainCarriesTheReportedTagSpec records the tag specification the
// executor reported in its hello with the chain: v1 only for debuglet-tag-v1,
// and legacy (0) for an executor that predates the report, reports no tagging
// or reports an identifier this dispatcher does not know. A disclosure for the
// chain keeps what registration recorded.
func TestRecordedChainCarriesTheReportedTagSpec(t *testing.T) {
	d, db, _ := newRegistryFixture(t)
	caps := func(tagging *pb.TaggingMode) *pb.ExecutorCapabilities {
		return &pb.ExecutorCapabilities{SchemaVersion: 1, Protocols: []string{"tcp"}, EnforcementMode: "ebpf", Tagging: tagging}
	}
	for i, tc := range []struct {
		name string
		caps *pb.ExecutorCapabilities
		want int64
	}{
		{"v1", caps(&pb.TaggingMode{Ipv4: "ebpf", Ipv6: "none", Scion: "none", TagSpec: "debuglet-tag-v1"}), tag.TagSpecV1},
		{"pre-v1 executor", caps(&pb.TaggingMode{Ipv4: "ebpf", Ipv6: "none", Scion: "none"}), tag.TagSpecLegacy},
		{"no tagging report", caps(nil), tag.TagSpecLegacy},
		{"no capability report", nil, tag.TagSpecLegacy},
		{"unknown spec", caps(&pb.TaggingMode{Ipv4: "ebpf", Ipv6: "none", Scion: "none", TagSpec: "debuglet-tag-v9"}), tag.TagSpecLegacy},
	} {
		t.Run(tc.name, func(t *testing.T) {
			id := "spec-" + string(rune('a'+i))
			tail := bytes.Repeat([]byte{byte(0x60 + i)}, 32)
			anchor := chainKey(tail, 0)
			attributionRegisterWith(t, d, id, anchor, tc.caps)
			attributionHeartbeat(t, d, id, &pb.HeartbeatRequest{TeslaKeyEpoch: 5, TeslaKey: tail})
			chain, err := database.New(db).GetAttributionChain(t.Context(), database.GetAttributionChainParams{ExecutorID: id, ChainID: tag.ChainID(anchor)})
			if err != nil || chain.TagSpec != tc.want {
				t.Fatalf("recorded tag_spec=%d, %v; want %d", chain.TagSpec, err, tc.want)
			}
			if n := attributionKeyRows(t, d); n != i+1 {
				t.Fatalf("%d keys on record; want %d", n, i+1)
			}
		})
	}
}

func TestPruneAttributionAdvancesRetainedFrom(t *testing.T) {
	d, db, _ := newRegistryFixture(t)
	if err := d.ConfigureAttribution(config.AttributionConfig{RetentionDays: 0}); err == nil {
		t.Fatal("a zero retention was accepted")
	}
	if err := d.ConfigureAttribution(config.AttributionConfig{RetentionDays: 1}); err != nil {
		t.Fatal(err)
	}
	now := time.Now().Add(48 * time.Hour)
	if err := d.PruneAttribution(t.Context(), now); err != nil {
		t.Fatal(err)
	}
	retained, err := database.New(db).GetAttributionRetention(t.Context())
	if err != nil || retained != now.Add(-24*time.Hour).UnixNano() {
		t.Fatalf("retained_from=%d, %v; want now less one day", retained, err)
	}
}
