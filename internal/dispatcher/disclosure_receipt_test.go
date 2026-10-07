// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package dispatcher

import (
	"bytes"
	"testing"
	"time"

	"github.com/netsec-ethz/debuglet/internal/dispatcher/tag"
	pb "github.com/netsec-ethz/debuglet/protocol"
)

type heldDisclosureBackend struct {
	tag.Backend
	entered, release chan struct{}
}

func (b *heldDisclosureBackend) Save(id string, chain tag.Chain, epoch int64, key []byte, at time.Time) error {
	close(b.entered)
	<-b.release
	return b.Backend.Save(id, chain, epoch, key, at)
}

func TestDisclosureReceiptFollowsRealDurableCommit(t *testing.T) {
	d, db, _ := newRegistryFixture(t)
	const id = "receipt"
	tail := bytes.Repeat([]byte{0x6D}, 32)
	anchor := chainKey(tail, 0)
	attributionRegister(t, d, id, anchor)
	held := &heldDisclosureBackend{Backend: attributionBackend{db: db}, entered: make(chan struct{}), release: make(chan struct{})}
	d.keystore = tag.NewPersistentKeyStore(held)
	mutation := effectTestMutation(t, d, id)
	type result struct {
		response *pb.HeartbeatResponse
		err      error
	}
	done := make(chan result, 1)
	go func() {
		defer mutation.Finish()
		response, err := d.OnHeartbeat(mutation.Context(), mutation, &pb.HeartbeatRequest{ExecutorId: id, TeslaKeyEpoch: 3, TeslaKey: chainKey(tail, 3)})
		done <- result{response, err}
	}()
	select {
	case <-held.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("write not reached")
	}
	select {
	case got := <-done:
		t.Fatal("receipt before commit", got)
	default:
	}
	if n := attributionKeyRows(t, d); n != 0 {
		t.Fatal("uncommitted row visible", n)
	}
	close(held.release)
	got := <-done
	if got.err != nil || len(got.response.GetDisclosureReceipts()) != 1 || got.response.DisclosureReceipts[0].StoredThroughEpoch != 3 {
		t.Fatal(got)
	}
	if n := attributionKeyRows(t, d); n != 1 {
		t.Fatal("receipt before row commit", n)
	}
	// A restarted key store proves duplicate coverage from the actual database.
	d.keystore = tag.NewPersistentKeyStore(attributionBackend{db: db})
	heartbeat := func(epoch int64, key []byte, extra []*pb.TeslaDisclosure) []*pb.TeslaDisclosureReceipt {
		t.Helper()
		m := effectTestMutation(t, d, id)
		defer m.Finish()
		out, err := d.OnHeartbeat(m.Context(), m, &pb.HeartbeatRequest{ExecutorId: id, TeslaKeyEpoch: epoch, TeslaKey: key, ExtraDisclosures: extra})
		if err != nil {
			t.Fatal(err)
		}
		return out.DisclosureReceipts
	}
	if receipts := heartbeat(3, chainKey(tail, 3), nil); len(receipts) != 1 {
		t.Fatal(receipts)
	}
	if _, err := db.Exec("CREATE TRIGGER fail_disclosure BEFORE INSERT ON attribution_keys BEGIN SELECT RAISE(FAIL, 'controlled storage failure'); END"); err != nil {
		t.Fatal(err)
	}
	if receipts := heartbeat(5, tail, nil); len(receipts) != 0 {
		t.Fatal("failed storage acknowledged", receipts)
	}
	if n := attributionKeyRows(t, d); n != 1 {
		t.Fatal(n)
	}
	if _, err := db.Exec("DROP TRIGGER fail_disclosure"); err != nil {
		t.Fatal(err)
	}
	if receipts := heartbeat(5, tail, nil); len(receipts) != 1 || receipts[0].StoredThroughEpoch != 5 {
		t.Fatal(receipts)
	}
	// An ignored lower submission is a prefix receipt, not acceptance of its bytes.
	if receipts := heartbeat(4, bytes.Repeat([]byte{0xFF}, 32), nil); len(receipts) != 1 || receipts[0].StoredThroughEpoch != 4 {
		t.Fatal(receipts)
	}
	if receipts := heartbeat(5, bytes.Repeat([]byte{0xFF}, 32), nil); len(receipts) != 0 {
		t.Fatal("conflicting key acknowledged", receipts)
	}
	if receipts := heartbeat(0, nil, make([]*pb.TeslaDisclosure, 5)); len(receipts) != 0 {
		t.Fatal("oversized extras acknowledged", receipts)
	}
	d.keystore = tag.NewKeyStore()
	if receipts := heartbeat(5, tail, nil); len(receipts) != 0 {
		t.Fatal("memory store acknowledged", receipts)
	}
}
