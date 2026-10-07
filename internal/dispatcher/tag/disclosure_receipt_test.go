// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package tag

import (
	"errors"
	"testing"
	"time"
)

func TestDurableDisclosureCoverageRequiresCommittedBackend(t *testing.T) {
	keys := hashChain(0xD3, 8)
	chain := Chain{Anchor: keys[0]}
	memory := NewKeyStore()
	if err := memory.Store("executor", chain, time.Time{}, 3, keys[3]); err != nil {
		t.Fatal(err)
	}
	if _, ok := memory.DurableThrough("executor", chain.Anchor); ok {
		t.Fatal("memory-only store acknowledged durable completion")
	}
	backend := &memoryBackend{keys: map[string][]byte{}, fail: errors.New("write failure")}
	durable := NewPersistentKeyStore(backend)
	if err := durable.Store("executor", chain, time.Time{}, 3, keys[3]); err == nil {
		t.Fatal("write succeeded")
	}
	if _, ok := durable.DurableThrough("executor", chain.Anchor); ok {
		t.Fatal("failed write acknowledged")
	}
	backend.fail = nil
	for _, epoch := range []int64{3, 3, 5, 4} {
		if err := durable.Store("executor", chain, time.Time{}, epoch, keys[epoch]); err != nil {
			t.Fatal(err)
		}
	}
	if through, ok := durable.DurableThrough("executor", chain.Anchor); !ok || through != 5 || backend.saves != 2 {
		t.Fatalf("through=%d ok=%v saves=%d", through, ok, backend.saves)
	}
	restarted := NewPersistentKeyStore(backend)
	if err := restarted.Store("executor", chain, time.Time{}, 4, keys[4]); err != nil {
		t.Fatal(err)
	}
	if through, ok := restarted.DurableThrough("executor", chain.Anchor); !ok || through != 5 {
		t.Fatal(through, ok)
	}
}
