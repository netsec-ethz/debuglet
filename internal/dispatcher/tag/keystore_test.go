// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package tag

import (
	"bytes"
	"testing"
)

func key(b byte) []byte { return bytes.Repeat([]byte{b}, 32) }

// TestKeyStoreKeepsDisclosuresPerChain stores two chains of one executor with
// the same epochs, as an executor restart produces, and checks that each
// chain answers with its own keys.
func TestKeyStoreKeepsDisclosuresPerChain(t *testing.T) {
	ks := NewKeyStore()
	const id = "executor"
	anchorA, anchorB := key(0xA0), key(0xB0)
	for epoch := int64(1); epoch <= 3; epoch++ {
		if err := ks.Store(id, anchorA, epoch, key(0xA0+byte(epoch))); err != nil {
			t.Fatal(err)
		}
		if err := ks.Store(id, anchorB, epoch, key(0xB0+byte(epoch))); err != nil {
			t.Fatal(err)
		}
	}
	// A repeated disclosure does not replace the first one of its chain.
	if err := ks.Store(id, anchorB, 3, key(0xFF)); err != nil {
		t.Fatal(err)
	}
	for _, want := range []struct {
		anchor []byte
		key    byte
	}{{anchorA, 0xA3}, {anchorB, 0xB3}} {
		if epoch, k, ok := ks.LatestDisclosed(id, want.anchor); !ok || epoch != 3 || !bytes.Equal(k, key(want.key)) {
			t.Errorf("LatestDisclosed(%x) = (%d, %x, %v); want (3, %x, true)", want.anchor[0], epoch, k, ok, want.key)
		}
	}
	if k, ok := ks.Get(id, anchorA, 2); !ok || !bytes.Equal(k, key(0xA2)) {
		t.Errorf("Get(A, 2) = (%x, %v); want A's key", k, ok)
	}
	if _, _, ok := ks.LatestDisclosed(id, key(0xC0)); ok {
		t.Error("an unknown chain answered")
	}
	if _, _, ok := ks.LatestDisclosed("other", anchorA); ok {
		t.Error("another executor answered with this executor's chain")
	}
}

// TestKeyStoreBoundsChainsPerExecutor checks that a fifth chain evicts the
// oldest one and that an executor without an anchor keeps its disclosures.
func TestKeyStoreBoundsChainsPerExecutor(t *testing.T) {
	ks := NewKeyStore()
	const id = "executor"
	for c := byte(1); c <= maxChainsPerExecutor+1; c++ {
		if err := ks.Store(id, key(c), 1, key(0x10+c)); err != nil {
			t.Fatal(err)
		}
	}
	if _, _, ok := ks.LatestDisclosed(id, key(1)); ok {
		t.Error("the oldest chain was kept past the bound")
	}
	if n := len(ks.chains[id]); n != maxChainsPerExecutor {
		t.Errorf("executor keeps %d chains, want %d", n, maxChainsPerExecutor)
	}
	for c := byte(2); c <= maxChainsPerExecutor+1; c++ {
		if _, k, ok := ks.LatestDisclosed(id, key(c)); !ok || !bytes.Equal(k, key(0x10+c)) {
			t.Errorf("chain %d = (%x, %v); want its key", c, k, ok)
		}
	}

	if err := ks.Store("anchorless", nil, 4, key(0x44)); err != nil {
		t.Fatal(err)
	}
	if epoch, k, ok := ks.LatestDisclosed("anchorless", []byte{}); !ok || epoch != 4 || !bytes.Equal(k, key(0x44)) {
		t.Errorf("empty anchor = (%d, %x, %v); want (4, key, true)", epoch, k, ok)
	}
}
