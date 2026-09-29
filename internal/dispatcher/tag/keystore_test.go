// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package tag

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"strings"
	"testing"
)

func key(b byte) []byte { return bytes.Repeat([]byte{b}, 32) }

// hashChain returns k_0 … k_n of a chain with tail key(seed), k_i = H(k_{i+1}).
func hashChain(seed byte, n int) [][]byte {
	keys := make([][]byte, n+1)
	keys[n] = key(seed)
	for i := n - 1; i >= 0; i-- {
		sum := sha256.Sum256(keys[i+1])
		keys[i] = sum[:]
	}
	return keys
}

// rejected returns the *RejectedError in err, failing the test if there is none.
func rejected(t *testing.T, err error) *RejectedError {
	t.Helper()
	var r *RejectedError
	if !errors.As(err, &r) {
		t.Fatalf("Store = %v; want a rejection", err)
	}
	return r
}

// TestKeyStoreKeepsDisclosuresPerChain stores two chains of one executor with
// the same epochs, as an executor restart produces, and checks that each
// chain answers with its own keys.
func TestKeyStoreKeepsDisclosuresPerChain(t *testing.T) {
	ks := NewKeyStore()
	const id = "executor"
	chainA, chainB := hashChain(0xA0, 4), hashChain(0xB0, 4)
	for epoch := int64(1); epoch <= 3; epoch++ {
		if err := ks.Store(id, chainA[0], epoch, chainA[epoch]); err != nil {
			t.Fatal(err)
		}
		if err := ks.Store(id, chainB[0], epoch, chainB[epoch]); err != nil {
			t.Fatal(err)
		}
	}
	// A repeated disclosure is a no-op.
	if err := ks.Store(id, chainB[0], 3, chainB[3]); err != nil {
		t.Fatal(err)
	}
	for _, want := range []struct {
		name  string
		chain [][]byte
	}{{"A", chainA}, {"B", chainB}} {
		if epoch, k, ok := ks.LatestDisclosed(id, want.chain[0]); !ok || epoch != 3 || !bytes.Equal(k, want.chain[3]) {
			t.Errorf("LatestDisclosed(%s) = (%d, %x, %v); want (3, k_3, true)", want.name, epoch, k, ok)
		}
	}
	if k, ok := ks.Get(id, chainA[0], 2); !ok || !bytes.Equal(k, chainA[2]) {
		t.Errorf("Get(A, 2) = (%x, %v); want A's key", k, ok)
	}
	if _, _, ok := ks.LatestDisclosed(id, key(0xC0)); ok {
		t.Error("an unknown chain answered")
	}
	if _, _, ok := ks.LatestDisclosed("other", chainA[0]); ok {
		t.Error("another executor answered with this executor's chain")
	}
}

// TestKeyStoreBoundsChainsPerExecutor checks that a fifth chain evicts the
// oldest one and that an executor without an anchor has nothing verified.
func TestKeyStoreBoundsChainsPerExecutor(t *testing.T) {
	ks := NewKeyStore()
	const id = "executor"
	chains := make([][][]byte, maxChainsPerExecutor+2)
	for c := byte(1); c <= maxChainsPerExecutor+1; c++ {
		chains[c] = hashChain(c, 1)
		if err := ks.Store(id, chains[c][0], 1, chains[c][1]); err != nil {
			t.Fatal(err)
		}
	}
	if _, _, ok := ks.LatestDisclosed(id, chains[1][0]); ok {
		t.Error("the oldest chain was kept past the bound")
	}
	if n := len(ks.chains[id]); n != maxChainsPerExecutor {
		t.Errorf("executor keeps %d chains, want %d", n, maxChainsPerExecutor)
	}
	for c := byte(2); c <= maxChainsPerExecutor+1; c++ {
		if _, k, ok := ks.LatestDisclosed(id, chains[c][0]); !ok || !bytes.Equal(k, chains[c][1]) {
			t.Errorf("chain %d = (%x, %v); want its key", c, k, ok)
		}
	}

	rejected(t, ks.Store("anchorless", nil, 4, key(0x44)))
	if _, _, ok := ks.LatestDisclosed("anchorless", []byte{}); ok {
		t.Error("a disclosure without an anchor was stored")
	}
}

// TestKeyStoreVerifiesDisclosures checks each rule of Store against one chain:
// a valid disclosure is stored, a forged one is rejected and reported once, an
// older epoch is ignored, a different key for a stored epoch is rejected, and
// a disclosure past the walk bound is rejected without hashing.
func TestKeyStoreVerifiesDisclosures(t *testing.T) {
	ks := NewKeyStore()
	const id = "executor"
	chain := hashChain(0x5E, 8)
	anchor := chain[0]
	latest := func(wantEpoch int64) {
		t.Helper()
		if epoch, k, ok := ks.LatestDisclosed(id, anchor); !ok || epoch != wantEpoch || !bytes.Equal(k, chain[wantEpoch]) {
			t.Fatalf("LatestDisclosed = (%d, %x, %v); want (%d, k_%d, true)", epoch, k, ok, wantEpoch, wantEpoch)
		}
	}

	// No key yet is no disclosure; the first one hashes to the anchor.
	if err := ks.Store(id, anchor, 0, nil); err != nil {
		t.Fatal(err)
	}
	if err := ks.Store(id, anchor, 3, chain[3]); err != nil {
		t.Fatal(err)
	}
	latest(3)

	// A forged key is rejected, reported as the chain's first rejection once.
	if r := rejected(t, ks.Store(id, anchor, 5, key(0xEE))); !r.First {
		t.Error("the first rejection was not marked first")
	}
	if r := rejected(t, ks.Store(id, anchor, 6, key(0xEF))); r.First {
		t.Error("a repeated rejection was marked first")
	}
	if _, ok := ks.Get(id, anchor, 5); ok {
		t.Error("a forged key was stored")
	}

	// Later disclosures verify from the last verified key.
	if err := ks.Store(id, anchor, 5, chain[5]); err != nil {
		t.Fatal(err)
	}
	latest(5)

	// An older epoch is ignored, even its genuine key.
	if err := ks.Store(id, anchor, 4, chain[4]); err != nil {
		t.Fatal(err)
	}
	if _, ok := ks.Get(id, anchor, 4); ok {
		t.Error("an older epoch was stored")
	}
	latest(5)

	// A different key for a stored epoch is rejected and does not replace it.
	rejected(t, ks.Store(id, anchor, 3, chain[4]))
	if k, _ := ks.Get(id, anchor, 3); !bytes.Equal(k, chain[3]) {
		t.Error("a conflicting key replaced the stored one")
	}

	// A disclosure further than the bound from the last verified key is
	// rejected before any hashing.
	r := rejected(t, ks.Store(id, anchor, 5+maxVerifyWalk+1, key(0x01)))
	if r.Epoch != 5+maxVerifyWalk+1 || !strings.Contains(r.Reason, "bound") {
		t.Errorf("rejection = %v; want the walk bound for its epoch", r)
	}
	latest(5)
}
