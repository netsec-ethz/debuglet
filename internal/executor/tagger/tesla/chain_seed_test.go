// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 ETH Zurich

package tesla

import (
	"bytes"
	"testing"
	"time"
)

// TestChainSeedGivesEachGenerationItsOwnChain keeps one configured seed from
// producing the same chain twice, while each generation stays reproducible.
func TestChainSeedGivesEachGenerationItsOwnChain(t *testing.T) {
	seed := []byte("configured executor seed")
	anchor := func(generation int64) []byte {
		t.Helper()
		tail, err := ChainSeed(seed, generation)
		if err != nil {
			t.Fatal(err)
		}
		if len(tail) != keySize {
			t.Fatalf("tail is %d bytes, want %d", len(tail), keySize)
		}
		ks, err := NewKeySchedule(Config{Seed: tail, Delay: time.Second, ChainLength: 8})
		if err != nil {
			t.Fatal(err)
		}
		return ks.Anchor()
	}
	first, second := anchor(1), anchor(2)
	if bytes.Equal(first, second) {
		t.Fatalf("generations 1 and 2 share the anchor %x", first)
	}
	if again := anchor(1); !bytes.Equal(first, again) {
		t.Fatalf("generation 1 derived %x, then %x", first, again)
	}
}
