// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 ETH Zurich

package tag

import (
	"bytes"
	"crypto/subtle"
	"fmt"
	"sync"

	"github.com/netsec-ethz/debuglet/internal/executor/tagger/tesla"
)

// maxChainsPerExecutor bounds the key chains kept per executor. An executor
// announces a new chain anchor each time it restarts; when a further chain
// appears, the disclosures of the oldest one are dropped.
const maxChainsPerExecutor = 4

// maxVerifyWalk bounds the hashes spent verifying one disclosure: the epochs
// between it and the last verified key of its chain (or the anchor). It is the
// longest chain an executor can configure, one week of one-second epochs, so
// the first disclosure after a dispatcher restart still verifies.
const maxVerifyWalk = 7 * 24 * 60 * 60

// RejectedError reports a disclosure that was not stored because it does not
// extend its chain. First is set for the first rejection on that chain, so a
// caller can log a misbehaving executor once rather than on every heartbeat.
type RejectedError struct {
	Epoch  int64
	Reason string
	First  bool
}

func (e *RejectedError) Error() string {
	return fmt.Sprintf("disclosed key for epoch %d rejected: %s", e.Epoch, e.Reason)
}

// chainKeys holds the disclosures of one key chain, identified by its anchor.
type chainKeys struct {
	anchor []byte
	keys   map[int64][]byte // epoch → key bytes

	// latest is the highest disclosed epoch above zero, so LatestDisclosed
	// can answer in O(1) without scanning; zero means none yet.
	latest int64

	// rejected records that a disclosure of this chain was rejected.
	rejected bool
}

// KeyStore stores disclosed TESLA keys for retroactive packet verification.
// Keys are indexed by (executor_id, chain anchor, epoch). An empty anchor is
// the chain of an executor that published none.
type KeyStore struct {
	mu     sync.RWMutex
	chains map[string][]*chainKeys // executorID → chains, oldest first
}

func NewKeyStore() *KeyStore {
	return &KeyStore{chains: make(map[string][]*chainKeys)}
}

// chain returns the stored chain of executorID with the given anchor, or nil.
func (ks *KeyStore) chain(executorID string, anchor []byte) *chainKeys {
	for _, c := range ks.chains[executorID] {
		if bytes.Equal(c.anchor, anchor) {
			return c
		}
	}
	return nil
}

// Store saves a key disclosed on the chain with the given anchor once it
// verifies against the chain: H^(epoch-l)(key) must equal the last verified
// key k_l, or the anchor k_0 when none is stored yet. Disclosures are
// monotonic: an epoch below the latest is ignored, a repeat of a stored key is
// a no-op, and a different key for a stored epoch is rejected. An empty key is
// no disclosure. A rejection returns a *RejectedError and stores nothing.
func (ks *KeyStore) Store(executorID string, anchor []byte, epoch int64, key []byte) error {
	if len(key) == 0 {
		return nil
	}
	ks.mu.Lock()
	c := ks.chain(executorID, anchor)
	if c == nil {
		c = &chainKeys{anchor: anchor, keys: make(map[int64][]byte)}
		chains := append(ks.chains[executorID], c)
		if evicted := len(chains) - maxChainsPerExecutor; evicted > 0 {
			// Clear the dropped entries so the backing array does not keep
			// their keys reachable.
			clear(chains[:evicted])
			chains = chains[evicted:]
		}
		ks.chains[executorID] = chains
	}
	if stored, ok := c.keys[epoch]; ok {
		defer ks.mu.Unlock()
		if !bytes.Equal(stored, key) {
			return c.reject(epoch, "conflicts with the key stored for this epoch")
		}
		return nil
	}
	if epoch < c.latest {
		ks.mu.Unlock()
		return nil
	}
	base, baseKey := c.latest, c.keys[c.latest]
	if base == 0 {
		baseKey = anchor
	}
	ks.mu.Unlock()

	// Hash outside the lock; a key that extends any verified key of the chain
	// is authentic, so a disclosure stored meanwhile does not invalidate this.
	reason := ""
	switch {
	case len(anchor) == 0:
		reason = "the executor published no chain anchor"
	case epoch < 0:
		reason = "negative epoch"
	case epoch-base > maxVerifyWalk:
		reason = fmt.Sprintf("%d epochs past the last verified key exceeds the bound of %d", epoch-base, maxVerifyWalk)
	default:
		derived, err := tesla.DeriveFromDisclosed(key, epoch, base)
		if err != nil || subtle.ConstantTimeCompare(derived, baseKey) != 1 {
			reason = "does not hash to the last verified key or the chain anchor"
		}
	}

	ks.mu.Lock()
	defer ks.mu.Unlock()
	if reason != "" {
		return c.reject(epoch, reason)
	}
	if stored, ok := c.keys[epoch]; ok {
		if !bytes.Equal(stored, key) {
			return c.reject(epoch, "conflicts with the key stored for this epoch")
		}
		return nil
	}
	c.keys[epoch] = key
	if epoch > c.latest {
		c.latest = epoch
	}
	return nil
}

// reject records a rejected disclosure of c and returns its error.
func (c *chainKeys) reject(epoch int64, reason string) error {
	first := !c.rejected
	c.rejected = true
	return &RejectedError{Epoch: epoch, Reason: reason, First: first}
}

// Get retrieves a key disclosed on the chain with the given anchor.
func (ks *KeyStore) Get(executorID string, anchor []byte, epoch int64) ([]byte, bool) {
	ks.mu.RLock()
	defer ks.mu.RUnlock()
	c := ks.chain(executorID, anchor)
	if c == nil {
		return nil, false
	}
	k, ok := c.keys[epoch]
	return k, ok
}

// LatestDisclosed returns the epoch index and key of the most recently
// disclosed key on the chain of executorID with the given anchor. ok is false
// if no key of that chain has been stored yet.
func (ks *KeyStore) LatestDisclosed(executorID string, anchor []byte) (epoch int64, key []byte, ok bool) {
	ks.mu.RLock()
	defer ks.mu.RUnlock()
	c := ks.chain(executorID, anchor)
	if c == nil || c.latest == 0 {
		return 0, nil, false
	}
	k, has := c.keys[c.latest]
	if !has {
		return 0, nil, false
	}
	return c.latest, k, true
}

func (ks *KeyStore) PrintKeys() {
	fmt.Println("Stored keys:")
	ks.mu.RLock()
	defer ks.mu.RUnlock()
	for id, chains := range ks.chains {
		for _, c := range chains {
			for epoch, v := range c.keys {
				fmt.Printf("%s:%x:%d: %x\n", id, c.anchor, epoch, v)
			}
		}
	}
}
