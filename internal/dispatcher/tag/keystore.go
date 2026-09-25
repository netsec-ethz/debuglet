// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 ETH Zurich

package tag

import (
	"bytes"
	"fmt"
	"sync"
)

// maxChainsPerExecutor bounds the key chains kept per executor. An executor
// announces a new chain anchor each time it restarts; when a further chain
// appears, the disclosures of the oldest one are dropped.
const maxChainsPerExecutor = 4

// chainKeys holds the disclosures of one key chain, identified by its anchor.
type chainKeys struct {
	anchor []byte
	keys   map[int64][]byte // epoch → key bytes

	// latest is the highest disclosed epoch above zero, so LatestDisclosed
	// can answer in O(1) without scanning; zero means none yet.
	latest int64
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

// Store saves a key disclosed on the chain with the given anchor. If a key for
// this epoch of that chain is already stored it is a no-op (keys are immutable
// once disclosed).
func (ks *KeyStore) Store(executorID string, anchor []byte, epoch int64, key []byte) error {
	ks.mu.Lock()
	defer ks.mu.Unlock()
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
	if _, ok := c.keys[epoch]; ok {
		return nil
	}
	c.keys[epoch] = key
	if epoch > c.latest {
		c.latest = epoch
	}
	return nil
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
