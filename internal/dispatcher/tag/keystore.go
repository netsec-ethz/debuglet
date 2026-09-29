// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 ETH Zurich

package tag

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	"github.com/netsec-ethz/debuglet/internal/executor/tagger/tesla"
)

// maxChainsPerExecutor bounds the key chains cached per executor. An executor
// announces a new chain anchor each time it restarts; when a further chain
// appears, the oldest one leaves the cache. With a Backend its disclosures
// stay on record and are read back when needed.
const maxChainsPerExecutor = 4

// TagSpec is the tag specification every chain recorded today is used with:
// tag spec v1 (docs/verification.md). An executor does not report it yet.
const TagSpec = 1

// ChainID returns the public identifier of the chain with the given anchor k_0:
// the lowercase hex of the first 16 bytes of SHA-256(k_0). It is empty for an
// empty anchor.
func ChainID(anchor []byte) string {
	if len(anchor) == 0 {
		return ""
	}
	sum := sha256.Sum256(anchor)
	return hex.EncodeToString(sum[:16])
}

// maxVerifyWalk bounds the hashes spent verifying one disclosure: the epochs
// between it and the last verified key of its chain (or the anchor). It is the
// longest chain an executor can configure, one week of one-second epochs, so
// the first disclosure after a dispatcher restart still verifies.
const maxVerifyWalk = 7 * 24 * 60 * 60

// clockSkew is the lead of an executor's clock over the dispatcher's that a
// disclosure may show before it is rejected as lying ahead of wall-clock time.
const clockSkew = 5 * time.Second

// Chain names the key chain a disclosure belongs to: its public anchor k_0 and
// the schedule the executor registered with it. Epoch i starts at
// Start + i*Interval, and its key may be disclosed from the start of epoch
// i+DisclosureDelay. A zero Interval means the schedule is unknown; only the
// absolute walk bound then limits a disclosure's epoch. A zero
// DisclosureDelay is an executor that predates it and discloses after one
// epoch.
type Chain struct {
	Anchor          []byte
	Start           time.Time
	Interval        time.Duration
	DisclosureDelay int64
	// Length is L, the number of epochs the chain serves; zero is unknown.
	// It is recorded with the chain and does not bound a disclosure.
	Length int64
}

// Backend is the durable record a KeyStore caches. Save is called once for
// each disclosure that verified, before the cache holds it; Latest and Get
// read the record for a chain the cache does not hold. A Backend must store a
// key at most once per (executor, chain, epoch) and keep the first.
type Backend interface {
	Save(executorID string, chain Chain, epoch int64, key []byte, at time.Time) error
	Latest(executorID string, anchor []byte) (epoch int64, key []byte, ok bool, err error)
	Get(executorID string, anchor []byte, epoch int64) (key []byte, ok bool, err error)
}

// disclosureDelay returns d, one epoch for an executor that reported none.
func (c Chain) disclosureDelay() int64 {
	if c.DisclosureDelay <= 0 {
		return 1
	}
	return c.DisclosureDelay
}

// maxEpoch returns the highest epoch a disclosure received at now may carry:
// the epoch in progress at now, allowing for clockSkew, less the disclosure
// delay d. An honest executor discloses k_i no earlier than the start of
// epoch i+d, so a later epoch is an early disclosure. ok is false while the
// schedule is unknown; a negative result means nothing is disclosable yet.
func (c Chain) maxEpoch(now time.Time) (int64, bool) {
	if c.Interval <= 0 {
		return 0, false
	}
	elapsed := now.Add(clockSkew).Sub(c.Start)
	if elapsed < 0 {
		return -1, true
	}
	return int64(elapsed/c.Interval) - c.disclosureDelay(), true
}

// DisclosableAt returns when the key of epoch i may first be disclosed: the
// start of epoch i+d. ok is false while the schedule is unknown.
func (c Chain) DisclosableAt(epoch int64) (time.Time, bool) {
	if c.Interval <= 0 {
		return time.Time{}, false
	}
	return c.Start.Add(time.Duration(epoch+c.disclosureDelay()) * c.Interval), true
}

// RejectedError reports a disclosure that was not stored because it does not
// extend its chain. First is set for the first rejection on that chain, so a
// caller can log a misbehaving executor once rather than on every heartbeat;
// early disclosures count separately, so the first is logged even after
// another rejection. Early is set when the key was disclosed before its schedule allows: that is
// evidence of a misbehaving executor, since anyone who saw the key could forge
// tags for packets verifiers still attribute to its epoch.
type RejectedError struct {
	Epoch  int64
	Reason string
	First  bool
	Early  bool
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

	// rejected records that a disclosure of this chain was rejected, and
	// rejectedEarly that one was rejected as early; each is logged once.
	rejected, rejectedEarly bool
}

// KeyStore stores disclosed TESLA keys for retroactive packet verification.
// Keys are indexed by (executor_id, chain anchor, epoch). An empty anchor is
// the chain of an executor that published none. Without a Backend the store
// is memory only; with one, it is a cache over the durable record, and a
// chain that is not cached resumes from the latest key on record.
type KeyStore struct {
	mu      sync.RWMutex
	chains  map[string][]*chainKeys // executorID → chains, oldest first
	backend Backend
}

func NewKeyStore() *KeyStore {
	return &KeyStore{chains: make(map[string][]*chainKeys)}
}

// NewPersistentKeyStore returns a KeyStore that records every verified
// disclosure in backend and caches it in memory.
func NewPersistentKeyStore(backend Backend) *KeyStore {
	ks := NewKeyStore()
	ks.backend = backend
	return ks
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

// Store saves a key disclosed at now on the given chain once it verifies
// against the chain: H^(epoch-l)(key) must equal the last verified key k_l, or
// the anchor k_0 when none is stored yet. An epoch ahead of what the chain's
// schedule allows at now (see Chain) is rejected before any hashing, which
// bounds the work one heartbeat can cause. Disclosures are
// monotonic: an epoch below the latest is ignored, a repeat of a stored key is
// a no-op, and a different key for a stored epoch is rejected. An empty key is
// no disclosure. A rejection returns a *RejectedError and stores nothing.
func (ks *KeyStore) Store(executorID string, chain Chain, now time.Time, epoch int64, key []byte) error {
	if len(key) == 0 {
		return nil
	}
	anchor := chain.Anchor
	c, err := ks.cached(executorID, anchor)
	if err != nil {
		return err
	}
	ks.mu.Lock()
	if stored, ok := c.keys[epoch]; ok {
		defer ks.mu.Unlock()
		if !bytes.Equal(stored, key) {
			return c.reject(epoch, "conflicts with the key stored for this epoch", false)
		}
		return nil
	}
	if epoch < c.latest {
		ks.mu.Unlock()
		// An earlier epoch is only compared with the record: a conflicting
		// key is rejected as it would be from the cache.
		if ks.backend == nil || epoch <= 0 {
			return nil
		}
		stored, ok, err := ks.backend.Get(executorID, anchor, epoch)
		if err != nil || !ok || bytes.Equal(stored, key) {
			return err
		}
		ks.mu.Lock()
		defer ks.mu.Unlock()
		return c.reject(epoch, "conflicts with the key stored for this epoch", false)
	}
	base, baseKey := c.latest, c.keys[c.latest]
	if base == 0 {
		baseKey = anchor
	}
	ks.mu.Unlock()

	// Hash outside the lock; a key that extends any verified key of the chain
	// is authentic, so a disclosure stored meanwhile does not invalidate this.
	reason, early := "", false
	maxEpoch, scheduled := chain.maxEpoch(now)
	switch {
	case len(anchor) == 0:
		reason = "the executor published no chain anchor"
	case epoch < 0:
		reason = "negative epoch"
	case scheduled && epoch > maxEpoch:
		early = true
		at, _ := chain.DisclosableAt(epoch)
		reason = fmt.Sprintf("disclosed before its schedule allows: epoch %d is disclosable from %s (disclosure delay %d epochs), and wall-clock time allows at most epoch %d",
			epoch, at.UTC().Format(time.RFC3339), chain.disclosureDelay(), maxEpoch)
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
		return c.reject(epoch, reason, early)
	}
	if stored, ok := c.keys[epoch]; ok {
		if !bytes.Equal(stored, key) {
			return c.reject(epoch, "conflicts with the key stored for this epoch", false)
		}
		return nil
	}
	if epoch < c.latest {
		// A later disclosure was stored while this one was hashed; keep the
		// store monotonic.
		return nil
	}
	if ks.backend != nil {
		// Record before caching, so a key the cache holds is on record; a
		// failed write stores nothing and the next disclosure retries it.
		if err := ks.backend.Save(executorID, chain, epoch, key, now); err != nil {
			return fmt.Errorf("record disclosed key for epoch %d: %w", epoch, err)
		}
	}
	c.keys[epoch] = key
	if epoch > c.latest {
		c.latest = epoch
	}
	return nil
}

// cached returns the cache entry of a chain, creating it on a miss. With a
// Backend a new entry starts from the latest key on record, read outside the
// lock; the oldest cached chain of the executor is evicted beyond
// maxChainsPerExecutor.
func (ks *KeyStore) cached(executorID string, anchor []byte) (*chainKeys, error) {
	ks.mu.Lock()
	c := ks.chain(executorID, anchor)
	ks.mu.Unlock()
	if c != nil {
		return c, nil
	}
	loaded := &chainKeys{anchor: anchor, keys: make(map[int64][]byte)}
	if ks.backend != nil && len(anchor) > 0 {
		epoch, key, ok, err := ks.backend.Latest(executorID, anchor)
		if err != nil {
			return nil, fmt.Errorf("read disclosed keys on record: %w", err)
		}
		if ok && epoch > 0 {
			loaded.keys[epoch] = key
			loaded.latest = epoch
		}
	}
	ks.mu.Lock()
	defer ks.mu.Unlock()
	if c := ks.chain(executorID, anchor); c != nil {
		return c, nil // cached meanwhile
	}
	chains := append(ks.chains[executorID], loaded)
	if evicted := len(chains) - maxChainsPerExecutor; evicted > 0 {
		// Clear the dropped entries so the backing array does not keep
		// their keys reachable.
		clear(chains[:evicted])
		chains = chains[evicted:]
	}
	ks.chains[executorID] = chains
	return loaded, nil
}

// reject records a rejected disclosure of c and returns its error.
func (c *chainKeys) reject(epoch int64, reason string, early bool) error {
	flag := &c.rejected
	if early {
		flag = &c.rejectedEarly
	}
	first := !*flag
	*flag = true
	return &RejectedError{Epoch: epoch, Reason: reason, First: first, Early: early}
}

// Get retrieves a key disclosed on the chain with the given anchor.
// A key the cache does not hold is read from the Backend, if any.
func (ks *KeyStore) Get(executorID string, anchor []byte, epoch int64) ([]byte, bool) {
	ks.mu.RLock()
	if c := ks.chain(executorID, anchor); c != nil {
		if k, ok := c.keys[epoch]; ok {
			ks.mu.RUnlock()
			return k, true
		}
	}
	ks.mu.RUnlock()
	if ks.backend == nil {
		return nil, false
	}
	k, ok, err := ks.backend.Get(executorID, anchor, epoch)
	return k, ok && err == nil
}

// LatestDisclosed returns the epoch index and key of the most recently
// disclosed key on the chain of executorID with the given anchor. ok is false
// if no key of that chain has been stored yet. A chain the cache does not
// hold is answered from the Backend, if any.
func (ks *KeyStore) LatestDisclosed(executorID string, anchor []byte) (epoch int64, key []byte, ok bool) {
	ks.mu.RLock()
	c := ks.chain(executorID, anchor)
	if c != nil {
		defer ks.mu.RUnlock()
		k, has := c.keys[c.latest]
		if c.latest == 0 || !has {
			return 0, nil, false
		}
		return c.latest, k, true
	}
	ks.mu.RUnlock()
	if ks.backend == nil || len(anchor) == 0 {
		return 0, nil, false
	}
	epoch, key, ok, err := ks.backend.Latest(executorID, anchor)
	if err != nil || !ok || epoch <= 0 {
		return 0, nil, false
	}
	return epoch, key, true
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
