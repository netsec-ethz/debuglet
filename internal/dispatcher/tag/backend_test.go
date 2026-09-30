// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package tag

import (
	"bytes"
	"errors"
	"testing"
	"time"
)

// memoryBackend is a Backend over a map, keyed by executor, anchor and epoch.
type memoryBackend struct {
	keys  map[string][]byte
	saves int
	fail  error
}

func backendKey(executorID string, anchor []byte, epoch int64) string {
	return executorID + "/" + string(anchor) + "/" + string(rune(epoch))
}

func (b *memoryBackend) Save(executorID string, chain Chain, epoch int64, key []byte, _ time.Time) error {
	if b.fail != nil {
		return b.fail
	}
	b.saves++
	k := backendKey(executorID, chain.Anchor, epoch)
	if _, ok := b.keys[k]; !ok {
		b.keys[k] = key
	}
	return nil
}

func (b *memoryBackend) Latest(executorID string, anchor []byte) (int64, []byte, bool, error) {
	for epoch := int64(64); epoch > 0; epoch-- {
		if k, ok := b.keys[backendKey(executorID, anchor, epoch)]; ok {
			return epoch, k, true, nil
		}
	}
	return 0, nil, false, nil
}

func (b *memoryBackend) Get(executorID string, anchor []byte, epoch int64) ([]byte, bool, error) {
	k, ok := b.keys[backendKey(executorID, anchor, epoch)]
	return k, ok, nil
}

// TestPersistentKeyStoreIsACacheOverItsBackend checks that verified keys are
// recorded once, that a new store resumes a chain from the record with the
// usual monotonic and conflict rules, and that a failed record caches nothing.
func TestPersistentKeyStoreIsACacheOverItsBackend(t *testing.T) {
	backend := &memoryBackend{keys: map[string][]byte{}}
	const id = "executor"
	chainKeys := hashChain(0xD0, 6)
	chain := Chain{Anchor: chainKeys[0]}
	ks := NewPersistentKeyStore(backend)
	for _, epoch := range []int64{2, 2, 4} {
		if err := ks.Store(id, chain, time.Time{}, epoch, chainKeys[epoch]); err != nil {
			t.Fatal(err)
		}
	}
	if backend.saves != 2 {
		t.Fatalf("recorded %d keys; want k_2 and k_4 once each", backend.saves)
	}

	// A store without the chain cached resumes from the record.
	resumed := NewPersistentKeyStore(backend)
	if epoch, k, ok := resumed.LatestDisclosed(id, chain.Anchor); !ok || epoch != 4 || !bytes.Equal(k, chainKeys[4]) {
		t.Fatalf("LatestDisclosed from record = (%d, %x, %v)", epoch, k, ok)
	}
	if k, ok := resumed.Get(id, chain.Anchor, 2); !ok || !bytes.Equal(k, chainKeys[2]) {
		t.Fatalf("Get(2) from record = (%x, %v)", k, ok)
	}
	// k_2 conflicts with the record, k_3 is below the latest and ignored.
	if r := rejected(t, resumed.Store(id, chain, time.Time{}, 2, key(0xEE))); !r.First {
		t.Fatalf("conflict with the record = %+v", r)
	}
	if err := resumed.Store(id, chain, time.Time{}, 3, chainKeys[3]); err != nil {
		t.Fatal(err)
	}
	// k_5 verifies against the recorded k_4.
	if err := resumed.Store(id, chain, time.Time{}, 5, chainKeys[5]); err != nil {
		t.Fatal(err)
	}

	backend.fail = errors.New("disk full")
	if err := resumed.Store(id, chain, time.Time{}, 6, chainKeys[6]); err == nil || errors.As(err, new(*RejectedError)) {
		t.Fatalf("Store with a failing record = %v; want a plain error", err)
	}
	if epoch, _, _ := resumed.LatestDisclosed(id, chain.Anchor); epoch != 5 {
		t.Fatalf("a key whose record failed was cached: latest %d", epoch)
	}
	backend.fail = nil
	if err := resumed.Store(id, chain, time.Time{}, 6, chainKeys[6]); err != nil {
		t.Fatalf("retry after a failed record: %v", err)
	}
}
