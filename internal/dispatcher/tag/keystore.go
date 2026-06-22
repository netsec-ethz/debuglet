// Copyright 2025 ETH Zurich
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package tag

import (
	"fmt"
	"sync"
)

// KeyStore stores disclosed TESLA keys for retroactive packet verification.
// Keys are indexed by (executor_id, epoch).
type KeyStore struct {
	mu   sync.RWMutex
	keys map[string][]byte // "executorID:epoch" → key bytes

	// latestEpoch tracks the highest disclosed epoch per executor so
	// LatestDisclosed can answer in O(1) without scanning.
	latestEpoch map[string]int64 // executorID → highest stored epoch
}

func NewKeyStore() *KeyStore {
	return &KeyStore{
		keys:        make(map[string][]byte),
		latestEpoch: make(map[string]int64),
	}
}

func (ks *KeyStore) key(executorID string, epoch int64) string {
	return fmt.Sprintf("%s:%d", executorID, epoch)
}

// Store saves a disclosed key. If a key for this epoch is already stored it is
// a no-op (keys are immutable once disclosed).
func (ks *KeyStore) Store(executorID string, epoch int64, key []byte) error {
	ks.mu.Lock()
	defer ks.mu.Unlock()
	k := ks.key(executorID, epoch)
	if _, ok := ks.keys[k]; ok {
		return nil
	}
	ks.keys[k] = key
	if epoch > ks.latestEpoch[executorID] {
		ks.latestEpoch[executorID] = epoch
	}
	return nil
}

// Get retrieves a disclosed key.
func (ks *KeyStore) Get(executorID string, epoch int64) ([]byte, bool) {
	ks.mu.RLock()
	defer ks.mu.RUnlock()
	k, ok := ks.keys[ks.key(executorID, epoch)]
	return k, ok
}

// LatestDisclosed returns the epoch index and key of the most recently
// disclosed key for executorID. ok is false if no key has been stored yet.
func (ks *KeyStore) LatestDisclosed(executorID string) (epoch int64, key []byte, ok bool) {
	ks.mu.RLock()
	defer ks.mu.RUnlock()
	latest, exists := ks.latestEpoch[executorID]
	if !exists {
		return 0, nil, false
	}
	k, has := ks.keys[ks.key(executorID, latest)]
	if !has {
		return 0, nil, false
	}
	return latest, k, true
}

func (ks *KeyStore) PrintKeys() {
	fmt.Println("Stored keys:")
	ks.mu.RLock()
	defer ks.mu.RUnlock()
	for k, v := range ks.keys {
		fmt.Printf("%s: %x\n", k, v)
	}
}
