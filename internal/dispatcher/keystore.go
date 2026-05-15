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

package dispatcher

import (
	"fmt"
	"sync"
)

// KeyStore stores disclosed TESLA keys for retroactive packet verification.
// Keys are indexed by (executor_id, measurement_id, epoch).
type KeyStore struct {
	mu   sync.RWMutex
	keys map[string][]byte
}

func NewKeyStore() *KeyStore {
	return &KeyStore{
		keys: make(map[string][]byte),
	}
}

func (ks *KeyStore) key(executorID, measurementID string, epoch int64) string {
	return fmt.Sprintf("%s:%s:%d", executorID, measurementID, epoch)
}

// Store saves a disclosed key.
func (ks *KeyStore) Store(executorID, measurementID string, epoch int64, key []byte) {
	ks.mu.Lock()
	defer ks.mu.Unlock()
	ks.keys[ks.key(executorID, measurementID, epoch)] = key
}

// Get retrieves a disclosed key.
func (ks *KeyStore) Get(executorID, measurementID string, epoch int64) ([]byte, bool) {
	ks.mu.RLock()
	defer ks.mu.RUnlock()
	k, ok := ks.keys[ks.key(executorID, measurementID, epoch)]
	return k, ok
}
