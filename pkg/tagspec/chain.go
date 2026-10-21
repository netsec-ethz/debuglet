// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 ETH Zurich

package tagspec

import (
	"crypto/sha256"
	"fmt"
)

// DeriveFromDisclosed reconstructs the key at targetEpoch given a disclosed
// key at disclosedEpoch. Because the chain runs backward (k_i = H(k_{i+1})),
// a verifier can only derive keys at epochs ≤ disclosedEpoch by hashing the
// disclosed key forward (disclosedEpoch → targetEpoch, t ≤ disclosedEpoch):
//
//	k_t = H^(disclosedEpoch - t)(k_disclosedEpoch)
//
// To reconstruct a later (newer) key you would need an even newer disclosed
// key, since the chain cannot be inverted.
func DeriveFromDisclosed(disclosedKey []byte, disclosedEpoch, targetEpoch int64) ([]byte, error) {
	if targetEpoch > disclosedEpoch {
		return nil, fmt.Errorf("tesla: cannot derive epoch %d from disclosed epoch %d "+
			"(target must be ≤ disclosed in a backward chain)", targetEpoch, disclosedEpoch)
	}
	steps := disclosedEpoch - targetEpoch
	key := make([]byte, len(disclosedKey))
	copy(key, disclosedKey)
	h := sha256.New()
	for i := int64(0); i < steps; i++ {
		h.Reset()
		h.Write(key)
		key = h.Sum(nil)
	}
	return key, nil
}
