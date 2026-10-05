// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package sui

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/block-vision/sui-go-sdk/signer"
	"github.com/block-vision/sui-go-sdk/utils"
	"go.uber.org/zap"
)

// errSkippedEntry marks a keystore entry that is not an Ed25519 key.
var errSkippedEntry = errors.New("not an Ed25519 key entry")

// getKeypair decodes one keystore entry: base64 of a scheme flag byte
// followed by the 32-byte private key. Only Ed25519 (flag 0) is supported.
// Errors never include the entry.
func getKeypair(raw string) (*signer.Signer, error) {
	decoded, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		return nil, errors.New("entry is not base64")
	}
	if len(decoded) != 33 || decoded[0] != 0 {
		return nil, errSkippedEntry
	}
	return signer.NewSigner(decoded[1:]), nil
}

// LoadKeypair returns the key for address from a Sui keystore file (a JSON
// array of base64 entries). Errors name the path and the address, never the
// file's content.
func LoadKeypair(path string, address string, logger *zap.Logger) (*signer.Signer, error) {
	if err := ValidAddress(address); err != nil {
		return nil, err
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read keystore: %w", err)
	}

	var entries []string
	if err := json.Unmarshal(raw, &entries); err != nil {
		return nil, fmt.Errorf("keystore %s is not a JSON array of strings", path)
	}

	want := utils.NormalizeSuiAddress(address)
	for i, entry := range entries {
		sig, err := getKeypair(entry)
		if err != nil {
			logger.Debug("skipping keystore entry", zap.Int("index", i), zap.String("reason", err.Error()))
		} else if strings.EqualFold(string(want), sig.Address) {
			return sig, nil
		}
	}
	return nil, fmt.Errorf("keystore %s has no Ed25519 key for address %s", path, address)
}
