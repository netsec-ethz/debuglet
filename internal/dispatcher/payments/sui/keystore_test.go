// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package sui

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/block-vision/sui-go-sdk/signer"
	"go.uber.org/zap"
)

// keystoreEntry encodes a keystore entry: scheme flag byte, then the key.
func keystoreEntry(flag byte, seed []byte) string {
	return base64.StdEncoding.EncodeToString(append([]byte{flag}, seed...))
}

func writeFile(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "sui.keystore")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func writeKeystore(t *testing.T, entries ...string) string {
	t.Helper()
	raw, err := json.Marshal(entries)
	if err != nil {
		t.Fatal(err)
	}
	return writeFile(t, string(raw))
}

func TestLoadKeypairSkipsUnusableEntries(t *testing.T) {
	seed := bytes.Repeat([]byte{7}, 32)
	want := signer.NewSigner(seed)
	path := writeKeystore(t,
		"",                          // empty
		"!!not base64!!",            // not base64
		keystoreEntry(0, seed[:31]), // short key
		keystoreEntry(1, seed),      // secp256k1, unsupported
		keystoreEntry(0, bytes.Repeat([]byte{8}, 32)), // another address
		keystoreEntry(0, seed),
	)
	if _, err := LoadKeypair(path, "0xzz", zap.NewNop()); err == nil {
		t.Fatalf("LoadKeypair accepted a malformed address")
	}
	got, err := LoadKeypair(path, want.Address, zap.NewNop())
	if err != nil || got.Address != want.Address {
		t.Fatalf("LoadKeypair = (%v, %v), want the key of %s", got, err, want.Address)
	}
}

func TestLoadKeypairShortAddress(t *testing.T) {
	// A configured address may omit leading zeros; it matches the padded form.
	var seed []byte
	var s *signer.Signer
	for i := 0; i < 4096; i++ {
		seed = bytes.Repeat([]byte{byte(i), byte(i >> 8)}, 16)
		if s = signer.NewSigner(seed); strings.HasPrefix(s.Address, "0x0") {
			break
		}
	}
	if !strings.HasPrefix(s.Address, "0x0") {
		t.Skip("no fixture key with a leading zero")
	}
	short := "0x" + strings.TrimLeft(s.Address[2:], "0")
	got, err := LoadKeypair(writeKeystore(t, keystoreEntry(0, seed)), short, zap.NewNop())
	if err != nil || got.Address != s.Address {
		t.Fatalf("LoadKeypair(%s) = (%v, %v)", short, got, err)
	}
}

func TestLoadKeypairErrorsOmitContent(t *testing.T) {
	entry := keystoreEntry(0, bytes.Repeat([]byte{9}, 32))
	cases := map[string]string{
		"no matching key": writeKeystore(t, entry),
		"not JSON":        writeFile(t, "["+entry),
		"wrong JSON type": writeFile(t, `{"key": "`+entry+`"}`),
	}
	for name, path := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := LoadKeypair(path, testObjectID(5), zap.NewNop())
			if err == nil {
				t.Fatalf("LoadKeypair succeeded")
			}
			if strings.Contains(err.Error(), entry) || strings.Contains(err.Error(), entry[:12]) {
				t.Fatalf("error contains keystore content")
			}
		})
	}
}
