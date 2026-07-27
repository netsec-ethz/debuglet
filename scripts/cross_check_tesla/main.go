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

// Package main is a one-shot diagnostic tool that prints the expected TESLA
// tag for a known input so that the Python script can be cross-checked.
//
// Usage:
//
//	go run scripts/cross_check_tesla/main.go \
//	  -seed <hex_seed> -epoch <N> -measurement <id> \
//	  -payload <hex_bytes>
//
// Or with no flags to run the built-in self-test with a fixed seed.
package main

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"time"

	"debuglet/internal/executor/tagger/tesla"

	"golang.org/x/crypto/hkdf"
)

func main() {
	seedHex := flag.String("seed", "", "32-byte hex seed (k_L). If empty a fixed test seed is used.")
	epoch := flag.Int64("epoch", 3, "Target epoch to compute key for")
	disclosedEpoch := flag.Int64("disclosed", 5, "Epoch of the disclosed key")
	mid := flag.String("measurement", "test-measurement-id-001", "Measurement ID string")
	payloadHex := flag.String("payload", "", "Hex bytes of the IPv4 packet to tag (IPID and checksum already zeroed). If empty a test payload is used.")
	flag.Parse()

	// -----------------------------------------------------------------------
	// Build a KeySchedule from the seed.
	// -----------------------------------------------------------------------
	var seed []byte
	if *seedHex == "" {
		seed = make([]byte, 32)
		for i := range seed {
			seed[i] = 0xAB
		}
		fmt.Println("Using built-in test seed: " + hex.EncodeToString(seed))
	} else {
		var err error
		seed, err = hex.DecodeString(*seedHex)
		if err != nil {
			panic("bad -seed: " + err.Error())
		}
	}

	ks, err := tesla.NewKeySchedule(tesla.Config{
		Seed:        seed,
		ChainLength: 100,
		Delay:       10 * time.Second,
		Epoch:       time.Time{}, // zero → uses now, but we only use keyForEpoch
	})
	if err != nil {
		panic(err)
	}

	// -----------------------------------------------------------------------
	// Print anchor and chain keys.
	// -----------------------------------------------------------------------
	anchor := ks.Anchor()
	fmt.Printf("anchor (k_0)                     : %s\n", hex.EncodeToString(anchor))

	kTarget, err := ks.KeyAtEpoch(*epoch)
	if err != nil {
		panic(err)
	}
	fmt.Printf("k_%d (direct from schedule)       : %s\n", *epoch, hex.EncodeToString(kTarget))

	kDisclosed, err := ks.KeyAtEpoch(*disclosedEpoch)
	if err != nil {
		panic(err)
	}
	fmt.Printf("k_%d (disclosed key)              : %s\n", *disclosedEpoch, hex.EncodeToString(kDisclosed))

	// Reconstruct k_epoch from k_disclosed by hashing forward (disclosedEpoch - epoch) steps.
	kReconstructed, err := tesla.DeriveFromDisclosed(kDisclosed, *disclosedEpoch, *epoch)
	if err != nil {
		panic(err)
	}
	fmt.Printf("k_%d (reconstructed from k_%d)   : %s\n", *epoch, *disclosedEpoch, hex.EncodeToString(kReconstructed))

	// Verify chain consistency.
	chainOK := tesla.VerifyChain(anchor, kReconstructed, *epoch)
	fmt.Printf("VerifyChain H^%d(k_%d)==k_0       : %v\n", *epoch, *epoch, chainOK)

	// -----------------------------------------------------------------------
	// Derive ak.
	// -----------------------------------------------------------------------
	ak, err := tesla.DeriveAK(kReconstructed, []byte(*mid))
	if err != nil {
		panic(err)
	}
	fmt.Printf("measurement                      : %q\n", *mid)
	fmt.Printf("ak = HKDF(k_%d, measurement)     : %s\n", *epoch, hex.EncodeToString(ak))

	// Cross-check HKDF with Go's stdlib directly so Python can compare PRK.
	r := hkdf.New(sha256.New, kReconstructed, nil, []byte(*mid))
	akDirect := make([]byte, 32)
	io.ReadFull(r, akDirect)
	fmt.Printf("ak (hkdf.New direct)             : %s\n", hex.EncodeToString(akDirect))

	// Also print k0 and k1 for the SipHash.
	k0 := binary.LittleEndian.Uint64(ak[0:8])
	k1 := binary.LittleEndian.Uint64(ak[8:16])
	fmt.Printf("SipHash k0                       : 0x%016x\n", k0)
	fmt.Printf("SipHash k1                       : 0x%016x\n", k1)

	// -----------------------------------------------------------------------
	// Compute tag over payload.
	// -----------------------------------------------------------------------
	var payload []byte
	if *payloadHex == "" {
		payload = make([]byte, 20) // 20-byte zeroed IPv4 header
		payload[0] = 0x45          // version=4, IHL=5
		fmt.Printf("Using built-in test payload (zeroed 20-byte IPv4 header)\n")
	} else {
		payload, err = hex.DecodeString(*payloadHex)
		if err != nil {
			panic("bad -payload: " + err.Error())
		}
	}

	tag, err := tesla.ComputeBPFTag(ak, payload)
	if err != nil {
		panic(err)
	}
	fmt.Printf("payload (first 20B)              : %s\n", hex.EncodeToString(payload[:min(20, len(payload))]))
	fmt.Printf("BPF SipHash tag                  : 0x%04x (%d)\n", tag, tag)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
