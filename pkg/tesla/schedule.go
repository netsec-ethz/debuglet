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

// Package tesla implements a TESLA-inspired hash-chain key schedule for
// delayed disclosure of packet authentication keys.
//
// # Key Schedule Overview
//
// Keys form a backward hash chain: the executor generates a random secret
// seed k_L (the tail) and hashes it L times to obtain the public anchor k_0:
//
//	k_0 = H^L(k_L)          (public anchor, published at setup)
//	k_i = H(k_{i+1})        (each key is the hash of the next one)
//
// The executor uses key k_i during epoch i and discloses it after a
// configurable disclosure delay d has elapsed. A verifier who has buffered
// packets from epoch i can verify them once k_i is published by checking:
//
//	H^i(k_i) == k_0
//
// Given a disclosed key k_τ, the key for an earlier epoch t (t ≤ τ) is
// reconstructed by hashing forward τ-t times:
//
//	k_t = H^(τ-t)(k_τ)
//
// # Per-Measurement Derivation
//
// Because a single executor may service multiple measurements concurrently, an
// additional per-measurement key ak is derived from the current chain key:
//
//	ak = HKDF-SHA256(secret=k_i, info=measurement_id, length=32)
//
// # Authentication Tag
//
// The authentication tag written into the IPv4 IPID field is:
//
//	tag = HMAC-SHA256(ak, packet_payload)[0:2]   (16-bit truncation)
package tesla

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"sync"
	"time"

	"golang.org/x/crypto/hkdf"
)

// Config carries the tuneable parameters of the TESLA key schedule.
type Config struct {
	// Seed is the secret tail k_L of the hash chain. If nil, a random
	// 32-byte seed is generated on the first call to NewKeySchedule.
	// The seed is NEVER disclosed; it is only used internally to derive
	// keys by hashing backwards toward k_0.
	Seed []byte

	// ChainLength L is the total number of epochs supported by this
	// schedule. The keys k_0 … k_L are generated; k_0 is the public
	// anchor and k_L is derived from the seed.
	// Defaults to 3600 (one hour at 1-second intervals).
	ChainLength int64

	// Delay is the interval duration I (one epoch). A key disclosed after
	// the disclosure delay d (expressed as a number of epochs) has elapsed.
	// Defaults to 10 seconds.
	Delay time.Duration

	// Epoch is the reference wall-clock time that anchors epoch 0.
	// Defaults to the time NewKeySchedule is called.
	Epoch time.Time
}

// KeySchedule is a thread-safe TESLA hash-chain key schedule.
//
// Keys are indexed by epoch number t where t ∈ [0, L]:
//
//	epoch t covers the time interval [Epoch + t*Delay, Epoch + (t+1)*Delay).
//
// The chain direction is backward: k_0 is the public anchor and k_L is the
// private seed tail. Key k_t is used during epoch t and disclosed after the
// disclosure delay d has elapsed (i.e., once epoch t+d has started).
type KeySchedule struct {
	cfg Config

	// anchor is k_0 = H^L(seed), computed once at construction time.
	anchor []byte

	mu    sync.RWMutex
	cache map[int64][]byte // epoch → chain key (memoised)
}

// NewKeySchedule creates a KeySchedule from cfg.
//
// The chain direction is backward (k_i = H(k_{i+1})). The private seed k_L is
// stored internally and the public anchor k_0 = H^L(seed) is computed once.
//
// If cfg.Seed is empty a cryptographically random 32-byte seed is generated.
// If cfg.ChainLength is zero it defaults to 3600.
// If cfg.Delay is zero it defaults to 10 seconds.
func NewKeySchedule(cfg Config) (*KeySchedule, error) {
	if len(cfg.Seed) == 0 {
		cfg.Seed = make([]byte, 32)
		if _, err := io.ReadFull(rand.Reader, cfg.Seed); err != nil {
			return nil, fmt.Errorf("tesla: failed to generate seed: %w", err)
		}
	}
	if cfg.ChainLength == 0 {
		cfg.ChainLength = 3600
	}
	if cfg.Delay == 0 {
		cfg.Delay = 10 * time.Second
	}
	if cfg.Epoch.IsZero() {
		cfg.Epoch = time.Now()
	}

	// Pre-compute the full backward chain and store all keys.
	// k_L = seed (private tail), k_i = H(k_{i+1}) for i = L-1 … 0.
	cache := make(map[int64][]byte, cfg.ChainLength+1)

	key := make([]byte, len(cfg.Seed))
	copy(key, cfg.Seed)
	cache[cfg.ChainLength] = key

	h := sha256.New()
	for i := cfg.ChainLength - 1; i >= 0; i-- {
		h.Reset()
		h.Write(key)
		key = h.Sum(nil)
		cache[i] = key
	}

	return &KeySchedule{
		cfg:    cfg,
		anchor: cache[0],
		cache:  cache,
	}, nil
}

// Config returns a copy of the schedule's configuration.
func (ks *KeySchedule) Config() Config {
	return ks.cfg
}

// Anchor returns k_0, the public anchor that should be published at setup.
// Verifiers use it to check consistency: H^t(k_t) == k_0.
func (ks *KeySchedule) Anchor() []byte {
	out := make([]byte, len(ks.anchor))
	copy(out, ks.anchor)
	return out
}

// epochOf returns the epoch index for a given wall-clock time.
func (ks *KeySchedule) epochOf(t time.Time) int64 {
	elapsed := t.Sub(ks.cfg.Epoch)
	if elapsed < 0 {
		return 0
	}
	e := int64(elapsed / ks.cfg.Delay)
	if e > ks.cfg.ChainLength {
		e = ks.cfg.ChainLength
	}
	return e
}

// keyForEpoch returns the chain key k_epoch. Results are already fully cached
// during construction so this is always O(1).
func (ks *KeySchedule) keyForEpoch(epoch int64) []byte {
	ks.mu.RLock()
	k := ks.cache[epoch]
	ks.mu.RUnlock()
	return k
}

// CurrentKey returns the chain key k_t for the epoch that contains time t.
func (ks *KeySchedule) CurrentKey(t time.Time) []byte {
	return ks.keyForEpoch(ks.epochOf(t))
}

// DisclosedKey returns the epoch index and key that should be disclosed at
// time t. A key for epoch τ is disclosed once d disclosure-delay epochs have
// elapsed after τ. With d=1, the key for epoch (current−1) is disclosed when
// epoch current starts.
//
// If t is still within epoch 0 (no key is disclosable yet), ok is false.
func (ks *KeySchedule) DisclosedKey(t time.Time) (index int64, key []byte, ok bool) {
	current := ks.epochOf(t)
	if current < 1 {
		return 0, nil, false
	}
	// Disclose the key one epoch behind the current one (disclosure delay d=1).
	disclosable := current - 1
	return disclosable, ks.keyForEpoch(disclosable), true
}

// KeyAtEpoch returns the chain key for the given epoch index.
func (ks *KeySchedule) KeyAtEpoch(epoch int64) ([]byte, error) {
	if epoch < 0 || epoch > ks.cfg.ChainLength {
		return nil, fmt.Errorf("tesla: epoch %d out of range [0, %d]", epoch, ks.cfg.ChainLength)
	}
	return ks.keyForEpoch(epoch), nil
}

// VerifyChain checks that H^t(k_t) == k_0 (the public anchor).
// A verifier calls this after reconstructing k_t to confirm its authenticity.
func VerifyChain(anchor, key []byte, t int64) bool {
	h := sha256.New()
	cur := make([]byte, len(key))
	copy(cur, key)
	for i := int64(0); i < t; i++ {
		h.Reset()
		h.Write(cur)
		cur = h.Sum(nil)
	}
	return hmac.Equal(cur, anchor)
}

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

// DeriveAK computes the per-measurement authentication key:
//
//	ak = HKDF-SHA256(secret=k, info=measurementID, length=32)
//
// measurementID should be the raw bytes of the UUID (or any stable byte
// representation of the measurement identifier).
func DeriveAK(k []byte, measurementID []byte) ([]byte, error) {
	r := hkdf.New(sha256.New, k, nil, measurementID)
	ak := make([]byte, 32)
	if _, err := io.ReadFull(r, ak); err != nil {
		return nil, fmt.Errorf("tesla: HKDF failed: %w", err)
	}
	return ak, nil
}

// ComputeTag computes the 16-bit authentication tag for a packet payload:
//
//	tag = HMAC-SHA256(ak, payload)[0:2]
//
// The returned uint16 is in host byte order; the caller is responsible for
// writing it into the IPID field in network (big-endian) byte order.
func ComputeTag(ak, payload []byte) (uint16, error) {
	mac := hmac.New(sha256.New, ak)
	mac.Write(payload)
	sum := mac.Sum(nil)
	return binary.BigEndian.Uint16(sum[:2]), nil
}

// ComputeTagForPacket is a convenience wrapper that derives ak from the chain
// key at time t and then computes the tag over payload.
func (ks *KeySchedule) ComputeTagForPacket(t time.Time, measurementID, payload []byte) (uint16, error) {
	k := ks.CurrentKey(t)
	ak, err := DeriveAK(k, measurementID)
	if err != nil {
		return 0, err
	}
	return ComputeTag(ak, payload)
}

// VerifyTag checks whether tag matches the expected HMAC for the packet at a
// given epoch, given the disclosed key for that epoch and the measurement ID.
//
// If packet begins with a valid IPv4 header (version == 4, length ≥ 20), both
// the IPID field (bytes 4–5) and the IPv4 checksum field (bytes 10–11) are
// zeroed before hashing, exactly as TagPacket does. The caller should pass the
// full received packet bytes (with the IPID field containing the observed tag
// and the checksum field as received on the wire).
func VerifyTag(disclosedKey []byte, epoch int64, measurementID, packet []byte, tag uint16) (bool, error) {
	// Canonicalise IPv4 mutable fields before hashing, to match TagPacket.
	if len(packet) >= 20 && (packet[0]>>4) == 4 {
		pkt := make([]byte, len(packet))
		copy(pkt, packet)
		pkt[4] = 0  // IPID
		pkt[5] = 0
		pkt[10] = 0 // IPv4 checksum
		pkt[11] = 0
		packet = pkt
	}
	ak, err := DeriveAK(disclosedKey, measurementID)
	if err != nil {
		return false, err
	}
	expected, err := ComputeTag(ak, packet)
	if err != nil {
		return false, err
	}
	return expected == tag, nil
}

// siphash24 computes SipHash-2-4.
func siphash24(k0, k1 uint64, data []byte) uint64 {
	v0 := k0 ^ 0x736f6d6570736575
	v1 := k1 ^ 0x646f72616e646f6d
	v2 := k0 ^ 0x6c7967656e657261
	v3 := k1 ^ 0x7465646279746573

	blocks := len(data) / 8
	if blocks > 8 { // match tagger.c 64-byte limit
		blocks = 8
	}

	for i := 0; i < blocks; i++ {
		m := binary.LittleEndian.Uint64(data[i*8 : i*8+8])
		v3 ^= m
		for j := 0; j < 2; j++ {
			v0 += v1; v1 = (v1 << 13) | (v1 >> 51); v1 ^= v0; v0 = (v0 << 32) | (v0 >> 32)
			v2 += v3; v3 = (v3 << 16) | (v3 >> 48); v3 ^= v2
			v0 += v3; v3 = (v3 << 21) | (v3 >> 43); v3 ^= v0
			v2 += v1; v1 = (v1 << 17) | (v1 >> 47); v1 ^= v2; v2 = (v2 << 32) | (v2 >> 32)
		}
		v0 ^= m
	}

	b := uint64(len(data)) << 56
	if len(data) > 64 {
		b = 64 << 56
	}
	v3 ^= b
	for j := 0; j < 2; j++ {
		v0 += v1; v1 = (v1 << 13) | (v1 >> 51); v1 ^= v0; v0 = (v0 << 32) | (v0 >> 32)
		v2 += v3; v3 = (v3 << 16) | (v3 >> 48); v3 ^= v2
		v0 += v3; v3 = (v3 << 21) | (v3 >> 43); v3 ^= v0
		v2 += v1; v1 = (v1 << 17) | (v1 >> 47); v1 ^= v2; v2 = (v2 << 32) | (v2 >> 32)
	}
	v0 ^= b
	v2 ^= 0xff
	for j := 0; j < 4; j++ {
		v0 += v1; v1 = (v1 << 13) | (v1 >> 51); v1 ^= v0; v0 = (v0 << 32) | (v0 >> 32)
		v2 += v3; v3 = (v3 << 16) | (v3 >> 48); v3 ^= v2
		v0 += v3; v3 = (v3 << 21) | (v3 >> 43); v3 ^= v0
		v2 += v1; v1 = (v1 << 17) | (v1 >> 47); v1 ^= v2; v2 = (v2 << 32) | (v2 >> 32)
	}
	return v0 ^ v1 ^ v2 ^ v3
}

// ComputeBPFTag computes the BPF SipHash-2-4 tag for a packet payload.
// It does not perform packet canonicalization (which should be done by the caller or
// on raw packet payloads).
func ComputeBPFTag(ak, payload []byte) (uint16, error) {
	if len(ak) < 16 {
		return 0, fmt.Errorf("tesla: ak too short")
	}
	k0 := binary.LittleEndian.Uint64(ak[0:8])
	k1 := binary.LittleEndian.Uint64(ak[8:16])

	hashLength := len(payload)
	if hashLength > 64 {
		hashLength = 64
	}

	hash := siphash24(k0, k1, payload[:hashLength])
	return uint16(hash & 0xFFFF), nil
}

// ComputeBPFTagForPacket derives ak from the chain key at time t and then
// computes the BPF SipHash-2-4 tag over payload.
func (ks *KeySchedule) ComputeBPFTagForPacket(t time.Time, measurementID, payload []byte) (uint16, error) {
	k := ks.CurrentKey(t)
	ak, err := DeriveAK(k, measurementID)
	if err != nil {
		return 0, err
	}
	return ComputeBPFTag(ak, payload)
}

// VerifyBPFTag checks whether tag matches the expected SipHash for the packet
func VerifyBPFTag(disclosedKey []byte, epoch int64, measurementID, packet []byte, tag uint16) (bool, error) {
	if len(packet) >= 20 && (packet[0]>>4) == 4 {
		pkt := make([]byte, len(packet))
		copy(pkt, packet)
		pkt[4] = 0  // IPID
		pkt[5] = 0
		pkt[10] = 0 // IPv4 checksum
		pkt[11] = 0
		packet = pkt
	}
	ak, err := DeriveAK(disclosedKey, measurementID)
	if err != nil {
		return false, err
	}
	expected, err := ComputeBPFTag(ak, packet)
	if err != nil {
		return false, err
	}
	return expected == tag, nil
}
