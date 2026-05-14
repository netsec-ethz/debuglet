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
// Keys form a backward hash chain anchored at a random seed:
//
//	k_0 (seed, never disclosed)
//	k_{i+1} = H(k_i)
//
// Each key k_i is kept secret for a configurable delay period D. After D has
// elapsed the executor publishes k_i so that any observer who buffered packets
// can retroactively verify their authentication tags.
//
// # Per-Measurement Derivation
//
// Because a single executor may service multiple measurements concurrently, an
// additional per-measurement key ak is derived from the current chain key:
//
//	ak = HKDF-SHA256(k_i, info = measurement_id)
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
	// Seed is the root secret of the hash chain (k_0). If nil, a random
	// 32-byte seed is generated on the first call to NewKeySchedule.
	Seed []byte

	// Delay is how long a key is kept secret before it is disclosed.
	// Defaults to 10 seconds.
	Delay time.Duration

	// Epoch is the reference wall-clock time that anchors epoch 0.
	// Defaults to the time NewKeySchedule is called.
	Epoch time.Time
}

// KeySchedule is a thread-safe TESLA hash-chain key schedule.
//
// Keys are indexed by epoch number:
//
//	epoch i covers the time interval [Epoch + i*Delay, Epoch + (i+1)*Delay).
//
// The "current" key is the one whose epoch interval contains now.
// A key becomes "disclosable" once its epoch interval ended and an additional
// Delay has elapsed (i.e., after 2*Delay from its start time).
type KeySchedule struct {
	cfg Config

	mu    sync.RWMutex
	cache map[int64][]byte // epoch → derived key (memoised)
}

// NewKeySchedule creates a KeySchedule from cfg. If cfg.Seed is empty a
// cryptographically random 32-byte seed is generated. If cfg.Delay is zero
// it defaults to 10 seconds.
func NewKeySchedule(cfg Config) (*KeySchedule, error) {
	if len(cfg.Seed) == 0 {
		cfg.Seed = make([]byte, 32)
		if _, err := io.ReadFull(rand.Reader, cfg.Seed); err != nil {
			return nil, fmt.Errorf("tesla: failed to generate seed: %w", err)
		}
	}
	if cfg.Delay == 0 {
		cfg.Delay = 10 * time.Second
	}
	if cfg.Epoch.IsZero() {
		cfg.Epoch = time.Now()
	}
	return &KeySchedule{
		cfg:   cfg,
		cache: make(map[int64][]byte),
	}, nil
}

// Config returns a copy of the schedule's configuration.
func (ks *KeySchedule) Config() Config {
	return ks.cfg
}

// epochOf returns the epoch index for a given wall-clock time.
func (ks *KeySchedule) epochOf(t time.Time) int64 {
	elapsed := t.Sub(ks.cfg.Epoch)
	if elapsed < 0 {
		return 0
	}
	return int64(elapsed / ks.cfg.Delay)
}

// keyForEpoch computes k_epoch by applying the hash function epoch times to
// the seed. Results are memoised so repeated calls are O(1) amortised.
//
// The key chain is constructed forward:
//
//	k_0 = seed
//	k_{n+1} = SHA-256(k_n)
func (ks *KeySchedule) keyForEpoch(epoch int64) []byte {
	ks.mu.Lock()
	defer ks.mu.Unlock()

	if k, ok := ks.cache[epoch]; ok {
		return k
	}

	// Find the closest memoised predecessor.
	var start int64
	var key []byte

	// Walk backwards to find a cached ancestor.
	for i := epoch - 1; i >= 0; i-- {
		if k, ok := ks.cache[i]; ok {
			start = i
			key = k
			break
		}
	}
	if key == nil {
		// No cache hit: start from seed (epoch 0).
		key = make([]byte, len(ks.cfg.Seed))
		copy(key, ks.cfg.Seed)
		start = 0
	}

	// Hash forward from start to epoch.
	h := sha256.New()
	for i := start; i < epoch; i++ {
		h.Reset()
		h.Write(key)
		key = h.Sum(nil)
	}

	// Cache the computed key.
	ks.cache[epoch] = key
	return key
}

// CurrentKey returns the current TESLA key (the one for time t).
func (ks *KeySchedule) CurrentKey(t time.Time) []byte {
	return ks.keyForEpoch(ks.epochOf(t))
}

// DisclosedKey returns the epoch index and key that should be disclosed at
// time t. A key for epoch i is disclosed once the epoch for (i + 1) has
// started, i.e. after Delay has elapsed since epoch i ended.
//
// If t is still within epoch 0 (no key is disclosable yet), ok is false.
func (ks *KeySchedule) DisclosedKey(t time.Time) (index int64, key []byte, ok bool) {
	current := ks.epochOf(t)
	if current < 1 {
		return 0, nil, false
	}
	// Disclose the key one epoch behind the current one.
	disclosable := current - 1
	return disclosable, ks.keyForEpoch(disclosable), true
}

// KeyAtEpoch returns the raw key for the given epoch index. This is used by
// verifiers who received a disclosed key and want to reconstruct an older one.
func (ks *KeySchedule) KeyAtEpoch(epoch int64) ([]byte, error) {
	if epoch < 0 {
		return nil, fmt.Errorf("tesla: negative epoch %d", epoch)
	}
	return ks.keyForEpoch(epoch), nil
}

// DeriveFromDisclosed reconstructs the key at targetEpoch given a disclosed
// key at disclosedEpoch. Any verifier can call this without access to the
// seed, by hashing the disclosed key forward (disclosedEpoch → targetEpoch).
//
// Because keys are a forward hash chain, you can only derive keys at epochs
// ≥ disclosedEpoch. To reconstruct an earlier key you need a key from an
// even later epoch and hash forward from there, which requires the seed.
//
// In practice the executor discloses keys in order so observers always receive
// a later key and hash it forward to fill in gaps.
func DeriveFromDisclosed(disclosedKey []byte, disclosedEpoch, targetEpoch int64) ([]byte, error) {
	if targetEpoch < disclosedEpoch {
		return nil, fmt.Errorf("tesla: cannot derive epoch %d from disclosed epoch %d (target must be ≥ disclosed)", targetEpoch, disclosedEpoch)
	}
	key := make([]byte, len(disclosedKey))
	copy(key, disclosedKey)
	h := sha256.New()
	for i := disclosedEpoch; i < targetEpoch; i++ {
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
	
	if len(ak) < 16 {
		return false, fmt.Errorf("ak too short")
	}
	
	k0 := binary.LittleEndian.Uint64(ak[0:8])
	k1 := binary.LittleEndian.Uint64(ak[8:16])
	
	hashLength := len(packet)
	if hashLength > 64 {
		hashLength = 64
	}
	
	hash := siphash24(k0, k1, packet[:hashLength])
	expected := uint16(hash & 0xFFFF)
	return expected == tag, nil
}
