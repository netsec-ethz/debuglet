// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 ETH Zurich

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
// The executor uses key k_i during epoch i (1 ≤ i < L) and discloses it once
// the disclosure delay of d ≥ 2 epochs has elapsed, at the start of epoch i+d
// (see Disclosure). Because k_0 is public, epoch 0 has no signing key: nothing
// is tagged before epoch 1 starts. Because k_L is never disclosed, nothing is
// tagged from epoch L on either. A verifier who
// has buffered packets from epoch i can verify them once k_i is published by
// checking:
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
// The authentication tag written into the IPv4 IPID field follows the
// versioned tag specification TagSpec (docs/tag-spec.md):
//
//	tag = SipHash-2-4(ak[0:16], canonical(packet)) mod 2^16
//
// where canonical takes the first min(64, total length) bytes and zeroes the
// fields a router, NAT or checksum offload rewrites. The eBPF tagger
// (tagger.c) and the pure-Go fallback compute it identically; see HashInput
// and PacketTag.
//
// # Disclosure
//
// k_i is disclosed no earlier than the start of epoch i+d, where the
// disclosure delay d (Config.DisclosureDelay) is at least MinDisclosureDelay
// epochs. This is TESLA's safety condition: a verifier accepts k_i only for
// packets it received before k_i could have been disclosed, and it tries the
// packet's epoch t and its predecessor t-1 to absorb clock skew. With d = 1,
// k_{t-1} would be public during epoch t, so anyone who saw it could forge
// tags that verify for packets timestamped in epoch t. With d ≥ 2 the key of
// every candidate epoch is still secret while its packets are in flight; the
// margin (d-1)·I must exceed the verifier's clock tolerance plus the skew
// between the executor, the dispatcher and the capture host.
//
// A key is also disclosed no earlier than the first heartbeat after every
// kernel tagger of the chain has moved off it. Each eBPF tagger registers with
// the schedule as an InstalledKeyHolder and reports the epoch whose key its map
// slot may still hold; DisclosedKey never names that epoch or a later one. The
// kernel taggers refresh their key at each epoch boundary, so in the ordinary
// case the taggers have moved off k_i long before epoch i+d, and a delayed or
// failed refresh delays disclosure instead of leaving a disclosed key
// installed. At the end of the chain k_{L-1} follows the same rules: it is
// disclosed from the start of epoch L-1+d, once every tagger has removed it at
// Expiry. The pure-Go tagger
// reads CurrentKey for every packet and holds no key.
//
// Disclosure therefore lags the start of epoch i+d by up to one heartbeat
// interval, or longer while a refresh fails. A verifier waits for the key
// rather than treating a missing one as a failure.
//
// # Attribution
//
// Attribution reports whether packets tagged now can be attributed: not in
// epoch 0 or from Expiry, not while the clock cannot be trusted (see Time), not
// while a holder's latest refresh failed, and not once an installed key has
// held disclosure back for longer than one epoch. The executor sends it in its
// capability report.
//
// # Time
//
// Epochs advance on the monotonic clock from Epoch, whose wall reading is the
// origin the executor announces; a verifier maps a capture's wall time to an
// epoch from that origin (docs/tag-spec.md). Two clock conditions make that
// mapping wrong, and CurrentKey returns no key while either holds:
//
//   - The host clock was not ready when the chain started (Config.ClockUnready),
//     so the origin itself may be wrong. This holds for the chain's life; a
//     restart with a ready clock starts a new chain.
//   - The wall time elapsed since Epoch differs from the monotonic time elapsed
//     by more than MaxDrift (Drift): the wall clock was stepped, or the host was
//     suspended, which the monotonic clock does not count.
//
// Local epochs never decrease, so a disclosed key never regains signing
// authority whatever the wall clock does; CurrentKey also never returns the key
// of an epoch below the highest one it has already returned.
package tesla

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"time"

	"github.com/netsec-ethz/debuglet/pkg/tagspec"
	"golang.org/x/crypto/hkdf"
)

// DefaultChainHorizon is the uptime a default-sized chain covers. The
// default ChainLength is DefaultChainHorizon/EpochLength, so a longer epoch gives
// a shorter chain rather than a shorter usable lifetime.
const DefaultChainHorizon = 7 * 24 * time.Hour

// maxDefaultChainLength caps the derived default so a very short epoch cannot
// allocate an unreasonable amount of memory. Keys are 32 bytes each, so this
// bound is ~19 MiB.
const maxDefaultChainLength = 604800

// DefaultEpochLength is the epoch length I of a schedule that names none.
const DefaultEpochLength = 10 * time.Second

// MinDisclosureDelay is the shortest disclosure delay d, in epochs, a schedule
// accepts. A verifier tries a packet's epoch t and t-1; with d = 1 the key of
// t-1 is already public during epoch t (see Disclosure).
const MinDisclosureDelay = tagspec.MinDisclosureDelay

// DefaultDisclosureWindow is the wall-clock time a default disclosure delay
// covers: d defaults to the smallest number of epochs, and at least
// MinDisclosureDelay, whose length reaches it. Fifteen minutes is in the
// range TRACER uses (10 to 30 minutes), far beyond any verifier tolerance or
// disciplined clock skew, and still short enough that a result's tags become
// verifiable soon after the run. At the default epoch length of 10 seconds it
// is d = 90.
const DefaultDisclosureWindow = 15 * time.Minute

// DefaultDisclosureDelay returns the disclosure delay, in epochs, of a
// schedule with the given epoch length that names none.
func DefaultDisclosureDelay(epochLength time.Duration) int64 {
	if epochLength <= 0 {
		epochLength = DefaultEpochLength
	}
	d := int64((DefaultDisclosureWindow + epochLength - 1) / epochLength)
	return max(d, MinDisclosureDelay)
}

// verifierClockTolerance is the clock tolerance a verifier applies by default
// (tools/verify_pcap.py --clock-tolerance), which bounds MaxDrift.
const verifierClockTolerance = time.Second

// keySize is the length in bytes of one chain key (SHA-256 output).
const keySize = sha256.Size

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
	//
	// If zero, it is derived from EpochLength so that the chain covers
	// DefaultChainHorizon of uptime. Sizing this from a wall-clock horizon
	// matters: k_L is never disclosed, so the last signing epoch is L-1 and
	// from the start of epoch L (Expiry) the schedule has no signing key and
	// nothing is tagged.
	ChainLength int64

	// EpochLength is the interval duration I of one epoch. Defaults to
	// DefaultEpochLength.
	EpochLength time.Duration

	// DisclosureDelay d is the number of epochs after which a key is
	// disclosed: k_i is disclosed once epoch i+d has started. Zero derives
	// DefaultDisclosureDelay(EpochLength); otherwise it must be at least
	// MinDisclosureDelay.
	DisclosureDelay int64

	// Epoch is the reference wall-clock time that anchors epoch 0.
	// Defaults to the time NewKeySchedule is called, whose reading also
	// carries the monotonic reference the epochs advance from.
	Epoch time.Time

	// ClockUnready records that the host clock was not ready when Epoch was
	// read, so the announced origin cannot be trusted: no key signs and
	// Attribution reports UnattributableClockUnready for the chain's life.
	ClockUnready bool

	// Clock measures the time elapsed since Epoch. Nil uses the readings of
	// the instants themselves (see Clock).
	Clock Clock
}

// Clock measures the time from a schedule's origin to an instant on the two
// clocks the schedule compares.
type Clock interface {
	// Elapsed returns the time from origin to t on the monotonic clock, which
	// advances the epochs, and on the wall clock, from which a verifier maps
	// capture times to epochs.
	Elapsed(origin, t time.Time) (monotonic, wall time.Duration)
}

// hostClock reads both from the instants: a time.Now reading carries the
// host's monotonic reading next to its wall reading. Without a monotonic
// reading on both instants, monotonic falls back to wall elapsed time.
type hostClock struct{}

func (hostClock) Elapsed(origin, t time.Time) (time.Duration, time.Duration) {
	return t.Sub(origin), t.Round(0).Sub(origin.Round(0))
}

// KeySchedule is a thread-safe TESLA hash-chain key schedule.
//
// Keys are indexed by epoch number t where t ∈ [0, L]:
//
//	epoch t covers the time interval [Epoch + t*I, Epoch + (t+1)*I).
//
// The chain direction is backward: k_0 is the public anchor and k_L is the
// private seed tail. Key k_t is used during epoch t and disclosed after the
// disclosure delay d has elapsed (i.e., once epoch t+d has started).
//
// k_0 is public from setup, so it never signs: epoch 0, and any instant before
// Epoch, has no usable signing key. The first usable key is k_1 at Epoch+I
// and the last is k_{L-1}; from Expiry, the start of epoch L, no key signs.
//
// The set of registered InstalledKeyHolders and the highest epoch CurrentKey
// has returned are the mutable parts; every other field is fixed at
// construction.
type KeySchedule struct {
	cfg Config

	// signed is the highest epoch whose key CurrentKey has returned; no lower
	// epoch's key is returned again.
	signed atomic.Int64

	// holdersMu guards holders, the kernel taggers whose installed key caps
	// what DisclosedKey may name.
	holdersMu sync.Mutex
	holders   map[InstalledKeyHolder]struct{}

	// keys holds the whole precomputed chain as one contiguous buffer:
	// keys[i*keySize:(i+1)*keySize] is k_i for i ∈ [0, L]. A slice rather
	// than a map keeps a multi-day chain cheap (32 bytes per epoch, no
	// per-entry overhead) and makes lookups allocation-free.
	//
	// The buffer is written once during construction and never mutated
	// afterwards, so concurrent reads need no locking.
	keys []byte
}

// NewKeySchedule creates a KeySchedule from cfg.
//
// The chain direction is backward (k_i = H(k_{i+1})). The private seed k_L is
// stored internally and the public anchor k_0 = H^L(seed) is computed once.
//
// If cfg.Seed is empty a cryptographically random 32-byte seed is generated.
// A seed that is not exactly 32 bytes long is folded through SHA-256 so that
// k_L is always one key wide.
// If cfg.EpochLength is zero it defaults to DefaultEpochLength.
// If cfg.DisclosureDelay is zero it defaults to DefaultDisclosureDelay; a
// delay below MinDisclosureDelay is refused.
// If cfg.ChainLength is zero it is derived from EpochLength (see DefaultChainHorizon).
func NewKeySchedule(cfg Config) (*KeySchedule, error) {
	if len(cfg.Seed) == 0 {
		cfg.Seed = make([]byte, 32)
		if _, err := io.ReadFull(rand.Reader, cfg.Seed); err != nil {
			return nil, fmt.Errorf("tesla: failed to generate seed: %w", err)
		}
	}
	if cfg.EpochLength <= 0 {
		cfg.EpochLength = DefaultEpochLength
	}
	if cfg.DisclosureDelay == 0 {
		cfg.DisclosureDelay = DefaultDisclosureDelay(cfg.EpochLength)
	}
	if cfg.DisclosureDelay < MinDisclosureDelay {
		return nil, fmt.Errorf("tesla: disclosure delay must be at least %d epochs, got %d", MinDisclosureDelay, cfg.DisclosureDelay)
	}
	if cfg.ChainLength <= 0 {
		cfg.ChainLength = min(int64(DefaultChainHorizon/cfg.EpochLength), maxDefaultChainLength)
	}
	if cfg.Epoch.IsZero() {
		cfg.Epoch = time.Now()
	}
	if cfg.Clock == nil {
		cfg.Clock = hostClock{}
	}

	// Pre-compute the full backward chain into one contiguous buffer.
	// k_L = seed (private tail), k_i = H(k_{i+1}) for i = L-1 … 0.
	//
	// The seed may be any length; k_L is stored as the SHA-256 of the seed
	// when the seed is not already one key wide, so every slot is keySize.
	keys := make([]byte, (cfg.ChainLength+1)*keySize)
	tail := keys[cfg.ChainLength*keySize:]
	if len(cfg.Seed) == keySize {
		copy(tail, cfg.Seed)
	} else {
		sum := sha256.Sum256(cfg.Seed)
		copy(tail, sum[:])
	}

	h := sha256.New()
	for i := cfg.ChainLength - 1; i >= 0; i-- {
		h.Reset()
		h.Write(keys[(i+1)*keySize : (i+2)*keySize])
		h.Sum(keys[i*keySize : i*keySize : (i+1)*keySize])
	}

	return &KeySchedule{
		cfg:     cfg,
		keys:    keys,
		holders: make(map[InstalledKeyHolder]struct{}),
	}, nil
}

// InstalledKeyHolder is a signing path that keeps a chain key outside the
// schedule, such as a kernel map slot. InstalledEpoch reports the epoch whose
// key the path may still sign with, and false once it holds no key.
type InstalledKeyHolder interface {
	InstalledEpoch() (epoch int64, installed bool)
}

// RegisterInstalled adds h to the holders that cap DisclosedKey. A holder
// registers before it installs its first key.
func (ks *KeySchedule) RegisterInstalled(h InstalledKeyHolder) {
	ks.holdersMu.Lock()
	defer ks.holdersMu.Unlock()
	ks.holders[h] = struct{}{}
}

// UnregisterInstalled removes h once it can no longer sign with any key.
func (ks *KeySchedule) UnregisterInstalled(h InstalledKeyHolder) {
	ks.holdersMu.Lock()
	defer ks.holdersMu.Unlock()
	delete(ks.holders, h)
}

// RefreshReporter is an InstalledKeyHolder that also reports its refresh: the
// time of its last successful key install, zero before one, and the error of
// its latest attempt, nil after a success.
type RefreshReporter interface {
	LastRefresh() (installed time.Time, err error)
}

// Reasons why packets tagged now cannot be attributed. They are the fixed
// vocabulary of the executor capability report.
const (
	// UnattributableEpochZero: k_0 is public, so nothing sent in epoch 0, or
	// before Epoch, is tagged with a secret key.
	UnattributableEpochZero = "epoch_zero"
	// UnattributableChainExhausted: from Expiry no key signs.
	UnattributableChainExhausted = "chain_exhausted"
	// UnattributableRefreshFailing: a kernel tagger's latest key refresh
	// failed, so its slot is empty or may still hold a previous epoch's key.
	UnattributableRefreshFailing = "refresh_failing"
	// UnattributableDisclosureHeld: an installed key has held disclosure back
	// for longer than MaxDisclosureHold, so the keys of new tags stay withheld.
	UnattributableDisclosureHeld = "disclosure_held"
	// UnattributableClockUnready: the host clock was not ready when the chain
	// started, so its announced origin may map packets to the wrong epoch.
	UnattributableClockUnready = "clock_unready"
	// UnattributableClockDrift: the wall clock has moved away from the
	// monotonic clock since the chain started by more than MaxDrift.
	UnattributableClockDrift = "clock_drift"
)

// Attribution is whether packets tagged at one instant can be attributed once
// their key is disclosed, with the kernel refresh state that decides it.
type Attribution struct {
	Epoch int64
	// Reason is empty when attribution is available, otherwise one of the
	// Unattributable constants; the first that applies in the order
	// chain_exhausted, clock_unready, clock_drift, epoch_zero,
	// refresh_failing, disclosure_held wins.
	Reason string
	// InstalledEpoch is the oldest epoch a registered holder may still sign
	// with; it is meaningful only when Installed.
	InstalledEpoch int64
	Installed      bool
	// LastInstall is the oldest last successful install among the holders
	// that report one, and zero when none does.
	LastInstall time.Time
	// RefreshErr is the latest error of a failing holder, nil when none fails.
	RefreshErr error
	// HeldSince is when the installed key started holding disclosure back, the
	// end of InstalledEpoch; zero when disclosure is not held.
	HeldSince time.Time
}

// MaxDisclosureHold bounds how long an installed key may hold disclosure back
// before attribution is reported unavailable. One epoch covers the boundary
// refresh and its first retry at EpochLength/2; the hold at every boundary until the
// refresh lands is ordinary and stays well inside it.
func (ks *KeySchedule) MaxDisclosureHold() time.Duration { return ks.cfg.EpochLength }

// MaxDrift is the largest Drift at which a key still signs: half an epoch, and
// at most the verifier's default clock tolerance of one second. It is a safety
// threshold beyond which the verifier's epoch mapping is taken to be wrong, not
// a measured bound on clock uncertainty.
func (ks *KeySchedule) MaxDrift() time.Duration {
	return min(ks.cfg.EpochLength/2, verifierClockTolerance)
}

// Drift returns the wall time elapsed from Epoch to now less the monotonic
// time elapsed: positive after a forward wall step or a suspend, negative after
// a backward step.
func (ks *KeySchedule) Drift(now time.Time) time.Duration {
	monotonic, wall := ks.cfg.Clock.Elapsed(ks.cfg.Epoch, now)
	return wall - monotonic
}

// clockReason is the clock condition that makes attribution unavailable given
// the drift at one instant, or empty.
func (ks *KeySchedule) clockReason(drift time.Duration) string {
	switch {
	case ks.cfg.ClockUnready:
		return UnattributableClockUnready
	case drift > ks.MaxDrift() || -drift > ks.MaxDrift():
		return UnattributableClockDrift
	}
	return ""
}

// Attribution reports the state at now. Without a registered holder only the
// epoch decides it, which is also the pure-Go tagger's case.
func (ks *KeySchedule) Attribution(now time.Time) Attribution {
	monotonic, wall := ks.cfg.Clock.Elapsed(ks.cfg.Epoch, now)
	a := Attribution{Epoch: ks.epochAt(monotonic)}
	clock := ks.clockReason(wall - monotonic)
	var failingSince time.Time
	ks.holdersMu.Lock()
	for h := range ks.holders {
		if epoch, installed := h.InstalledEpoch(); installed && (!a.Installed || epoch < a.InstalledEpoch) {
			a.InstalledEpoch, a.Installed = epoch, true
		}
		r, ok := h.(RefreshReporter)
		if !ok {
			continue
		}
		last, err := r.LastRefresh()
		if !last.IsZero() && (a.LastInstall.IsZero() || last.Before(a.LastInstall)) {
			a.LastInstall = last
		}
		// Of several failing holders, name the one that has failed longest.
		if err != nil && (a.RefreshErr == nil || last.Before(failingSince)) {
			a.RefreshErr, failingSince = err, last
		}
	}
	ks.holdersMu.Unlock()
	// A boundary refresh that lands after the caller read now installs the
	// next epoch's key; report it as now's epoch, since a report never names
	// an installed epoch later than its own.
	if a.Installed && a.InstalledEpoch > a.Epoch {
		a.InstalledEpoch = a.Epoch
	}
	if a.Installed && a.InstalledEpoch < a.Epoch {
		a.HeldSince = ks.cfg.Epoch.Add(time.Duration(a.InstalledEpoch+1) * ks.cfg.EpochLength)
	}
	switch {
	case a.Epoch >= ks.cfg.ChainLength:
		a.Reason = UnattributableChainExhausted
	case clock != "":
		a.Reason = clock
	case a.Epoch < 1:
		a.Reason = UnattributableEpochZero
	case a.RefreshErr != nil:
		a.Reason = UnattributableRefreshFailing
	case !a.HeldSince.IsZero() && now.Sub(a.HeldSince) > ks.MaxDisclosureHold():
		a.Reason = UnattributableDisclosureHeld
	}
	return a
}

// EpochOf returns the epoch that contains t: 0 before Epoch, and at most L.
func (ks *KeySchedule) EpochOf(t time.Time) int64 { return ks.epochOf(t) }

// Config returns a copy of the schedule's configuration.
func (ks *KeySchedule) Config() Config {
	return ks.cfg
}

// Anchor returns k_0, the public anchor that should be published at setup.
// Verifiers use it to check consistency: H^t(k_t) == k_0.
func (ks *KeySchedule) Anchor() []byte {
	out := make([]byte, keySize)
	copy(out, ks.keys[:keySize])
	return out
}

// ChainLength returns L, the highest epoch this schedule can serve.
func (ks *KeySchedule) ChainLength() int64 { return ks.cfg.ChainLength }

// Exhausted reports whether time t falls at or past the end of the chain, the
// start of epoch L. k_L is never disclosed, so an exhausted schedule has no
// signing key and CurrentKey returns nil from then on.
func (ks *KeySchedule) Exhausted(t time.Time) bool {
	return ks.epochOf(t) >= ks.cfg.ChainLength
}

// Expiry returns the wall-clock time at which the chain runs out.
func (ks *KeySchedule) Expiry() time.Time {
	return ks.cfg.Epoch.Add(time.Duration(ks.cfg.ChainLength) * ks.cfg.EpochLength)
}

// FinalDisclosure returns when the last signing key k_{L-1} becomes
// disclosable: the start of epoch L-1+d, d-1 epochs after Expiry. Keys live
// only in this schedule, so a restart before then starts a new chain and the
// keys of the old chain's last undisclosed epochs are never published; the
// packets they tagged cannot be verified.
func (ks *KeySchedule) FinalDisclosure() time.Time {
	return ks.cfg.Epoch.Add(time.Duration(ks.cfg.ChainLength-1+ks.cfg.DisclosureDelay) * ks.cfg.EpochLength)
}

// epochOf returns the epoch index for a given time.
func (ks *KeySchedule) epochOf(t time.Time) int64 {
	monotonic, _ := ks.cfg.Clock.Elapsed(ks.cfg.Epoch, t)
	return ks.epochAt(monotonic)
}

// epochAt returns the epoch index after the given monotonic time from Epoch.
func (ks *KeySchedule) epochAt(elapsed time.Duration) int64 {
	if elapsed < 0 {
		return 0
	}
	e := int64(elapsed / ks.cfg.EpochLength)
	if e > ks.cfg.ChainLength {
		e = ks.cfg.ChainLength
	}
	return e
}

// keyForEpoch returns the chain key k_epoch. The chain is fully precomputed
// during construction so this is always O(1). The returned slice aliases the
// schedule's immutable buffer and must not be modified.
func (ks *KeySchedule) keyForEpoch(epoch int64) []byte {
	if epoch < 0 || epoch > ks.cfg.ChainLength {
		return nil
	}
	return ks.keys[epoch*keySize : (epoch+1)*keySize]
}

// CurrentKey returns the chain key k_t for the epoch that contains time t, or
// nil while no key is usable: epochOf maps epoch 0 and any instant before
// Epoch to 0, whose key is the public anchor (see KeySchedule), and every
// instant from the start of epoch L to L, whose key k_L is never disclosed.
// No key is usable either while the clock cannot be trusted (see Time), or for
// an epoch below the highest one whose key CurrentKey has already returned.
// Every signing path reads the key here, so this is the one place the rule is
// decided.
func (ks *KeySchedule) CurrentKey(t time.Time) []byte {
	monotonic, wall := ks.cfg.Clock.Elapsed(ks.cfg.Epoch, t)
	epoch := ks.epochAt(monotonic)
	if epoch < 1 || epoch >= ks.cfg.ChainLength || ks.clockReason(wall-monotonic) != "" {
		return nil
	}
	for {
		signed := ks.signed.Load()
		if epoch < signed {
			return nil
		}
		if epoch == signed || ks.signed.CompareAndSwap(signed, epoch) {
			return ks.keyForEpoch(epoch)
		}
	}
}

// currentAK derives the per-measurement key at time t, failing while no chain
// key is usable so no tag is ever derived from the public anchor.
func (ks *KeySchedule) currentAK(t time.Time, measurementID []byte) ([]byte, error) {
	k := ks.CurrentKey(t)
	if k == nil {
		return nil, fmt.Errorf("tesla: no usable signing key (epoch 0, chain exhausted, untrusted clock or an epoch already passed)")
	}
	return DeriveAK(k, measurementID)
}

// DisclosedKey returns the epoch index and key that should be disclosed at
// time t. The key for epoch τ is disclosed once the disclosure delay of d
// epochs has elapsed after τ: at the start of epoch τ+d, so at time t the
// disclosed epoch is epoch(t)−d.
//
// Before epoch d has started (no key is disclosable yet), ok is false. The
// disclosed key stops at k_{L-1}, the last signing key, once epoch L−1+d has
// started, even though the chain was exhausted at epoch L; k_L is never
// disclosed.
//
// A registered holder that may still sign with k_e caps the result at e-1, so
// a key is never disclosed while an installed copy of it can tag packets.
func (ks *KeySchedule) DisclosedKey(t time.Time) (index int64, key []byte, ok bool) {
	// The epoch, not capped at L, so the last keys are still disclosed d
	// epochs after their own.
	elapsed, _ := ks.cfg.Clock.Elapsed(ks.cfg.Epoch, t)
	if elapsed < 0 {
		return 0, nil, false
	}
	current := int64(elapsed / ks.cfg.EpochLength)
	if current < ks.cfg.DisclosureDelay {
		return 0, nil, false
	}
	disclosable := min(current-ks.cfg.DisclosureDelay, ks.cfg.ChainLength-1)
	ks.holdersMu.Lock()
	for h := range ks.holders {
		if epoch, installed := h.InstalledEpoch(); installed && epoch-1 < disclosable {
			disclosable = max(epoch-1, 0)
		}
	}
	ks.holdersMu.Unlock()
	return disclosable, ks.keyForEpoch(disclosable), true
}

// DisclosureDelay returns d, the number of epochs after which a key is
// disclosed.
func (ks *KeySchedule) DisclosureDelay() int64 { return ks.cfg.DisclosureDelay }

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
// measurementID is the ASCII of the run's canonical UUID (tagspec.DeriveAK).
func DeriveAK(k []byte, measurementID []byte) ([]byte, error) {
	return tagspec.DeriveAK(k, measurementID)
}

// ChainSeed derives the tail k_L of one chain from a configured seed:
//
//	k_L = HKDF-SHA256(secret=seed, info="debuglet tesla chain <generation>", length=32)
//
// Each generation of the same seed yields a different chain, so a restart
// with an unchanged seed does not reuse keys an earlier chain disclosed.
func ChainSeed(seed []byte, generation int64) ([]byte, error) {
	r := hkdf.New(sha256.New, seed, nil, []byte(fmt.Sprintf("debuglet tesla chain %d", generation)))
	tail := make([]byte, keySize)
	if _, err := io.ReadFull(r, tail); err != nil {
		return nil, fmt.Errorf("tesla: HKDF failed: %w", err)
	}
	return tail, nil
}
