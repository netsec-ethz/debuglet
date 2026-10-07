// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package client

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/netsec-ethz/debuglet/pkg/tagspec"
)

// Probe verification (docs/verification.md): which Debuglet run, if any, sent
// the packets of a capture. Packets are grouped by source address and epoch;
// every group gets one verdict, unless its packets reproduce different runs
// or only some reproduce any: then it is split into an entry per run, one
// for the ambiguous and one for the unmatched packets.

// Verdict is the outcome of one packet group.
type Verdict string

const (
	// VerdictVerified: every packet carries a valid tag of the named run at
	// the named epoch (or the epoch before it).
	VerdictVerified Verdict = "verified"
	// VerdictInvalid: the history covers the time and no candidate run
	// reproduces any of the tags (Reason tag_mismatch or no_run).
	VerdictInvalid Verdict = "invalid"
	// VerdictPending: the key is not disclosed yet; retry after PendingUntil.
	VerdictPending Verdict = "pending"
	// VerdictMissing: the dispatcher holds no schedule or key for the time.
	// This is no evidence either way.
	VerdictMissing Verdict = "missing"
	// VerdictUnsupported: the group cannot be checked; Reason says why.
	VerdictUnsupported Verdict = "unsupported"
)

// VerifyMethod names how a group's verdict was established.
type VerifyMethod string

const (
	// VerifyMethodOffline: the verifier checked the tags itself against
	// disclosed keys. It shows the packets came from the run only if they
	// were captured before the disclosure, which rests on the capture's own
	// timestamps.
	VerifyMethodOffline VerifyMethod = "offline"
	// VerifyMethodServer: the executor confirmed the tags before their key
	// was disclosed, and the dispatcher signed a receipt of its answer
	// (POST /attribution/verify).
	VerifyMethodServer VerifyMethod = "server"
)

// Machine reasons of a group verdict.
const (
	ReasonTagMismatch = "tag_mismatch" // invalid: no packet of the group matches a candidate run
	ReasonNoRun       = "no_run"       // invalid: no run was active from the address

	ReasonNotDisclosed = "not_disclosed" // pending: a needed key is not disclosed yet

	ReasonNotRetained = "not_retained" // missing: the time is before the retained history
	ReasonKeysMissing = "keys_missing" // missing: the history lacks a key that should be disclosed

	ReasonIPv6              = tagspec.UnsupportedIPv6
	ReasonNotIPv4           = tagspec.UnsupportedNotIPv4
	ReasonTooShort          = tagspec.UnsupportedTooShort
	ReasonMalformed         = tagspec.UnsupportedMalformed
	ReasonFragment          = tagspec.UnsupportedFragment
	ReasonLinkType          = "link_type"           // no IP packet could be extracted from the frame
	ReasonTagSpec           = "tag_spec"            // a candidate tags with another or the pre-v1 tag spec
	ReasonDisclosureDelay   = "disclosure_delay"    // a candidate reports a disclosure delay below 2 epochs
	ReasonSchedule          = "schedule"            // a candidate's schedule is unusable
	ReasonBadKey            = "bad_key"             // a served key does not hash to the chain anchor
	ReasonNoSigningKey      = "no_signing_key"      // captured in epoch 0 or after the chain ran out
	ReasonKeyPublic         = "key_public"          // every candidate key may have been public at capture time
	ReasonAmbiguous         = "ambiguous"           // more than one run reproduces every tag
	ReasonUnmatched         = "unmatched"           // no candidate reproduces these packets, but others of their group match
	ReasonTooManyCandidates = "too_many_candidates" // the lookup named more than 32 runs
	ReasonWorkCap           = "work_cap"            // over a verification work cap
)

// Verification limits (docs/verification.md#limits).
const (
	// MaxVerifyTagComputations bounds the tag computations of one Verify
	// (packets × candidates × epochs). Groups beyond it are unsupported.
	MaxVerifyTagComputations = 1_000_000
	// maxVerifyCandidates is the most runs one lookup may name.
	maxVerifyCandidates = 32
	// maxVerifyLookups bounds the candidate lookups of one Verify: one per
	// group, where packets of a source without a run form a group per
	// second.
	maxVerifyLookups = 1024
	// maxVerifyKeyRequests bounds the key pages one Verify fetches.
	maxVerifyKeyRequests = 256
	// maxVerifyHashWalk bounds the SHA-256 steps of all chain walks of one
	// Verify; each chain is walked at most once, and never beyond its
	// chain_length.
	maxVerifyHashWalk = 1 << 24
	// DefaultClockTolerance is the default bound on how far the capture
	// clock may lag true time.
	DefaultClockTolerance = time.Second
	// disclosureSkew is the executor clock lead the dispatcher tolerates
	// when it accepts a disclosure (clockSkew in internal/dispatcher/tag), so
	// a key may be public this much before its scheduled time.
	disclosureSkew = 5 * time.Second
	// disclosureGrace is how long after its scheduled time a key still
	// counts as about to be disclosed: the executor discloses on its next
	// heartbeat after every tagger has moved off the key.
	disclosureGrace = 2 * time.Minute
	// noRunWindow groups packets of a source for which the lookup named no
	// run: epochs are whole seconds, so no run can start within it unseen.
	noRunWindow = time.Second
)

// VerifyOptions tune Verify.
type VerifyOptions struct {
	// CaptureClock is supplied independently by the capture operator. Its bound
	// may increase ClockTolerance; its digest must bind the exact capture.
	CaptureClock *CaptureClockTrust
	// At, when set, is taken as the capture time of every packet instead of
	// the capture's own timestamps.
	At time.Time
	// Offline never uploads packets: groups whose key is not disclosed yet
	// are pending. Without it, Client.Verify sends the first 64 bytes of the
	// packets of such groups to the dispatcher for a server-assisted check.
	Offline bool
	// ClockTolerance bounds how far the capture host's clock may lag true
	// time. A key is used only if it was still secret at the capture time
	// plus this. Zero is DefaultClockTolerance.
	ClockTolerance time.Duration
	// RequestRate (requests per second) and RequestBurst pace the history
	// requests of Client.Verify as a token bucket, to stay within the
	// dispatcher's per-client rate limit. Zero is the documented limit,
	// DefaultVerifyRequestRate and DefaultVerifyRequestBurst; a negative
	// rate disables pacing. After a 429 every request waits for the
	// Retry-After either way.
	RequestRate  float64
	RequestBurst int
}

// VerifyGroup is the verdict of the packets of one source address in one
// epoch.
type VerifyGroup struct {
	Verdict Verdict `json:"verdict"`
	// Reason is the machine reason of any verdict but verified.
	Reason string `json:"reason,omitempty"`
	// Detail explains the verdict in a sentence.
	Detail string `json:"detail"`
	// Method is how the verdict was established; empty when nothing was
	// checked.
	Method VerifyMethod `json:"method,omitempty"`
	// Source is the packets' source address; empty for frames without IP.
	Source     string `json:"source,omitempty"`
	RunID      string `json:"run_id,omitempty"`
	ExecutorID string `json:"executor_id,omitempty"`
	// Epoch is the capture epoch under the run's (or the address's first
	// candidate's) schedule; zero when there is none.
	Epoch int64 `json:"epoch,omitempty"`
	// Time is the capture time of the group's first packet.
	Time time.Time `json:"time"`
	// PendingUntil is when the last key the group needs is disclosed.
	PendingUntil *time.Time `json:"pending_until,omitempty"`
	// Packets are indices into the verified packets, in capture order.
	Packets []int `json:"packets"`
	// Matched counts the packets whose tag some candidate run reproduces,
	// Unmatched those it does not; a count of matches is only meaningful
	// together with the non-matches (docs/tag-spec.md §7). For an entry of
	// a split group they count the entry's own packets; Split has the
	// group's.
	Matched   int `json:"matched"`
	Unmatched int `json:"unmatched"`
	// Candidates counts the runs the group was checked against.
	Candidates int `json:"candidates"`
	// AmbiguousRuns lists the runs that each reproduce every tag.
	AmbiguousRuns []string `json:"ambiguous_runs,omitempty"`
	// FalseMatchBound bounds the probability that packets not sent by the
	// run match it by chance: N·C(n,k)·(E·2⁻¹⁶)^k for N candidates, E = 2
	// epochs and k of the group's n packets, which is N·(E·2⁻¹⁶)^n for an
	// unsplit group (docs/tag-spec.md §7). It underflows to zero for large k.
	FalseMatchBound float64 `json:"false_match_bound,omitempty"`
	// DisclosedAt is when the latest key the verdict used became due for
	// disclosure; packets captured before it (by a trustworthy clock) cannot
	// have been forged with that key.
	DisclosedAt *time.Time `json:"disclosed_at,omitempty"`
	// Split describes the address-and-epoch group this entry was split
	// from, when not all its packets reproduce one run; nil otherwise.
	Split *VerifySplit `json:"split,omitempty"`
	// ReceiptKeyID names the dispatcher key that signed the receipt of a
	// server verdict.
	ReceiptKeyID string `json:"receipt_key_id,omitempty"`

	lookup int     // index of the lookup answer that formed the group
	keys   []int64 // epochs of the named run's chain the verdict used
}

// VerifySplit describes a packet group that was split: its packets of each
// run, those several runs reproduce (ambiguous) and those no run reproduces
// (unmatched) are reported as separate entries, each carrying this record,
// so that every entry's match count can be read against the whole group's
// (docs/tag-spec.md §7).
type VerifySplit struct {
	// Packets counts the packets of the whole group.
	Packets int `json:"packets"`
	// Matched counts those some candidate run reproduces, Unmatched those
	// no candidate does.
	Matched   int `json:"matched"`
	Unmatched int `json:"unmatched"`
	// Runs lists the runs packets were attributed to.
	Runs []string `json:"runs"`
}

// VerifyCounts counts groups by verdict.
type VerifyCounts struct {
	Verified    int `json:"verified"`
	Invalid     int `json:"invalid"`
	Pending     int `json:"pending"`
	Missing     int `json:"missing"`
	Unsupported int `json:"unsupported"`
}

// VerifyReport is the result of Verify or VerifyEvidence.
type VerifyReport struct {
	// TagSpec is the tag specification the tags were checked under.
	TagSpec string `json:"tag_spec"`
	// CheckedAt is the time verification ran (for VerifyEvidence, the time
	// the bundle was created).
	CheckedAt time.Time `json:"checked_at"`
	// At is the capture time override, if any.
	At *time.Time `json:"at,omitempty"`
	// Dispatcher is the dispatcher the history came from.
	Dispatcher string `json:"dispatcher,omitempty"`
	// ClockTolerance is the capture clock lag bound applied.
	ClockToleranceMS int64 `json:"clock_tolerance_ms"`
	// HistoryAuthenticated means every used lookup was signed by a dispatcher
	// key obtained through this client's trusted connection or supplied by the
	// caller, not merely by a public key embedded in an evidence bundle.
	HistoryAuthenticated bool `json:"history_authenticated"`
	// CaptureTimeTrusted means an independent receiver record bound these
	// exact timestamps to the named schedule origins.
	CaptureTimeTrusted     bool `json:"capture_time_trusted"`
	SchedulesAuthenticated bool `json:"schedules_authenticated"`
	// Packets counts the packets checked.
	Packets int           `json:"packets"`
	Counts  VerifyCounts  `json:"counts"`
	Groups  []VerifyGroup `json:"groups"`

	material verifyMaterial
}

// verifyMaterial is what an evidence bundle needs to repeat the check.
type verifyMaterial struct {
	issuer     string
	packets    []CapturedPacket
	lookups    []EvidenceLookup
	chains     map[chainRef]*chainState
	apiVersion string
	// receipts are the signed answers of server-assisted checks, with the
	// keys that verify them.
	receipts    []EvidenceReceipt
	receiptKeys []EvidenceReceiptKey
}

// attributionSource answers the dated lookups of the attribution history: the
// dispatcher's public routes, or an evidence bundle.
type attributionSource interface {
	// candidates lists the runs active from ip within one epoch of at.
	candidates(ctx context.Context, ip netip.Addr, at time.Time) (EvidenceLookup, error)
	// keys returns the disclosed keys of a chain from from to to (both
	// inclusive), ascending, and the from of the next page, if any.
	keys(ctx context.Context, executorID, chain string, from, to int64) ([]EvidenceKey, *int64, error)
	// describe names the source for the report.
	describe() (dispatcher, apiVersion string)
}

type chainRef struct{ executor, chain string }

// chainState is the resolved key material of one chain.
type chainState struct {
	schedule EvidenceSchedule
	// unusable is the reason the chain cannot be used, if any.
	unusable string
	// disclosedThrough is the largest disclosed_through any lookup reported.
	disclosedThrough int64
	needed           map[int64]bool
	// keys holds the derived keys of needed epochs, status the reason a
	// needed epoch has no key (not_disclosed, keys_missing, work_cap,
	// bad_key).
	keys   map[int64][]byte
	status map[int64]string
	// anchorEpoch is the epoch of the disclosed key the walk started from.
	anchorEpoch int64
}

func (s EvidenceSchedule) interval() time.Duration {
	return time.Duration(s.EpochSeconds) * time.Second
}

// epochOf is the epoch containing at (floor division, negative before t0).
func (s EvidenceSchedule) epochOf(at time.Time) int64 {
	d := at.UnixNano() - s.T0UnixNs
	i := int64(s.interval())
	e := d / i
	if d%i != 0 && d < 0 {
		e--
	}
	return e
}

func (s EvidenceSchedule) epochStart(e int64) time.Time {
	return time.Unix(0, s.T0UnixNs+e*int64(s.interval()))
}

// dueAt is the scheduled disclosure of the key of epoch e.
func (s EvidenceSchedule) dueAt(e int64) time.Time {
	return s.epochStart(e + s.DisclosureDelayEpochs)
}

// usable returns why the schedule cannot be used for verification, or "".
func (s EvidenceSchedule) usable() string {
	switch {
	case s.TagSpec != tagspec.Version:
		return ReasonTagSpec
	case s.DisclosureDelayEpochs < tagspec.MinDisclosureDelay:
		return ReasonDisclosureDelay
	case s.EpochSeconds <= 0 || s.EpochSeconds > 1<<20 || len(s.K0) != sha256.Size || s.ChainID == "" ||
		s.ChainLength < 0 || s.DisclosureDelayEpochs > 1<<30 || s.DisclosureDelayEpochs*s.EpochSeconds > 366*24*3600 ||
		s.T0UnixNs < -(1<<61) || s.T0UnixNs > 1<<61:
		return ReasonSchedule
	}
	return ""
}

// verifier holds the state of one verification.
type verifier struct {
	src       attributionSource
	now       time.Time
	tolerance time.Duration
	packets   []CapturedPacket
	times     []time.Time

	lookups     []EvidenceLookup
	chains      map[chainRef]*chainState
	keyRequests int
	hashBudget  int64
	tagBudget   int
	akCache     map[akRef][]byte
}

type akRef struct {
	chain chainRef
	epoch int64
	run   string
}

// pendingGroup is a group formed by a lookup, before its verdict.
type pendingGroup struct {
	source  string
	indices []int
	lookup  int
	epoch   int64
	// verdict is set for groups decided without tag checks.
	decided *VerifyGroup
}

// verifyOffline runs the offline verification of packets against src.
func verifyOffline(ctx context.Context, src attributionSource, packets []CapturedPacket, opts VerifyOptions, now time.Time) (VerifyReport, error) {
	if len(packets) == 0 {
		return VerifyReport{}, errNoPackets
	}
	if len(packets) > MaxCapturePackets {
		return VerifyReport{}, fmt.Errorf("client: verify: more than %d packets", MaxCapturePackets)
	}
	if opts.ClockTolerance < 0 {
		return VerifyReport{}, errors.New("client: verify: negative clock tolerance")
	}
	tolerance := opts.ClockTolerance
	if tolerance == 0 {
		tolerance = DefaultClockTolerance
	}
	if opts.CaptureClock != nil {
		if !opts.At.IsZero() {
			return VerifyReport{}, errors.New("client: receiver clock trust cannot be combined with a timestamp override")
		}
		bound, err := opts.CaptureClock.tolerance()
		if err != nil {
			return VerifyReport{}, err
		}
		tolerance = max(tolerance, bound)
	}
	v := &verifier{
		src: src, now: now, tolerance: tolerance, packets: packets,
		chains: map[chainRef]*chainState{}, hashBudget: maxVerifyHashWalk,
		tagBudget: MaxVerifyTagComputations, akCache: map[akRef][]byte{},
	}
	v.times = make([]time.Time, len(packets))
	for i, p := range packets {
		v.times[i] = p.CapturedAt
		if !opts.At.IsZero() {
			v.times[i] = opts.At
		}
	}

	var groups []VerifyGroup
	unsupported := map[[2]string][]int{}
	bySource := map[netip.Addr][]int{}
	for i, p := range packets {
		addr, reason := classify(p.Data)
		if reason != "" {
			key := [2]string{"", reason}
			if addr.IsValid() {
				key[0] = addr.String()
			}
			unsupported[key] = append(unsupported[key], i)
			continue
		}
		bySource[addr] = append(bySource[addr], i)
	}
	for key, idx := range unsupported {
		g := VerifyGroup{Verdict: VerdictUnsupported, Reason: key[1], Source: key[0], Packets: idx, lookup: -1}
		groups = append(groups, v.finish(g))
	}

	// Pass 1: form the groups of every source, one lookup per group. The
	// lookups go round-robin over the sources, busiest first, so that every
	// source gets its first lookup before any source gets its second: over
	// the lookup cap, the addresses left unchecked are the tails of sources
	// without a run (one lookup per second each), not whole probe sources.
	type sourceQueue struct {
		addr netip.Addr
		idx  []int
	}
	queues := make([]*sourceQueue, 0, len(bySource))
	for a, idx := range bySource {
		sort.SliceStable(idx, func(x, y int) bool { return v.times[idx[x]].Before(v.times[idx[y]]) })
		queues = append(queues, &sourceQueue{addr: a, idx: idx})
	}
	slices.SortFunc(queues, func(a, b *sourceQueue) int {
		if len(a.idx) != len(b.idx) {
			return len(b.idx) - len(a.idx)
		}
		return a.addr.Compare(b.addr)
	})
	var pending []pendingGroup
	var capped []*sourceQueue
	for active := queues; len(active) > 0; {
		var next []*sourceQueue
		for _, q := range active {
			if len(v.lookups) >= maxVerifyLookups {
				capped = append(capped, q)
				continue
			}
			at := v.times[q.idx[0]]
			answer, err := src.candidates(ctx, q.addr, at)
			if err != nil {
				// The groups formed so far, this source's and those of
				// every source not reached yet in this round or the next.
				groups, pkts := len(pending), 0
				for _, g := range pending {
					pkts += len(g.indices)
				}
				rest := map[*sourceQueue]bool{}
				for _, r := range append(slices.Clone(active), next...) {
					if len(r.idx) > 0 {
						rest[r] = true
					}
				}
				for r := range rest {
					groups++
					pkts += len(r.idx)
				}
				return VerifyReport{}, rateLimited(err, groups, pkts, true)
			}
			answer.IP, answer.At = q.addr.String(), at.UTC()
			v.lookups = append(v.lookups, answer)
			li := len(v.lookups) - 1
			// The answer names the runs active within one epoch of at, so
			// it covers the packets up to the end of the current epoch of
			// every run it names (the shortest one first). Without a run
			// it covers a second, the shortest epoch.
			end, epoch, found := at.Add(noRunWindow), int64(0), false
			for _, c := range answer.Candidates {
				if c.Schedule.EpochSeconds <= 0 || c.Schedule.EpochSeconds > 1<<20 {
					continue
				}
				e := c.Schedule.epochOf(at)
				if ce := c.Schedule.epochStart(e + 1); !found || ce.Before(end) {
					end = ce
				}
				if !found {
					epoch, found = e, true
				}
			}
			n := sort.Search(len(q.idx), func(k int) bool { return !v.times[q.idx[k]].Before(end) })
			n = max(n, 1)
			pending = append(pending, pendingGroup{source: q.addr.String(), indices: q.idx[:n:n], lookup: li, epoch: epoch})
			if q.idx = q.idx[n:]; len(q.idx) > 0 {
				next = append(next, q)
			}
		}
		active = next
	}
	if len(capped) > 0 {
		unchecked := 0
		for _, q := range capped {
			unchecked += len(q.idx)
		}
		detail := fmt.Sprintf("the capture needs more than %d history lookups (one per source address and epoch, one per second for an address without a run); "+
			"%d packets of %d addresses were not checked. Filter the capture to the probe traffic, for example with dbl verify --source ADDRESS or tcpdump -w probe.pcap src host ADDRESS",
			maxVerifyLookups, unchecked, len(capped))
		for _, q := range capped {
			pending = append(pending, pendingGroup{source: q.addr.String(), indices: q.idx, lookup: -1,
				decided: &VerifyGroup{Verdict: VerdictUnsupported, Reason: ReasonWorkCap, Detail: detail}})
		}
	}

	// Pass 2: collect the key epochs every group needs, per chain, then
	// resolve each chain once.
	for _, g := range pending {
		if g.decided != nil {
			continue
		}
		for _, c := range v.usableCandidates(g.lookup) {
			st := v.chain(c)
			for _, i := range g.indices {
				epochs, _ := v.epochPlan(c.Schedule, v.times[i])
				for _, e := range epochs {
					st.needed[e] = true
				}
			}
		}
	}
	refs := make([]chainRef, 0, len(v.chains))
	for r := range v.chains {
		refs = append(refs, r)
	}
	slices.SortFunc(refs, func(a, b chainRef) int {
		return strings.Compare(a.executor+"\x00"+a.chain, b.executor+"\x00"+b.chain)
	})
	for _, r := range refs {
		if err := v.resolveChain(ctx, r, v.chains[r]); err != nil {
			pkts := 0
			for _, g := range pending {
				pkts += len(g.indices)
			}
			return VerifyReport{}, rateLimited(err, len(pending), pkts, false)
		}
	}

	// Pass 3: decide every group.
	for _, g := range pending {
		if g.decided != nil {
			d := *g.decided
			d.Source, d.Packets, d.lookup = g.source, g.indices, g.lookup
			groups = append(groups, v.finish(d))
			continue
		}
		for _, d := range v.decide(g) {
			groups = append(groups, v.finish(d))
		}
	}

	sortGroups(groups)
	dispatcher, apiVersion := src.describe()
	rep := VerifyReport{
		TagSpec: tagspec.ID, CheckedAt: now.UTC(), Dispatcher: dispatcher,
		ClockToleranceMS: tolerance.Milliseconds(), Packets: len(packets), Groups: groups, Counts: countGroups(groups),
		material: verifyMaterial{packets: packets, lookups: v.lookups, chains: v.chains, apiVersion: apiVersion},
	}
	if !opts.At.IsZero() {
		at := opts.At.UTC()
		rep.At = &at
	}
	if opts.CaptureClock != nil {
		if err := opts.CaptureClock.check(rep.Evidence()); err != nil {
			return VerifyReport{}, err
		}
		rep.CaptureTimeTrusted = true
	}
	return rep, nil
}

// sortGroups orders groups by verdict, run, time, source and reason.
func sortGroups(groups []VerifyGroup) {
	rank := map[Verdict]int{VerdictVerified: 0, VerdictInvalid: 1, VerdictPending: 2, VerdictMissing: 3, VerdictUnsupported: 4}
	slices.SortStableFunc(groups, func(a, b VerifyGroup) int {
		if rank[a.Verdict] != rank[b.Verdict] {
			return rank[a.Verdict] - rank[b.Verdict]
		}
		if a.RunID != b.RunID {
			return strings.Compare(a.RunID, b.RunID)
		}
		if c := a.Time.Compare(b.Time); c != 0 {
			return c
		}
		if a.Source != b.Source {
			return strings.Compare(a.Source, b.Source)
		}
		return strings.Compare(a.Reason, b.Reason)
	})
}

// countGroups counts groups by verdict.
func countGroups(groups []VerifyGroup) VerifyCounts {
	var counts VerifyCounts
	for _, g := range groups {
		switch g.Verdict {
		case VerdictVerified:
			counts.Verified++
		case VerdictInvalid:
			counts.Invalid++
		case VerdictPending:
			counts.Pending++
		case VerdictMissing:
			counts.Missing++
		default:
			counts.Unsupported++
		}
	}
	return counts
}

// rateLimited turns a request that waited for the rate limit until the
// context ended into a *RateLimitedError naming the unchecked groups.
func rateLimited(err error, groups, packets int, partial bool) error {
	var p *errPaced
	if !errors.As(err, &p) {
		return err
	}
	return &RateLimitedError{Throttled: p.throttled, UncheckedGroups: groups, UncheckedPackets: packets, Partial: partial, Err: p.err}
}
