// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package client

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"math"
	"net/http"
	"net/netip"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/netsec-ethz/debuglet/pkg/tagspec"
)

// classify returns the source address of a packet and why v1 does not cover
// it, if it does not.
func classify(data []byte) (netip.Addr, string) {
	if len(data) == 0 {
		return netip.Addr{}, ReasonLinkType
	}
	var addr netip.Addr
	switch data[0] >> 4 {
	case 4:
		if len(data) >= 20 {
			addr = netip.AddrFrom4([4]byte(data[12:16]))
		}
	case 6:
		if len(data) >= 24 {
			addr = netip.AddrFrom16([16]byte(data[8:24]))
		}
	}
	if _, err := tagspec.HashInput(data); err != nil {
		var u *tagspec.UnsupportedError
		if errors.As(err, &u) {
			return addr, u.Reason
		}
		return addr, ReasonMalformed
	}
	return addr, ""
}

// chain returns the state of a candidate's chain, creating it on first use. A
// chain reported with two different schedules is unusable.
func (v *verifier) chain(c EvidenceCandidate) *chainState {
	r := chainRef{c.ExecutorID, c.Schedule.ChainID}
	st := v.chains[r]
	if st == nil {
		st = &chainState{schedule: c.Schedule, needed: map[int64]bool{}, keys: map[int64][]byte{}, status: map[int64]string{}}
		v.chains[r] = st
	} else if !st.schedule.equal(c.Schedule) {
		st.unusable = ReasonSchedule
	}
	st.disclosedThrough = max(st.disclosedThrough, c.DisclosedThrough)
	return st
}

func (s EvidenceSchedule) equal(o EvidenceSchedule) bool {
	return s.ChainID == o.ChainID && bytes.Equal(s.K0, o.K0) && s.T0UnixNs == o.T0UnixNs && s.EpochSeconds == o.EpochSeconds &&
		s.DisclosureDelayEpochs == o.DisclosureDelayEpochs && s.ChainLength == o.ChainLength && s.TagSpec == o.TagSpec
}

// candidateReason is why a candidate cannot be checked, or "".
func (v *verifier) candidateReason(c EvidenceCandidate) string {
	if r := c.Schedule.usable(); r != "" {
		return r
	}
	if !isCanonicalUUID(c.RunID) || isNilUUID(c.RunID) || strings.TrimSpace(c.ExecutorID) == "" || c.DisclosedThrough < 0 {
		return ReasonSchedule
	}
	if st := v.chains[chainRef{c.ExecutorID, c.Schedule.ChainID}]; st != nil && st.unusable != "" {
		return st.unusable
	}
	return ""
}

// usableCandidates returns the candidates of a lookup that can be checked,
// registering their chains.
func (v *verifier) usableCandidates(lookup int) []EvidenceCandidate {
	var out []EvidenceCandidate
	for _, c := range v.lookups[lookup].Candidates {
		if v.candidateReason(c) != "" {
			continue
		}
		v.chain(c)
		if v.candidateReason(c) == "" {
			out = append(out, c)
		}
	}
	return out
}

// maxVerifyTime bounds capture times (±73 years around 1970 in nanoseconds)
// to keep epoch arithmetic in range.
const maxVerifyTime = int64(1) << 61

// epochPlan returns the candidate epochs of a packet captured at under a
// schedule: t and t-1, without epoch 0 and epochs from the chain's end on (no
// signing key), and without any epoch whose key may have been public at the
// capture time plus the clock tolerance (docs/tag-spec.md §6). excluded names
// the reason of an exclusion, key_public before no_signing_key.
func (v *verifier) epochPlan(s EvidenceSchedule, at time.Time) (epochs []int64, excluded string) {
	ns := at.UnixNano()
	if ns > maxVerifyTime || ns < -maxVerifyTime {
		return nil, ReasonNoSigningKey
	}
	t := s.epochOf(at)
	for _, e := range []int64{t, t - 1} {
		switch {
		case e < 1 || (s.ChainLength > 0 && e >= s.ChainLength):
			if excluded == "" {
				excluded = ReasonNoSigningKey
			}
		case !at.Add(v.tolerance).Before(s.dueAt(e).Add(-disclosureSkew)):
			excluded = ReasonKeyPublic
		default:
			epochs = append(epochs, e)
		}
	}
	return epochs, excluded
}

// resolveChain obtains the keys of the needed epochs of one chain: one
// disclosed key at or above the largest needed epoch, checked once against
// k0 by a single walk that derives every lower needed key on the way.
func (v *verifier) resolveChain(ctx context.Context, r chainRef, st *chainState) error {
	if st.unusable != "" || len(st.needed) == 0 {
		return nil
	}
	epochs := make([]int64, 0, len(st.needed))
	for e := range st.needed {
		epochs = append(epochs, e)
	}
	slices.Sort(epochs)
	var disclosed []int64
	for _, e := range epochs {
		if e <= st.disclosedThrough {
			disclosed = append(disclosed, e)
			continue
		}
		if v.now.Before(st.schedule.dueAt(e).Add(disclosureGrace)) {
			st.status[e] = ReasonNotDisclosed
		} else {
			st.status[e] = ReasonKeysMissing
		}
	}
	markRest := func(reason string) {
		for _, e := range disclosed {
			st.status[e] = reason
		}
	}
	for len(disclosed) > 0 {
		target := disclosed[len(disclosed)-1]
		var found *EvidenceKey
		for from := target; found == nil; {
			if v.keyRequests >= maxVerifyKeyRequests {
				markRest(ReasonWorkCap)
				return nil
			}
			v.keyRequests++
			keys, next, err := v.src.keys(ctx, r.executor, r.chain, from, st.disclosedThrough)
			if err != nil {
				var httpErr *HTTPError
				if errors.As(err, &httpErr) && httpErr.StatusCode == http.StatusNotFound {
					markRest(ReasonKeysMissing)
					return nil
				}
				return err
			}
			for i := range keys {
				if keys[i].Epoch >= target && keys[i].Epoch <= st.disclosedThrough {
					found = &keys[i]
					break
				}
			}
			if next == nil || *next <= from {
				break
			}
			from = *next
		}
		if found == nil {
			// Lost above target: the lower epochs may still be derivable
			// from a key between them and target.
			st.status[target] = ReasonKeysMissing
			disclosed = disclosed[:len(disclosed)-1]
			continue
		}
		tau := found.Epoch
		if len(found.Key) != sha256.Size || (st.schedule.ChainLength > 0 && tau > st.schedule.ChainLength) {
			markRest(ReasonBadKey)
			return nil
		}
		if tau > v.hashBudget {
			markRest(ReasonWorkCap)
			return nil
		}
		v.hashBudget -= tau
		cur := bytes.Clone(found.Key)
		derived := map[int64][]byte{}
		for e := tau; e >= 1; e-- {
			if st.needed[e] {
				derived[e] = bytes.Clone(cur)
			}
			sum := sha256.Sum256(cur)
			cur = sum[:]
		}
		if subtle.ConstantTimeCompare(cur, st.schedule.K0) != 1 {
			markRest(ReasonBadKey)
			return nil
		}
		st.anchorEpoch = tau
		for e, k := range derived {
			st.keys[e] = k
			delete(st.status, e)
		}
		return nil
	}
	return nil
}

// ak returns the per-measurement key of a run at an epoch, cached.
func (v *verifier) ak(c EvidenceCandidate, e int64, chainKey []byte) []byte {
	ref := akRef{chainRef{c.ExecutorID, c.Schedule.ChainID}, e, c.RunID}
	if ak, ok := v.akCache[ref]; ok {
		return ak
	}
	ak, err := tagspec.DeriveAK(chainKey, []byte(c.RunID))
	if err != nil {
		return nil
	}
	v.akCache[ref] = ak
	return ak
}

// packetCheck is the outcome of checking one packet against the candidates.
type packetCheck struct {
	// runs maps each run that reproduces the tag to the epoch whose key did.
	runs map[string]int64
	// definite: every candidate epoch was checked with a key that was still
	// secret at capture time, and none reproduced the tag.
	definite bool
	// The reasons a candidate epoch could not be checked.
	pending, missing, badKey, capped bool
	pendingUntil                     time.Time
	public, noKey                    bool
}

// decide checks the tags of one group against the candidates of its lookup.
// A group whose packets do not all reproduce one run is split: the packets
// of each run, the ambiguous and the unmatched ones become entries of their
// own (docs/verification.md#results).
func (v *verifier) decide(g pendingGroup) []VerifyGroup {
	answer := v.lookups[g.lookup]
	out := VerifyGroup{Source: g.source, Packets: g.indices, lookup: g.lookup, Epoch: g.epoch}
	first := v.times[g.indices[0]]
	if answer.Truncated || len(answer.Candidates) > maxVerifyCandidates {
		out.Verdict, out.Reason = VerdictUnsupported, ReasonTooManyCandidates
		return []VerifyGroup{out}
	}
	if len(answer.Candidates) == 0 {
		out.Epoch = 0
		if first.Before(answer.RetainedFrom) {
			out.Verdict, out.Reason = VerdictMissing, ReasonNotRetained
			return []VerifyGroup{out}
		}
		out.Verdict, out.Reason, out.Method = VerdictInvalid, ReasonNoRun, VerifyMethodOffline
		out.Unmatched = len(g.indices)
		return []VerifyGroup{out}
	}
	usable := v.usableCandidates(g.lookup)
	unusable := ""
	for _, c := range answer.Candidates {
		if r := v.candidateReason(c); r != "" && (unusable == "" || reasonPriority(r) < reasonPriority(unusable)) {
			unusable = r
		}
	}
	out.Candidates = len(usable)
	if len(usable) == 0 {
		out.Verdict, out.Reason = VerdictUnsupported, unusable
		return []VerifyGroup{out}
	}
	cost := 0
	for _, i := range g.indices {
		for _, c := range usable {
			epochs, _ := v.epochPlan(c.Schedule, v.times[i])
			cost += len(epochs)
		}
	}
	if cost > v.tagBudget {
		out.Verdict, out.Reason = VerdictUnsupported, ReasonWorkCap
		out.Detail = fmt.Sprintf("checking this group would exceed the cap of %d tag computations; split or filter the capture", MaxVerifyTagComputations)
		return []VerifyGroup{out}
	}
	v.tagBudget -= cost

	checks := make([]packetCheck, len(g.indices))
	var matchedIdx, unmatchedIdx []int // positions in g.indices
	for k, i := range g.indices {
		checks[k] = v.checkPacket(usable, i)
		if len(checks[k].runs) > 0 {
			matchedIdx = append(matchedIdx, k)
		} else {
			unmatchedIdx = append(unmatchedIdx, k)
		}
	}
	if len(matchedIdx) == 0 {
		out.Unmatched = len(g.indices)
		v.unmatchedVerdict(&out, checks, unmatchedIdx, unusable, false)
		return []VerifyGroup{out}
	}

	// The runs that reproduce every matched packet.
	var common []string
	for run := range checks[matchedIdx[0]].runs {
		all := true
		for _, k := range matchedIdx[1:] {
			if _, ok := checks[k].runs[run]; !ok {
				all = false
				break
			}
		}
		if all {
			common = append(common, run)
		}
	}
	sort.Strings(common)
	if len(unmatchedIdx) == 0 && len(common) > 0 {
		out.Matched = len(g.indices)
		if len(common) > 1 {
			out.Verdict, out.Reason, out.AmbiguousRuns = VerdictUnsupported, ReasonAmbiguous, common
			return []VerifyGroup{out}
		}
		v.verifiedEntry(&out, usable, common[0], checks, matchedIdx, len(g.indices))
		return []VerifyGroup{out}
	}

	// Split. Every matched packet goes to the one run that every matched
	// packet reproduces, if there is one, and otherwise to the one run it
	// reproduces; a packet that reproduces several runs stays ambiguous.
	byRun := map[string][]int{}
	var ambiguous []int
	ambiguousRuns := map[string]bool{}
	for _, k := range matchedIdx {
		switch {
		case len(common) == 1:
			byRun[common[0]] = append(byRun[common[0]], k)
		case len(common) == 0 && len(checks[k].runs) == 1:
			for run := range checks[k].runs {
				byRun[run] = append(byRun[run], k)
			}
		default:
			ambiguous = append(ambiguous, k)
			for run := range checks[k].runs {
				if len(common) == 0 || slices.Contains(common, run) {
					ambiguousRuns[run] = true
				}
			}
		}
	}
	split := &VerifySplit{Packets: len(g.indices), Matched: len(matchedIdx), Unmatched: len(unmatchedIdx)}
	runs := make([]string, 0, len(byRun))
	for run := range byRun {
		runs = append(runs, run)
	}
	sort.Strings(runs)
	split.Runs = runs
	entry := func(ks []int) VerifyGroup {
		e := VerifyGroup{Source: g.source, lookup: g.lookup, Epoch: g.epoch, Candidates: len(usable), Split: split}
		for _, k := range ks {
			e.Packets = append(e.Packets, g.indices[k])
		}
		return e
	}
	var entries []VerifyGroup
	for _, run := range runs {
		e := entry(byRun[run])
		e.Matched = len(byRun[run])
		v.verifiedEntry(&e, usable, run, checks, byRun[run], len(g.indices))
		entries = append(entries, e)
	}
	if len(ambiguous) > 0 {
		e := entry(ambiguous)
		e.Matched = len(ambiguous)
		e.Verdict, e.Reason = VerdictUnsupported, ReasonAmbiguous
		for run := range ambiguousRuns {
			e.AmbiguousRuns = append(e.AmbiguousRuns, run)
		}
		sort.Strings(e.AmbiguousRuns)
		entries = append(entries, e)
	}
	if len(unmatchedIdx) > 0 {
		e := entry(unmatchedIdx)
		e.Unmatched = len(unmatchedIdx)
		v.unmatchedVerdict(&e, checks, unmatchedIdx, unusable, true)
		entries = append(entries, e)
	}
	return entries
}

// checkPacket checks the tag of packet i against every usable candidate.
func (v *verifier) checkPacket(usable []EvidenceCandidate, i int) packetCheck {
	pkt := v.packets[i].Data
	id, _ := tagspec.PacketID(pkt)
	in, _ := tagspec.HashInput(pkt)
	pc := packetCheck{runs: map[string]int64{}}
	checked, blocked := false, false
	for _, c := range usable {
		st := v.chains[chainRef{c.ExecutorID, c.Schedule.ChainID}]
		epochs, excluded := v.epochPlan(c.Schedule, v.times[i])
		switch excluded {
		case ReasonKeyPublic:
			pc.public = true
		case ReasonNoSigningKey:
			pc.noKey = true
		}
		for _, e := range epochs {
			key, ok := st.keys[e]
			if !ok {
				blocked = true
				switch st.status[e] {
				case ReasonNotDisclosed:
					pc.pending = true
					if due := c.Schedule.dueAt(e); due.After(pc.pendingUntil) {
						pc.pendingUntil = due
					}
				case ReasonBadKey:
					pc.badKey = true
				case ReasonWorkCap:
					pc.capped = true
				default:
					pc.missing = true
				}
				continue
			}
			checked = true
			if tag, err := tagspec.ComputeTag(v.ak(c, e, key), in); err == nil && tag == id {
				if _, seen := pc.runs[c.RunID]; !seen {
					pc.runs[c.RunID] = e
				}
			}
		}
	}
	// A packet whose tag may be valid under a key that was already public
	// when it was captured is no evidence against the run.
	pc.definite = len(pc.runs) == 0 && checked && !blocked && !pc.public
	return pc
}

// verifiedEntry makes e the verified entry of run over the packets at
// positions ks of a group of n packets. The false-match bound is that of
// the best of N candidates matching some k of the n packets by chance:
// N·C(n, k)·(2·2⁻¹⁶)^k, which is N·(2·2⁻¹⁶)^n for an unsplit group.
func (v *verifier) verifiedEntry(e *VerifyGroup, usable []EvidenceCandidate, run string, checks []packetCheck, ks []int, n int) {
	e.Verdict, e.Method, e.RunID = VerdictVerified, VerifyMethodOffline, run
	for _, c := range usable {
		if c.RunID != run {
			continue
		}
		e.ExecutorID = c.ExecutorID
		e.Epoch = c.Schedule.epochOf(v.times[e.Packets[0]])
		seen := map[int64]bool{}
		for _, k := range ks {
			seen[checks[k].runs[run]] = true
		}
		for ep := range seen {
			e.keys = append(e.keys, ep)
		}
		slices.Sort(e.keys)
		due := c.Schedule.dueAt(e.keys[len(e.keys)-1]).Add(-disclosureSkew).UTC()
		e.DisclosedAt = &due
		break
	}
	e.FalseMatchBound = falseMatchBound(len(usable), n, len(ks))
}

// falseMatchBound is min(1, N·C(n, k)·(2·2⁻¹⁶)^k), computed in logarithms.
func falseMatchBound(candidates, n, k int) float64 {
	lc := func(x int) float64 { r, _ := math.Lgamma(float64(x) + 1); return r }
	choose := 0.0
	if k < n {
		choose = lc(n) - lc(k) - lc(n-k)
	}
	return math.Min(math.Exp(math.Log(float64(candidates))+choose+float64(k)*math.Log(2.0/65536)), 1)
}

// unmatchedVerdict sets the verdict of the packets at positions ks, none of
// which any candidate reproduces. partial tells that other packets of the
// group do match: the unmatched ones are then not attributed, but they are
// no evidence that the group was not sent by Debuglet either (they may have
// been altered on the way), so they are unsupported, not invalid.
func (v *verifier) unmatchedVerdict(out *VerifyGroup, checks []packetCheck, ks []int, unusable string, partial bool) {
	var definite, pending, missing, badKey, capped, public, noKey bool
	var until time.Time
	for _, k := range ks {
		c := checks[k]
		definite = definite || c.definite
		pending = pending || c.pending
		missing = missing || c.missing
		badKey = badKey || c.badKey
		capped = capped || c.capped
		public = public || c.public
		noKey = noKey || c.noKey
		if c.pendingUntil.After(until) {
			until = c.pendingUntil
		}
	}
	mismatch := func() {
		if partial {
			out.Verdict, out.Reason, out.Method = VerdictUnsupported, ReasonUnmatched, VerifyMethodOffline
		} else {
			out.Verdict, out.Reason, out.Method = VerdictInvalid, ReasonTagMismatch, VerifyMethodOffline
		}
	}
	switch {
	case unusable != "":
		// A candidate that cannot be checked may be the sender.
		out.Verdict, out.Reason = VerdictUnsupported, unusable
	case definite:
		mismatch()
	case pending:
		out.Verdict, out.Reason = VerdictPending, ReasonNotDisclosed
		u := until.UTC()
		out.PendingUntil = &u
	case missing:
		out.Verdict, out.Reason = VerdictMissing, ReasonKeysMissing
	case badKey:
		out.Verdict, out.Reason = VerdictUnsupported, ReasonBadKey
	case capped:
		out.Verdict, out.Reason = VerdictUnsupported, ReasonWorkCap
	case public:
		out.Verdict, out.Reason = VerdictUnsupported, ReasonKeyPublic
	case noKey:
		out.Verdict, out.Reason = VerdictUnsupported, ReasonNoSigningKey
	default:
		mismatch()
	}
}

// reasonPriority orders the reasons a candidate is unusable.
func reasonPriority(r string) int {
	switch r {
	case ReasonTagSpec:
		return 0
	case ReasonDisclosureDelay:
		return 1
	}
	return 2
}

// finish sets a group's time and its explanation.
func (v *verifier) finish(g VerifyGroup) VerifyGroup {
	if len(g.Packets) > 0 {
		g.Time = v.times[g.Packets[0]]
		for _, i := range g.Packets[1:] {
			if v.times[i].Before(g.Time) {
				g.Time = v.times[i]
			}
		}
		g.Time = g.Time.UTC()
	}
	if g.Detail == "" {
		g.Detail = v.explain(g)
	}
	return g
}

func (v *verifier) explain(g VerifyGroup) string {
	n := len(g.Packets)
	switch g.Reason {
	case "":
		d := fmt.Sprintf("every packet carries a valid tag of run %s on executor %s", g.RunID, g.ExecutorID)
		if g.DisclosedAt != nil {
			d += fmt.Sprintf("; this shows the run sent them if they were captured before %s, when the key became public",
				g.DisclosedAt.Format(time.RFC3339))
		}
		if g.Split != nil {
			d += fmt.Sprintf(". The packets of this address and epoch reproduce different runs or not all match: these %d of its %d packets are attributed to this run, the others are reported separately",
				len(g.Packets), g.Split.Packets)
		}
		return d
	case ReasonTagMismatch:
		return fmt.Sprintf("%d of %d packets carry no valid tag of the %d run(s) active from this address: they were not sent by Debuglet, or were altered on the way (for example by NAT or segmentation offload)",
			g.Unmatched, n, g.Candidates)
	case ReasonNoRun:
		return "no Debuglet run was active from this address at that time, so these packets were not sent by Debuglet"
	case ReasonUnmatched:
		d := fmt.Sprintf("%d packets of this address and epoch carry no valid tag of the %d run(s) active from it", g.Unmatched, g.Candidates)
		if g.Split != nil {
			d = fmt.Sprintf("%d of the %d packets of this address and epoch carry no valid tag of the %d run(s) active from it, while the other %d do", g.Unmatched, g.Split.Packets, g.Candidates, g.Split.Matched)
		}
		return d + ": they are attributed to no run. They were altered on the way (for example by NAT or segmentation offload) or sent by other software from the same address"
	case ReasonNotDisclosed:
		if g.PendingUntil != nil {
			return fmt.Sprintf("the key for this epoch is disclosed at %s; retry after then", g.PendingUntil.Format(time.RFC3339))
		}
		return "the key for this epoch is not disclosed yet; retry later"
	case ReasonNotRetained:
		if g.lookup >= 0 {
			return fmt.Sprintf("no history retained for that time: the dispatcher keeps history from %s on, so nothing can be concluded",
				v.lookups[g.lookup].RetainedFrom.UTC().Format(time.RFC3339))
		}
		return "no history retained for that time, so nothing can be concluded"
	case ReasonKeysMissing:
		return "no history retained for that time: the dispatcher does not hold the key of this epoch (it was lost or never disclosed), so nothing can be concluded"
	case ReasonIPv6:
		return "IPv6 is not tagged"
	case ReasonNotIPv4:
		return "not an IP packet"
	case ReasonTooShort:
		return "the capture holds fewer bytes than the tag covers (64); capture with a larger snap length, for example tcpdump -s 128"
	case ReasonMalformed:
		return "malformed IPv4 header"
	case ReasonFragment:
		return "IPv4 fragments are never tagged"
	case ReasonLinkType:
		return "unknown link-layer type; no IP packet could be read from these frames"
	case ReasonTagSpec:
		return fmt.Sprintf("the executor tags with a tag specification other than %s (or the unversioned pre-v1 tag), which this verifier does not implement", tagspec.ID)
	case ReasonDisclosureDelay:
		return "the executor discloses its keys less than 2 epochs after using them, so its tags could be forged; the executor must be updated"
	case ReasonSchedule:
		return "the executor's key schedule, as the dispatcher reports it, is unusable"
	case ReasonBadKey:
		return "the dispatcher served a key that does not belong to the executor's key chain"
	case ReasonNoSigningKey:
		return "captured while the executor had no signing key (its first epoch, or after its key chain ran out); such packets carry no tag"
	case ReasonKeyPublic:
		return "every key that could have tagged these packets may already have been public at the capture time, so the tags prove nothing"
	case ReasonAmbiguous:
		if g.Split != nil {
			return fmt.Sprintf("each of these packets reproduces more than one of the runs %s; capture more packets of the flow to tell them apart", strings.Join(g.AmbiguousRuns, ", "))
		}
		return fmt.Sprintf("%d runs each reproduce every tag; capture more packets of the flow to tell them apart", len(g.AmbiguousRuns))
	case ReasonTooManyCandidates:
		return fmt.Sprintf("more than %d runs were active from this address; the dispatcher's answer is incomplete", maxVerifyCandidates)
	case ReasonWorkCap:
		return "over a verification work cap; split or filter the capture"
	}
	return string(g.Verdict)
}
