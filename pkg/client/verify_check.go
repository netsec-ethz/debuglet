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

// decide checks the tags of one group against the candidates of its lookup.
func (v *verifier) decide(g pendingGroup) VerifyGroup {
	answer := v.lookups[g.lookup]
	out := VerifyGroup{Source: g.source, Packets: g.indices, lookup: g.lookup, Epoch: g.epoch}
	first := v.times[g.indices[0]]
	if answer.Truncated || len(answer.Candidates) > maxVerifyCandidates {
		out.Verdict, out.Reason = VerdictUnsupported, ReasonTooManyCandidates
		return out
	}
	if len(answer.Candidates) == 0 {
		out.Epoch = 0
		if first.Before(answer.RetainedFrom) {
			out.Verdict, out.Reason = VerdictMissing, ReasonNotRetained
			return out
		}
		out.Verdict, out.Reason, out.Method = VerdictInvalid, ReasonNoRun, VerifyMethodOffline
		out.Unmatched = len(g.indices)
		return out
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
		return out
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
		return out
	}
	v.tagBudget -= cost

	// matches[k] maps each run that reproduces packet k's tag to the epoch
	// whose key did.
	matches := make([]map[string]int64, len(g.indices))
	var definiteFailure, blockedPending, blockedMissing, blockedBadKey, blockedCap bool
	var excludedPublic, excludedNoKey bool
	var pendingUntil time.Time
	for k, i := range g.indices {
		pkt := v.packets[i].Data
		id, _ := tagspec.PacketID(pkt)
		in, _ := tagspec.HashInput(pkt)
		runs := map[string]int64{}
		checked, blocked, public := false, false, false
		for _, c := range usable {
			st := v.chains[chainRef{c.ExecutorID, c.Schedule.ChainID}]
			epochs, excluded := v.epochPlan(c.Schedule, v.times[i])
			switch excluded {
			case ReasonKeyPublic:
				excludedPublic, public = true, true
			case ReasonNoSigningKey:
				excludedNoKey = true
			}
			for _, e := range epochs {
				key, ok := st.keys[e]
				if !ok {
					blocked = true
					switch st.status[e] {
					case ReasonNotDisclosed:
						blockedPending = true
						if due := c.Schedule.dueAt(e); due.After(pendingUntil) {
							pendingUntil = due
						}
					case ReasonBadKey:
						blockedBadKey = true
					case ReasonWorkCap:
						blockedCap = true
					default:
						blockedMissing = true
					}
					continue
				}
				checked = true
				if tag, err := tagspec.ComputeTag(v.ak(c, e, key), in); err == nil && tag == id {
					if _, seen := runs[c.RunID]; !seen {
						runs[c.RunID] = e
					}
				}
			}
		}
		matches[k] = runs
		if len(runs) > 0 {
			out.Matched++
			continue
		}
		out.Unmatched++
		// A packet whose tag may be valid under a key that was already
		// public when it was captured is no evidence against the run.
		if checked && !blocked && !public {
			definiteFailure = true
		}
	}

	if out.Unmatched == 0 {
		var runs []string
		for run := range matches[0] {
			all := true
			for _, m := range matches[1:] {
				if _, ok := m[run]; !ok {
					all = false
					break
				}
			}
			if all {
				runs = append(runs, run)
			}
		}
		sort.Strings(runs)
		switch {
		case len(runs) == 1:
			out.Verdict, out.Method, out.RunID = VerdictVerified, VerifyMethodOffline, runs[0]
			for _, c := range usable {
				if c.RunID != runs[0] {
					continue
				}
				out.ExecutorID = c.ExecutorID
				out.Epoch = c.Schedule.epochOf(first)
				seen := map[int64]bool{}
				for _, m := range matches {
					seen[m[runs[0]]] = true
				}
				for e := range seen {
					out.keys = append(out.keys, e)
				}
				slices.Sort(out.keys)
				due := c.Schedule.dueAt(out.keys[len(out.keys)-1]).Add(-disclosureSkew).UTC()
				out.DisclosedAt = &due
				break
			}
			bound := float64(len(usable)) * math.Pow(2.0/65536, float64(len(g.indices)))
			out.FalseMatchBound = math.Min(bound, 1)
		case len(runs) > 1:
			out.Verdict, out.Reason, out.AmbiguousRuns = VerdictUnsupported, ReasonAmbiguous, runs
		default:
			out.Verdict, out.Reason, out.Method = VerdictInvalid, ReasonMixedRuns, VerifyMethodOffline
		}
		return out
	}
	switch {
	case unusable != "":
		// A candidate that cannot be checked may be the sender.
		out.Verdict, out.Reason = VerdictUnsupported, unusable
	case definiteFailure:
		out.Verdict, out.Reason, out.Method = VerdictInvalid, ReasonTagMismatch, VerifyMethodOffline
	case blockedPending:
		out.Verdict, out.Reason = VerdictPending, ReasonNotDisclosed
		until := pendingUntil.UTC()
		out.PendingUntil = &until
	case blockedMissing:
		out.Verdict, out.Reason = VerdictMissing, ReasonKeysMissing
	case blockedBadKey:
		out.Verdict, out.Reason = VerdictUnsupported, ReasonBadKey
	case blockedCap:
		out.Verdict, out.Reason = VerdictUnsupported, ReasonWorkCap
	case excludedPublic:
		out.Verdict, out.Reason = VerdictUnsupported, ReasonKeyPublic
	case excludedNoKey:
		out.Verdict, out.Reason = VerdictUnsupported, ReasonNoSigningKey
	default:
		out.Verdict, out.Reason, out.Method = VerdictInvalid, ReasonTagMismatch, VerifyMethodOffline
	}
	return out
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
		return d
	case ReasonTagMismatch:
		return fmt.Sprintf("%d of %d packets carry no valid tag of the %d run(s) active from this address: they were not sent by Debuglet, or were altered on the way (for example by NAT or segmentation offload)",
			g.Unmatched, n, g.Candidates)
	case ReasonNoRun:
		return "no Debuglet run was active from this address at that time, so these packets were not sent by Debuglet"
	case ReasonMixedRuns:
		return "the packets carry tags of different runs; verify the traffic of each destination separately"
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
		return fmt.Sprintf("%d runs each reproduce every tag; capture more packets of the flow to tell them apart", len(g.AmbiguousRuns))
	case ReasonTooManyCandidates:
		return fmt.Sprintf("more than %d runs were active from this address; the dispatcher's answer is incomplete", maxVerifyCandidates)
	case ReasonWorkCap:
		return "over a verification work cap; split or filter the capture"
	}
	return string(g.Verdict)
}
