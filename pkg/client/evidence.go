// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package client

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"runtime/debug"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/netsec-ethz/debuglet/pkg/tagspec"
	"github.com/netsec-ethz/debuglet/pkg/wire"
)

// The evidence bundle (docs/verification.md#evidence) lets a verifier repeat
// a check without the capture and without the dispatcher: it carries the
// first 64 bytes of every packet with its capture time, the dispatcher's
// answers the verdicts rest on, and the disclosed keys used.

const (
	// EvidenceFormat names the bundle format.
	EvidenceFormat = "debuglet-verification-evidence"
	// EvidenceFormatVersion is the bundle format version this client writes
	// and reads.
	EvidenceFormatVersion = 1
	// MaxEvidenceBytes bounds a bundle read by ReadEvidence.
	MaxEvidenceBytes = 256 << 20
)

// Evidence is a verification evidence bundle.
type Evidence struct {
	Format        string             `json:"format"`
	FormatVersion int                `json:"format_version"`
	CreatedAt     time.Time          `json:"created_at"`
	Tool          EvidenceTool       `json:"tool"`
	TagSpec       int                `json:"tag_spec"`
	Dispatcher    EvidenceDispatcher `json:"dispatcher"`
	// At is the capture time override the verification used, if any; the
	// packets' captured_at already carry it.
	At *time.Time `json:"at,omitempty"`
	// ClockToleranceMS is the capture clock lag bound applied.
	ClockToleranceMS int64           `json:"clock_tolerance_ms"`
	Packets          EvidencePackets `json:"packets"`
	Groups           []EvidenceGroup `json:"groups"`
	// Lookups are the dispatcher's answers to the candidate lookups, one
	// per group formed from them.
	Lookups []EvidenceLookup `json:"lookups"`
	// Chains carry, per executor chain, its schedule and every disclosed key
	// the verification used. Each key hashes to the schedule's k0.
	Chains []EvidenceChain `json:"chains"`
	// Receipts are the dispatcher's signed receipts of server-assisted
	// checks, and ReceiptKeys the keys that verify them.
	Receipts    []EvidenceReceipt    `json:"receipts"`
	ReceiptKeys []EvidenceReceiptKey `json:"receipt_keys,omitempty"`
}

// EvidenceTool names the program that wrote a bundle.
type EvidenceTool struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// EvidenceDispatcher names the dispatcher whose history a bundle records.
type EvidenceDispatcher struct {
	// Issuer is the signed identity; URL is the API retrieval address, which may
	// differ behind a TLS terminator or a path-prefix proxy.
	Issuer     string `json:"issuer,omitempty"`
	URL        string `json:"url"`
	APIVersion string `json:"api_version"`
}

// EvidencePackets are the verified packets in order.
type EvidencePackets struct {
	Count int `json:"count"`
	// Digest is "sha256:" and the hex SHA-256 over uint16 length ‖ data ‖
	// int64 captured_at_ns (big-endian) of every packet in order.
	Digest string           `json:"digest"`
	Items  []EvidencePacket `json:"items"`
}

// EvidencePacket is one packet: the first 64 bytes of the IP packet (all of
// a shorter one), and its capture time.
type EvidencePacket struct {
	Data       []byte    `json:"data"`
	CapturedAt time.Time `json:"captured_at"`
}

// EvidenceGroup is the recorded verdict of one group. Schedule and Keys are
// those of the named run's chain for the epochs the verdict used.
type EvidenceGroup struct {
	Verdict      Verdict      `json:"verdict"`
	Reason       string       `json:"reason,omitempty"`
	Method       VerifyMethod `json:"method,omitempty"`
	Source       string       `json:"source,omitempty"`
	RunID        string       `json:"run_id,omitempty"`
	ExecutorID   string       `json:"executor_id,omitempty"`
	Epoch        int64        `json:"epoch,omitempty"`
	PendingUntil *time.Time   `json:"pending_until,omitempty"`
	Packets      []int        `json:"packets"`
	Matched      int          `json:"matched"`
	Unmatched    int          `json:"unmatched"`
	// Split records the group an entry was split from (VerifyGroup.Split).
	Split    *VerifySplit      `json:"split,omitempty"`
	Schedule *EvidenceSchedule `json:"schedule,omitempty"`
	Keys     []EvidenceKey     `json:"keys,omitempty"`
}

// EvidenceSchedule is the public TESLA schedule of one executor chain: the
// key of epoch e covers [t0 + e·I, t0 + (e+1)·I) and is disclosed from
// t0 + (e+d)·I.
type EvidenceSchedule struct {
	// ChainID identifies the chain.
	ChainID string `json:"chain_id"`
	// K0 is the chain anchor; every key hashes to it.
	K0 []byte `json:"k0"`
	// T0UnixNs is the start of epoch 0.
	T0UnixNs int64 `json:"t0_unix_ns"`
	// EpochSeconds is the epoch length I.
	EpochSeconds int64 `json:"epoch_seconds"`
	// DisclosureDelayEpochs is d; below 2 is refused.
	DisclosureDelayEpochs int64 `json:"disclosure_delay_epochs"`
	// ChainLength is L; zero is unknown.
	ChainLength int64 `json:"chain_length"`
	// TagSpec is the executor-reported tag specification version; 0 is the
	// unversioned pre-v1 tag, which is unsupported.
	TagSpec       int64                          `json:"tag_spec"`
	OperatorProof *wire.AttributionScheduleProof `json:"operator_proof,omitempty"`
}

// EvidenceKey is one disclosed chain key.
type EvidenceKey struct {
	Epoch int64  `json:"epoch"`
	Key   []byte `json:"key"`
}

// EvidenceCandidate is one run a lookup named.
type EvidenceCandidate struct {
	ExecutorID string    `json:"executor_id"`
	RunID      string    `json:"run_id"`
	ActiveFrom time.Time `json:"active_from"`
	ActiveTo   time.Time `json:"active_to"`
	// IPSource is observed or advertised (see AttributionCandidate).
	IPSource             string           `json:"ip_source,omitempty"`
	Schedule             EvidenceSchedule `json:"schedule"`
	DisclosedThrough     int64            `json:"disclosed_through"`
	DisclosedThroughAtNs int64            `json:"disclosed_through_at_ns,omitempty"`
	NextDisclosureAtNs   int64            `json:"next_disclosure_at_ns,omitempty"`
}

// EvidenceLookup is the dispatcher's answer to one dated candidate lookup.
type EvidenceLookup struct {
	IP           string                   `json:"ip"`
	At           time.Time                `json:"at"`
	RetainedFrom time.Time                `json:"retained_from"`
	Truncated    bool                     `json:"truncated,omitempty"`
	Candidates   []EvidenceCandidate      `json:"candidates"`
	Statement    *wire.AttributionReceipt `json:"statement,omitempty"`
}

// EvidenceChain is one chain with the keys a verification used.
type EvidenceChain struct {
	ExecutorID string           `json:"executor_id"`
	Schedule   EvidenceSchedule `json:"schedule"`
	Keys       []EvidenceKey    `json:"keys"`
}

// EvidenceReceipt is a signed dispatcher receipt of POST /attribution/verify:
// Signature is the Ed25519 signature by the key KeyID over Payload, the
// canonical JSON of an AttributionReceiptPayload. Packets are the indices of
// the bundle's packets the request sent, in request order; the payload's
// digest covers exactly those.
type EvidenceReceipt struct {
	KeyID     string `json:"key_id"`
	Payload   []byte `json:"payload"`
	Signature []byte `json:"signature"`
	Packets   []int  `json:"packets"`
}

// PacketDigest returns the digest of an evidence packet list.
func PacketDigest(items []EvidencePacket) string {
	packets := make([]wire.AttributionVerifyPacket, len(items))
	for i, p := range items {
		packets[i] = wire.AttributionVerifyPacket{Data: p.Data, CapturedAt: p.CapturedAt}
	}
	return wire.PacketsDigest(packets)
}

// toolVersion is this module's version, as the build records it.
func toolVersion() string {
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, dep := range info.Deps {
			if dep.Path == "github.com/netsec-ethz/debuglet" {
				return dep.Version
			}
		}
		if info.Main.Path == "github.com/netsec-ethz/debuglet" && info.Main.Version != "" {
			return info.Main.Version
		}
	}
	return "unknown"
}

// Evidence returns the evidence bundle of a verification. Tool names this
// package; a program writing the bundle may replace it.
func (r VerifyReport) Evidence() Evidence {
	m := r.material
	ev := Evidence{
		Format: EvidenceFormat, FormatVersion: EvidenceFormatVersion, CreatedAt: r.CheckedAt,
		Tool:    EvidenceTool{Name: "github.com/netsec-ethz/debuglet/pkg/client", Version: toolVersion()},
		TagSpec: tagspec.Version, Dispatcher: EvidenceDispatcher{URL: r.Dispatcher, APIVersion: m.apiVersion, Issuer: m.issuer},
		At: r.At, ClockToleranceMS: r.ClockToleranceMS,
		Groups: []EvidenceGroup{}, Lookups: m.lookups, Chains: []EvidenceChain{}, Receipts: []EvidenceReceipt{},
		ReceiptKeys: m.receiptKeys,
	}
	if len(m.receipts) > 0 {
		ev.Receipts = m.receipts
	}
	if ev.Lookups == nil {
		ev.Lookups = []EvidenceLookup{}
	}
	ev.Packets.Items = make([]EvidencePacket, len(m.packets))
	for i, p := range m.packets {
		data := p.Data
		if len(data) > tagspec.MaxInput {
			data = data[:tagspec.MaxInput]
		}
		at := p.CapturedAt
		if r.At != nil {
			at = *r.At
		}
		ev.Packets.Items[i] = EvidencePacket{Data: bytes.Clone(data), CapturedAt: at.UTC()}
	}
	ev.Packets.Count = len(ev.Packets.Items)
	ev.Packets.Digest = PacketDigest(ev.Packets.Items)

	refs := make([]chainRef, 0, len(m.chains))
	for ref, st := range m.chains {
		if len(st.keys) > 0 {
			refs = append(refs, ref)
		}
	}
	slices.SortFunc(refs, func(a, b chainRef) int {
		return strings.Compare(a.executor+"\x00"+a.chain, b.executor+"\x00"+b.chain)
	})
	for _, ref := range refs {
		st := m.chains[ref]
		ev.Chains = append(ev.Chains, EvidenceChain{ExecutorID: ref.executor, Schedule: st.schedule, Keys: st.sortedKeys(nil)})
	}
	for _, g := range r.Groups {
		eg := EvidenceGroup{
			Verdict: g.Verdict, Reason: g.Reason, Method: g.Method, Source: g.Source, RunID: g.RunID,
			ExecutorID: g.ExecutorID, Epoch: g.Epoch, PendingUntil: g.PendingUntil, Packets: g.Packets,
			Matched: g.Matched, Unmatched: g.Unmatched, Split: g.Split,
		}
		if g.RunID != "" && g.lookup >= 0 {
			for _, c := range m.lookups[g.lookup].Candidates {
				if c.RunID == g.RunID {
					if st := m.chains[chainRef{c.ExecutorID, c.Schedule.ChainID}]; st != nil {
						s := st.schedule
						eg.Schedule = &s
						eg.Keys = st.sortedKeys(g.keys)
					}
					break
				}
			}
		}
		ev.Groups = append(ev.Groups, eg)
	}
	return ev
}

// sortedKeys returns the chain's keys at the given epochs, or all of them.
func (st *chainState) sortedKeys(epochs []int64) []EvidenceKey {
	if epochs == nil {
		for e := range st.keys {
			epochs = append(epochs, e)
		}
		slices.Sort(epochs)
	}
	out := make([]EvidenceKey, 0, len(epochs))
	for _, e := range epochs {
		if k, ok := st.keys[e]; ok {
			out = append(out, EvidenceKey{Epoch: e, Key: bytes.Clone(k)})
		}
	}
	return out
}

// WriteEvidence writes a bundle as indented JSON.
func WriteEvidence(w io.Writer, ev Evidence) error {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	return enc.Encode(ev)
}

// ReadEvidence reads a bundle of at most MaxEvidenceBytes and checks its
// format and version.
func ReadEvidence(r io.Reader) (Evidence, error) {
	data, err := io.ReadAll(io.LimitReader(r, MaxEvidenceBytes+1))
	if err != nil {
		return Evidence{}, fmt.Errorf("client: read evidence: %w", err)
	}
	if len(data) > MaxEvidenceBytes {
		return Evidence{}, fmt.Errorf("client: read evidence: bundle exceeds %d MiB", MaxEvidenceBytes>>20)
	}
	var ev Evidence
	dec := json.NewDecoder(bytes.NewReader(data))
	if err := dec.Decode(&ev); err != nil {
		return Evidence{}, fmt.Errorf("client: read evidence: %w", err)
	}
	if dec.More() {
		return Evidence{}, errors.New("client: read evidence: trailing data after the bundle")
	}
	if ev.Format != EvidenceFormat {
		return Evidence{}, fmt.Errorf("client: read evidence: not a verification evidence bundle (format %q)", ev.Format)
	}
	if ev.FormatVersion != EvidenceFormatVersion {
		return Evidence{}, fmt.Errorf("client: read evidence: format_version %d is not supported (this client reads %d)", ev.FormatVersion, EvidenceFormatVersion)
	}
	return ev, nil
}

// IsEvidence reports whether data starts like an evidence bundle rather than
// a capture: a JSON object.
func IsEvidence(prefix []byte) bool {
	return len(bytes.TrimLeft(prefix, " \t\r\n")) > 0 && bytes.TrimLeft(prefix, " \t\r\n")[0] == '{'
}

// EvidenceMismatchError reports a bundle whose recorded verdicts differ from
// those its own packets, history and keys yield.
type EvidenceMismatchError struct {
	Group int
	Msg   string
}

func (e *EvidenceMismatchError) Error() string {
	return fmt.Sprintf("client: evidence does not check out: group %d: %s", e.Group, e.Msg)
}

// ErrEvidenceDigest reports packets that do not match the bundle's digest.
var ErrEvidenceDigest = errors.New("client: evidence does not check out: the packets do not match the recorded digest")

// VerifyEvidence checks a bundle again, offline: the packet digest, every key
// against its chain anchor, every receipt's signature under the embedded key
// it names, its validity at the receipt's query time and the receipt's digest
// of the packets it lists, and every group's verdict recomputed from the
// packets, the recorded lookups, keys and receipts as of the bundle's
// creation. It returns the recomputed report, with an *EvidenceReceiptError
// for a receipt that does not verify and an *EvidenceMismatchError when a
// recorded verdict differs. Included history statements must bind the exact
// lookup and schedules. Embedded keys establish consistency, not issuer trust;
// use VerifyEvidenceWithTrust with independently obtained keys for that.
func VerifyEvidence(ctx context.Context, ev Evidence) (VerifyReport, error) {
	return verifyEvidence(ctx, ev, nil)
}

// VerifyEvidenceWithTrust verifies every history statement and server receipt
// with keys supplied independently of the bundle. It fails on unsigned history
// or a statement for another dispatcher. Packet capture times still require
// the receiver's own trusted clock evidence.
func VerifyEvidenceWithTrust(ctx context.Context, ev Evidence, trust EvidenceTrust) (VerifyReport, error) {
	if trust.Dispatcher == "" || len(trust.Keys) == 0 {
		return VerifyReport{}, errors.New("client: evidence trust needs a dispatcher and trusted signing keys")
	}
	return verifyEvidence(ctx, ev, &trust)
}

func verifyEvidence(ctx context.Context, ev Evidence, trust *EvidenceTrust) (VerifyReport, error) {
	if ev.Format != EvidenceFormat || ev.FormatVersion != EvidenceFormatVersion {
		return VerifyReport{}, fmt.Errorf("client: evidence format %q version %d is not supported", ev.Format, ev.FormatVersion)
	}
	if ev.TagSpec != tagspec.Version {
		return VerifyReport{}, fmt.Errorf("client: evidence names tag spec %d; this client implements %s", ev.TagSpec, tagspec.ID)
	}
	if ev.Packets.Count != len(ev.Packets.Items) || len(ev.Packets.Items) == 0 || len(ev.Packets.Items) > MaxCapturePackets {
		return VerifyReport{}, errors.New("client: evidence does not check out: the packet count is wrong")
	}
	if len(ev.Lookups) > maxVerifyLookups || len(ev.Chains) > maxVerifyLookups*maxVerifyCandidates || ev.ClockToleranceMS < 0 {
		return VerifyReport{}, errors.New("client: evidence exceeds the verification limits")
	}
	for _, p := range ev.Packets.Items {
		if len(p.Data) > tagspec.MaxInput {
			return VerifyReport{}, errors.New("client: evidence does not check out: a packet holds more than 64 bytes")
		}
	}
	if ev.Packets.Digest != PacketDigest(ev.Packets.Items) {
		return VerifyReport{}, ErrEvidenceDigest
	}
	keys := ev.ReceiptKeys
	issuer := ev.Dispatcher.Issuer
	if issuer == "" {
		issuer = ev.Dispatcher.URL
	}
	if trust != nil {
		if issuer != trust.Dispatcher {
			return VerifyReport{}, errors.New("client: evidence names a different dispatcher")
		}
		keys = trust.Keys
	}
	for i, lookup := range ev.Lookups {
		for _, candidate := range lookup.Candidates {
			fingerprint := ""
			if trust != nil && trust.ExecutorCertificates != nil {
				fingerprint = trust.ExecutorCertificates[candidate.ExecutorID]
				if fingerprint == "" {
					return VerifyReport{}, fmt.Errorf("client: no trusted certificate for executor %s", candidate.ExecutorID)
				}
			} else if candidate.Schedule.OperatorProof != nil {
				fingerprint = wire.AttributionCertificateID(candidate.Schedule.OperatorProof.Certificate)
			}
			if fingerprint != "" {
				if err := wire.VerifyAttributionSchedule(candidate.ExecutorID, historySchedule(candidate.Schedule), fingerprint); err != nil {
					return VerifyReport{}, fmt.Errorf("client: executor schedule: %w", err)
				}
			}
		}
		if lookup.Statement == nil {
			if trust != nil {
				return VerifyReport{}, fmt.Errorf("client: evidence lookup %d is unsigned", i)
			}
			continue
		}
		if err := checkHistory(lookup, issuer, keys); err != nil {
			return VerifyReport{}, fmt.Errorf("client: evidence lookup %d: %w", i, err)
		}
	}
	budget := int64(maxVerifyHashWalk)
	for i, c := range ev.Chains {
		if err := checkChainKeys(c, &budget); err != nil {
			return VerifyReport{}, fmt.Errorf("client: evidence does not check out: chain %d: %w", i, err)
		}
	}
	packets := make([]CapturedPacket, len(ev.Packets.Items))
	for i, p := range ev.Packets.Items {
		packets[i] = CapturedPacket{Data: p.Data, CapturedAt: p.CapturedAt}
	}
	src := &evidenceSource{ev: ev}
	if len(ev.Receipts) > maxVerifyLookups {
		return VerifyReport{}, errors.New("client: evidence exceeds the verification limits")
	}
	payloads := make([]AttributionReceiptPayload, len(ev.Receipts))
	for i, r := range ev.Receipts {
		p, err := checkReceipt(r, keys, ev.Packets.Items)
		if err != nil {
			return VerifyReport{}, &EvidenceReceiptError{Receipt: i, Msg: err.Error()}
		}
		if trust != nil && p.Dispatcher != trust.Dispatcher {
			return VerifyReport{}, errors.New("client: receipt names a different dispatcher")
		}
		payloads[i] = p
	}
	rep, err := verifyOffline(ctx, src, packets, VerifyOptions{ClockTolerance: time.Duration(ev.ClockToleranceMS) * time.Millisecond}, ev.CreatedAt)
	if err != nil {
		return VerifyReport{}, err
	}
	rep.At = ev.At
	rep.material.receiptKeys = ev.ReceiptKeys
	rep.material.issuer = ev.Dispatcher.Issuer
	rep.HistoryAuthenticated = trust != nil
	rep.SchedulesAuthenticated = trust != nil && trust.ExecutorCertificates != nil
	if len(ev.Receipts) > 0 {
		rep.material.receipts, rep.material.receiptKeys = ev.Receipts, ev.ReceiptKeys
		rep.Groups = applyReceipts(rep.Groups, ev.Receipts, payloads, itemTimes(ev.Packets.Items))
		rep.Counts = countGroups(rep.Groups)
	}
	again := rep.Evidence()
	want, got := slices.Clone(ev.Groups), again.Groups
	byFirst := func(gs []EvidenceGroup) {
		sort.SliceStable(gs, func(a, b int) bool { return firstPacket(gs[a]) < firstPacket(gs[b]) })
	}
	byFirst(want)
	byFirst(got)
	if len(want) != len(got) {
		return rep, &EvidenceMismatchError{Group: -1, Msg: fmt.Sprintf("records %d groups, the packets form %d", len(want), len(got))}
	}
	for i := range want {
		a, _ := json.Marshal(want[i])
		b, _ := json.Marshal(got[i])
		if !bytes.Equal(a, b) {
			return rep, &EvidenceMismatchError{Group: i, Msg: fmt.Sprintf("recorded %s %s, recomputed %s %s",
				want[i].Verdict, want[i].Reason, got[i].Verdict, got[i].Reason)}
		}
	}
	return rep, nil
}

// checkChainKeys checks that every key of a chain hashes to its anchor, by
// one walk from the highest key down through the lower ones.
func checkChainKeys(c EvidenceChain, budget *int64) error {
	keys := slices.Clone(c.Keys)
	slices.SortFunc(keys, func(a, b EvidenceKey) int { return int(min(max(b.Epoch-a.Epoch, -1), 1)) })
	if len(keys) == 0 {
		return nil
	}
	top := keys[0].Epoch
	if top < 1 || (c.Schedule.ChainLength > 0 && top > c.Schedule.ChainLength) || top > *budget {
		return fmt.Errorf("key epoch %d out of range", top)
	}
	*budget -= top
	cur, next := bytes.Clone(keys[0].Key), 1
	for e := top; e >= 1; e-- {
		for next < len(keys) && keys[next].Epoch == e {
			if !bytes.Equal(keys[next].Key, cur) {
				return fmt.Errorf("the key of epoch %d does not belong to the chain", e)
			}
			next++
		}
		sum := sha256.Sum256(cur)
		cur = sum[:]
	}
	if next != len(keys) || !bytes.Equal(cur, c.Schedule.K0) {
		return errors.New("the keys do not hash to the chain anchor")
	}
	return nil
}

func firstPacket(g EvidenceGroup) int {
	if len(g.Packets) == 0 {
		return -1
	}
	return g.Packets[0]
}

// evidenceSource answers lookups and key requests from a bundle.
type evidenceSource struct{ ev Evidence }

func (s *evidenceSource) candidates(_ context.Context, ip netip.Addr, at time.Time) (EvidenceLookup, error) {
	for _, l := range s.ev.Lookups {
		if a, err := netip.ParseAddr(l.IP); err == nil && a == ip && l.At.Equal(at) {
			return l, nil
		}
	}
	return EvidenceLookup{}, fmt.Errorf("client: evidence does not check out: it records no lookup of %s at %s", ip, at.UTC().Format(time.RFC3339Nano))
}

func (s *evidenceSource) keys(_ context.Context, executorID, chain string, from, to int64) ([]EvidenceKey, *int64, error) {
	var out []EvidenceKey
	for _, c := range s.ev.Chains {
		if c.ExecutorID != executorID || c.Schedule.ChainID != chain {
			continue
		}
		for _, k := range c.Keys {
			if k.Epoch >= from && k.Epoch <= to {
				out = append(out, k)
			}
		}
	}
	slices.SortFunc(out, func(a, b EvidenceKey) int { return int(min(max(a.Epoch-b.Epoch, -1), 1)) })
	return out, nil, nil
}

func (s *evidenceSource) describe() (string, string) {
	return s.ev.Dispatcher.URL, s.ev.Dispatcher.APIVersion
}
