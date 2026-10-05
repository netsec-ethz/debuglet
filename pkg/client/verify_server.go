// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package client

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"sort"
	"time"

	"github.com/netsec-ethz/debuglet/pkg/wire"
)

// Server-assisted verification (docs/verification.md, method server): the
// groups that are pending because their key is not disclosed yet are sent to
// POST /attribution/verify, whose executor answers before disclosure. The
// dispatcher signs every answer; the signed receipt, not the response, is
// what changes a group's verdict, so an evidence bundle repeats the same
// change from its receipts.

type (
	AttributionVerifyPacket   = wire.AttributionVerifyPacket
	AttributionVerifyResponse = wire.AttributionVerifyResponse
	AttributionVerifyGroup    = wire.AttributionVerifyGroup
	AttributionReceipt        = wire.AttributionReceipt
	AttributionReceiptPayload = wire.AttributionReceiptPayload
	AttributionReceiptKeys    = wire.AttributionReceiptKeys
	AttributionReceiptKey     = wire.AttributionReceiptKey
)

const (
	routeAttributionVerify = "attribution/verify"
	routeReceiptKeys       = "attribution/receipt-keys"
	// verifyAPIVersion is the first API version with the server method.
	verifyAPIVersion = "1.16"
	// Limits of one POST /attribution/verify (docs/verification.md#limits).
	maxServerPackets = 256
	maxServerGroups  = 16
)

// AttributionVerify sends packets to POST /attribution/verify (API 1.16).
// The answer is checked for shape only; VerifyReceipt checks its receipt.
func (c *Client) AttributionVerify(ctx context.Context, packets []AttributionVerifyPacket) (AttributionVerifyResponse, error) {
	if len(packets) == 0 || len(packets) > maxServerPackets {
		return AttributionVerifyResponse{}, fmt.Errorf("client: attribution verify takes 1 to %d packets", maxServerPackets)
	}
	body, err := json.Marshal(wire.AttributionVerifyRequest{Packets: packets})
	if err != nil {
		return AttributionVerifyResponse{}, err
	}
	ctx = context.WithValue(ctx, requiredVersionKey{}, verifyAPIVersion)
	data, err := c.do(ctx, http.MethodPost, routeAttributionVerify, nil, body, http.StatusOK)
	if err != nil {
		return AttributionVerifyResponse{}, err
	}
	var doc AttributionVerifyResponse
	if err := c.decode(http.MethodPost, routeAttributionVerify, data, &doc); err != nil {
		return AttributionVerifyResponse{}, err
	}
	if doc.Groups == nil || doc.Receipt.KeyID == "" || len(doc.Receipt.Payload) == 0 || len(doc.Receipt.Signature) != ed25519.SignatureSize {
		return AttributionVerifyResponse{}, c.protocolErr(http.MethodPost, routeAttributionVerify, "incomplete verification answer")
	}
	return doc, nil
}

// AttributionReceiptKeys reads GET /attribution/receipt-keys (API 1.16).
func (c *Client) AttributionReceiptKeys(ctx context.Context) (AttributionReceiptKeys, error) {
	ctx = context.WithValue(ctx, requiredVersionKey{}, verifyAPIVersion)
	data, err := c.do(ctx, http.MethodGet, routeReceiptKeys, nil, nil, http.StatusOK)
	if err != nil {
		return AttributionReceiptKeys{}, err
	}
	var doc AttributionReceiptKeys
	if err := c.decode(http.MethodGet, routeReceiptKeys, data, &doc); err != nil {
		return AttributionReceiptKeys{}, err
	}
	if doc.Keys == nil {
		return AttributionReceiptKeys{}, c.protocolErr(http.MethodGet, routeReceiptKeys, "no keys")
	}
	return doc, nil
}

// EvidenceReceiptKey is a key that verifies receipts, as the dispatcher
// published it at GET /attribution/receipt-keys. A bundle embeds the keys of
// its receipts; they are the dispatcher's claim like the rest of the bundle,
// so compare the key IDs with the dispatcher's published keys before relying
// on a server verdict.
type EvidenceReceiptKey struct {
	KeyID     string     `json:"key_id"`
	PublicKey []byte     `json:"public_key"`
	ValidFrom time.Time  `json:"valid_from"`
	ValidTo   *time.Time `json:"valid_to"`
}

// ReceiptKeyID is the key ID of an Ed25519 public key: the hex of the first
// 16 bytes of its SHA-256.
func ReceiptKeyID(public []byte) string {
	sum := sha256.Sum256(public)
	return hex.EncodeToString(sum[:16])
}

// EvidenceReceiptError reports a receipt that does not verify.
type EvidenceReceiptError struct {
	Receipt int
	Msg     string
}

func (e *EvidenceReceiptError) Error() string {
	return fmt.Sprintf("client: receipt %d does not verify: %s", e.Receipt, e.Msg)
}

// checkReceipt verifies a receipt's signature under the key it names, that
// the key was valid at the receipt's query time, that the receipt's digest is
// that of the packets it lists, and that its groups name only those packets.
func checkReceipt(r EvidenceReceipt, keys []EvidenceReceiptKey, items []EvidencePacket) (AttributionReceiptPayload, error) {
	k := slices.IndexFunc(keys, func(k EvidenceReceiptKey) bool { return k.KeyID == r.KeyID })
	if k < 0 {
		return AttributionReceiptPayload{}, fmt.Errorf("no receipt key %q is known", r.KeyID)
	}
	key := keys[k]
	if len(key.PublicKey) != ed25519.PublicKeySize || ReceiptKeyID(key.PublicKey) != key.KeyID {
		return AttributionReceiptPayload{}, fmt.Errorf("receipt key %q is not the key its ID names", r.KeyID)
	}
	if !ed25519.Verify(key.PublicKey, r.Payload, r.Signature) {
		return AttributionReceiptPayload{}, errors.New("the signature does not verify")
	}
	var p AttributionReceiptPayload
	if err := decodeStrict(r.Payload, &p); err != nil {
		return AttributionReceiptPayload{}, fmt.Errorf("the payload does not parse: %v", err)
	}
	at, err := time.Parse(time.RFC3339Nano, p.QueryAt)
	if err != nil || at.Before(key.ValidFrom) || (key.ValidTo != nil && !at.Before(*key.ValidTo)) {
		return AttributionReceiptPayload{}, fmt.Errorf("query_at %q is outside the validity of key %s", p.QueryAt, key.KeyID)
	}
	if len(r.Packets) == 0 || len(r.Packets) > maxServerPackets {
		return AttributionReceiptPayload{}, errors.New("it lists no packets or too many")
	}
	sent := make([]AttributionVerifyPacket, len(r.Packets))
	for i, idx := range r.Packets {
		if idx < 0 || idx >= len(items) {
			return AttributionReceiptPayload{}, errors.New("it lists a packet the bundle does not hold")
		}
		sent[i] = AttributionVerifyPacket{Data: items[idx].Data, CapturedAt: items[idx].CapturedAt}
	}
	if wire.PacketsDigest(sent) != p.PacketsDigest {
		return AttributionReceiptPayload{}, errors.New("its packets digest does not match the packets")
	}
	for _, g := range p.Groups {
		for _, i := range g.Packets {
			if i < 0 || i >= len(r.Packets) {
				return AttributionReceiptPayload{}, errors.New("a group names a packet outside the request")
			}
		}
	}
	return p, nil
}

// serverAnswer is one receipt group's answer for one packet of the report.
type serverAnswer struct {
	group wire.AttributionReceiptGroup
	id    int // the receipt group, unique across receipts
	keyID string
}

// applyReceipts changes the pending groups that verified receipts answered.
// The packets of a group a receipt covers take the executor's verdict: the
// one run that reproduces every tag is verified, anything the executor could
// not check is unsupported. An answer that no single candidate reproduces
// every tag (pending, unmatched) leaves the group pending: two runs from one
// address in one epoch answer so as well as forged traffic, and the offline
// check after disclosure splits the group per run. Packets of the group no
// receipt covers stay pending in an entry of their own. Only answers with method server count: an answer from
// a key disclosed since is repeated offline after a retry.
func applyReceipts(groups []VerifyGroup, receipts []EvidenceReceipt, payloads []AttributionReceiptPayload, times []time.Time) []VerifyGroup {
	answers := map[int][]serverAnswer{}
	id := 0
	for r, p := range payloads {
		for _, g := range p.Groups {
			id++
			if g.Method != string(VerifyMethodServer) {
				continue
			}
			for _, i := range g.Packets {
				pkt := receipts[r].Packets[i]
				answers[pkt] = append(answers[pkt], serverAnswer{group: g, id: id, keyID: receipts[r].KeyID})
			}
		}
	}
	if len(answers) == 0 {
		return groups
	}
	var out []VerifyGroup
	for _, g := range groups {
		if g.Verdict != VerdictPending {
			out = append(out, g)
			continue
		}
		var sent, rest []int
		for _, i := range g.Packets {
			if len(answers[i]) > 0 {
				sent = append(sent, i)
			} else {
				rest = append(rest, i)
			}
		}
		decided, ok := serverVerdict(g, sent, answers)
		if !ok {
			out = append(out, g)
			continue
		}
		decided.Time = earliest(sent, times)
		out = append(out, decided)
		if len(rest) > 0 {
			left := g
			left.Packets, left.Unmatched, left.Time = rest, len(rest), earliest(rest, times)
			out = append(out, left)
		}
	}
	sortGroups(out)
	return out
}

func earliest(indices []int, times []time.Time) time.Time {
	t := times[indices[0]]
	for _, i := range indices[1:] {
		if times[i].Before(t) {
			t = times[i]
		}
	}
	return t.UTC()
}

// serverVerdict is the verdict of the packets sent of a pending group, or
// false when the answers decide nothing.
func serverVerdict(g VerifyGroup, sent []int, answers map[int][]serverAnswer) (VerifyGroup, bool) {
	if len(sent) == 0 {
		return VerifyGroup{}, false
	}
	byID := map[int]serverAnswer{}
	for _, i := range sent {
		for _, a := range answers[i] {
			byID[a.id] = a
		}
	}
	ids := make([]int, 0, len(byID))
	for id := range byID {
		ids = append(ids, id)
	}
	sort.Ints(ids)
	out := VerifyGroup{Source: g.Source, Packets: sent, Candidates: g.Candidates, Split: g.Split, lookup: g.lookup,
		Method: VerifyMethodServer, Epoch: g.Epoch, ReceiptKeyID: byID[ids[0]].keyID}
	var runs []string
	for _, id := range ids {
		a := byID[id].group
		switch a.Verdict {
		case string(VerdictUnsupported):
			out.Verdict, out.Reason, out.Matched, out.ReceiptKeyID = VerdictUnsupported, a.Reason, 0, byID[id].keyID
			out.Detail = fmt.Sprintf("the executor could not check these packets (%s)", a.Reason)
			if a.Reason == ReasonAmbiguous {
				out.Detail = "more than one run reproduces every tag, as the executor answered before disclosure; capture more packets of the flow"
			}
			return out, true
		case string(VerdictVerified):
			if !slices.Contains(runs, a.RunID) {
				runs = append(runs, a.RunID)
			}
		}
	}
	slices.Sort(runs)
	if len(runs) > 1 {
		out.Verdict, out.Reason, out.AmbiguousRuns, out.Matched = VerdictUnsupported, ReasonAmbiguous, runs, len(sent)
		out.Detail = fmt.Sprintf("each of %d runs reproduces every tag of some of these packets, as the executor answered before disclosure", len(runs))
		return out, true
	}
	covered := func(verdict string) (wire.AttributionReceiptGroup, bool) {
		var last wire.AttributionReceiptGroup
		for _, i := range sent {
			k := slices.IndexFunc(answers[i], func(a serverAnswer) bool { return a.group.Verdict == verdict })
			if k < 0 {
				return last, false
			}
			last = answers[i][k].group
		}
		return last, true
	}
	if a, ok := covered(string(VerdictVerified)); ok && len(runs) == 1 {
		out.Verdict, out.RunID, out.ExecutorID, out.Epoch, out.Matched = VerdictVerified, a.RunID, a.ExecutorID, a.Epoch, len(sent)
		out.FalseMatchBound = falseMatchBound(max(g.Candidates, 1), len(sent), len(sent))
		out.keys = []int64{}
		out.Detail = fmt.Sprintf("every packet carries a valid tag of run %s on executor %s, as the executor confirmed before the key was disclosed (receipt key %s)",
			a.RunID, a.ExecutorID, out.ReceiptKeyID)
		return out, true
	}
	return VerifyGroup{}, false
}

// serverPass sends the pending groups of rep to the dispatcher and applies
// the receipts. A dispatcher without the server method (API before 1.16)
// leaves them pending.
func (s *clientSource) serverPass(ctx context.Context, rep *VerifyReport) error {
	items := rep.Evidence().Packets.Items
	type batch struct{ packets []int }
	var batches []batch
	var cur batch
	groups := 0
	for _, g := range rep.Groups {
		if g.Verdict != VerdictPending || g.lookup < 0 {
			continue
		}
		send := g.Packets[:min(len(g.Packets), maxServerPackets)]
		chains := map[chainRef]bool{}
		for _, c := range rep.material.lookups[g.lookup].Candidates {
			chains[chainRef{c.ExecutorID, c.Schedule.ChainID}] = true
		}
		weight := max(len(chains), 1)
		if len(cur.packets)+len(send) > maxServerPackets || groups+weight > maxServerGroups {
			if len(cur.packets) > 0 {
				batches = append(batches, cur)
			}
			cur, groups = batch{}, 0
		}
		cur.packets = append(cur.packets, send...)
		groups += weight
	}
	if len(cur.packets) > 0 {
		batches = append(batches, cur)
	}
	if len(batches) == 0 {
		return nil
	}
	var keys []EvidenceReceiptKey
	var receipts []EvidenceReceipt
	var payloads []AttributionReceiptPayload
	for _, b := range batches {
		sent := make([]AttributionVerifyPacket, len(b.packets))
		for i, idx := range b.packets {
			sent[i] = AttributionVerifyPacket{Data: items[idx].Data, CapturedAt: items[idx].CapturedAt}
		}
		resp, err := paced(ctx, s.pace, func() (AttributionVerifyResponse, error) { return s.c.AttributionVerify(ctx, sent) })
		var httpErr *HTTPError
		if errors.As(err, &httpErr) {
			// No server method here, or not now: the groups stay pending.
			break
		}
		if err != nil {
			return rateLimited(err, len(batches), len(b.packets), false)
		}
		if keys == nil {
			published, err := paced(ctx, s.pace, func() (AttributionReceiptKeys, error) { return s.c.AttributionReceiptKeys(ctx) })
			if err != nil {
				return fmt.Errorf("client: verify: read the receipt keys: %w", err)
			}
			keys = make([]EvidenceReceiptKey, 0, len(published.Keys))
			for _, k := range published.Keys {
				keys = append(keys, EvidenceReceiptKey{KeyID: k.KeyID, PublicKey: k.PublicKey, ValidFrom: k.ValidFrom.UTC(), ValidTo: k.ValidTo})
			}
		}
		r := EvidenceReceipt{KeyID: resp.Receipt.KeyID, Payload: resp.Receipt.Payload, Signature: resp.Receipt.Signature, Packets: b.packets}
		p, err := checkReceipt(r, keys, items)
		if err != nil {
			return &EvidenceReceiptError{Receipt: len(receipts), Msg: err.Error()}
		}
		receipts, payloads = append(receipts, r), append(payloads, p)
	}
	if len(receipts) == 0 {
		return nil
	}
	used := map[string]bool{}
	for _, r := range receipts {
		used[r.KeyID] = true
	}
	for _, k := range keys {
		if used[k.KeyID] {
			rep.material.receiptKeys = append(rep.material.receiptKeys, k)
		}
	}
	rep.material.receipts = receipts
	rep.Groups = applyReceipts(rep.Groups, receipts, payloads, itemTimes(items))
	rep.Counts = countGroups(rep.Groups)
	return nil
}

func itemTimes(items []EvidencePacket) []time.Time {
	times := make([]time.Time, len(items))
	for i, p := range items {
		times[i] = p.CapturedAt
	}
	return times
}
