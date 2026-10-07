// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package client

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"

	"github.com/netsec-ethz/debuglet/pkg/wire"
)

// EvidenceTrust identifies a dispatcher and its signing keys obtained outside
// the evidence bundle, for example from its authenticated HTTPS key endpoint.
// Pin old keys before a dispatcher is retired; a bundle cannot establish its
// own identity by supplying another public key.
type EvidenceTrust struct {
	Dispatcher           string               `json:"dispatcher"`
	Keys                 []EvidenceReceiptKey `json:"keys"`
	ExecutorCertificates map[string]string    `json:"executor_certificates,omitempty"`
}

func (s *clientSource) historyKeys(ctx context.Context, id string) error {
	if slices.ContainsFunc(s.receiptKeys, func(k EvidenceReceiptKey) bool { return k.KeyID == id }) {
		return nil
	}
	published, err := paced(ctx, s.pace, func() (AttributionReceiptKeys, error) { return s.c.AttributionReceiptKeys(ctx) })
	if err != nil {
		return fmt.Errorf("client: verify: read history signing keys: %w", err)
	}
	s.receiptKeys = nil
	for _, key := range published.Keys {
		s.receiptKeys = append(s.receiptKeys, EvidenceReceiptKey{KeyID: key.KeyID, PublicKey: key.PublicKey, ValidFrom: key.ValidFrom, ValidTo: key.ValidTo})
	}
	return nil
}

func historySchedule(s EvidenceSchedule) wire.AttributionSchedule {
	return wire.AttributionSchedule{ChainID: s.ChainID, K0: s.K0, T0UnixNs: s.T0UnixNs, EpochSeconds: s.EpochSeconds, DisclosureDelayEpochs: s.DisclosureDelayEpochs, ChainLength: s.ChainLength, TagSpec: s.TagSpec, OperatorProof: s.OperatorProof}
}

func historyLookup(lookup EvidenceLookup) wire.AttributionCandidates {
	out := wire.AttributionCandidates{IP: lookup.IP, At: lookup.At, RetainedFrom: lookup.RetainedFrom, Truncated: lookup.Truncated, Candidates: []wire.AttributionCandidate{}}
	for _, c := range lookup.Candidates {
		out.Candidates = append(out.Candidates, wire.AttributionCandidate{
			ExecutorID: c.ExecutorID, RunID: c.RunID, ActiveFrom: c.ActiveFrom, ActiveTo: c.ActiveTo, IPSource: c.IPSource,
			Schedule:         historySchedule(c.Schedule),
			DisclosedThrough: c.DisclosedThrough, DisclosedThroughAtNs: c.DisclosedThroughAtNs, NextDisclosureAtNs: c.NextDisclosureAtNs,
		})
	}
	return out
}

func checkHistory(lookup EvidenceLookup, dispatcher string, keys []EvidenceReceiptKey) error {
	proof := lookup.Statement
	if proof == nil || len(proof.Payload) > 2<<20 || len(lookup.Candidates) > maxAttributionCandidates {
		return errors.New("client: missing or excessive history statement")
	}
	i := slices.IndexFunc(keys, func(k EvidenceReceiptKey) bool { return k.KeyID == proof.KeyID })
	if i < 0 {
		return fmt.Errorf("client: unknown history signing key %q", proof.KeyID)
	}
	key := keys[i]
	if len(key.PublicKey) != ed25519.PublicKeySize || ReceiptKeyID(key.PublicKey) != key.KeyID || !ed25519.Verify(key.PublicKey, proof.Payload, proof.Signature) {
		return errors.New("client: history signature does not verify")
	}
	var payload wire.AttributionHistoryPayload
	if err := decodeStrict(proof.Payload, &payload); err != nil {
		return fmt.Errorf("client: history statement: %w", err)
	}
	if payload.Format != wire.AttributionHistoryFormat || payload.Dispatcher == "" || payload.Dispatcher != dispatcher || payload.SignedAt.Before(key.ValidFrom) || (key.ValidTo != nil && !payload.SignedAt.Before(*key.ValidTo)) {
		return errors.New("client: history statement has a different issuer, format or invalid signing time")
	}
	expected, err := wire.AttributionHistoryBytes(wire.AttributionHistoryPayload{Format: payload.Format, Dispatcher: dispatcher, SignedAt: payload.SignedAt, Lookup: historyLookup(lookup)})
	if err != nil || !bytes.Equal(expected, proof.Payload) {
		return errors.New("client: history statement does not bind this lookup and its schedules")
	}
	return nil
}

// ReadEvidenceTrust reads a separately stored trust file. Do not load it from
// the evidence being verified; that would let its author select the signer.
func ReadEvidenceTrust(data []byte) (EvidenceTrust, error) {
	var trust EvidenceTrust
	if len(data) > 128<<10 {
		return trust, errors.New("client: evidence trust exceeds 128 KiB")
	}
	if err := json.Unmarshal(data, &trust); err != nil {
		return trust, err
	}
	if trust.Dispatcher == "" || len(trust.Keys) == 0 || len(trust.Keys) > 128 {
		return trust, errors.New("client: evidence trust requires a dispatcher and 1 to 128 signing keys")
	}
	for _, key := range trust.Keys {
		if len(key.PublicKey) != ed25519.PublicKeySize || ReceiptKeyID(key.PublicKey) != key.KeyID || key.ValidFrom.IsZero() || (key.ValidTo != nil && !key.ValidTo.After(key.ValidFrom)) {
			return trust, errors.New("client: invalid evidence trust key")
		}
	}
	if len(trust.ExecutorCertificates) > 128 {
		return trust, errors.New("client: too many trusted executor certificates")
	}
	for executor, fingerprint := range trust.ExecutorCertificates {
		decoded, err := hex.DecodeString(fingerprint)
		if executor == "" || len(executor) > 128 || err != nil || len(decoded) != 32 || hex.EncodeToString(decoded) != fingerprint {
			return trust, errors.New("client: invalid executor certificate pin")
		}
	}
	return trust, nil
}
