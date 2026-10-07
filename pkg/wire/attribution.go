// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package wire

import (
	"encoding/json"
	"time"
)

// AttributionSchedule is the public TESLA schedule of one executor chain. The
// key of epoch t covers the packets sent from T0UnixNs + t*EpochSeconds to
// T0UnixNs + (t+1)*EpochSeconds and is disclosed no earlier than
// T0UnixNs + (t+DisclosureDelayEpochs)*EpochSeconds. Its field names follow
// those of GET /executors/{id}/tesla.
type AttributionSchedule struct {
	// ChainID identifies the chain: the lowercase hex of the first 16 bytes
	// of SHA-256(K0).
	ChainID string `json:"chain_id"`
	// K0 is the chain anchor, the key of epoch 0; every disclosed key hashes
	// to it.
	K0 []byte `json:"k0"`
	// T0UnixNs is the start of epoch 0 in Unix nanoseconds.
	T0UnixNs int64 `json:"t0_unix_ns"`
	// EpochSeconds is the epoch length I in seconds.
	EpochSeconds int64 `json:"epoch_seconds"`
	// DisclosureDelayEpochs is the disclosure delay d in epochs; zero is an
	// executor that predates it, whose tags a verifier must not accept.
	DisclosureDelayEpochs int64 `json:"disclosure_delay_epochs"`
	// ChainLength is L, the number of epochs the chain serves; zero is unknown.
	ChainLength int64 `json:"chain_length"`
	// TagSpec is the tag specification version the executor reported when it
	// registered the chain: TagSpecVersionV1, or TagSpecVersionLegacy for an
	// executor that did not report debuglet-tag-v1. Verifiers of tag spec v1
	// must treat a legacy chain as unsupported, not as a mismatch.
	TagSpec int64 `json:"tag_spec"`
	// OperatorProof is signed by the executor's enrolled TLS key. Offline
	// trust requires a separately known certificate fingerprint.
	OperatorProof *AttributionScheduleProof `json:"operator_proof,omitempty"`
}

// Tag specification versions of an AttributionSchedule.
const (
	// TagSpecVersionLegacy is a chain tagged with the pre-v1, non-standard
	// tag, including every chain of an executor that predates tag spec
	// reports: unsupported under tag spec v1.
	TagSpecVersionLegacy int64 = 0
	// TagSpecVersionV1 is TagSpecV1 (docs/tag-spec.md).
	TagSpecVersionV1 int64 = 1
)

// AttributionCandidate is one run that was active from the queried address
// near the queried time. It names the run and its executor only, never the
// account that submitted it.
type AttributionCandidate struct {
	ExecutorID string    `json:"executor_id"`
	RunID      string    `json:"run_id"`
	ActiveFrom time.Time `json:"active_from"`
	ActiveTo   time.Time `json:"active_to"`
	// IPSource is observed when the address is the one the dispatcher saw on
	// the executor's control connection, advertised when it is the executor's
	// own claim.
	IPSource string              `json:"ip_source"`
	Schedule AttributionSchedule `json:"schedule"`
	// DisclosedThrough is the latest epoch whose disclosed key is on record,
	// 0 when none is.
	DisclosedThrough int64 `json:"disclosed_through"`
	// DisclosedThroughAtNs is when the dispatcher recorded the key of
	// DisclosedThrough, in Unix nanoseconds; 0 when none is on record.
	DisclosedThroughAtNs int64 `json:"disclosed_through_at_ns"`
	// NextDisclosureAtNs is the earliest Unix nanoseconds the key of epoch
	// DisclosedThrough+1 may be disclosed; 0 when the schedule is unknown.
	NextDisclosureAtNs int64 `json:"next_disclosure_at_ns"`
}

// AttributionCandidates answers GET /attribution/candidates.
type AttributionCandidates struct {
	IP string    `json:"ip"`
	At time.Time `json:"at"`
	// RetainedFrom is the start of the retained history: for an earlier
	// time the absence of a candidate is no evidence of absence.
	RetainedFrom time.Time              `json:"retained_from"`
	Candidates   []AttributionCandidate `json:"candidates"`
	// Truncated is set when more runs matched than the answer lists.
	Truncated bool `json:"truncated"`
	// Statement authenticates this dated lookup under the dispatcher's receipt
	// key. Its public key must be obtained through a separately trusted channel.
	Statement *AttributionReceipt `json:"statement,omitempty"`
}

// AttributionKey is one disclosed key of a chain.
type AttributionKey struct {
	Epoch int64  `json:"epoch"`
	Key   []byte `json:"key"`
}

// AttributionKeys answers GET /attribution/keys: one page of the disclosed
// keys of a chain in ascending epoch order. Undisclosed epochs are absent.
type AttributionKeys struct {
	ExecutorID string           `json:"executor_id"`
	ChainID    string           `json:"chain_id"`
	Keys       []AttributionKey `json:"keys"`
	// NextEpoch is the from_epoch of the next page, nil on the last one.
	NextEpoch *int64 `json:"next_epoch"`
}

// AttributionHistoryPayload binds a dated lookup, including its schedule,
// run list and retention boundary, to a dispatcher and signing time.
// Format separates history statements from packet verification receipts.
type AttributionHistoryPayload struct {
	Format     string                `json:"format"`
	Dispatcher string                `json:"dispatcher"`
	SignedAt   time.Time             `json:"signed_at"`
	Lookup     AttributionCandidates `json:"lookup"`
}

const AttributionHistoryFormat = "debuglet-attribution-history-v1"

// AttributionHistoryBytes returns the stable JSON signed by the dispatcher.
// The statement itself is excluded to avoid recursive signatures.
func AttributionHistoryBytes(p AttributionHistoryPayload) ([]byte, error) {
	p.Lookup.Statement = nil
	return json.Marshal(p)
}
