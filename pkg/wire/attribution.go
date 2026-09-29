// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package wire

import "time"

// AttributionSchedule is the public TESLA schedule of one executor chain. The
// key of epoch t covers the packets sent from T0 + t*Interval to
// T0 + (t+1)*Interval and is disclosed from T0 + (t+DelayEpochs)*Interval.
type AttributionSchedule struct {
	// Chain identifies the chain; it is derived from K0.
	Chain string `json:"chain"`
	// K0 is the chain anchor, the key of epoch 0; every disclosed key hashes
	// to it.
	K0 []byte `json:"k0"`
	// T0 is the start of epoch 0 in Unix nanoseconds.
	T0 int64 `json:"t0"`
	// Interval is the epoch length I in seconds.
	Interval int64 `json:"interval"`
	// DelayEpochs is the disclosure delay d; zero is an executor that predates
	// it, whose tags a verifier must not accept.
	DelayEpochs int64 `json:"delay_epochs"`
	// ChainLength is L, the number of epochs the chain serves; zero is unknown.
	ChainLength int64 `json:"chain_length"`
	// TagSpec is the tag specification version the chain tags with.
	TagSpec int `json:"tag_spec"`
}

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
	Chain      string           `json:"chain"`
	Keys       []AttributionKey `json:"keys"`
	// NextEpoch is the from_epoch of the next page, nil on the last one.
	NextEpoch *int64 `json:"next_epoch"`
}
