// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package guestio

// MeshConfig describes a bounded service over an already admitted experiment.
// The host checks every identity and endpoint against its readiness result.
type MeshConfig struct {
	Kind          string     `json:"kind"`
	Self          string     `json:"self"`
	Group         string     `json:"group"`
	Fingerprint   string     `json:"fingerprint"`
	Peers         []MeshPeer `json:"peers"`
	StartMS       int64      `json:"start_ms"`
	DurationMS    int64      `json:"duration_ms"`
	IntervalMS    int64      `json:"interval_ms,omitempty"`
	WindowMS      int64      `json:"window_ms,omitempty"`
	MaxBytes      int64      `json:"max_bytes,omitempty"`
	MaxTransferMS int64      `json:"max_transfer_ms,omitempty"`
}

type MeshPeer struct {
	Participant string `json:"participant"`
	RunID       string `json:"run_id"`
	ExecutorID  string `json:"executor_id"`
	TCPAddress  string `json:"tcp_address"`
	UDPAddress  string `json:"udp_address,omitempty"`
}

type MeshRequest struct {
	Config    *MeshConfig `json:"config,omitempty"`
	Service   uint32      `json:"service,omitempty"`
	Peer      string      `json:"peer,omitempty"`
	Bytes     int64       `json:"bytes,omitempty"`
	TimeoutMS int64       `json:"timeout_ms,omitempty"`
}

type MeshSnapshot struct {
	OK             bool             `json:"ok"`
	Error          string           `json:"error"`
	Rows           []map[string]any `json:"rows"`
	WindowStartMS  int64            `json:"window_start_ms"`
	WindowEndMS    int64            `json:"window_end_ms"`
	SkippedWindows int              `json:"skipped_windows"`
}

type MeshTransfer struct {
	Peer          string  `json:"peer"`
	SentBytes     int64   `json:"sent_bytes"`
	ReceivedBytes int64   `json:"received_bytes"`
	DurationMS    float64 `json:"duration_ms"`
	GoodputMbps   float64 `json:"goodput_mbps"`
	Complete      bool    `json:"ok"`
	Error         string  `json:"error"`
}
