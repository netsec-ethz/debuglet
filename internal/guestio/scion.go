// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package guestio

const (
	SCIONMaxPayload = 4096
	SCIONBufferSize = 32768
	SCIONLocalPath  = "local"
)

// SCIONPath describes an outbound path snapshot. ID is opaque and stable across
// list reordering; discovery does not guarantee that the path remains usable.
type SCIONPath struct {
	ID          string           `json:"id"`
	Source      string           `json:"source"`
	Destination string           `json:"destination"`
	Interfaces  []SCIONInterface `json:"interfaces"`
	HopCount    int              `json:"hop_count"`
	MTU         uint16           `json:"mtu"`
	ExpiresMS   int64            `json:"expires_ms"`
}

type SCIONInterface struct {
	IA string `json:"ia"`
	ID uint64 `json:"id"`
}

type SCIONExchange struct {
	Data       []byte  `json:"data"`
	PathID     string  `json:"path_id"`
	Sender     string  `json:"sender"`
	DurationMS float64 `json:"duration_ms"`
	Size       int     `json:"size"`
	Truncated  bool    `json:"truncated"`
}

type SCIONDatagram struct {
	Data         []byte `json:"data"`
	Sender       string `json:"sender"`
	ReceivedAtMS int64  `json:"received_at_ms"`
	Size         int    `json:"size"`
	Truncated    bool   `json:"truncated"`
}

// SCIONRequest is a bounded request shared by the six optional SCION imports.
type SCIONRequest struct {
	Address   string `json:"address,omitempty"`
	PathID    string `json:"path_id,omitempty"`
	Payload   []byte `json:"payload,omitempty"`
	MaxBytes  int    `json:"max_bytes,omitempty"`
	TimeoutNS int64  `json:"timeout_ns,omitempty"`
}

type SCIONResponse struct {
	Error    string         `json:"error,omitempty"`
	Paths    []SCIONPath    `json:"paths,omitempty"`
	Path     *SCIONPath     `json:"path,omitempty"`
	Exchange *SCIONExchange `json:"exchange,omitempty"`
	Datagram *SCIONDatagram `json:"datagram,omitempty"`
	Address  string         `json:"address,omitempty"`
	Bytes    int            `json:"bytes,omitempty"`
}
