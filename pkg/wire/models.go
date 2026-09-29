// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

// Package wire defines the HTTP JSON types shared by the dispatcher and Go
// client. Request and log bytes may be represented as base64 strings at the
// server boundary or as decoded byte slices in the client.
package wire

// Request describes one debuglet in a batch. Binary is a base64 string on the
// server and a byte slice (encoded by encoding/json) in the client.
type Request[Binary ~string | ~[]byte] struct {
	// OrderID must be unique within one batch.
	OrderID int64 `json:"order_id"`
	// StartTimestamp is an optional Unix epoch start time.
	StartTimestamp *int64   `json:"start_time,omitempty"`
	ExecutorID     string   `json:"executor_id"`
	Args           []string `json:"args,omitempty"`
	Wasm           Binary   `json:"wasm"`
	Policy         Policy   `json:"policy"`
}

// Policy is the network policy requested for a debuglet.
type Policy struct {
	FloorBW     int64    `json:"floor_bw"`
	CeilBW      int64    `json:"ceil_bw"`
	TimeoutMS   int64    `json:"timeout_ms"`
	Addresses   []string `json:"addresses"`
	RequireICMP bool     `json:"require_icmp"`
	ListenUDP   bool     `json:"listen_udp"`
	ListenTCP   bool     `json:"listen_tcp"`
	ListenSCION bool     `json:"listen_scion"`
}

// Executor is one executor as reported by GET executors.
type Executor struct {
	Capabilities           *ExecutorCapabilities `json:"capabilities,omitempty"`
	ID                     string                `json:"id"`
	Ready                  bool                  `json:"ready"`
	LastSeen               int64                 `json:"last_seen"`
	Version                string                `json:"version"`
	TeslaDelaySec          int64                 `json:"tesla_delay_sec"`
	TeslaAnchorTimestampNs int64                 `json:"tesla_anchor_timestamp_ns"`
	TeslaAnchorKey         []byte                `json:"tesla_anchor_key"` // k_0, the public chain anchor
	PricePerBw             int64                 `json:"price_per_bw"`
	Currency               string                `json:"currency"`
	// Admission is ready, maintenance or offline; empty from older dispatchers.
	Admission  string          `json:"admission"`
	Display    ExecutorDisplay `json:"display"`
	SCIONISDAS ObservedString  `json:"scion_isd_as"`
	// Listeners are the transports the executor can open run listeners on.
	Listeners ObservedList `json:"listeners"`
	// Clock is the executor-reported kernel clock state. Host platform detail
	// is operator-only and never part of this public listing.
	Clock ObservedClock `json:"clock"`
}

// State is a debuglet's reported state. Unknown state strings are preserved.
type State struct {
	State      string `json:"state"`
	Error      string `json:"error"`
	ExecutorID string `json:"executor_id"`
}

// LogPage is one page of guest output. The server omits an empty Error when
// serializing its response; clients may also receive the explicit empty string.
type LogPage[Binary ~string | ~[]byte] struct {
	State   string             `json:"state"`
	Error   string             `json:"error"`
	After   int64              `json:"after"`
	Logs    []LogEntry[Binary] `json:"logs"`
	HasMore bool               `json:"has_more"`
	Output  OutputStatus       `json:"output"`
}

// OutputStatus describes the stored output independently of the workload state.
// State is open: unknown future values do not establish completeness. A final
// cursor is present only for complete or truncated output, and is zero if empty.
type OutputStatus struct {
	State       string `json:"state"`
	FinalCursor *int64 `json:"final_cursor"`
	LossReason  string `json:"loss_reason"`
}

// LogEntry is one stored output chunk. Output is base64 text on the server and
// the exact guest bytes in the client; Timestamp is the server's opaque string.
type LogEntry[Binary ~string | ~[]byte] struct {
	ID        int64  `json:"id"`
	Timestamp string `json:"timestamp"`
	Output    Binary `json:"output"`
}

// User is the account a request authenticated as, as reported by GET me.
type User struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	// Role reports the account's permissions; it is not a credential.
	Role string `json:"role"`
}

// Version reports a dispatcher's version identities. Version is the configured
// string retained from before the HTTP contract was versioned. APIVersion is
// the HTTP contract served, APIVersions lists its supported major versions,
// BinaryVersion and BinaryRevision identify the build, and ProtocolVersion is
// the executor control protocol. Every field beyond Version is empty for older
// dispatchers; current dispatchers omit an empty BinaryRevision.
type Version struct {
	Version         string   `json:"version"`
	APIVersion      string   `json:"api_version"`
	APIVersions     []string `json:"api_versions"`
	BinaryVersion   string   `json:"binary_version"`
	BinaryRevision  string   `json:"binary_revision"`
	ProtocolVersion string   `json:"protocol_version"`
}
