package api

type DebugletPolicy struct {
	FloorBW   int64    `json:"floor_bw"`
	CeilBW    int64    `json:"ceil_bw"`
	TimeoutMS int64    `json:"timeout_ms"`
	Addresses []string `json:"addresses"`
}

type DebugletRequest struct {
	// Optional start time as unix epoch time
	StartTimestamp *int64         `json:"start_time,omitempty"`
	ExecutorID     string         `json:"executor_id"`
	Wasm           string         `json:"wasm"`
	Policy         DebugletPolicy `json:"policy"`
}

type ExecutorResponse struct {
	ID       string `json:"id"`
	Ready    bool   `json:"ready"`
	LastSeen int64  `json:"last_seen"`

	TeslaDelaySec          int64  `json:"tesla_delay_sec"`
	TeslaAnchorTimestampNs int64  `json:"tesla_anchor_timestamp_ns"`
	TeslaAnchorKey         []byte `json:"tesla_anchor_key"` // k_0, the public chain anchor
}

// ExecutorByIPResponse is returned by GET /executors/by-ip?ip=<ip>.
// It identifies which executor corresponds to a given source IP and lists the
// most recent debuglet IDs that were dispatched to it.
type ExecutorByIPResponse struct {
	ExecutorID  string   `json:"executor_id"`
	DebugletIDs []string `json:"debuglet_ids"` // newest first, up to ?n= (default 10)
}

// ExecutorTeslaResponse is returned by GET /executors/:id/tesla.
// It provides all parameters needed by an external verifier to reconstruct
// chain keys and validate packet authentication tags.
type ExecutorTeslaResponse struct {
	ExecutorID        string `json:"executor_id"`
	AnchorKey         string `json:"anchor_key"`          // base64-encoded k_0
	AnchorTimestampNs int64  `json:"anchor_timestamp_ns"` // Unix nanoseconds of epoch 0
	DelaySec          int64  `json:"delay_sec"`           // epoch duration in seconds
	DisclosedEpoch    int64  `json:"disclosed_epoch"`     // index of latest disclosed key
	DisclosedKey      string `json:"disclosed_key"`       // base64-encoded k_τ, empty if none yet
}
