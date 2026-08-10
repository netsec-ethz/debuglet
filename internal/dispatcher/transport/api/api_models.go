package api

import (
	"debuglet/internal/dispatcher"
	"debuglet/internal/dispatcher/resource"
	"encoding/base64"
	"errors"
	"net"
	"strings"
	"time"
)

type VersionResponse struct {
	Version string `json:"version"`
}

type DebugletPolicyRequest struct {
	FloorBW   int64    `json:"floor_bw"`
	CeilBW    int64    `json:"ceil_bw"`
	TimeoutMS int64    `json:"timeout_ms"`
	Addresses []string `json:"addresses"`
}

type DebugletRequest struct {
	// Optional start time as unix epoch time
	StartTimestamp *int64                `json:"start_time,omitempty"`
	ExecutorID     string                `json:"executor_id"`
	Args           []string              `json:"args,omitempty"`
	Wasm           string                `json:"wasm"`
	Policy         DebugletPolicyRequest `json:"policy"`
}

type DebugletDeleteRequest struct {
	DebugletID string `json:"debuglet_id"`
	ExecutorID string `json:"executor_id"`
}

type ExecutorResponse struct {
	ID       string `json:"id"`
	Ready    bool   `json:"ready"`
	LastSeen int64  `json:"last_seen"`
	Version  string `json:"version"`

	TeslaDelaySec          int64  `json:"tesla_delay_sec"`
	TeslaAnchorTimestampNs int64  `json:"tesla_anchor_timestamp_ns"`
	TeslaAnchorKey         []byte `json:"tesla_anchor_key"` // k_0, the public chain anchor
	PricePerBw             int64  `json:"price_per_bw"`
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

type DestinationLimitRequest struct {
	Destination string `json:"destination"`
	Limit       int64  `json:"limit"`
}

type DebugletStateResponse struct {
	State      string `json:"state"`
	Logs       string `json:"logs"` // base64-encoded
	Error      string `json:"error"`
	ExecutorID string `json:"executor_id"`
}

type SubmitDebugletsRequest struct {
	Debuglets     []DebugletRequest `json:"debuglets"`
	TransactionId string            `json:"transaction_id"`
	AuthKey       string            `json:"auth_key"`
}

type BalanceResponse struct {
	Balance int64 `json:"balance"`
}

type IntentResponse struct {
	Method string `json:"method"`
	Intent any    `json:"intent"`
}

type SuiIntent struct {
	TransactionId   string `json:"transaction_id"`
	AuthKey         string `json:"auth_key"`
	Price           int64  `json:"price"`
	ExpiresAt       int64  `json:"expires_at"`
	RegistryAddress string `json:"registry_address"`
	ReceiverAddress string `json:"receiver_address"`
}

type DummyIntent struct {
	TransactionID string `json:"transaction_id"`
	AuthKey       string `json:"auth_key"`
}

type PaymentIntentRequest struct {
	Debuglets     []DebugletRequest `json:"debuglets"`
	PaymentMethod string            `json:"payment_method"`
}

// ================ HELPERS ================

func APIToSpec(r DebugletRequest) (dispatcher.DebugletSpec, error) {
	decoded, err := base64.StdEncoding.DecodeString(r.Wasm)
	if err != nil {
		return dispatcher.DebugletSpec{}, errors.New("invalid wasm code")
	}
	if strings.TrimSpace(r.ExecutorID) == "" {
		return dispatcher.DebugletSpec{}, errors.New("missing executor ID")
	}

	var startTime *time.Time
	if st := r.StartTimestamp; st != nil {
		tmp := time.Unix(*st, 0).UTC()
		startTime = &tmp
	}

	// remove accidental ports from the policy addresses
	var addrs []string
	for _, a := range r.Policy.Addresses {
		host, _, err := net.SplitHostPort(a)
		if err != nil {
			addrs = append(addrs, a)
		} else {
			addrs = append(addrs, host)
		}
	}

	return dispatcher.DebugletSpec{
		StartTime:  startTime,
		ExecutorID: r.ExecutorID,
		Args:       r.Args,
		Wasm:       decoded,
		Policy: dispatcher.DebugletPolicy{
			FloorBW:   resource.Bitrate(r.Policy.FloorBW),
			CeilBW:    resource.Bitrate(r.Policy.CeilBW),
			Timeout:   time.Duration(r.Policy.TimeoutMS) * time.Millisecond,
			Addresses: addrs,
		},
	}, nil
}
