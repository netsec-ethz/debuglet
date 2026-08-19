package api

import (
	"debuglet/internal/dispatcher/models"
	"debuglet/internal/dispatcher/resource"
	"encoding/base64"
	"errors"
	"net"
	"strings"
	"time"

	"github.com/google/uuid"
)

type VersionResponse struct {
	Version string `json:"version"`
}

type DebugletPolicyRequest struct {
	FloorBW     int64    `json:"floor_bw"`
	CeilBW      int64    `json:"ceil_bw"`
	TimeoutMS   int64    `json:"timeout_ms"`
	Addresses   []string `json:"addresses"`
	RequireICMP bool     `json:"require_icmp"`
	ListenUDP   bool     `json:"listen_udp"`
	ListenTCP   bool     `json:"listen_tcp"`
	ListenSCION bool     `json:"listen_scion"`
}

type DebugletRequest struct {
	// Must be unique accross a single request
	OrderID int64 `json:"request_id"`
	// Optional start time as unix epoch time
	StartTimestamp *int64                `json:"start_time,omitempty"`
	ExecutorID     string                `json:"executor_id"`
	Args           []string              `json:"args,omitempty"`
	Wasm           string                `json:"wasm"`
	Policy         DebugletPolicyRequest `json:"policy"`
}

type SubmitDebugletsRequest struct {
	Debuglets     []DebugletRequest `json:"debuglets"`
	TransactionId string            `json:"transaction_id"`
	AuthKey       string            `json:"auth_key"`
}

type DebugletResponse struct {
	ID         uuid.UUID `json:"id"`
	StartTime  int64     `json:"start_time"`
	EndTime    int64     `json:"end_time"`
	Usage      int64     `json:"usage"`
	ExecutorID string    `json:"executor_id"`
	Addresses  []string  `json:"addresses"`
	State      string    `json:"state"`
}

type DebugletDeleteRequest struct {
	DebugletID uuid.UUID `json:"debuglet_id"`
	ExecutorID string    `json:"executor_id"`
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
	Currency               string `json:"currency"`
}

// ExecutorByIPResponse is returned by GET /executors/by-ip?ip=<ip>.
// It identifies which executor corresponds to a given source IP and lists the
// most recent debuglet IDs that were dispatched to it.
type ExecutorByIPResponse struct {
	ExecutorID  string      `json:"executor_id"`
	DebugletIDs []uuid.UUID `json:"debuglet_ids"` // newest first, up to ?n= (default 10)
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
	Error      string `json:"error"`
	ExecutorID string `json:"executor_id"`
}

type DebugletLogsResponse struct {
	State   string             `json:"state"`
	Error   string             `json:"error,omitempty"`
	After   int64              `json:"after"`
	Logs    []DebugletLogEntry `json:"logs"`
	HasMore bool               `json:"has_more"`
}

type DebugletLogEntry struct {
	ID        int64  `json:"id"`
	Timestamp string `json:"timestamp"`
	Output    string `json:"output"` // base64-encoded
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
	CoinType        string `json:"coin_type"`
	ExpiresAtS      int64  `json:"expires_at_s"`
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

type UserResponse struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type CreateUserRequest struct {
	Name string `json:"name"`
}

// ================ HELPERS ================

func APIToSpec(r DebugletRequest) (models.DebugletSpec, error) {
	decoded, err := base64.StdEncoding.DecodeString(r.Wasm)
	if err != nil {
		return models.DebugletSpec{}, errors.New("invalid wasm code")
	}
	if strings.TrimSpace(r.ExecutorID) == "" {
		return models.DebugletSpec{}, errors.New("missing executor ID")
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

	return models.DebugletSpec{
		StartTime:  startTime,
		ExecutorID: r.ExecutorID,
		Args:       r.Args,
		Wasm:       decoded,
		Policy: models.DebugletPolicy{
			FloorBW:     resource.Bitrate(r.Policy.FloorBW),
			CeilBW:      resource.Bitrate(r.Policy.CeilBW),
			Timeout:     time.Duration(r.Policy.TimeoutMS) * time.Millisecond,
			Addresses:   addrs,
			RequireICMP: r.Policy.RequireICMP,
			ListenUDP:   r.Policy.ListenUDP,
			ListenTCP:   r.Policy.ListenTCP,
			ListenSCION: r.Policy.ListenSCION,
		},
	}, nil
}
