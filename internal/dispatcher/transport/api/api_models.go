// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package api

import (
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/models"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/resource"
	"math"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
)

// VersionResponse reports the version identities of a dispatcher. They are
// independent: api_version is the HTTP contract this dispatcher serves,
// binary_version identifies the build and protocol_version is the executor
// control protocol, which no HTTP client speaks. Version is the dispatcher's
// configured string, retained for clients written before the contract was
// versioned.
type VersionResponse struct {
	Version         string   `json:"version"`
	APIVersion      string   `json:"api_version"`
	APIVersions     []string `json:"api_versions"`
	BinaryVersion   string   `json:"binary_version"`
	BinaryRevision  string   `json:"binary_revision,omitempty"`
	ProtocolVersion string   `json:"protocol_version"`
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
	OrderID int64 `json:"order_id"`
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
	RefundAddress string            `json:"refund_address"`
}

type UserResponse struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	// Role is the account's role, "user" or "operator". It reports what the
	// account may do; it is not a credential and grants nothing by itself.
	Role string `json:"role"`
}

type CreateUserRequest struct {
	Name string `json:"name"`
}

// ================ HELPERS ================

// maxTimeoutMS and maxBandwidthBPS are the bounds of the domain, named here as
// the request fields they bound. api/openapi.yaml documents the same bounds.
const (
	maxTimeoutMS    = models.MaxPolicyTimeoutMS
	maxBandwidthBPS = models.MaxPolicyBandwidthBPS
)

// minStartTimestamp and maxStartTimestamp bound start_time, in Unix seconds.
// Below zero a start time is not a Unix timestamp, and above the bound the
// reserved window no longer fits the nanosecond timeline the dispatcher
// reserves capacity on. api/openapi.yaml documents the same bounds.
const (
	minStartTimestamp = int64(0)
	maxStartTimestamp = int64(math.MaxInt64) / int64(time.Second)
)

// validatePolicy rejects a requested policy the API does not admit. It runs
// where a policy first enters the system, pricing an intent and admitting a
// submission, so that what the contract documents is what the server enforces.
// It checks the numbers as they were requested: they are converted into internal
// units and then summed, and neither conversion nor sum may depend on a client
// having checked them first.
func validatePolicy(orderID int64, policy DebugletPolicyRequest) *echo.HTTPError {
	switch models.CheckPolicyNumbers(policy.FloorBW, policy.CeilBW, policy.TimeoutMS) {
	case models.PolicyBoundTimeout:
		return policyError(orderID, fmt.Sprintf("timeout_ms must be positive and at most %d", maxTimeoutMS))
	case models.PolicyBoundFloor:
		return policyError(orderID, fmt.Sprintf("floor_bw must be between 0 and %d bits per second", maxBandwidthBPS))
	case models.PolicyBoundCeil:
		return policyError(orderID, fmt.Sprintf("ceil_bw must be between 0 and %d bits per second", maxBandwidthBPS))
	case models.PolicyBoundCeilBelowFloor:
		return policyError(orderID, "ceil_bw must be at least floor_bw")
	}
	return nil
}

// validateStartTimestamp rejects a start time that is not a Unix second the
// dispatcher can reserve a window from. time.Unix wraps silently outside this
// range, which would turn a far future start into an arbitrary past one.
func validateStartTimestamp(start *int64) error {
	if start == nil {
		return nil
	}
	if *start < minStartTimestamp || *start > maxStartTimestamp {
		return fmt.Errorf("start_time must be a Unix timestamp between %d and %d", minStartTimestamp, maxStartTimestamp)
	}
	return nil
}

func policyError(orderID int64, reason string) *echo.HTTPError {
	return apiError(http.StatusBadRequest, CodeInvalidPolicy,
		fmt.Sprintf("invalid policy (order %d): %s", orderID, reason))
}

func APIToSpec(r DebugletRequest) (models.DebugletSpec, error) {
	decoded, err := base64.StdEncoding.DecodeString(r.Wasm)
	if err != nil {
		return models.DebugletSpec{}, errors.New("invalid wasm code")
	}
	if strings.TrimSpace(r.ExecutorID) == "" {
		return models.DebugletSpec{}, errors.New("missing executor ID")
	}

	if err := validateStartTimestamp(r.StartTimestamp); err != nil {
		return models.DebugletSpec{}, err
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
