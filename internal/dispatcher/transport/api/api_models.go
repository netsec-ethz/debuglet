// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package api

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/netsec-ethz/debuglet/internal/bitrate"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/models"
	"github.com/netsec-ethz/debuglet/pkg/wire"
	"math"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
)

// VersionResponse reports the dispatcher's independent version identities.
type VersionResponse wire.Version

// MarshalJSON preserves the response's optional build revision.
func (v VersionResponse) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		wire.Version
		BinaryRevision string `json:"binary_revision,omitempty"`
	}{wire.Version(v), v.BinaryRevision})
}

type DebugletPolicyRequest = wire.Policy

type DebugletRequest = wire.Request[string]

type SubmitDebugletsRequest struct {
	Retry         *wire.RetryLink   `json:"retry,omitempty"`
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

type ExecutorResponse = wire.Executor

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
//
// The key of epoch t is disclosed no earlier than
// anchor_timestamp_ns + (t + disclosure_delay_epochs) * epoch_seconds. A
// verifier accepts a packet captured at time c with the key of its epoch t or
// t-1 only while that key was still secret at c.
type ExecutorTeslaResponse struct {
	ExecutorID        string `json:"executor_id"`
	AnchorKey         string `json:"anchor_key"`          // base64-encoded k_0
	AnchorTimestampNs int64  `json:"anchor_timestamp_ns"` // Unix nanoseconds of epoch 0
	DelaySec          int64  `json:"delay_sec"`           // deprecated name of epoch_seconds
	EpochSeconds      int64  `json:"epoch_seconds"`       // epoch length I in seconds
	// DisclosureDelayEpochs is d; 0 for an executor that predates it, which
	// disclosed after one epoch and whose tags a verifier must not accept.
	DisclosureDelayEpochs  int64  `json:"disclosure_delay_epochs"`
	DisclosureDelaySeconds int64  `json:"disclosure_delay_seconds"` // d * epoch_seconds
	DisclosedEpoch         int64  `json:"disclosed_epoch"`          // index of latest disclosed key
	DisclosedKey           string `json:"disclosed_key"`            // base64-encoded k_τ, empty if none yet
	// NextDisclosureEpoch is disclosed_epoch+1, and NextDisclosureAtNs the
	// earliest Unix nanoseconds its key may be disclosed.
	NextDisclosureEpoch int64 `json:"next_disclosure_epoch"`
	NextDisclosureAtNs  int64 `json:"next_disclosure_at_ns"`
}

type DestinationLimitRequest struct {
	Destination string `json:"destination"`
	Limit       int64  `json:"limit"`
}

type DebugletStateResponse = wire.State

type DebugletLogsResponse wire.LogPage[string]

// MarshalJSON preserves the response's optional workload error.
func (p DebugletLogsResponse) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		wire.LogPage[string]
		Error string `json:"error,omitempty"`
	}{wire.LogPage[string](p), p.Error})
}

type DebugletLogEntry = wire.LogEntry[string]

type BalanceResponse struct {
	Balance int64 `json:"balance"`
}

type IntentResponse struct {
	Retry  *wire.RetryReceipt `json:"retry,omitempty"`
	Method string             `json:"method"`
	Intent any                `json:"intent"`
	// Quote states the prices the intent stored. It is absent when a retry
	// recovers an intent created earlier.
	Quote *wire.Quote `json:"quote,omitempty"`
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
	Retry         *wire.RetryLink   `json:"retry,omitempty"`
	Debuglets     []DebugletRequest `json:"debuglets"`
	PaymentMethod string            `json:"payment_method"`
	RefundAddress string            `json:"refund_address"`
}

type UserResponse = wire.User

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
		return policyFieldError(orderID, "policy.timeout_ms", "out_of_range", fmt.Sprintf("timeout_ms must be positive and at most %d", maxTimeoutMS))
	case models.PolicyBoundFloor:
		return policyFieldError(orderID, "policy.floor_bw", "out_of_range", fmt.Sprintf("floor_bw must be between 0 and %d bits per second", maxBandwidthBPS))
	case models.PolicyBoundCeil:
		return policyFieldError(orderID, "policy.ceil_bw", "out_of_range", fmt.Sprintf("ceil_bw must be between 0 and %d bits per second", maxBandwidthBPS))
	case models.PolicyBoundCeilBelowFloor:
		return policyFieldError(orderID, "policy.ceil_bw", "below_floor", "ceil_bw must be at least floor_bw")
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
	requested, err := submittedConfiguration(r)
	if err != nil {
		return models.DebugletSpec{}, err
	}
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

	return models.DebugletSpec{
		Requested:  requested,
		StartTime:  startTime,
		ExecutorID: r.ExecutorID,
		Args:       r.Args,
		Wasm:       decoded,
		Policy:     specPolicy(r.Policy),
	}, nil
}

// specPolicy converts a requested policy into the dispatcher's units.
func specPolicy(p DebugletPolicyRequest) models.DebugletPolicy {
	// remove accidental ports from the policy addresses
	var addrs []string
	for _, a := range p.Addresses {
		host, _, err := net.SplitHostPort(a)
		if err != nil {
			addrs = append(addrs, a)
		} else {
			addrs = append(addrs, host)
		}
	}
	return models.DebugletPolicy{
		FloorBW:     bitrate.Bitrate(p.FloorBW),
		CeilBW:      bitrate.Bitrate(p.CeilBW),
		Timeout:     time.Duration(p.TimeoutMS) * time.Millisecond,
		Addresses:   addrs,
		RequireICMP: p.RequireICMP,
		ListenUDP:   p.ListenUDP,
		ListenTCP:   p.ListenTCP,
		ListenSCION: p.ListenSCION,
	}
}
