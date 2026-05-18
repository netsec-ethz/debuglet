// Copyright 2025 ETH Zurich
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package api

type DebugletRequest struct {
	ExecutorID string   `json:"executor_id"`
	Code       string   `json:"code"`
	Addresses  []string `json:"addresses"`

	Policy struct {
		FloorBW   int64 `json:"floor_bw"`
		CeilBW    int64 `json:"ceil_bw"`
		TimeoutMS int64 `json:"timeout_ms"`
	} `json:"policy"`
}

type MeasurementRequest struct {
	Debuglets []DebugletRequest `json:"debuglets"`
}

type MeasurementResponse struct {
	MeasurementID string `json:"measurement_id"`
	Sessions      []struct {
		ExecutorID string `json:"executor_id"`
		SessionID  string `json:"session_id"`
	} `json:"sessions"`
}

// ExecutorByIPResponse is returned by GET /executors/by-ip?ip=<ip>.
// It identifies which executor corresponds to a given source IP and lists the
// most recent measurement IDs that were dispatched to it.
type ExecutorByIPResponse struct {
	ExecutorID     string   `json:"executor_id"`
	MeasurementIDs []string `json:"measurement_ids"` // newest first, up to ?n= (default 10)
}

// ExecutorTeslaResponse is returned by GET /executors/:id/tesla.
// It provides all parameters needed by an external verifier to reconstruct
// chain keys and validate packet authentication tags.
type ExecutorTeslaResponse struct {
	ExecutorID           string `json:"executor_id"`
	AnchorKey            string `json:"anchor_key"`             // base64-encoded k_0
	AnchorTimestampNs    int64  `json:"anchor_timestamp_ns"`    // Unix nanoseconds of epoch 0
	DelaySec             int64  `json:"delay_sec"`              // epoch duration in seconds
	DisclosedEpoch       int64  `json:"disclosed_epoch"`        // index of latest disclosed key
	DisclosedKey         string `json:"disclosed_key"`          // base64-encoded k_τ, empty if none yet
}
