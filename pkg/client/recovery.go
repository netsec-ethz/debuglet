// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package client

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/netsec-ethz/debuglet/pkg/wire"
)

type RecoveryDocument = wire.Recovery
type RecoveryObservation = wire.RecoveryObservation
type RecoveryObserver = wire.RecoveryObserver
type RetainedRun = wire.RetainedRun
type ControlBinding = wire.ControlBinding

// Recovery makes one bounded request for a known run's recovery observation.
// Unknown classifications and failed workloads are successful inspections;
// neither an absent row nor a start marker establishes that replay is safe.
func (c *Client) Recovery(ctx context.Context, id string) (RecoveryDocument, error) {
	if err := validateJobID(id); err != nil {
		return RecoveryDocument{}, err
	}
	route := routeDebuglet + "/" + id + "/recovery"
	data, err := c.do(ctx, http.MethodGet, route, nil, nil, http.StatusOK)
	if err != nil {
		return RecoveryDocument{}, err
	}
	var doc RecoveryDocument
	if err := c.decode(http.MethodGet, route, data, &doc); err != nil {
		return RecoveryDocument{}, err
	}
	if !validRecoveryDocument(data, doc, id) {
		return RecoveryDocument{}, c.protocolErr(http.MethodGet, route, "inconsistent recovery document")
	}
	return doc, nil
}

func validRecoveryDocument(data []byte, doc RecoveryDocument, id string) bool {
	fields := recoveryFields(data, "id", "executor_id", "state", "error", "checked_at", "original_binding", "control_status", "observation")
	if fields == nil || string(fields["error"]) == "null" || doc.ID != id || strings.TrimSpace(doc.ExecutorID) == "" || strings.TrimSpace(doc.State) == "" || doc.CheckedAt.IsZero() || strings.TrimSpace(doc.ControlStatus) == "" {
		return false
	}
	if !validRecoveryBinding(fields["original_binding"], doc.OriginalBinding) {
		return false
	}
	switch doc.ControlStatus {
	case "current", "unavailable":
		if doc.OriginalBinding == nil {
			return false
		}
	case "legacy":
		if doc.OriginalBinding != nil {
			return false
		}
	}
	observation := doc.Observation
	fields = recoveryFields(fields["observation"], "classification", "observer", "received_at", "current_at_check", "retained")
	if fields == nil || strings.TrimSpace(observation.Classification) == "" {
		return false
	}
	provenance := observation.Observer != nil
	if provenance != (observation.ReceivedAt != nil) || provenance != (observation.CurrentAtCheck != nil) {
		return false
	}
	if provenance {
		observer := observation.Observer
		metadata := recoveryFields(fields["observer"], "executor_id", "binding")
		if metadata == nil || observer.ExecutorID != doc.ExecutorID || observation.ReceivedAt.IsZero() || !validRecoveryBinding(metadata["binding"], &observer.Binding) {
			return false
		}
		if doc.ControlStatus == "current" && *observation.CurrentAtCheck && observer.Binding != *doc.OriginalBinding {
			return false
		}
	}
	if retained := observation.Retained; retained != nil {
		metadata := recoveryFields(fields["retained"], "original_binding", "started", "started_at", "start_time")
		if metadata == nil || string(metadata["started"]) == "null" || !provenance || !validRecoveryBinding(metadata["original_binding"], retained.OriginalBinding) || retained.Started != (retained.StartedAt != nil) {
			return false
		}
		if retained.StartedAt != nil && retained.StartedAt.IsZero() || retained.StartTime != nil && retained.StartTime.IsZero() {
			return false
		}
		if (retained.OriginalBinding == nil) != (doc.OriginalBinding == nil) {
			return false
		}
		if retained.OriginalBinding != nil && (*retained.OriginalBinding != *doc.OriginalBinding || *retained.OriginalBinding == observation.Observer.Binding) {
			return false
		}
	}
	switch observation.Classification {
	case "not_attempted":
		return doc.OriginalBinding != nil && !provenance && observation.Retained == nil
	case "unavailable", "unsupported", "failed", "invalid":
		return !provenance && observation.Retained == nil
	case "absent", "filtered":
		return provenance && observation.Retained == nil
	case "retained_unstarted":
		return provenance && observation.Retained != nil && observation.Retained.OriginalBinding != nil && !observation.Retained.Started
	case "started_unknown":
		return provenance && observation.Retained != nil && observation.Retained.OriginalBinding != nil && observation.Retained.Started
	case "legacy":
		return provenance && observation.Retained != nil && observation.Retained.OriginalBinding == nil
	default:
		return true // Future classifications remain observations, never replay advice.
	}
}

func validRecoveryBinding(data []byte, binding *ControlBinding) bool {
	if binding == nil {
		return strings.TrimSpace(string(data)) == "null"
	}
	return recoveryFields(data, "dispatcher_incarnation", "session_id") != nil &&
		isCanonicalUUID(binding.DispatcherIncarnation) && !isNilUUID(binding.DispatcherIncarnation) &&
		isCanonicalUUID(binding.SessionID) && !isNilUUID(binding.SessionID)
}

func recoveryFields(data []byte, required ...string) map[string]json.RawMessage {
	var fields map[string]json.RawMessage
	if json.Unmarshal(data, &fields) != nil || fields == nil {
		return nil
	}
	for _, key := range required {
		if _, ok := fields[key]; !ok {
			return nil
		}
	}
	return fields
}
