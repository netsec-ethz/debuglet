// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package client

import (
	"context"
	"net/http"
	"strings"

	"github.com/netsec-ethz/debuglet/pkg/wire"
)

type CancellationDocument = wire.Cancellation

// Cancellation inspects a recorded request without retrying it. This optional
// API 1.9 route is absent on older dispatchers; Cancel remains compatible.
func (c *Client) Cancellation(ctx context.Context, id string) (CancellationDocument, error) {
	if err := validateJobID(id); err != nil {
		return CancellationDocument{}, err
	}
	route := routeDebuglet + "/" + id + "/cancellation"
	data, err := c.do(ctx, http.MethodGet, route, nil, nil, http.StatusOK)
	if err != nil {
		return CancellationDocument{}, err
	}
	var doc CancellationDocument
	if err := c.decode(http.MethodGet, route, data, &doc); err != nil {
		return CancellationDocument{}, err
	}
	fields := recoveryFields(data, "id", "request_id", "executor_id", "original_binding", "requested_at", "attempted_at", "acknowledged_at", "checked_at", "disposition", "reason", "state", "error")
	valid := fields != nil && doc.ID == id && isCanonicalUUID(doc.RequestID) && !isNilUUID(doc.RequestID) &&
		strings.TrimSpace(doc.ExecutorID) != "" && strings.TrimSpace(doc.State) != "" && strings.TrimSpace(doc.Disposition) != "" &&
		!doc.RequestedAt.IsZero() && !doc.CheckedAt.IsZero() &&
		string(fields["reason"]) != "null" && string(fields["error"]) != "null" &&
		validRecoveryBinding(fields["original_binding"], doc.OriginalBinding)
	if doc.AttemptedAt != nil {
		valid = valid && !doc.AttemptedAt.IsZero() && doc.OriginalBinding != nil
	}
	if doc.AcknowledgedAt != nil {
		valid = valid && !doc.AcknowledgedAt.IsZero() && doc.AttemptedAt != nil
	}
	switch doc.Disposition {
	case "requested":
		valid = valid && doc.AttemptedAt == nil && doc.AcknowledgedAt == nil && doc.Reason == ""
	case "delivery_attempted":
		valid = valid && doc.AttemptedAt != nil && doc.AcknowledgedAt == nil && doc.Reason == ""
	case "acknowledged":
		valid = valid && doc.AcknowledgedAt != nil && doc.Reason == ""
	case "not_needed":
		valid = valid && doc.AttemptedAt == nil && doc.AcknowledgedAt == nil && strings.TrimSpace(doc.Reason) != ""
	case "unresolved":
		valid = valid && doc.AcknowledgedAt == nil && strings.TrimSpace(doc.Reason) != ""
	}

	if !valid {
		return CancellationDocument{}, c.protocolErr(http.MethodGet, route, "inconsistent cancellation document")
	}
	return doc, nil
}
