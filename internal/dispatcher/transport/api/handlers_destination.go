// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package api

import (
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/netsec-ethz/debuglet/internal/bitrate"
	"github.com/netsec-ethz/debuglet/internal/dispatcher"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/resource"

	"github.com/labstack/echo/v4"
)

// localOperatorActor is recorded for a change the local development bypass
// makes, which names no account.
const localOperatorActor = "local"

// PATCH /destination
//
// PatchDestinationLimit changes a dispatcher-wide destination policy, which
// affects every account's admission decisions. It is therefore an operator
// operation rather than something a submitter may do to its own runs.
func (h *Handler) PatchDestinationLimit(c echo.Context) error {
	operator, err := requireOperator(c)
	if err != nil {
		return err
	}
	var req DestinationLimitRequest
	if err := c.Bind(&req); err != nil {
		return bindError(err)
	}
	// The limit becomes the capacity every run on the destination is shared
	// out of and summed against, so it is held to the same range as the
	// bandwidth of a policy. A negative one would refuse every allocation.
	if req.Limit < 0 || req.Limit > maxBandwidthBPS {
		return apiError(http.StatusBadRequest, CodeInvalidPolicy,
			fmt.Sprintf("invalid policy: limit must be between 0 and %d bits per second", maxBandwidthBPS))
	}
	if req.Destination == "" || len(req.Destination) > dispatcher.MaxDestinationLength {
		return apiError(http.StatusBadRequest, CodeInvalidRequest,
			fmt.Sprintf("destination must be between 1 and %d bytes", dispatcher.MaxDestinationLength))
	}
	if len(req.Reason) > dispatcher.MaxDestinationPolicyReason {
		return apiError(http.StatusBadRequest, CodeInvalidRequest,
			fmt.Sprintf("reason must be at most %d bytes", dispatcher.MaxDestinationPolicyReason))
	}
	if req.Reason == "" && (req.Denied || bitrate.Bitrate(req.Limit) < h.dispatcher.DestinationLimit(req.Destination)) {
		return apiError(http.StatusBadRequest, CodeInvalidRequest, "reason is required to deny a destination or to lower its limit")
	}
	change := dispatcher.DestinationPolicyChange{Limit: bitrate.Bitrate(req.Limit), Denied: req.Denied, Reason: req.Reason}
	if req.ExpiresAt != "" {
		expires, err := time.Parse(time.RFC3339, req.ExpiresAt)
		if err != nil || !expires.After(time.Now()) {
			return apiError(http.StatusBadRequest, CodeInvalidRequest, "expires_at must be an RFC 3339 time in the future")
		}
		change.ExpiresAt = expires
	}
	actor := localOperatorActor
	if operator.Authenticated {
		actor = operator.UserUUID.String()
	}
	// A refused policy changes nothing. Otherwise the policy is recorded, and
	// 204 says every executor holding an allocation on the destination also
	// received the recomputed share.
	if err := h.dispatcher.SetDestinationPolicy(c.Request().Context(), actor, req.Destination, change); err != nil {
		if errors.Is(err, dispatcher.ErrInvalidDestinationPolicy) {
			return apiError(http.StatusBadRequest, CodeInvalidRequest, "invalid destination policy")
		}
		if errors.Is(err, resource.ErrCapacityFull) {
			return apiErrorFrom(http.StatusConflict, CodeCapacityExhausted,
				"limit is below the floors admitted on the destination, active or reserved", err)
		}
		if errors.Is(err, dispatcher.ErrDestinationPolicyNotRecorded) {
			return apiErrorFrom(http.StatusInternalServerError, CodeInternal, "destination policy could not be recorded", err)
		}
		if errors.Is(err, dispatcher.ErrDenialUnsupported) && !errors.Is(err, dispatcher.ErrOrderedBandwidthUnsupported) {
			return apiErrorFrom(http.StatusInternalServerError, CodeInternal,
				"destination policy recorded; upgrade executors that predate destination denials to revoke active traffic", err)
		}
		if errors.Is(err, dispatcher.ErrOrderedBandwidthUnsupported) {
			return apiErrorFrom(http.StatusInternalServerError, CodeInternal,
				"destination limit recorded; upgrade legacy executors to confirm ordered application", err)
		}
		return apiErrorFrom(http.StatusInternalServerError, CodeInternal,
			"destination limit recorded but not delivered to every executor", err)
	}
	return c.NoContent(http.StatusNoContent)
}

// GET /destinations
//
// GetDestinationPolicies lists the current recorded policy of every
// destination that has one, with who set it, why, and whether every executor
// holding an allocation there acknowledged it.
func (h *Handler) GetDestinationPolicies(c echo.Context) error {
	if _, err := requireOperator(c); err != nil {
		return err
	}
	policies, err := h.dispatcher.ListDestinationPolicies(c.Request().Context())
	if err != nil {
		return apiErrorFrom(http.StatusInternalServerError, CodeInternal, "destination policies could not be read", err)
	}
	response := DestinationPoliciesResponse{Destinations: make([]DestinationPolicyResponse, 0, len(policies))}
	for _, policy := range policies {
		entry := DestinationPolicyResponse{
			Destination: policy.Destination, Kind: policy.Kind, Denied: policy.Kind == dispatcher.DestinationPolicyDeny,
			Reason: policy.Reason, Actor: policy.Actor, SetAt: policy.SetAt, ExpiresAt: policy.ExpiresAt,
			Revision: policy.Revision, Delivery: "confirmed", Recipients: policy.Recipients, Unconfirmed: policy.Unconfirmed,
		}
		if policy.Limit != nil {
			limit := int64(*policy.Limit)
			entry.Limit = &limit
		}
		if policy.Unconfirmed > 0 {
			entry.Delivery = "unconfirmed"
		}
		response.Destinations = append(response.Destinations, entry)
	}
	return c.JSON(http.StatusOK, response)
}
