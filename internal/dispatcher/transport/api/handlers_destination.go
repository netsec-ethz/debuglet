// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package api

import (
	"fmt"
	"net/http"

	"github.com/netsec-ethz/debuglet/internal/dispatcher/resource"

	"github.com/labstack/echo/v4"
)

// PATCH /destination
//
// PatchDestinationLimit changes a dispatcher-wide bandwidth limit, which
// affects every account's admission decisions. It is therefore an operator
// operation rather than something a submitter may do to its own runs.
func (h *Handler) PatchDestinationLimit(c echo.Context) error {
	if _, err := requireOperator(c); err != nil {
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
	h.dispatcher.SetDestinationLimit(req.Destination, resource.Bitrate(req.Limit))
	return c.NoContent(http.StatusNoContent)
}
