package api

import (
	"debuglet/internal/dispatcher/resource"
	"net/http"

	"github.com/labstack/echo/v4"
)

func (h *Handler) UpdateDestinationLimit(c echo.Context) error {
	// TODO: This endpoint requires authentication from the destination
	var req DestinationLimitRequest
	if err := c.Bind(&req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid request body: "+err.Error())
	}
	h.dispatcher.SetDestinationLimit(req.Destination, resource.Bitrate(req.Limit))
	return c.NoContent(http.StatusNoContent)
}
