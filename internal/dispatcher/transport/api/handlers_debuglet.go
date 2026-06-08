package api

import (
	"debuglet/internal/dispatcher"
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/labstack/echo/v4"
)

// POST /submit
func (h *Handler) SubmitDebuglets(c echo.Context) error {
	var reqs []DebugletRequest
	if err := c.Bind(&reqs); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid request body: "+err.Error())
	}
	if len(reqs) == 0 {
		return echo.NewHTTPError(http.StatusBadRequest, "no debuglets provided")
	}

	var specs []dispatcher.DebugletSpec
	for i, req := range reqs {
		decoded, err := base64.StdEncoding.DecodeString(req.Wasm)
		if err != nil {
			return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("invalid wasm code (i=%d)", i))
		}
		if strings.TrimSpace(req.ExecutorID) == "" {
			return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("missing executor ID (i=%d)", i))
		}

		var startTime *time.Time
		if st := req.StartTimestamp; st != nil {
			tmp := time.Unix(*st, 0)
			startTime = &tmp
		}

		specs = append(specs, dispatcher.DebugletSpec{
			StartTime:  startTime,
			ExecutorID: req.ExecutorID,
			Wasm:       decoded,
			Policy: dispatcher.DebugletPolicy{
				FloorBW:   req.Policy.FloorBW,
				CeilBW:    req.Policy.CeilBW,
				Timeout:   time.Duration(req.Policy.TimeoutMS) * time.Millisecond,
				Addresses: req.Policy.Addresses,
			},
		})
	}

	if IDs, err := h.dispatcher.SubmitDebuglets(c.Request().Context(), specs); err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to initialize debuglets:"+err.Error())
	} else {
		return c.JSON(http.StatusOK, IDs)
	}
}
