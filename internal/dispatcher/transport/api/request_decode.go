// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package api

import (
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"

	"github.com/labstack/echo/v4"
	"github.com/netsec-ethz/debuglet/pkg/wire"
)

// decodeMeasurementRequest refuses unsupported fields before an intent or
// submission can have effects. Decoder text may contain credentials and is
// never used as a public diagnostic.
func decodeMeasurementRequest(c echo.Context, value any) error {
	mediaType, _, err := mime.ParseMediaType(c.Request().Header.Get(echo.HeaderContentType))
	if err != nil || mediaType != echo.MIMEApplicationJSON {
		return apiError(http.StatusUnsupportedMediaType, CodeUnsupportedMediaType, "request body must be application/json")
	}
	decoder := json.NewDecoder(c.Request().Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		if err.Error() == `json: unknown field "listen_icmp"` {
			const message = "listen_icmp is not supported; use require_icmp to request ICMP probes"
			return echo.NewHTTPError(http.StatusBadRequest, ErrorResponse{
				Code: CodeInvalidRequest, Message: message,
				FieldErrors: []wire.FieldError{{Field: "policy.listen_icmp", Code: "unsupported_field", Message: message}},
			})
		}
		return bindError(err)
	}
	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		return bindError(err)
	}
	return nil
}

func policyFieldError(orderID int64, field, code, reason string) *echo.HTTPError {
	failure := policyError(orderID, reason)
	body := failure.Message.(ErrorResponse)
	body.FieldErrors = []wire.FieldError{{Field: field, Code: code, Message: reason, OrderID: &orderID}}
	failure.Message = body
	return failure
}
