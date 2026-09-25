package api

import (
	"errors"
	"net/http"
	"strings"
	"unicode/utf8"

	"github.com/labstack/echo/v4"
	"go.uber.org/zap"
)

// ErrorResponse is the documented error envelope of the HTTP API. Every
// failure answers with this object: Code is a stable identifier a client
// branches on, Message is a bounded human-readable diagnostic it must not
// parse. Internal diagnostics are never part of it; they stay in the
// dispatcher's log. api/openapi.yaml lists the codes.
type ErrorResponse struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// Documented failure codes. New codes may appear within a contract major
// version, so a client must treat an unknown code as a plain failure of the
// status it arrived with.
const (
	// CodeInvalidRequest is a malformed or incomplete request.
	CodeInvalidRequest = "invalid_request"
	// CodeInvalidPolicy is a request whose debuglet policy cannot be priced or
	// scheduled: a timeout outside 1..maxTimeoutMS milliseconds, a negative
	// floor, a ceiling below the floor, or a batch whose total price overflows.
	CodeInvalidPolicy = "invalid_policy"
	// CodeUnknownExecutor names an executor that is not registered.
	CodeUnknownExecutor = "unknown_executor"
	// CodeIntentMismatch is a submission whose debuglets differ from the ones
	// the payment intent was created for.
	CodeIntentMismatch = "intent_mismatch"
	// CodePaymentIncomplete is a submission for a transaction that is not paid.
	CodePaymentIncomplete = "payment_incomplete"
	// CodeUnsupportedPaymentMethod is a payment method this API does not admit.
	CodeUnsupportedPaymentMethod = "unsupported_payment_method"
	// CodePaymentsDisabled is a chain payment method while blockchain payments
	// are disabled.
	CodePaymentsDisabled = "payments_disabled"
	// CodeUnsupportedAPIVersion is a required contract version this dispatcher
	// does not serve.
	CodeUnsupportedAPIVersion = "unsupported_api_version"
	// CodeUnauthorized is a missing, malformed, unknown, expired or revoked
	// credential, or an auth key that does not match the transaction. It says
	// that the request was not authenticated, never which of those it was.
	CodeUnauthorized = "unauthorized"
	// CodeForbidden is an authenticated request whose account may not perform
	// the operation: an operator operation asked for by an ordinary account, or
	// a cookie-authenticated state change without its CSRF token. Access to
	// another account's object is not reported with this code; it answers
	// not_found, so the response is no existence oracle.
	CodeForbidden = "forbidden"
	// CodeNotFound is a debuglet, user or executor that does not exist.
	CodeNotFound = "not_found"
	// CodeCapacityExhausted is a batch the scheduler cannot admit within the
	// executor's remaining capacity, or a destination limit below the floors
	// already admitted on that destination.
	CodeCapacityExhausted = "capacity_exhausted"
	// CodeCancelRefused is a cancellation the dispatcher did not accept.
	CodeCancelRefused = "cancel_refused"
	// CodeMethodNotAllowed is a method the route does not serve.
	CodeMethodNotAllowed = "method_not_allowed"
	// CodeUnsupportedMediaType is a body representation the route does not read.
	CodeUnsupportedMediaType = "unsupported_media_type"
	// CodePayloadTooLarge is a body beyond the accepted size.
	CodePayloadTooLarge = "payload_too_large"
	// CodeInternal is a failure inside the dispatcher. Its details are logged,
	// never returned.
	CodeInternal = "internal_error"
	// CodeUnavailable is a temporarily unavailable capability.
	CodeUnavailable = "service_unavailable"
)

// maxEchoedValue bounds a caller-supplied value repeated in a message.
const maxEchoedValue = 64

// apiError builds a failure that serializes as the documented envelope. Echo
// passes a message value it does not recognize through to the response, so the
// envelope also reaches a client on an Echo instance that was built without
// the API error handler.
func apiError(status int, code, message string) *echo.HTTPError {
	return echo.NewHTTPError(status, ErrorResponse{Code: code, Message: message})
}

// apiErrorFrom is apiError with a private cause. The cause is logged by the
// API error handler and never serialized.
func apiErrorFrom(status int, code, message string, cause error) *echo.HTTPError {
	failure := apiError(status, code, message)
	if cause != nil {
		failure.SetInternal(cause)
	}
	return failure
}

// bindError reports a request body Echo could not decode. Echo's own
// description of the caller's bytes is kept, its wrapper and internal decoder
// error are not.
func bindError(err error) *echo.HTTPError {
	message := "invalid request body"
	var httpErr *echo.HTTPError
	if errors.As(err, &httpErr) {
		if detail, ok := httpErr.Message.(string); ok && strings.TrimSpace(detail) != "" {
			message += ": " + echoed(detail)
		}
	}
	return apiErrorFrom(http.StatusBadRequest, CodeInvalidRequest, message, err)
}

// echoed bounds a caller-supplied value that a message repeats back, so that
// an arbitrarily long or invalid request value cannot shape the response.
func echoed(value string) string {
	value = strings.ToValidUTF8(value, "�")
	value = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, value)
	if len(value) <= maxEchoedValue {
		return value
	}
	value = value[:maxEchoedValue]
	for !utf8.ValidString(value) {
		value = value[:len(value)-1]
	}
	return value + "..."
}

// errorHandler serializes every failure of the API as the documented envelope,
// including the ones Echo raises itself, and keeps private diagnostics in the
// log. It is installed by RegisterRoutes.
func (h *Handler) errorHandler(err error, c echo.Context) {
	if c.Response().Committed {
		return
	}
	status, body, internal := errorEnvelope(err)
	if internal != nil && h.logger != nil {
		h.logger.Warn("request failed",
			zap.String("route", c.Path()),
			zap.Int("status", status),
			zap.String("code", body.Code),
			zap.Error(internal))
	}
	if c.Request().Method == http.MethodHead {
		_ = c.NoContent(status)
		return
	}
	_ = c.JSON(status, body)
}

// errorEnvelope classifies one failure into the response envelope and the
// private cause to log. A value the API did not construct itself is reported
// by its status alone: nothing about it is known to be safe to return.
func errorEnvelope(err error) (int, ErrorResponse, error) {
	var httpErr *echo.HTTPError
	if !errors.As(err, &httpErr) {
		return http.StatusInternalServerError, ErrorResponse{Code: CodeInternal, Message: "internal server error"}, err
	}
	internal := httpErr.Internal
	if inner, ok := internal.(*echo.HTTPError); ok {
		httpErr, internal = inner, inner.Internal
	}
	status := httpErr.Code
	if status < 100 || status > 599 {
		status = http.StatusInternalServerError
	}
	switch message := httpErr.Message.(type) {
	case ErrorResponse:
		if message.Code == "" {
			message.Code = codeForStatus(status)
		}
		return status, message, internal
	case string:
		return status, ErrorResponse{Code: codeForStatus(status), Message: message}, internal
	default:
		return status, ErrorResponse{Code: codeForStatus(status), Message: http.StatusText(status)}, err
	}
}

// codeForStatus is the documented code of a failure that carries no more
// specific one, such as an unrouted request.
func codeForStatus(status int) string {
	switch status {
	case http.StatusBadRequest:
		return CodeInvalidRequest
	case http.StatusUnauthorized:
		return CodeUnauthorized
	case http.StatusForbidden:
		return CodeForbidden
	case http.StatusNotFound:
		return CodeNotFound
	case http.StatusMethodNotAllowed:
		return CodeMethodNotAllowed
	case http.StatusConflict:
		return CodeCapacityExhausted
	case http.StatusRequestEntityTooLarge:
		return CodePayloadTooLarge
	case http.StatusUnsupportedMediaType:
		return CodeUnsupportedMediaType
	case http.StatusServiceUnavailable:
		return CodeUnavailable
	default:
		if status >= 500 {
			return CodeInternal
		}
		return CodeInvalidRequest
	}
}
