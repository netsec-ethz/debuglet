package client

import (
	"errors"
	"fmt"
)

// HTTPError reports a response the client did not accept: any status other
// than the one expected for the route, including other 2xx codes. Code is the
// dispatcher's stable failure code, the field to branch on; Message is a
// bounded, sanitized diagnostic for a human and must not be parsed. A server
// that sends no documented envelope leaves Code empty. Unrecognized JSON
// bodies use a generic diagnostic. Recognized auth_key fields and known
// submission keys are redacted. Path never contains a query or request body.
type HTTPError struct {
	Method     string
	Path       string
	StatusCode int
	Code       string
	Message    string
}

func (e *HTTPError) Error() string {
	if e.Message == "" {
		return fmt.Sprintf("%s %s: unexpected status %d", e.Method, e.Path, e.StatusCode)
	}
	if e.Code == "" {
		return fmt.Sprintf("%s %s: status %d: %s", e.Method, e.Path, e.StatusCode, e.Message)
	}
	return fmt.Sprintf("%s %s: status %d (%s): %s", e.Method, e.Path, e.StatusCode, e.Code, e.Message)
}

// Documented failure codes of the dispatcher's HTTP API. They are the stable
// part of an error: a client selects behaviour by comparing HTTPError.Code
// against these values instead of matching on Message. A dispatcher may add a
// code within a contract major version, so treat an unknown code as a plain
// failure of the status it arrived with.
const (
	// CodeInvalidRequest is a malformed or incomplete request.
	CodeInvalidRequest = "invalid_request"
	// CodeInvalidPolicy is a policy that cannot be priced or scheduled.
	CodeInvalidPolicy = "invalid_policy"
	// CodeUnknownExecutor names an executor that is not registered.
	CodeUnknownExecutor = "unknown_executor"
	// CodeIntentMismatch is a submission whose debuglets differ from the ones
	// the payment intent was created for.
	CodeIntentMismatch = "intent_mismatch"
	// CodePaymentIncomplete is a submission for a transaction that is not paid.
	CodePaymentIncomplete = "payment_incomplete"
	// CodeUnsupportedPaymentMethod is a payment method the API does not admit.
	CodeUnsupportedPaymentMethod = "unsupported_payment_method"
	// CodePaymentsDisabled is a chain payment method while blockchain payments
	// are disabled.
	CodePaymentsDisabled = "payments_disabled"
	// CodeUnsupportedAPIVersion is APIVersion being unavailable on that server.
	CodeUnsupportedAPIVersion = "unsupported_api_version"
	// CodeUnauthorized is a missing, malformed, expired or revoked credential.
	// It is the failure a client answers by logging in again.
	CodeUnauthorized = "unauthorized"
	// CodeForbidden is an authenticated account that may not perform the
	// operation. Logging in again does not help; another account is needed.
	CodeForbidden = "forbidden"
	// CodeNotFound is a debuglet, user or executor that does not exist.
	CodeNotFound = "not_found"
	// CodeCapacityExhausted is a batch the scheduler cannot admit.
	CodeCapacityExhausted = "capacity_exhausted"
	// CodeCancelRefused is a cancellation the dispatcher did not accept.
	CodeCancelRefused = "cancel_refused"
	// CodeMethodNotAllowed is a method the route does not serve.
	CodeMethodNotAllowed = "method_not_allowed"
	// CodeUnsupportedMediaType is a body representation the route does not read.
	CodeUnsupportedMediaType = "unsupported_media_type"
	// CodePayloadTooLarge is a body beyond the accepted size.
	CodePayloadTooLarge = "payload_too_large"
	// CodeInternal is a failure inside the dispatcher, with no detail exposed.
	CodeInternal = "internal_error"
	// CodeUnavailable is a temporarily unavailable capability.
	CodeUnavailable = "service_unavailable"
)

// SubmissionError reports a failed SubmitTEST. Stage is "intent" or "submit".
// TransactionID is retained when the intent had already been created.
// OutcomeUnknown is set conservatively when the submission may have been
// accepted by the server although no valid response was observed (transport
// or read failure after sending, malformed success, an unexpected submission
// 2xx, or a server 5xx); it is uncertainty, not proof of acceptance. A validated
// pre-send failure or a 4xx response is a rejection with OutcomeUnknown false,
// and so is a 503 that carries service_unavailable or payments_disabled at the
// intent stage: nothing was priced or written.
type SubmissionError struct {
	Stage          string
	TransactionID  string
	OutcomeUnknown bool
	Err            error
}

func (e *SubmissionError) Error() string {
	outcome := "rejected"
	if e.OutcomeUnknown {
		outcome = "outcome unknown"
	}
	if e.TransactionID != "" {
		return fmt.Sprintf("submission %s at stage %s (transaction %s): %v", outcome, e.Stage, e.TransactionID, e.Err)
	}
	return fmt.Sprintf("submission %s at stage %s: %v", outcome, e.Stage, e.Err)
}

func (e *SubmissionError) Unwrap() error { return e.Err }

// Code returns the dispatcher's failure code when the submission failed on a
// response that carried one, and "" otherwise. It never changes how the
// outcome itself is classified: OutcomeUnknown stays the only statement about
// whether the submission may have been accepted.
func (e *SubmissionError) Code() string {
	var httpErr *HTTPError
	if errors.As(e.Err, &httpErr) {
		return httpErr.Code
	}
	return ""
}
