package client

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
)

const (
	stageIntent = "intent"
	stageSubmit = "submit"
)

var (
	errInvalidBatch = errors.New("client: invalid prepared batch (use Prepare)")
	errRemoteTEST   = errors.New("client: TEST submission to a non-loopback endpoint requires AllowRemoteTEST")
)

// intentResponse mirrors the TEST payment intent response.
type intentResponse struct {
	Method string `json:"method"`
	Intent struct {
		TransactionID string `json:"transaction_id"`
		AuthKey       string `json:"auth_key"`
	} `json:"intent"`
}

// SubmitTEST creates a TEST payment intent for the batch and submits it.
func (c *Client) SubmitTEST(ctx context.Context, batch *PreparedBatch) (Submission, error) {
	if batch == nil || batch.count == 0 || len(batch.debuglets) == 0 {
		return Submission{}, &SubmissionError{Stage: stageIntent, Err: errInvalidBatch}
	}
	if c == nil || c.http == nil {
		return Submission{}, &SubmissionError{Stage: stageIntent, Err: errors.New("client: Client must be created with New")}
	}
	if !c.loopback && !c.options.AllowRemoteTEST {
		return Submission{}, &SubmissionError{Stage: stageIntent, Err: errRemoteTEST}
	}
	if err := ctx.Err(); err != nil {
		return Submission{}, &SubmissionError{Stage: stageIntent, Err: err}
	}

	// Step 1: payment intent. No transaction ID exists yet, so none is ever
	// reported; the outcome is unknown only for a 5xx or a malformed success.
	data, err := c.do(ctx, http.MethodPut, routeIntent, nil, intentEnvelope(batch.debuglets), http.StatusOK)
	if err != nil {
		return Submission{}, &SubmissionError{Stage: stageIntent, OutcomeUnknown: outcomeUnknown(stageIntent, err), Err: err}
	}
	var intent intentResponse
	if err := c.decode(http.MethodPut, routeIntent, data, &intent); err != nil {
		return Submission{}, &SubmissionError{Stage: stageIntent, OutcomeUnknown: true, Err: err}
	}
	if intent.Method != "TEST" {
		// The supplied method may itself contain the decoded auth key.
		err := c.protocolErr(http.MethodPut, routeIntent, "payment method is not TEST")
		return Submission{}, &SubmissionError{Stage: stageIntent, OutcomeUnknown: true, Err: err}
	}
	transactionID := intent.Intent.TransactionID
	if strings.TrimSpace(transactionID) == "" {
		err := c.protocolErr(http.MethodPut, routeIntent, "missing transaction_id")
		return Submission{}, &SubmissionError{Stage: stageIntent, OutcomeUnknown: true, Err: err}
	}
	authKey := intent.Intent.AuthKey // may be empty; never exposed

	// Step 2: submission with the identical frozen debuglets bytes.
	if err := ctx.Err(); err != nil {
		return Submission{}, &SubmissionError{Stage: stageSubmit, TransactionID: transactionID, Err: err}
	}
	body, err := submitEnvelope(batch.debuglets, transactionID, authKey)
	if err != nil {
		return Submission{}, &SubmissionError{Stage: stageSubmit, TransactionID: transactionID, Err: err}
	}
	data, err = c.do(ctx, http.MethodPut, routeDebuglet, nil, body, http.StatusOK, authKey)
	if err != nil {
		return Submission{}, &SubmissionError{Stage: stageSubmit, TransactionID: transactionID, OutcomeUnknown: outcomeUnknown(stageSubmit, err), Err: err}
	}
	var ids []string
	if err := c.decode(http.MethodPut, routeDebuglet, data, &ids); err != nil {
		return Submission{}, &SubmissionError{Stage: stageSubmit, TransactionID: transactionID, OutcomeUnknown: true, Err: err}
	}
	if err := c.validateSubmittedIDs(ids, batch.count); err != nil {
		return Submission{}, &SubmissionError{Stage: stageSubmit, TransactionID: transactionID, OutcomeUnknown: true, Err: err}
	}
	return Submission{IDs: ids, TransactionID: transactionID}, nil
}

// validateSubmittedIDs requires one nonzero canonical UUID per request with
// no duplicates.
func (c *Client) validateSubmittedIDs(ids []string, count int) error {
	if len(ids) != count {
		return c.protocolErr(http.MethodPut, routeDebuglet, fmt.Sprintf("returned %d ids for %d debuglets", len(ids), count))
	}
	seen := make(map[string]struct{}, len(ids))
	for i, id := range ids {
		if !isCanonicalUUID(id) {
			return c.protocolErr(http.MethodPut, routeDebuglet, fmt.Sprintf("id %d is not a canonical UUID", i))
		}
		if isNilUUID(id) {
			return c.protocolErr(http.MethodPut, routeDebuglet, fmt.Sprintf("id %d is the nil UUID", i))
		}
		if _, duplicate := seen[id]; duplicate {
			return c.protocolErr(http.MethodPut, routeDebuglet, fmt.Sprintf("id %d duplicates an earlier id", i))
		}
		seen[id] = struct{}{}
	}
	return nil
}

// outcomeUnknown classifies a request failure conservatively. A server 5xx
// means the request may have been processed at either stage, except a 503
// that carries service_unavailable or payments_disabled at the intent stage:
// the dispatcher answers those before anything is priced or written. A protocol
// error (malformed success, oversized body) is uncertainty at either stage.
// A transport or read failure counts as unknown only once the submission
// request itself has been handed to the transport. Unexpected submission 2xx
// may also mean acceptance; 4xx and redirects remain rejections.
func outcomeUnknown(stage string, err error) bool {
	var httpErr *HTTPError
	if errors.As(err, &httpErr) {
		if stage == stageIntent && httpErr.StatusCode == http.StatusServiceUnavailable &&
			(httpErr.Code == CodeUnavailable || httpErr.Code == CodePaymentsDisabled) {
			return false
		}
		return httpErr.StatusCode >= 500 ||
			(stage == stageSubmit && httpErr.StatusCode >= 200 && httpErr.StatusCode < 300)
	}
	var protoErr *protocolError
	if errors.As(err, &protoErr) {
		return true
	}
	return stage == stageSubmit
}
