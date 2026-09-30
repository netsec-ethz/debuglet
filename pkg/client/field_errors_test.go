// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package client

import (
	"net/http"
	"strings"
	"testing"
)

func TestSubmissionFieldErrorsPreserveFailureAndRedactCredentials(t *testing.T) {
	for _, tc := range []struct {
		name, fields string
		want         int
	}{
		{"valid", `[{"field":"policy.listen_tcp","code":"unsupported","message":"cannot listen secret-value","order_id":0}]`, 1},
		{"old server", `null`, 0},
		{"invalid order", `[{"field":"policy.listen_tcp","code":"unsupported","message":"cannot listen","order_id":"0"}]`, 0},
		{"credential in field", `[{"field":"secret_value","code":"unsupported","message":"cannot listen"}]`, 0},
		{"malformed", `[{}]`, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeServer(t, "")
			f.handle("PUT /payment/intent", jsonHandler(http.StatusBadRequest, `{"code":"invalid_policy","message":"request refused","auth_key":"secret_value","field_errors":`+tc.fields+`}`))
			_, err := f.client(t, Options{Credential: "secret-value"}).SubmitTEST(testContext(t), sampleBatch(t))
			failure, response := asSubmissionError(t, err), asHTTPError(t, err)
			if failure.OutcomeUnknown || failure.Stage != "intent" || response.Code != CodeInvalidPolicy || response.StatusCode != http.StatusBadRequest || len(response.FieldErrors) != tc.want {
				t.Fatalf("field details changed failure: %+v HTTP=%+v", failure, response)
			}
			if tc.want > 0 && (strings.Contains(response.FieldErrors[0].Message, "secret-value") || response.FieldErrors[0].OrderID == nil || *response.FieldErrors[0].OrderID != 0) {
				t.Fatalf("field details lost redaction or order zero: %+v", response.FieldErrors)
			}
			if len(f.requests()) != 1 {
				t.Fatal("refused intent caused more requests")
			}
		})
	}
}
