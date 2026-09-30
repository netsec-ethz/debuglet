// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package api

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func TestMeasurementRequestsRejectUnsupportedFieldsBeforeEffects(t *testing.T) {
	f := ccNewFixture(t)
	_, token, _ := authAccount(t, f, "request-fields")
	for _, route := range []string{"/payment/intent", "/debuglet"} {
		for _, body := range []string{
			`{"debuglets":[{"order_id":0,"policy":{"listen_icmp":true}}]}`,
			`{"debuglets":[],"unexpected":"private-value"}`,
			`{"debuglets":[]} {"auth_key":"private-value"}`,
		} {
			status, _, response, _ := authRequest(t, f, http.MethodPut, route, []byte(body), map[string]string{"Authorization": "Bearer " + token})
			if status != http.StatusBadRequest || strings.Contains(string(response), "private-value") {
				t.Fatalf("%s: status %d body %s", route, status, response)
			}
			var failure ErrorResponse
			if err := json.Unmarshal(response, &failure); err != nil || failure.Code != CodeInvalidRequest {
				t.Fatalf("%s: invalid refusal: %s (%v)", route, response, err)
			}
			if strings.Contains(body, "listen_icmp") && (len(failure.FieldErrors) != 1 || failure.FieldErrors[0].Field != "policy.listen_icmp" || failure.FieldErrors[0].Code != "unsupported_field") {
				t.Fatalf("unsupported ICMP field was not identified: %s", response)
			}
		}
	}
	blAssertNoRows(t, f, "transactions", "debuglet_order", "debuglets")
}

func TestNumericPolicyFailureIdentifiesOrderAndField(t *testing.T) {
	for _, tc := range boundsRejectedPolicies() {
		policy := boundsDebuglets(tc.edit)[0].Policy
		failure := validatePolicy(17, policy).Message.(ErrorResponse)
		if len(failure.FieldErrors) != 1 {
			t.Fatalf("%s: missing field failure: %+v", tc.name, failure)
		}
		field := failure.FieldErrors[0]
		if field.Field != "policy."+tc.field || field.OrderID == nil || *field.OrderID != 17 {
			t.Fatalf("%s: wrong field/order: %+v", tc.name, field)
		}
	}
}
