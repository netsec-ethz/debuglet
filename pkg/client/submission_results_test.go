// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package client

import (
	"encoding/json"
	"fmt"
	"net/http"
	"reflect"
	"strings"
	"testing"
)

func TestFailedSubmissionValidatesAdmittedIDs(t *testing.T) {
	for _, tc := range []struct {
		name, field, key string
		status           int
		want             []string
	}{
		{"known admission", `["` + fixtureID + `"]`, "", 500, []string{fixtureID}},
		{"missing metadata", `null`, "", 500, nil},
		{"wrong count", `["` + fixtureID + `"]`, "", 500, nil},
		{"invalid identity", `["not-an-id"]`, "", 500, nil},
		{"nil identity", `["00000000-0000-0000-0000-000000000000"]`, "", 500, nil},
		{"uppercase identity", `["` + strings.ToUpper(fixtureID) + `"]`, "", 500, nil},
		{"duplicate identities", `["` + fixtureID + `","` + fixtureID + `"]`, "", 500, nil},
		{"incomplete identity list", `["` + fixtureID + `",7]`, "", 500, nil},
		{"credential shaped like an identity", `["` + fixtureID + `"]`, fixtureID, 500, nil},
		{"field on refusal is not admission", `["` + fixtureID + `"]`, "", 400, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeServer(t, "")
			f.handle("PUT /payment/intent", intentHandler(fixtureTx, tc.key))
			f.handle("PUT /debuglet", jsonHandler(tc.status, `{"code":"internal_error","message":"submission failed","admitted_ids":`+tc.field+`}`))
			requests := []Request{{OrderID: 0, ExecutorID: fixtureExecutor, Wasm: []byte("wasm"), Policy: Policy{TimeoutMS: 1000}}}
			if tc.name == "duplicate identities" || tc.name == "incomplete identity list" || tc.name == "wrong count" {
				second := requests[0]
				second.OrderID = 1
				requests = append(requests, second)
			}
			batch, err := Prepare(requests)
			if err != nil {
				t.Fatal(err)
			}
			_, err = f.client(t, Options{}).SubmitTEST(testContext(t), batch)
			se, he := asSubmissionError(t, err), asHTTPError(t, err)
			if !reflect.DeepEqual(se.AdmittedIDs, tc.want) || se.TransactionID != fixtureTx || se.OutcomeUnknown != (tc.status == 500) || he.StatusCode != tc.status || se.Code() != CodeInternal {
				t.Fatalf("failure classification changed: %+v HTTP=%+v", se, he)
			}
			if len(f.requests()) != 2 {
				t.Fatal("failed submission was replayed or inspected automatically")
			}
		})
	}
}

func TestFailedSubmissionRetainsLargeIdentityReceipt(t *testing.T) {
	const count = 300 // The identity list is larger than the generic error limit.
	ids := make([]string, count)
	requests := make([]Request, count)
	for i := range ids {
		ids[i] = fmt.Sprintf("00000000-0000-4000-8000-%012x", i+1)
		requests[i] = Request{OrderID: int64(i), ExecutorID: fixtureExecutor, Wasm: []byte("wasm"), Policy: Policy{TimeoutMS: 1000}}
	}
	batch, err := Prepare(requests)
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(map[string]any{"code": CodeInternal, "message": strings.Repeat("x", maxErrorBody+100), "admitted_ids": ids})
	if err != nil {
		t.Fatal(err)
	}
	f := newFakeServer(t, "")
	f.handle("PUT /payment/intent", intentHandler(fixtureTx, ""))
	f.handle("PUT /debuglet", jsonHandler(http.StatusInternalServerError, string(body)))
	_, err = f.client(t, Options{}).SubmitTEST(testContext(t), batch)
	se, he := asSubmissionError(t, err), asHTTPError(t, err)
	if !reflect.DeepEqual(se.AdmittedIDs, ids) || !se.OutcomeUnknown || len(he.Message) != maxErrorBody || len(f.requests()) != 2 {
		t.Fatalf("large failure receipt: IDs=%d unknown=%t diagnostic=%d requests=%d", len(se.AdmittedIDs), se.OutcomeUnknown, len(he.Message), len(f.requests()))
	}
}

func TestIncompleteSubmissionIdentityReceiptStaysUnknown(t *testing.T) {
	for _, body := range []string{
		`{"code":"internal_error","message":"failed","admitted_ids":["` + fixtureID + `"`,
		`{"code":"internal_error","message":"failed","admitted_ids":["` + fixtureID + `"],"padding":"` + strings.Repeat("x", maxSuccessBody) + `"}`,
	} {
		f := newFakeServer(t, "")
		f.handle("PUT /payment/intent", intentHandler(fixtureTx, ""))
		f.handle("PUT /debuglet", jsonHandler(http.StatusInternalServerError, body))
		_, err := f.client(t, Options{}).SubmitTEST(testContext(t), sampleBatch(t))
		se, he := asSubmissionError(t, err), asHTTPError(t, err)
		if len(se.AdmittedIDs) != 0 || !se.OutcomeUnknown || se.TransactionID != fixtureTx || he.Message != unsafeErrorMessage || he.StatusCode != 500 || len(f.requests()) != 2 {
			t.Fatalf("incomplete receipt was trusted: %+v HTTP=%+v", se, he)
		}
	}
}
