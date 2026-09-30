// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package api

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/netsec-ethz/debuglet/internal/dispatcher"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/config"
	"github.com/netsec-ethz/debuglet/internal/uploadsize"
	"go.uber.org/zap"
)

func TestRawBatchLimitsAndRequestQuotaLeaveControlUsable(t *testing.T) {
	f := ccNewFixtureConfigured(t, zap.NewNop(), &cpPeer{id: ccExecutorID, price: ccPricePerBwS, currency: "TEST"}, func(d *dispatcher.Dispatcher) error {
		limits := config.DefaultAdmissionConfig()
		limits.Account.RequestsPerMinute = 4
		return d.ConfigureDataLimits(limits, config.RetentionConfig{})
	})
	contract := oaContract(t)
	_, token, owner := authAccount(t, f, "bounded owner")
	_, otherToken, _ := authAccount(t, f, "separate owner")
	sub := f.submit(owner, nil) // intent and submission consume two tokens.
	for _, target := range []string{"/payment/intent", "/debuglet"} {
		body := map[string]any{"debuglets": make([]DebugletRequest, uploadsize.MaxBatchRuns+1)}
		if target == "/payment/intent" {
			body["payment_method"] = "TEST"
		} else {
			body["transaction_id"] = "unknown"
			body["auth_key"] = "unknown"
		}
		data, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		status, code, responseBody, _ := authRequest(t, f, http.MethodPut, target, data, authBearer(token))
		oaCheckResponse(t, contract, http.MethodPut, target, status, responseBody)
		if status != http.StatusRequestEntityTooLarge || code != CodePayloadTooLarge {
			t.Fatalf("%s: %d %s", target, status, code)
		}
	}
	status, code, body, response := authRequest(t, f, http.MethodPut, "/payment/intent", []byte(`{"debuglets":[],"payment_method":"TEST"}`), authBearer(token))
	oaCheckResponse(t, contract, http.MethodPut, "/payment/intent", status, body)
	if status != http.StatusTooManyRequests || code != CodeAccountQuota || response.Header.Get("Retry-After") == "" {
		t.Fatalf("request quota: %d %s", status, code)
	}
	if status, _ := authAs(t, f, otherToken, http.MethodPut, "/payment/intent", []byte(`{"debuglets":[],"payment_method":"TEST"}`)); status == http.StatusTooManyRequests {
		t.Fatal("another account exhausted")
	}
	if status, _ := authAs(t, f, token, http.MethodGet, "/debuglet/"+sub.IDs[0]+"/state", nil); status != http.StatusOK {
		t.Fatalf("state at quota: %d", status)
	}
	cancelBody, _ := json.Marshal(map[string]any{"debuglet_id": sub.IDs[0], "executor_id": ccExecutorID})
	if status, _ := authAs(t, f, token, http.MethodDelete, "/debuglet", cancelBody); status != http.StatusNoContent {
		t.Fatalf("cancellation at admission quota: %d", status)
	}
}

func TestEncodedModuleBoundsBeforeDecodedAllocation(t *testing.T) {
	// Module lengths are inspected without allocating decoded input. The HTTP
	// envelope itself is independently covered by raw known/chunked body tests.
	for _, n := range []int{uploadsize.MaxModuleBytes, uploadsize.MaxModuleBytes + 1} {
		encoded := strings.Repeat("A", (n+2)/3*4)
		if n%3 == 1 {
			encoded = encoded[:len(encoded)-2] + "=="
		} else if n%3 == 2 {
			encoded = encoded[:len(encoded)-1] + "="
		}
		err := validateUploadBatch([]DebugletRequest{{Wasm: encoded}})
		if (err != nil) != (n > uploadsize.MaxModuleBytes) {
			t.Fatalf("decoded bytes%d: %v", n, err)
		}
	}
	if err := validateUploadBatch(make([]DebugletRequest, uploadsize.MaxBatchRuns)); err != nil {
		t.Fatal(err)
	}
}
