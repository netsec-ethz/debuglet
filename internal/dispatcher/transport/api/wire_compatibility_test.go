// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package api

import (
	"encoding/json"
	"net/http"
	"reflect"
	"testing"

	"github.com/netsec-ethz/debuglet/internal/dispatcher/models"
	"github.com/netsec-ethz/debuglet/pkg/client"
)

func TestSharedWireEncodingPreservesOptionalAndBinaryFields(t *testing.T) {
	policy := `"policy":{"floor_bw":0,"ceil_bw":0,"timeout_ms":0,"addresses":null,"require_icmp":false,"listen_udp":false,"listen_tcp":false,"listen_scion":false}`
	version := `"version":"","api_version":"","api_versions":null,"binary_version":"","protocol_version":""`
	for _, tc := range []struct {
		name  string
		value any
		want  string
	}{
		{"server empty wasm", DebugletRequest{}, `{"order_id":0,"executor_id":"","wasm":"",` + policy + `}`},
		{"client nil wasm", client.Request{}, `{"order_id":0,"executor_id":"","wasm":null,` + policy + `}`},
		{"client empty wasm", client.Request{Wasm: []byte{}}, `{"order_id":0,"executor_id":"","wasm":"",` + policy + `}`},
		{"client binary wasm", client.Request{Wasm: []byte{0, 255, 10}}, `{"order_id":0,"executor_id":"","wasm":"AP8K",` + policy + `}`},
		{"server logs", DebugletLogsResponse{}, `{"state":"","after":0,"logs":null,"has_more":false,"output":{"state":"","final_cursor":null,"loss_reason":""}}`},
		{"client logs", client.LogPage{}, `{"state":"","error":"","after":0,"logs":null,"has_more":false,"output":{"state":"","final_cursor":null,"loss_reason":""}}`},
		{"server failed logs", DebugletLogsResponse{Error: "failed", Logs: []DebugletLogEntry{{Output: "AP8K"}}}, `{"state":"","error":"failed","after":0,"logs":[{"id":0,"timestamp":"","output":"AP8K"}],"has_more":false,"output":{"state":"","final_cursor":null,"loss_reason":""}}`},
		{"client binary logs", client.LogEntry{Output: []byte{0, 255, 10}}, `{"id":0,"timestamp":"","output":"AP8K"}`},
		{"server version", VersionResponse{}, `{` + version + `}`},
		{"client version", client.ServerVersion{}, `{` + version + `,"binary_revision":""}`},
		{"server revision", VersionResponse{BinaryRevision: "abc"}, `{` + version + `,"binary_revision":"abc"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data, err := json.Marshal(tc.value)
			if err != nil {
				t.Fatal(err)
			}
			var got, want any
			if err := json.Unmarshal(data, &got); err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal([]byte(tc.want), &want); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("JSON = %s, want %s", data, tc.want)
			}
		})
	}
}

func TestSharedRequestKeepsInvalidWasmAtSubmissionValidation(t *testing.T) {
	f := modeNewFixture(t)
	f.registerExecutor()
	debuglets := modeDebuglets()
	debuglets[0].Wasm = "!!!"
	f.mock.ExpectQuery(modeGetTransactionQuery).
		WithArgs(modeChainTxID).
		WillReturnRows(modeTransactionRows(modeChainTxID, "", "TEST", "", modeRequestHash(t, debuglets), models.Paid))

	rec := f.do(http.MethodPut, "/debuglet", modeSubmitBody(modeChainTxID, "", debuglets))
	assertEnvelope(t, "invalid wasm submission", rec, http.StatusBadRequest,
		CodeInvalidRequest, "invalid request (i=0): invalid wasm code")
	f.expectationsMet("invalid wasm submission")
	if n := f.recentDebugletIDs(); n != 0 {
		t.Fatalf("executor dispatch history has %d entries, want 0", n)
	}
}
