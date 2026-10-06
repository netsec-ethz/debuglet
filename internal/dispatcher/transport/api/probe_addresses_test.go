// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/netsec-ethz/debuglet/pkg/wire"
	pb "github.com/netsec-ethz/debuglet/protocol"
)

// A public executor's observed address is in the public listing, as a RIPE
// Atlas probe's is; a private one's is withheld from everyone but operators,
// and nothing else about it is.
func TestPrivateExecutorWithholdsOnlyAddresses(t *testing.T) {
	f := ccNewFixtureWith(t)
	account, token, c := authAccount(t, f, "probe-viewer")
	private := apiTestOwner(t, f.d, "private-probe")
	if err := apiTestRegister(f.ctx, f.d, private, &pb.HelloResponse{ExecutorId: "private-probe", Currency: "TEST",
		VantagePoint: &pb.VantagePointReport{SchemaVersion: 1, AddressOptOut: true}}, "192.0.2.77"); err != nil {
		t.Fatal(err)
	}
	private.MarkRegistered()
	list := func() map[string]wire.Executor {
		t.Helper()
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/executors", nil).WithContext(f.ctx)
		req.Header.Set("Authorization", "Bearer "+token)
		f.root.Config.Handler.ServeHTTP(rec, req)
		oaCheckResponse(t, oaContract(t), http.MethodGet, "/executors", rec.Code, rec.Body.Bytes())
		var nodes []wire.Executor
		if err := json.Unmarshal(rec.Body.Bytes(), &nodes); err != nil {
			t.Fatal(err)
		}
		out := map[string]wire.Executor{}
		for _, n := range nodes {
			out[n.ID] = n
		}
		if !strings.Contains(rec.Body.String(), `"is_public":false`) {
			t.Fatalf("listing lacks is_public: %s", rec.Body.String())
		}
		return out
	}
	nodes := list()
	if n := nodes[ccExecutorID]; n.IsPublic == nil || !*n.IsPublic || n.AddressV4 == nil || *n.AddressV4 != "127.0.0.1" {
		t.Fatalf("public executor's observed address not listed: %+v", n.ProbeAddressing)
	}
	n := nodes["private-probe"]
	if n.IsPublic == nil || *n.IsPublic || n.AddressV4 != nil || n.AddressV6 != nil {
		t.Fatalf("private executor's address listed: %+v", n.ProbeAddressing)
	}
	if n.AddressObservations == nil || n.AddressObservations.V4 == nil || n.AddressObservations.V4.Via != wire.AddressViaControl || n.IPMetadata == nil {
		t.Fatalf("private executor lost its public facts: %+v", n)
	}
	if selected, err := c.Nodes(f.ctx); err != nil || len(selected) != 2 {
		t.Fatalf("SDK listing: %+v %v", selected, err)
	}
	authGrantOperator(t, f, account.ID)
	if n := list()["private-probe"]; n.AddressV4 == nil || *n.AddressV4 != "192.0.2.77" {
		t.Fatalf("operator does not see the private address: %+v", n.ProbeAddressing)
	}
}
