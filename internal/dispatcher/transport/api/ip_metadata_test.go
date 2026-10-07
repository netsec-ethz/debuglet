// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/netsec-ethz/debuglet/internal/dispatcher"
	"github.com/netsec-ethz/debuglet/internal/ipmetadata"
	"github.com/netsec-ethz/debuglet/pkg/client"
	"github.com/netsec-ethz/debuglet/pkg/wire"
	pb "github.com/netsec-ethz/debuglet/protocol"
	"go.uber.org/zap"
)

func TestIPMetadataHTTPContractAndSDK(t *testing.T) {
	databases, err := ipmetadata.Open("../../../ipmetadata/testdata/asn.mmdb", "../../../ipmetadata/testdata/city.mmdb")
	if err != nil {
		t.Fatal(err)
	}
	defer databases.Close()
	f := ccNewFixtureConfigured(t, zap.NewNop(), &cpPeer{id: ccExecutorID, price: ccPricePerBwS, currency: "TEST"}, func(d *dispatcher.Dispatcher) error { return d.ConfigureIPMetadata(databases) }, LocalDevelopment(true))
	id := "metadata-fixture"
	owner := apiTestOwner(t, f.d, id)
	host := "8.8.4.4"
	hello := &pb.HelloResponse{ExecutorId: id, PublicHost: &host, VantagePoint: &pb.VantagePointReport{SchemaVersion: 1}}
	if err := apiTestRegister(f.ctx, f.d, owner, hello, "8.8.8.8"); err != nil {
		t.Fatal(err)
	}
	owner.MarkRegistered()
	mutation := apiTestMutation(t, f.ctx, owner)
	_, err = f.d.OnHeartbeat(f.ctx, mutation, &pb.HeartbeatRequest{ExecutorId: id})
	mutation.Finish()
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	f.root.Config.Handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/executors", nil).WithContext(f.ctx))
	oaCheckResponse(t, oaContract(t), http.MethodGet, "/executors", rec.Code, rec.Body.Bytes())
	var nodes []wire.Executor
	if err := json.Unmarshal(rec.Body.Bytes(), &nodes); err != nil {
		t.Fatal(err)
	}
	// The observed control address is listed as address_v4 (here to the local
	// operator; see TestPrivateExecutorWithholdsOnlyAddresses for the public
	// view). The advertised public_host is a claim and is never listed.
	if strings.Contains(rec.Body.String(), "8.8.4.4") || strings.Count(rec.Body.String(), "8.8.8.8") != 1 {
		t.Fatalf("public listing published a claimed address: %s", rec.Body.String())
	}
	for _, n := range nodes {
		if n.ID != id {
			continue
		}
		if n.AddressV4 == nil || *n.AddressV4 != "8.8.8.8" || n.ASNV4 == nil || *n.ASNV4 != 64500 || n.PrefixV4 == nil ||
			*n.PrefixV4 != n.IPMetadata.Observed.ASN.Value.Prefix || n.AddressObservations.V4.LookupSource == nil {
			t.Fatalf("addressing: %+v", n.ProbeAddressing)
		}
	}
	c := f.client(f.root.URL, false)
	selected, err := c.SelectExecutor(f.ctx, id, client.ExecutorFilter{ASN: 64500, Country: "CH"})
	if err != nil || selected.IPMetadata.Observed.ASN.Value.Name != "Synthetic network" || selected.Display.City.Source != nil {
		t.Fatalf("SDK metadata: %+v %v", selected, err)
	}
	city, country := selected.Location()
	if city.Value == nil || *city.Value != "Fixture city" || country.Value == nil || *country.Value != "CH" {
		t.Fatalf("client location fallback: %+v %+v", city, country)
	}
	// The real submission/export path also carries explicit unknown reasons for
	// its loopback peer, through the same portable-result validator.
	result, err := c.Export(f.ctx, f.submit(c, nil).IDs[0])
	if err != nil {
		t.Fatal(err)
	}
	if m := result.Provenance.VantagePoint.IPMetadata; m == nil || m.Observed.ASN.Reason != "non_global" || m.Advertised.Location.Reason != "no_address" {
		t.Fatalf("result metadata: %+v", m)
	}
}
