// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/netsec-ethz/debuglet/internal/dispatcher"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/config"
	"github.com/netsec-ethz/debuglet/pkg/client"
	"github.com/netsec-ethz/debuglet/pkg/wire"
	pb "github.com/netsec-ethz/debuglet/protocol"
	"go.uber.org/zap"
)

// Operator display metadata and the executor's ISD-AS and listener report
// reach GET /executors, the SDK filter and the admission snapshot, each with
// the source that asserted it.
func TestVantageMetadataCrossesControlHTTPAndSDK(t *testing.T) {
	peer := &cpPeer{id: ccExecutorID, price: ccPricePerBwS, currency: "TEST"}
	f := ccNewFixtureConfigured(t, zap.NewNop(), peer, func(d *dispatcher.Dispatcher) error {
		return d.ConfigureExecutorDisplay(map[string]config.ExecutorDisplay{
			ccExecutorID: {DisplayName: "ETH lab", City: "Zurich", Country: "CH"},
		})
	}, LocalDevelopment(true))
	c := f.client(f.root.URL, false)
	list := func() wire.Executor {
		t.Helper()
		rec := httptest.NewRecorder()
		f.root.Config.Handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/executors", nil).WithContext(f.ctx))
		oaCheckResponse(t, oaContract(t), http.MethodGet, "/executors", rec.Code, rec.Body.Bytes())
		var nodes []wire.Executor
		if err := json.Unmarshal(rec.Body.Bytes(), &nodes); err != nil || len(nodes) != 1 {
			t.Fatalf("executors: %s %v", rec.Body.String(), err)
		}
		return nodes[0]
	}
	node := list()
	if d := node.Display; *d.DisplayName.Value != "ETH lab" || *d.Country.Value != "CH" || *d.City.Source != wire.SourceOperator || d.Network != (wire.LabelledString{}) {
		t.Fatalf("display: %+v", d)
	}
	// Before its first heartbeat the executor is listed but offline.
	if node.SCIONISDAS != (wire.ObservedString{}) || node.Listeners.Value != nil || node.Admission != wire.AdmissionOffline {
		t.Fatalf("legacy peer invented vantage facts: %+v", node)
	}
	if _, err := f.peer.direct.Heartbeat(f.ctx, &pb.HeartbeatRequest{ExecutorId: ccExecutorID}); err != nil {
		t.Fatal(err)
	}
	if node := list(); node.Admission != wire.AdmissionReady || node.Listeners.Value != nil {
		t.Fatalf("after heartbeat: %+v", node)
	}
	filter := client.ExecutorFilter{ISDAS: "1-ff00:0:110"}
	if _, err := c.SelectExecutor(f.ctx, "", filter); err == nil {
		t.Fatal("unknown ISD-AS matched")
	}

	if _, err := f.peer.direct.Heartbeat(f.ctx, &pb.HeartbeatRequest{ExecutorId: ccExecutorID,
		VantagePoint: &pb.VantagePointReport{SchemaVersion: 1, ScionIsdAs: "1-ff00:0:0110", Listeners: []string{"udp", "scion"}}}); err != nil {
		t.Fatal(err)
	}
	node = list()
	if ia := node.SCIONISDAS; ia.Value == nil || *ia.Value != "1-ff00:0:110" || *ia.Source != wire.SourceExecutorReported || ia.ObservedAt == nil {
		t.Fatalf("isd-as: %+v", ia)
	}
	if l := node.Listeners; !reflect.DeepEqual(l.Value, []string{"udp", "scion"}) || *l.Source != wire.SourceExecutorReported {
		t.Fatalf("listeners: %+v", l)
	}
	if selected, err := c.SelectExecutor(f.ctx, "", filter); err != nil || selected.ID != ccExecutorID {
		t.Fatalf("isd-as selection: %+v %v", selected, err)
	}

	doc, err := c.Export(f.ctx, f.submit(c, nil).IDs[0])
	if err != nil {
		t.Fatal(err)
	}
	v := doc.Provenance.VantagePoint
	if ia := v.SCIONISDAS; ia.Value == nil || *ia.Value != "1-ff00:0:110" || *ia.Source != wire.SourceExecutorReported || ia.Stale == nil || *ia.Stale {
		t.Fatalf("admitted isd-as: %+v", ia)
	}
	if *v.Display.DisplayName.Value != "ETH lab" || *v.Display.DisplayName.Source != wire.SourceOperator {
		t.Fatalf("admitted display: %+v", v.Display)
	}

	// A malformed report clears the observation instead of keeping it, and
	// neither hides the executor nor clears the capabilities sent beside it.
	if _, err := f.peer.direct.Heartbeat(f.ctx, &pb.HeartbeatRequest{ExecutorId: ccExecutorID,
		Capabilities: &pb.ExecutorCapabilities{SchemaVersion: 1, Protocols: []string{"tcp"}},
		VantagePoint: &pb.VantagePointReport{SchemaVersion: 1, ScionIsdAs: "1-0"}}); err != nil {
		t.Fatal(err)
	}
	if node := list(); node.SCIONISDAS != (wire.ObservedString{}) || node.Listeners.Value != nil {
		t.Fatalf("malformed report kept: %+v", node)
	} else if !node.Ready || node.Admission != wire.AdmissionReady || node.Capabilities == nil || !reflect.DeepEqual(node.Capabilities.Protocols, []string{"tcp"}) {
		t.Fatalf("malformed vantage report affected the executor: %+v", node)
	}

	path := filepath.Join(t.TempDir(), "maintenance")
	if err := os.WriteFile(path, []byte(`{"schema_version":1,"paused":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(dispatcher.MaintenanceFileEnv, path)
	if node := list(); node.Admission != wire.AdmissionMaintenance {
		t.Fatalf("admission under maintenance: %q", node.Admission)
	}
}
