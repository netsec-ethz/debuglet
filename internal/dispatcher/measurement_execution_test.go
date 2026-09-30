// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package dispatcher

import (
	"encoding/json"
	"testing"

	"github.com/netsec-ethz/debuglet/internal/dispatcher/database"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/models"
	"github.com/netsec-ethz/debuglet/pkg/wire"
	pb "github.com/netsec-ethz/debuglet/protocol"
)

func TestMeasurementExecutionReceiptsAreAtomicAndFirstWins(t *testing.T) {
	f := newTGFixture(t, nil)
	run := f.seedDirect(t, tgFloorA)
	if _, err := f.db.Exec("CREATE TRIGGER reject_observation BEFORE INSERT ON measurement_execution BEGIN SELECT RAISE(ABORT,'fixture'); END"); err != nil {
		t.Fatal(err)
	}
	if err := f.state(t, run.id, pb.RunState_RUN_STATE_STARTED); err == nil {
		t.Fatal("state accepted without observation")
	}
	if f.row(t, run.id).State != models.RunStateUploaded {
		t.Fatal("state survived observation rollback")
	}
	if _, err := f.db.Exec("DROP TRIGGER reject_observation"); err != nil {
		t.Fatal(err)
	}
	if err := f.state(t, run.id, pb.RunState_RUN_STATE_STARTED); err != nil {
		t.Fatal(err)
	}
	first, err := f.q.GetMeasurementExecution(f.ctx, run.row.ID)
	if err != nil || !first.StartedObservedNs.Valid || first.TerminalObservedNs.Valid {
		t.Fatalf("first receipt: %+v %v", first, err)
	}
	if err := f.state(t, run.id, pb.RunState_RUN_STATE_STARTED); err != nil {
		t.Fatal(err)
	}
	if err := f.exit(t, run.id, 7, nil); err != nil {
		t.Fatal(err)
	}
	if err := f.exit(t, run.id, 0, nil); err != nil {
		t.Fatal(err)
	}
	if err := f.state(t, run.id, pb.RunState_RUN_STATE_STARTED); err != nil {
		t.Fatal(err)
	}
	last, err := f.q.GetMeasurementExecution(f.ctx, run.row.ID)
	if err != nil || last.StartedObservedNs != first.StartedObservedNs || !last.TerminalObservedNs.Valid || !last.ExitCode.Valid || last.ExitCode.Int64 != 7 {
		t.Fatalf("immutable receipts: %+v %v", last, err)
	}
}

func TestMeasurementEndpointMustMatchAdmission(t *testing.T) {
	f := newTGFixture(t, nil)
	run := f.seedDirect(t, tgFloorA)
	host := "127.0.0.1"
	provenance := wire.ResultProvenance{AdmittedPolicy: wire.Policy{ListenTCP: true}, VantagePoint: &wire.VantagePoint{PublicHost: wire.LabelledString{Value: &host}}}
	data, _ := json.Marshal(provenance)
	if err := f.q.CreateDebugletProvenance(f.ctx, database.CreateDebugletProvenanceParams{DebugletID: run.row.ID, Document: string(data)}); err != nil {
		t.Fatal(err)
	}
	report := func(address string) error {
		mutation := effectTestMutation(t, f.d, tgExecutorID)
		defer mutation.Finish()
		_, err := f.d.OnDebugletState(f.ctx, mutation, &pb.DebugletStateRequest{DebugletId: run.id.String(), ExecutorId: tgExecutorID, State: pb.RunState_RUN_STATE_STARTED, TcpListener: &pb.ListenerEndpoint{Address: address}})
		return err
	}
	for _, address := range []string{"127.0.0.2:9000", "127.0.0.1:0", "127.0.0.1:not-a-port"} {
		if report(address) == nil {
			t.Fatalf("accepted %s", address)
		}
	}
	if f.row(t, run.id).State != models.RunStateUploaded {
		t.Fatal("invalid endpoint advanced state")
	}
	if err := report("127.0.0.1:9000"); err != nil {
		t.Fatal(err)
	}
	if err := report("127.0.0.1:9001"); err != nil {
		t.Fatal(err)
	}
	observed, err := f.q.GetMeasurementExecution(f.ctx, run.row.ID)
	if err != nil || observed.TcpEndpoint != "127.0.0.1:9000" {
		t.Fatalf("endpoint: %+v %v", observed, err)
	}
}
