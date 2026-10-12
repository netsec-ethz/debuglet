// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package dispatcher

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/netsec-ethz/debuglet/internal/daemonlog"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/models"
	pb "github.com/netsec-ethz/debuglet/protocol"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// One run finishes, one receives a remote deadline, and a third is cancelled by
// that failure. Normal logs must distinguish the initiating failure from the
// cancelled sibling without changing uncertain admission or replay behavior.
func TestUploadFailureLogsBeforeSiblingCancellation(t *testing.T) {
	core, logs := observer.New(zap.InfoLevel)
	peer := &fbPeer{tgPeer: &tgPeer{}, answer: map[string]error{}}
	f := newFBFixture(t, peer, func(d *Dispatcher) { d.logger = zap.New(core) })
	requestID := uuid.New()
	ctx := daemonlog.WithRequestID(f.ctx, requestID)
	specs := f.batch(t, tgFloorA, tgFloorA, tgFloorA)
	for i := range specs {
		specs[i].Args = []string{fmt.Sprintf("participant-%d", i)}
	}
	finished, siblingEntered := make(chan string, 1), make(chan struct{})
	peer.scriptUpload(func(ctx context.Context, req *pb.UploadRequest) error {
		if req.GetArgs()[0] == specs[0].Args[0] {
			finished <- req.GetId()
			return nil
		}
		peer.refuse(req.GetId(), status.Error(codes.NotFound, "absent"))
		if req.GetArgs()[0] == specs[2].Args[0] {
			close(siblingEntered)
			<-ctx.Done()
			return status.FromContextError(ctx.Err()).Err()
		}
		var first string
		select {
		case first = <-finished:
		case <-ctx.Done():
			return status.FromContextError(ctx.Err()).Err()
		}
		select {
		case <-siblingEntered:
		case <-ctx.Done():
			return status.FromContextError(ctx.Err()).Err()
		}
		if err := fbWaitState(ctx, f.db, first, models.RunStateUploaded); err != nil {
			return err
		}
		if err := f.exit(t, uuid.MustParse(first), 0, nil); err != nil {
			return err
		}
		return status.Error(codes.DeadlineExceeded, "private-upload-secret\nremote storage text")
	})
	ids, err := f.d.SubmitDebuglets(ctx, specs, nil)
	if !errors.Is(err, ErrAdmissionCommitted) || len(ids) != 3 {
		t.Fatalf("submission = %v, %v; want three committed runs and upload failure", ids, err)
	}
	tgAssertRow(t, f.row(t, ids[0]), models.RunStateExited, tgNull)
	for _, id := range ids[1:] {
		row := f.row(t, id)
		tgAssertRow(t, row, models.RunStateUnreconciled, tgNull)
		tgAssertReserved(t, f, tgDebuglet{id: id, row: row}, 2*tgFloorA)
	}
	failures := logs.FilterMessage("Run upload failed").All()
	byID := map[string]observer.LoggedEntry{}
	for _, failure := range failures {
		byID[failure.ContextMap()["run_id"].(string)] = failure
	}
	if len(failures) != 2 {
		t.Fatalf("got %d failure events, want remote failure and cancelled sibling", len(failures))
	}
	for index, want := range map[int]string{1: "DeadlineExceeded", 2: "Canceled"} {
		entry, ok := byID[ids[index].String()]
		if !ok {
			t.Fatalf("missing diagnostic for run %s", ids[index])
		}
		fields := entry.ContextMap()
		if entry.Level != zap.WarnLevel || fields["upload_stage"] != "executor_upload" || fields["grpc_code"] != want || fields["request_id"] != requestID.String() || fields["request_context_code"] != "OK" {
			t.Fatalf("failure %d = %v", index, fields)
		}
		wantContext := "OK"
		if index == 2 {
			wantContext = "Canceled"
		}
		if fields["context_code"] != wantContext || fields["executor_id"] != tgExecutorID || fields["session_id"] != f.row(t, ids[index]).SessionID || fields["elapsed_ms"].(int64) < 0 {
			t.Fatalf("failure context %d = %v", index, fields)
		}
	}
	for _, entry := range logs.All() {
		if strings.Contains(fmt.Sprint(entry.ContextMap()), "private-upload-secret") || strings.Contains(fmt.Sprint(entry.ContextMap()), "remote storage text") {
			t.Fatal("normal logs copied remote error text")
		}
	}
	before := f.snapshot(t)
	repeated, err := f.d.SubmitDebuglets(ctx, specs, nil)
	if err != nil || fmt.Sprint(repeated) != fmt.Sprint(ids) || len(peer.recordedUploads()) != 3 {
		t.Fatalf("repeat replayed or lost the admitted receipt: %v %v, uploads=%d", repeated, err, len(peer.recordedUploads()))
	}
	tgAssertSnapshot(t, f, before, "repeated partial submission")
}

func TestUploadFailureLogsLocalBoundary(t *testing.T) {
	for _, stage := range []string{"session_lookup", "record_uploaded"} {
		t.Run(stage, func(t *testing.T) {
			var peer *tgPeer
			if stage == "record_uploaded" {
				peer = &tgPeer{}
			}
			f := newTGFixture(t, peer)
			core, logs := observer.New(zap.InfoLevel)
			f.d.logger = zap.New(core)
			if stage == "record_uploaded" {
				_, err := f.db.Exec(fmt.Sprintf(`CREATE TRIGGER fail_uploaded BEFORE UPDATE OF state ON debuglets WHEN NEW.state = %d BEGIN SELECT RAISE(ABORT, 'private-database-secret'); END`, models.RunStateUploaded))
				if err != nil {
					t.Fatal(err)
				}
			}
			ids, err := f.d.SubmitDebuglets(f.ctx, []models.DebugletSpec{f.spec(t, tgFloorA)}, nil)
			if !errors.Is(err, ErrAdmissionCommitted) || len(ids) != 1 {
				t.Fatalf("submission = %v, %v", ids, err)
			}
			entries := logs.FilterMessage("Run upload failed").All()
			if len(entries) != 1 || entries[0].ContextMap()["upload_stage"] != stage || entries[0].ContextMap()["run_id"] != ids[0].String() || entries[0].ContextMap()["context_code"] != "OK" {
				t.Fatalf("upload boundary not identified: %v", entries)
			}
			if strings.Contains(fmt.Sprint(entries[0].ContextMap()), "private-database-secret") {
				t.Fatal("normal log copied SQL error text")
			}
		})
	}
}
