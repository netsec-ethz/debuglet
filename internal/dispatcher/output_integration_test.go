// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package dispatcher

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	"github.com/netsec-ethz/debuglet/internal/dispatcher/database"
	executordb "github.com/netsec-ethz/debuglet/internal/executor/database"
	"github.com/netsec-ethz/debuglet/internal/executor/outputstore"
	"github.com/netsec-ethz/debuglet/internal/sqlitedb"
	pb "github.com/netsec-ethz/debuglet/protocol"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// TestOutputSpoolReconcilesWithEnrolledDispatcher joins the actual dispatcher
// store and enrolled TLS stream to an independently reopened executor spool.
// It leaves a committed receipt unprocessed locally; it is not a process-kill
// test and does not replace the executor delivery-loop tests.
func TestOutputSpoolReconcilesWithEnrolledDispatcher(t *testing.T) {
	f := newOutputTLS(t)
	client, owner := f.connect(f.identity, true)
	original := owner.Binding()
	writer, err := outputWriterFor(owner, &pb.ControlBinding{DispatcherIncarnation: original.Incarnation, SessionId: original.SessionID})
	if err != nil {
		t.Fatal(err)
	}
	id := outputTestRun(t, f.d, writer, nil)
	path := filepath.Join(t.TempDir(), "spool.sqlite")
	db, err := sqlitedb.Open(path, sqlitedb.Create())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if _, err := sqlitedb.Migrate(t.Context(), db, executordb.MigrationFS(), sqlitedb.Latest); err != nil {
		t.Fatal(err)
	}
	spool, err := outputstore.New(db, outputstore.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	if err := spool.Admit(t.Context(), id, original, pb.OutputVersion); err != nil {
		t.Fatal(err)
	}
	for _, body := range []string{"one", "two"} {
		if _, err := spool.Append(t.Context(), id, time.Now().UTC(), []byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	frames, err := spool.Frames(t.Context(), id, 0, 64)
	if err != nil || len(frames) != 2 {
		t.Fatalf("spool: %+v %v", frames, err)
	}
	stream := outputClientStream(t, f.ctx, client, id, original)
	if receipt, err := stream.Recv(); err != nil || receipt.CommittedSequence != 0 {
		t.Fatalf("identity receipt: %v %v", receipt, err)
	}
	sendFrame := func(frame outputstore.Frame) {
		t.Helper()
		if err := stream.Send(&pb.DebugletStreamRequest{Msg: &pb.DebugletStreamRequest_Output{Output: &pb.DebugletOutput{
			Sequence: frame.Sequence, Timestamp: timestamppb.New(frame.Timestamp), Output: frame.Output,
		}}}); err != nil {
			t.Fatal(err)
		}
	}
	sendFrame(frames[0])
	// Observe the real receiver transaction, without receiving or processing ACK.
	phase, done := context.WithTimeout(f.ctx, 5*time.Second)
	defer done()
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	q := database.New(f.d.db)
	for {
		row, err := q.GetDebugletOutput(phase, id)
		if err != nil {
			t.Fatal(err)
		}
		if row.CommittedSequence == 1 {
			break
		}
		select {
		case <-phase.Done():
			t.Fatal("dispatcher prefix did not commit", phase.Err())
		case <-tick.C:
		}
	}
	client.Close()
	retained, err := spool.Get(t.Context(), id)
	if err != nil || retained.AcknowledgedSequence != 0 || retained.QueuedFrames != 2 {
		t.Fatalf("unprocessed receipt deleted spool: %+v %v", retained, err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	db, err = sqlitedb.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	spool, err = outputstore.New(db, outputstore.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	if err := spool.InterruptOpen(t.Context()); err != nil {
		t.Fatal(err)
	}
	retained, err = spool.Get(t.Context(), id)
	if err != nil || retained.Binding != original || retained.End == nil || retained.End.Reason != pb.OutputReasonExecutorInterrupted {
		t.Fatalf("reopened identity/end: %+v %v", retained, err)
	}
	client, replacement := f.connect(f.identity, false)
	if replacement.Binding() == original {
		t.Fatal("reconnect reused original binding")
	}
	stream = outputClientStream(t, f.ctx, client, id, original)
	receipt, err := stream.Recv()
	if err != nil || receipt.CommittedSequence != 1 || receipt.End != nil {
		t.Fatalf("reconciled receipt: %v %v", receipt, err)
	}
	// A retransmitted original frame is idempotent across the new binding.
	sendFrame(frames[0])
	receipt, err = stream.Recv()
	if err != nil || receipt.CommittedSequence != 1 || receipt.End != nil {
		t.Fatalf("duplicate receipt: %v %v", receipt, err)
	}
	if err := spool.Acknowledge(t.Context(), id, receipt.CommittedSequence, nil); err != nil {
		t.Fatal(err)
	}
	// Revoking the authenticated identity stops even an already-open stream.
	if _, err := f.store.Revoke(f.ctx, writer.executorID); err != nil {
		t.Fatal(err)
	}
	sendFrame(frames[1])
	if _, err := stream.Recv(); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("revoked append: %v", err)
	}
	retained, err = spool.Get(t.Context(), id)
	if err != nil || retained.AcknowledgedSequence != 1 || retained.QueuedFrames != 1 {
		t.Fatalf("revocation discarded local suffix: %+v %v", retained, err)
	}
	client.Close()
	client, replacement = f.connect(f.identity, true)
	if replacement.Binding() == original {
		t.Fatal("reenrollment reused original binding")
	}
	stream = outputClientStream(t, f.ctx, client, id, original)
	receipt, err = stream.Recv()
	if err != nil || receipt.CommittedSequence != 1 || receipt.End != nil {
		t.Fatalf("reenrolled receipt: %v %v", receipt, err)
	}
	frames, err = spool.Frames(t.Context(), id, receipt.CommittedSequence, 64)
	if err != nil || len(frames) != 1 || frames[0].Sequence != 2 || string(frames[0].Output) != "two" {
		t.Fatalf("missing suffix: %+v %v", frames, err)
	}
	sendFrame(frames[0])
	receipt, err = stream.Recv()
	if err != nil || receipt.CommittedSequence != 2 || receipt.End != nil {
		t.Fatalf("suffix receipt: %v %v", receipt, err)
	}
	if err := spool.Acknowledge(t.Context(), id, receipt.CommittedSequence, nil); err != nil {
		t.Fatal(err)
	}
	if err := stream.Send(&pb.DebugletStreamRequest{Msg: &pb.DebugletStreamRequest_End{End: retained.End}}); err != nil {
		t.Fatal(err)
	}
	receipt, err = stream.Recv()
	if err != nil || !proto.Equal(receipt.End, retained.End) {
		t.Fatalf("final receipt: %v %v", receipt, err)
	}
	if err := spool.Acknowledge(t.Context(), id, receipt.CommittedSequence, receipt.End); err != nil {
		t.Fatal(err)
	}
	after, err := spool.Get(t.Context(), id)
	if err != nil || !after.EndAcknowledged || after.QueuedFrames != 0 || after.QueuedBytes != 0 {
		t.Fatalf("final spool: %+v %v", after, err)
	}
	row, err := q.GetDebugletOutput(t.Context(), id)
	if err != nil || row.CommittedSequence != 2 || row.FrameCount != 2 || row.ByteCount != 6 || row.Status != "truncated" || row.Reason != pb.OutputReasonExecutorInterrupted || !row.FinalCursor.Valid {
		t.Fatalf("receiver finality: %+v %v", row, err)
	}
	for i, want := range []string{"one", "two"} {
		stored, err := q.GetSequencedDebugletLog(t.Context(), database.GetSequencedDebugletLogParams{DebugletID: row.DebugletID, SourceSequence: sql.NullInt64{Int64: int64(i + 1), Valid: true}})
		if err != nil || string(stored.Output) != want {
			t.Fatalf("stored sequence%d: %q %v", i+1, stored.Output, err)
		}
	}
	usage, err := q.GetOutputNodeUsage(t.Context())
	if err != nil || usage.ChargedBytes != pb.OutputRunCharge+2*pb.OutputFrameCharge+6 {
		t.Fatalf("duplicate quota: %+v %v", usage, err)
	}
}
