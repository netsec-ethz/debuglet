// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package dispatcher

import (
	"context"
	"database/sql"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/netsec-ethz/debuglet/internal/controlsession"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/config"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/database"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/models"
	pb "github.com/netsec-ethz/debuglet/protocol"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func outputTestWriter() outputWriter {
	binding := controlsession.Binding{Incarnation: uuid.NewString(), SessionID: uuid.NewString()}
	return outputWriter{executorID: "output-executor", binding: binding, original: binding, fingerprint: "admitted-certificate", version: pb.OutputVersion}
}

func outputTestRun(t *testing.T, d *Dispatcher, writer outputWriter, user *uuid.UUID) uuid.UUID {
	t.Helper()
	q := database.New(d.db)
	if writer.fingerprint != "" {
		if err := q.SetExecutorEnrollment(t.Context(), database.SetExecutorEnrollmentParams{ExecutorID: writer.executorID, Fingerprint: writer.fingerprint, EnrolledAt: models.NewUTCTime(time.Now())}); err != nil {
			t.Fatal(err)
		}
	}
	tx, err := d.db.BeginTx(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	q = q.WithTx(tx)
	id := uuid.New()
	_, err = q.CreateDebuglet(t.Context(), database.CreateDebugletParams{Uuid: id, ExecutorID: writer.executorID,
		StartTime: models.NewUTCTime(time.Now()), EndTime: models.NewUTCTime(time.Now().Add(time.Hour)),
		State: models.RunStateStarted, DispatcherIncarnation: writer.original.Incarnation, SessionID: writer.original.SessionID})
	if err != nil {
		t.Fatal(err)
	}
	if user != nil {
		if err := q.InsertDebugletUser(t.Context(), database.InsertDebugletUserParams{DebUuid: id, UserUuid: *user}); err != nil {
			t.Fatal(err)
		}
	}
	if err := d.createOutputMetadata(t.Context(), q, id, writer.version, writer.fingerprint); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	return id
}

func outputFrame(sequence int64, body string) *pb.DebugletOutput {
	return &pb.DebugletOutput{Sequence: sequence, Output: []byte(body), Timestamp: timestamppb.New(time.Unix(123, 456))}
}

func requireOutputReceipt(t *testing.T, d *Dispatcher, writer outputWriter, id uuid.UUID, frame *pb.DebugletOutput, end *pb.DebugletOutputEnd) *pb.DebugletStreamResponse {
	t.Helper()
	receipt, err := d.storeOutput(t.Context(), writer, id, frame, end)
	if err != nil {
		t.Fatal(err)
	}
	return receipt
}

func TestDurableOutputSequenceAndFinality(t *testing.T) {
	d := newTerminalPeerDispatcher(t)
	writer := outputTestWriter()
	id := outputTestRun(t, d, writer, nil)
	if got := requireOutputReceipt(t, d, writer, id, nil, nil); got.CommittedSequence != 0 || got.End != nil {
		t.Fatalf("initial receipt: %v", got)
	}
	if _, err := d.storeOutput(t.Context(), writer, id, outputFrame(2, "gap"), nil); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("gap: %v", err)
	}
	first := requireOutputReceipt(t, d, writer, id, outputFrame(1, "one"), nil)
	if first.CommittedSequence != 1 || first.End != nil {
		t.Fatalf("first receipt: %v", first)
	}
	if replay := requireOutputReceipt(t, d, writer, id, outputFrame(1, "one"), nil); !proto.Equal(first, replay) {
		t.Fatalf("replay: %v", replay)
	}
	for _, frame := range []*pb.DebugletOutput{outputFrame(1, "other"), {Sequence: 1, Output: []byte("one"), Timestamp: timestamppb.New(time.Unix(124, 0))}} {
		if _, err := d.storeOutput(t.Context(), writer, id, frame, nil); status.Code(err) != codes.InvalidArgument {
			t.Fatalf("conflicting duplicate: %v", err)
		}
	}
	// Terminal state can precede the final chunk. It cannot finalize output.
	if _, err := d.db.ExecContext(t.Context(), "UPDATE debuglets SET state = ? WHERE uuid = ?", models.RunStateExited, id); err != nil {
		t.Fatal(err)
	}
	requireOutputReceipt(t, d, writer, id, outputFrame(2, "two"), nil)
	end := &pb.DebugletOutputEnd{LastSequence: 2, Status: pb.DebugletOutputStatus_DEBUGLET_OUTPUT_STATUS_COMPLETE}
	if _, err := d.storeOutput(t.Context(), writer, id, nil, &pb.DebugletOutputEnd{LastSequence: 1, Status: end.Status}); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("early end: %v", err)
	}
	final := requireOutputReceipt(t, d, writer, id, nil, end)
	if final.CommittedSequence != 2 || !proto.Equal(final.End, end) {
		t.Fatalf("final receipt: %v", final)
	}
	if replay := requireOutputReceipt(t, d, writer, id, nil, end); !proto.Equal(final, replay) {
		t.Fatalf("final replay: %v", replay)
	}
	if replay := requireOutputReceipt(t, d, writer, id, nil, nil); !proto.Equal(final, replay) {
		t.Fatalf("resumed receipt: %v", replay)
	}
	if _, err := d.storeOutput(t.Context(), writer, id, outputFrame(3, "late"), nil); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("data after finality: %v", err)
	}
	badEnd := &pb.DebugletOutputEnd{LastSequence: 2, Status: pb.DebugletOutputStatus_DEBUGLET_OUTPUT_STATUS_TRUNCATED, Reason: pb.OutputReasonProducerFailed}
	if _, err := d.storeOutput(t.Context(), writer, id, nil, badEnd); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("conflicting end: %v", err)
	}
	q := database.New(d.db)
	row, err := q.GetDebugletOutput(t.Context(), id)
	if err != nil {
		t.Fatal(err)
	}
	usage, err := q.GetOutputNodeUsage(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if row.FrameCount != 2 || row.ByteCount != 6 || !row.FinalCursor.Valid || row.FinalCursor.Int64 != row.LastLogID || usage.ChargedBytes != pb.OutputRunCharge+6+2*pb.OutputFrameCharge {
		t.Fatalf("duplicate charge or incorrect final cursor: row=%+v usage=%+v", row, usage)
	}
}

func TestDurableOutputConcurrentDuplicate(t *testing.T) {
	d := newTerminalPeerDispatcher(t)
	writer := outputTestWriter()
	id := outputTestRun(t, d, writer, nil)
	var wg sync.WaitGroup
	errs := make(chan error, 12)
	for range 12 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			receipt, err := d.storeOutput(context.Background(), writer, id, outputFrame(1, "same"), nil)
			if err == nil && receipt.CommittedSequence != 1 {
				err = errors.New("wrong receipt")
			}
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	row, err := database.New(d.db).GetDebugletOutput(t.Context(), id)
	if err != nil {
		t.Fatal(err)
	}
	if row.FrameCount != 1 || row.ByteCount != 4 {
		t.Fatalf("duplicate storage: %+v", row)
	}
}

func TestDurableOutputResumeAuthority(t *testing.T) {
	d := newTerminalPeerDispatcher(t)
	writer := outputTestWriter()
	id := outputTestRun(t, d, writer, nil)
	requireOutputReceipt(t, d, writer, id, outputFrame(1, "before"), nil)
	resumed := writer
	resumed.binding = controlsession.Binding{Incarnation: uuid.NewString(), SessionID: uuid.NewString()}
	if got := requireOutputReceipt(t, d, resumed, id, nil, nil); got.CommittedSequence != 1 {
		t.Fatal(got)
	}
	requireOutputReceipt(t, d, resumed, id, outputFrame(2, "after"), nil)
	for name, change := range map[string]func(*outputWriter){
		"executor":         func(w *outputWriter) { w.executorID = "another" },
		"original binding": func(w *outputWriter) { w.original.SessionID = uuid.NewString() },
		"certificate":      func(w *outputWriter) { w.fingerprint = "another" },
		"unverified":       func(w *outputWriter) { w.fingerprint = "" },
		"downgrade":        func(w *outputWriter) { w.version = 0 },
	} {
		t.Run(name, func(t *testing.T) {
			invalid := resumed
			change(&invalid)
			if _, err := d.storeOutput(t.Context(), invalid, id, nil, nil); status.Code(err) != codes.PermissionDenied {
				t.Fatalf("authority accepted: %v", err)
			}
		})
	}
	q := database.New(d.db)
	if err := q.SetExecutorEnrollment(t.Context(), database.SetExecutorEnrollmentParams{ExecutorID: writer.executorID, Fingerprint: "rotated", EnrolledAt: models.NewUTCTime(time.Now())}); err != nil {
		t.Fatal(err)
	}
	if _, err := d.storeOutput(t.Context(), resumed, id, outputFrame(3, "rotated"), nil); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("rotated credential: %v", err)
	}
	if _, err := q.DeleteExecutorEnrollment(t.Context(), writer.executorID); err != nil {
		t.Fatal(err)
	}
	if _, err := d.storeOutput(t.Context(), writer, id, nil, nil); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("revoked original session: %v", err)
	}
}

func TestDurableOutputQuotasFinalizeAcceptedPrefix(t *testing.T) {
	for _, kind := range []string{"run bytes", "run frames", "account", "node"} {
		t.Run(kind, func(t *testing.T) {
			d := newTerminalPeerDispatcher(t)
			limits := config.DefaultOutputConfig()
			reason := pb.OutputReasonLimit
			switch kind {
			case "run bytes":
				limits.RunBytes = 1
			case "run frames":
				limits.RunFrames = 1
			case "account":
				limits.AccountBytes = pb.OutputRunCharge + pb.OutputFrameCharge + 1
				reason = pb.OutputReasonStorageLimit
			case "node":
				limits.NodeBytes = pb.OutputRunCharge + pb.OutputFrameCharge + 1
				reason = pb.OutputReasonStorageLimit
			}
			if err := d.ConfigureOutputLimits(limits); err != nil {
				t.Fatal(err)
			}
			writer := outputTestWriter()
			id := outputTestRun(t, d, writer, nil)
			requireOutputReceipt(t, d, writer, id, outputFrame(1, "a"), nil)
			receipt := requireOutputReceipt(t, d, writer, id, outputFrame(2, "b"), nil)
			if receipt.CommittedSequence != 1 || receipt.End == nil || receipt.End.LastSequence != 1 || receipt.End.Status != pb.DebugletOutputStatus_DEBUGLET_OUTPUT_STATUS_TRUNCATED || receipt.End.Reason != reason {
				t.Fatalf("quota receipt: %v", receipt)
			}
			if got := requireOutputReceipt(t, d, writer, id, nil, nil); !proto.Equal(got, receipt) {
				t.Fatalf("quota resume: %v", got)
			}
			usage, err := database.New(d.db).GetOutputNodeUsage(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			if usage.ChargedBytes != pb.OutputRunCharge+pb.OutputFrameCharge+1 || usage.FrameCount != 1 {
				t.Fatalf("rejected suffix charged: %+v", usage)
			}
		})
	}
}

func TestDurableOutputEmptyAndUnverified(t *testing.T) {
	d := newTerminalPeerDispatcher(t)
	writer := outputTestWriter()
	writer.fingerprint = ""
	id := outputTestRun(t, d, writer, nil)
	end := &pb.DebugletOutputEnd{LastSequence: 0, Status: pb.DebugletOutputStatus_DEBUGLET_OUTPUT_STATUS_COMPLETE}
	got := requireOutputReceipt(t, d, writer, id, nil, end)
	if !proto.Equal(got.End, end) {
		t.Fatal(got)
	}
	row, err := database.New(d.db).GetDebugletOutput(t.Context(), id)
	if err != nil {
		t.Fatal(err)
	}
	if !row.FinalCursor.Valid || row.FinalCursor.Int64 != 0 {
		t.Fatalf("empty cursor: %+v", row.FinalCursor)
	}
	writer.binding.SessionID = uuid.NewString()
	if _, err := d.storeOutput(t.Context(), writer, id, nil, nil); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("unverified cross-session resume: %v", err)
	}
}

func TestDurableOutputFailedCommitHasNoReceipt(t *testing.T) {
	d := newTerminalPeerDispatcher(t)
	writer := outputTestWriter()
	id := outputTestRun(t, d, writer, nil)
	if _, err := d.db.ExecContext(t.Context(), `CREATE TABLE output_parent (id INTEGER PRIMARY KEY);
		CREATE TABLE output_deferred (parent_id INTEGER REFERENCES output_parent(id) DEFERRABLE INITIALLY DEFERRED);
		CREATE TRIGGER reject_output AFTER INSERT ON debuglet_logs BEGIN INSERT INTO output_deferred VALUES (1); END`); err != nil {
		t.Fatal(err)
	}
	if receipt, err := d.storeOutput(t.Context(), writer, id, outputFrame(1, "lost"), nil); err == nil || receipt != nil {
		t.Fatalf("failed write returned receipt: %v %v", receipt, err)
	}
	q := database.New(d.db)
	row, err := q.GetDebugletOutput(t.Context(), id)
	if err != nil {
		t.Fatal(err)
	}
	usage, err := q.GetOutputNodeUsage(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if row.CommittedSequence != 0 || usage.ChargedBytes != pb.OutputRunCharge {
		t.Fatalf("failed write changed progress: %+v %+v", row, usage)
	}
	if _, err := q.GetSequencedDebugletLog(t.Context(), database.GetSequencedDebugletLogParams{DebugletID: row.DebugletID, SourceSequence: sql.NullInt64{Int64: 1, Valid: true}}); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("uncommitted output exists: %v", err)
	}
	if _, err := d.db.ExecContext(t.Context(), "DROP TRIGGER reject_output"); err != nil {
		t.Fatal(err)
	}
	requireOutputReceipt(t, d, writer, id, outputFrame(1, "lost"), nil)
}

func TestDurableOutputEmptyFramesAndOversizedInput(t *testing.T) {
	d := newTerminalPeerDispatcher(t)
	limits := config.DefaultOutputConfig()
	limits.RunFrames = 2
	if err := d.ConfigureOutputLimits(limits); err != nil {
		t.Fatal(err)
	}
	writer := outputTestWriter()
	id := outputTestRun(t, d, writer, nil)
	for _, frame := range []*pb.DebugletOutput{{Sequence: 1, Timestamp: timestamppb.Now(), Output: make([]byte, pb.MaxOutputFrameBytes+1)}, {Sequence: 1}, outputFrame(0, "bad")} {
		if _, err := d.storeOutput(t.Context(), writer, id, frame, nil); status.Code(err) != codes.InvalidArgument {
			t.Fatalf("invalid frame: %v", err)
		}
	}
	for seq := int64(1); seq <= 2; seq++ {
		requireOutputReceipt(t, d, writer, id, &pb.DebugletOutput{Sequence: seq, Timestamp: timestamppb.Now()}, nil)
	}
	receipt := requireOutputReceipt(t, d, writer, id, outputFrame(3, ""), nil)
	if receipt.End == nil || receipt.End.Reason != pb.OutputReasonLimit || receipt.CommittedSequence != 2 {
		t.Fatalf("empty frames evaded quota: %v", receipt)
	}
	usage, err := database.New(d.db).GetOutputNodeUsage(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if usage.ChargedBytes != pb.OutputRunCharge+2*pb.OutputFrameCharge {
		t.Fatalf("empty frame charge: %+v", usage)
	}
}

// Retained history counts against the default shared-deployment limits.
// Only an explicit local configuration can disable aggregate accounting caps.
func TestDurableOutputDefaultLimitsCountRetainedHistory(t *testing.T) {
	d := newTerminalPeerDispatcher(t)
	outputTestRun(t, d, outputTestWriter(), nil)
	if _, err := d.db.ExecContext(t.Context(), "UPDATE output_node_usage SET charged_bytes = ?", int64(1)<<40); err != nil {
		t.Fatal(err)
	}
	if full, err := d.outputStorageFull(t.Context(), database.New(d.db), 0, pb.OutputRunCharge); err != nil || !full {
		t.Fatalf("default cap ignored history: %v %v", full, err)
	}
	d.outputLimits.AccountBytes = 0
	d.outputLimits.NodeBytes = 0
	if full, err := d.outputStorageFull(t.Context(), database.New(d.db), 0, pb.OutputRunCharge); err != nil || full {
		t.Fatalf("explicit local cap disablement: %v %v", full, err)
	}
}

func TestDurableOutputAdmissionChargeRollsBack(t *testing.T) {
	d := newTerminalPeerDispatcher(t)
	writer := outputTestWriter()
	id := outputTestRun(t, d, writer, nil)
	limits := config.DefaultOutputConfig()
	limits.NodeBytes = pb.OutputRunCharge
	if err := d.ConfigureOutputLimits(limits); err != nil {
		t.Fatal(err)
	}
	// Remove just this metadata and recreate it in a transaction whose reserve
	// must fail. The failed attempt cannot change quota accounting.
	if _, err := d.db.ExecContext(t.Context(), "DELETE FROM debuglet_output WHERE debuglet_id = (SELECT id FROM debuglets WHERE uuid = ?)", id); err != nil {
		t.Fatal(err)
	}
	tx, err := d.db.BeginTx(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	q := database.New(d.db).WithTx(tx)
	if err := d.createOutputMetadata(t.Context(), q, id, writer.version, writer.fingerprint); !errors.Is(err, ErrOutputCapacity) {
		tx.Rollback()
		t.Fatalf("full admission: %v", err)
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	if _, err := database.New(d.db).GetDebugletOutput(t.Context(), id); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("failed admission metadata survived: %v", err)
	}
	usage, err := database.New(d.db).GetOutputNodeUsage(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if usage.ChargedBytes != pb.OutputRunCharge {
		t.Fatalf("failed admission charge: %+v", usage)
	}
}

func TestLegacyOutputRemainsUnsequenced(t *testing.T) {
	d := newTerminalPeerDispatcher(t)
	writer := outputTestWriter()
	writer.version, writer.fingerprint = 0, ""
	id := outputTestRun(t, d, writer, nil)
	receipt := requireOutputReceipt(t, d, writer, id, outputFrame(0, "legacy"), nil)
	if receipt.CommittedSequence != 0 || receipt.End != nil {
		t.Fatalf("invented legacy finality: %v", receipt)
	}
	var sequence sql.NullInt64
	if err := d.db.QueryRowContext(t.Context(), "SELECT source_sequence FROM debuglet_logs WHERE debuglet_id = (SELECT id FROM debuglets WHERE uuid = ?)", id).Scan(&sequence); err != nil {
		t.Fatal(err)
	}
	if sequence.Valid {
		t.Fatal("invented legacy sequence")
	}
	writer.binding.SessionID = uuid.NewString()
	if _, err := d.storeOutput(t.Context(), writer, id, nil, nil); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("legacy cross-session resume: %v", err)
	}
}

func TestDurableOutputAccountQuotaUsesStoredOwnership(t *testing.T) {
	d := newTerminalPeerDispatcher(t)
	limits := config.DefaultOutputConfig()
	limits.AccountBytes = 2*pb.OutputRunCharge + pb.OutputFrameCharge + 1
	if err := d.ConfigureOutputLimits(limits); err != nil {
		t.Fatal(err)
	}
	q := database.New(d.db)
	alice, err := q.CreateUser(t.Context(), database.CreateUserParams{Uuid: uuid.New(), Name: "alice"})
	if err != nil {
		t.Fatal(err)
	}
	bob, err := q.CreateUser(t.Context(), database.CreateUserParams{Uuid: uuid.New(), Name: "bob"})
	if err != nil {
		t.Fatal(err)
	}
	writer := outputTestWriter()
	first := outputTestRun(t, d, writer, &alice.Uuid)
	second := outputTestRun(t, d, writer, &alice.Uuid)
	sibling := outputTestRun(t, d, writer, &bob.Uuid)
	requireOutputReceipt(t, d, writer, first, outputFrame(1, "a"), nil)
	refused := requireOutputReceipt(t, d, writer, second, outputFrame(1, "b"), nil)
	if refused.End == nil || refused.End.LastSequence != 0 || refused.End.Reason != pb.OutputReasonStorageLimit {
		t.Fatalf("account cap bypass: %v", refused)
	}
	progress := requireOutputReceipt(t, d, writer, sibling, outputFrame(1, "c"), nil)
	if progress.CommittedSequence != 1 || progress.End != nil {
		t.Fatalf("another account blocked: %v", progress)
	}
	aliceUsage, err := q.GetOutputAccountUsage(t.Context(), alice.ID)
	if err != nil {
		t.Fatal(err)
	}
	bobUsage, err := q.GetOutputAccountUsage(t.Context(), bob.ID)
	if err != nil {
		t.Fatal(err)
	}
	if aliceUsage.ChargedBytes != limits.AccountBytes || bobUsage.ChargedBytes != pb.OutputRunCharge+pb.OutputFrameCharge+1 {
		t.Fatalf("wrong account charges: %+v %+v", aliceUsage, bobUsage)
	}
}

// A session end finalizes output that no later session could continue, and
// leaves enrolled output resumable. Committed prefixes stay as stored.
func TestSessionEndInterruptsOnlyUnresumableOutput(t *testing.T) {
	d := newTerminalPeerDispatcher(t)
	ctx := t.Context()
	unenrolled := outputTestWriter()
	unenrolled.fingerprint = ""
	enrolled := outputTestWriter()
	enrolled.binding, enrolled.original = unenrolled.binding, unenrolled.original
	other := outputTestWriter()
	other.fingerprint = ""
	stranded := outputTestRun(t, d, unenrolled, nil)
	resumable := outputTestRun(t, d, enrolled, nil)
	elsewhere := outputTestRun(t, d, other, nil)
	if _, err := d.storeOutput(ctx, unenrolled, stranded, &pb.DebugletOutput{Sequence: 1, Timestamp: timestamppb.Now(), Output: []byte("kept")}, nil); err != nil {
		t.Fatal(err)
	}

	d.interruptUnresumableOutput(unenrolled.binding)
	d.interruptUnresumableOutput(unenrolled.binding)

	q := database.New(d.db)
	row, err := q.GetDebugletOutput(ctx, stranded)
	if err != nil || !row.FinalSequence.Valid || row.FinalSequence.Int64 != 1 || row.Status != "truncated" || row.Reason != pb.OutputReasonExecutorInterrupted {
		t.Fatalf("unenrolled output after session end=%+v err=%v", row, err)
	}
	for name, id := range map[string]uuid.UUID{"enrolled": resumable, "other session": elsewhere} {
		if row, err := q.GetDebugletOutput(ctx, id); err != nil || row.FinalSequence.Valid {
			t.Fatalf("%s output finalized: %+v err=%v", name, row, err)
		}
	}
}
