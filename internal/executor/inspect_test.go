package executor

import (
	"context"
	"database/sql"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/netsec-ethz/debuglet/internal/controlsession"
	"github.com/netsec-ethz/debuglet/internal/executor/database"
	"github.com/netsec-ethz/debuglet/internal/executor/scheduler"
	pb "github.com/netsec-ethz/debuglet/protocol"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func inspectStoredRun(t *testing.T, db *sql.DB, id uuid.UUID, binding controlsession.Binding, started bool, transaction string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), terminalTestBound)
	defer cancel()
	queries := database.New(db)
	if err := queries.CreateDebuglet(ctx, database.CreateDebugletParams{
		Uuid: id, DispatcherIncarnation: binding.Incarnation, SessionID: binding.SessionID,
		StartTime: database.NewUTCTime(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)), Args: []string{"argument"},
		Wasm: []byte("\x00asm\x01\x00\x00\x00 stored guest program"), TransactionID: transaction,
		FloorBw: 64000, CeilBw: 128000, TimeoutMs: 1000, Addresses: []string{"127.0.0.1"},
	}); err != nil {
		t.Fatal(err)
	}
	if started {
		if _, err := queries.UpdateDebugletStarted(ctx, database.UpdateDebugletStartedParams{
			Uuid: id, StartedAt: database.NewUTCTime(time.Now()),
		}); err != nil {
			t.Fatal(err)
		}
	}
}

func inspectRequest(id string) *pb.InspectRetainedRunRequest {
	return &pb.InspectRetainedRunRequest{DebugletId: id, ControlBinding: operationWireBinding()}
}

// Inspection describes retained rows and refuses to invent an answer: the
// current session's own rows are filtered, unknown identities are absent, and
// nothing it reads is scheduled, started, finalized or deleted.
func TestInspectRetainedRunOverControlProtocol(t *testing.T) {
	storage, db := newTerminalStorage(t)
	peer := newOperationPeer()
	e, client := newExecutorRPCFixture(t, peer, storage)
	var runtimes atomic.Int32
	e.newRuntime = func(scheduler.Spec) runtimeDebuglet { runtimes.Add(1); return &operationRuntime{} }

	current, old := operationBinding(), controlsession.Binding{
		Incarnation: operationBinding().Incarnation, SessionID: "0f3b31ce-2d0b-4d5f-9df3-5a2d9b1c6a11"}
	live, unstarted, started, legacy, missing := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	inspectStoredRun(t, db, live, current, false, "live")
	inspectStoredRun(t, db, unstarted, old, false, "old-unstarted")
	inspectStoredRun(t, db, started, old, true, "old-started")
	inspectStoredRun(t, db, legacy, controlsession.Binding{}, true, "legacy")

	ctx, cancel := context.WithTimeout(context.Background(), terminalTestBound)
	defer cancel()
	for _, tc := range []struct {
		name    string
		id      uuid.UUID
		status  pb.RetainedRunStatus
		binding controlsession.Binding
		started bool
	}{
		{"current_binding_is_filtered", live, pb.RetainedRunStatus_RETAINED_RUN_STATUS_FILTERED, controlsession.Binding{}, false},
		{"old_binding_unstarted", unstarted, pb.RetainedRunStatus_RETAINED_RUN_STATUS_FOUND, old, false},
		{"old_binding_started", started, pb.RetainedRunStatus_RETAINED_RUN_STATUS_FOUND, old, true},
		{"legacy_row", legacy, pb.RetainedRunStatus_RETAINED_RUN_STATUS_FOUND, controlsession.Binding{}, true},
		{"unknown_identity_is_absent", missing, pb.RetainedRunStatus_RETAINED_RUN_STATUS_ABSENT, controlsession.Binding{}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := client.InspectRetainedRun(ctx, inspectRequest(tc.id.String()))
			if err != nil {
				t.Fatal(err)
			}
			if resp.GetStatus() != tc.status {
				t.Fatalf("status=%v want=%v", resp.GetStatus(), tc.status)
			}
			if tc.status != pb.RetainedRunStatus_RETAINED_RUN_STATUS_FOUND {
				if resp.GetRun() != nil {
					t.Fatal("a miss carried metadata")
				}
				return
			}
			run := resp.GetRun()
			if run.GetDebugletId() != tc.id.String() || run.GetStarted() != tc.started {
				t.Fatalf("metadata mismatch: %+v", run)
			}
			if tc.started != (run.GetStartedAt() != nil) {
				t.Fatalf("start marker disagrees with its timestamp: %+v", run)
			}
			if run.GetStartTime() == nil {
				t.Fatal("stored due time was dropped")
			}
			if tc.binding.Valid() {
				if run.GetOriginalBinding().GetDispatcherIncarnation() != tc.binding.Incarnation ||
					run.GetOriginalBinding().GetSessionId() != tc.binding.SessionID {
					t.Fatalf("original ownership was rewritten: %+v", run.GetOriginalBinding())
				}
			} else if run.GetOriginalBinding() != nil {
				t.Fatalf("row without ownership reported one: %+v", run.GetOriginalBinding())
			}
		})
	}

	rows, err := database.New(db).ListDebuglets(ctx, database.ListDebugletsParams{Limit: 16})
	if err != nil || len(rows) != 4 {
		t.Fatalf("inspection changed stored rows: %d error=%v", len(rows), err)
	}
	for _, row := range rows {
		if len(row.Wasm) == 0 {
			t.Fatal("inspection disturbed a stored guest program")
		}
	}
	if peer.reportCalls.Load() != 0 || runtimes.Load() != 0 {
		t.Fatal("inspection scheduled work or reported a terminal result")
	}
	if _, found, err := storage.RetainedTerminal(ctx, started); err != nil || found {
		t.Fatalf("inspection retained a terminal event: found=%v error=%v", found, err)
	}
}

// Malformed input and a backend without inspection are errors, never a
// successful answer that the requested work never existed.
func TestInspectRetainedRunRejectsMalformedAndUnsupported(t *testing.T) {
	storage, _ := newTerminalStorage(t)
	_, client := newExecutorRPCFixture(t, newOperationPeer(), storage)
	ctx, cancel := context.WithTimeout(context.Background(), terminalTestBound)
	defer cancel()

	for _, tc := range []struct {
		name string
		req  *pb.InspectRetainedRunRequest
		code codes.Code
	}{
		{"empty_identity", inspectRequest(""), codes.InvalidArgument},
		{"nil_identity", inspectRequest(uuid.Nil.String()), codes.InvalidArgument},
		{"uppercase_identity", inspectRequest(strings.ToUpper(uuid.New().String())), codes.InvalidArgument},
		{"urn_identity", inspectRequest("urn:uuid:" + uuid.New().String()), codes.InvalidArgument},
		{"missing_binding", &pb.InspectRetainedRunRequest{DebugletId: uuid.New().String()}, codes.InvalidArgument},
		{"another_session", &pb.InspectRetainedRunRequest{DebugletId: uuid.New().String(),
			ControlBinding: &pb.ControlBinding{DispatcherIncarnation: operationBinding().Incarnation,
				SessionId: "0f3b31ce-2d0b-4d5f-9df3-5a2d9b1c6a11"}}, codes.PermissionDenied},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := client.InspectRetainedRun(ctx, tc.req)
			if status.Code(err) != tc.code {
				t.Fatalf("status=%v want=%v response=%+v", status.Code(err), tc.code, resp)
			}
			if resp.GetStatus() == pb.RetainedRunStatus_RETAINED_RUN_STATUS_ABSENT {
				t.Fatal("a rejected request answered that no such row exists")
			}
		})
	}

	// A scheduler that cannot inspect answers UNIMPLEMENTED, not a miss.
	_, volatile := newExecutorRPCFixture(t, newOperationPeer(), newFixtureMemoryStorage(t))
	resp, err := volatile.InspectRetainedRun(ctx, inspectRequest(uuid.New().String()))
	if status.Code(err) != codes.Unimplemented {
		t.Fatalf("scheduler without inspection answered %v: %+v", status.Code(err), resp)
	}
	if resp.GetStatus() == pb.RetainedRunStatus_RETAINED_RUN_STATUS_ABSENT {
		t.Fatal("an unsupported backend answered that no such row exists")
	}
}

// A stored row too large to describe fails with a bounded diagnostic instead
// of an oversized or truncated answer.
func TestInspectRetainedRunRejectsOversizedRow(t *testing.T) {
	storage, db := newTerminalStorage(t)
	_, client := newExecutorRPCFixture(t, newOperationPeer(), storage)
	ctx, cancel := context.WithTimeout(context.Background(), terminalTestBound)
	defer cancel()

	old := controlsession.Binding{
		Incarnation: operationBinding().Incarnation, SessionID: "0f3b31ce-2d0b-4d5f-9df3-5a2d9b1c6a11"}
	oversized, ordinary := uuid.New(), uuid.New()
	inspectStoredRun(t, db, oversized, old, false, strings.Repeat("t", maxInspectedTransactionID+1))
	inspectStoredRun(t, db, ordinary, old, false, strings.Repeat("t", maxInspectedTransactionID))

	resp, err := client.InspectRetainedRun(ctx, inspectRequest(oversized.String()))
	if status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("oversized row answered %v: %+v", status.Code(err), resp)
	}
	if resp.GetStatus() == pb.RetainedRunStatus_RETAINED_RUN_STATUS_ABSENT {
		t.Fatal("an oversized row answered that no such row exists")
	}
	if message := status.Convert(err).Message(); len(message) > 256 {
		t.Fatalf("oversized row produced an unbounded diagnostic: %d bytes", len(message))
	}
	// The bound is exact: one byte less is still described.
	resp, err = client.InspectRetainedRun(ctx, inspectRequest(ordinary.String()))
	if err != nil || resp.GetStatus() != pb.RetainedRunStatus_RETAINED_RUN_STATUS_FOUND {
		t.Fatalf("row at the bound was refused: %+v error=%v", resp, err)
	}
	if len(resp.GetRun().GetTransactionId()) != maxInspectedTransactionID {
		t.Fatal("described transaction identifier was truncated")
	}
	rows, err := database.New(db).ListDebuglets(ctx, database.ListDebugletsParams{Limit: 8})
	if err != nil || len(rows) != 2 {
		t.Fatalf("a refused inspection changed stored rows: %d error=%v", len(rows), err)
	}
}
