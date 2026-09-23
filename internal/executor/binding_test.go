package executor

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/netsec-ethz/debuglet/internal/controlsession"
	executordb "github.com/netsec-ethz/debuglet/internal/executor/database"
	"github.com/netsec-ethz/debuglet/internal/executor/scheduler"
	pb "github.com/netsec-ethz/debuglet/protocol"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	_ "modernc.org/sqlite"
)

type uploadBindingScheduler struct {
	*abortTestScheduler
	inserted []scheduler.Spec
}

func (s *uploadBindingScheduler) Insert(_ context.Context, spec scheduler.Spec) error {
	s.inserted = append(s.inserted, spec)
	return nil
}

func TestUploadAndAbortValidateRunBinding(t *testing.T) {
	var cancelCalls atomic.Int32
	storage := &uploadBindingScheduler{abortTestScheduler: &abortTestScheduler{cancel: func(context.Context, uuid.UUID, error) (bool, error) {
		cancelCalls.Add(1)
		return false, scheduler.ErrBindingMismatch
	}}}
	e, _ := newExecutorRPCFixture(t, newOperationPeer(), storage)
	ctx, cancel := context.WithTimeout(context.Background(), operationTestBound)
	defer cancel()
	request := &pb.UploadRequest{Id: "716c23c5-2bc9-43f9-9425-860ba03f4c3c", ControlBinding: operationWireBinding(), Wasm: []byte("tracked accepted bytes"), TransactionId: "local-binding-fixture",
		Policy: &pb.DebugletPolicy{FloorBw: 64000, CeilBw: 1000000, TimeoutMs: 30000}}
	if _, err := e.OnUpload(ctx, operationBinding(), request); err != nil {
		t.Fatal(err)
	}
	if len(storage.inserted) != 1 || storage.inserted[0].Binding != operationBinding() || storage.inserted[0].DebugletID.String() != request.Id {
		t.Fatal("Upload did not persist its admitted immutable binding")
	}
	for _, tc := range []struct {
		name string
		edit func(*pb.UploadRequest)
		code codes.Code
	}{
		{"missing_binding", func(r *pb.UploadRequest) { r.ControlBinding = nil }, codes.InvalidArgument},
		{"malformed_binding", func(r *pb.UploadRequest) { r.ControlBinding.SessionId = "invalid" }, codes.InvalidArgument},
		{"foreign_binding", func(r *pb.UploadRequest) { r.ControlBinding.SessionId = uuid.NewString() }, codes.PermissionDenied},
		{"nil_id", func(r *pb.UploadRequest) { r.Id = uuid.Nil.String() }, codes.InvalidArgument},
		{"uppercase_id", func(r *pb.UploadRequest) { r.Id = strings.ToUpper(r.Id) }, codes.InvalidArgument},
		{"compact_id", func(r *pb.UploadRequest) { r.Id = strings.ReplaceAll(r.Id, "-", "") }, codes.InvalidArgument},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := proto.Clone(request).(*pb.UploadRequest)
			tc.edit(req)
			if _, err := e.OnUpload(ctx, operationBinding(), req); status.Code(err) != tc.code {
				t.Fatalf("Upload code=%v want%v", status.Code(err), tc.code)
			}
			if len(storage.inserted) != 1 {
				t.Fatal("rejected Upload reached persistence")
			}
		})
	}
	for _, id := range []string{uuid.Nil.String(), strings.ToUpper(request.Id), strings.ReplaceAll(request.Id, "-", "")} {
		if _, err := e.OnAbort(ctx, operationBinding(), &pb.AbortRequest{DebugletId: id}); status.Code(err) != codes.InvalidArgument {
			t.Fatalf("malformed Abort code=%v", status.Code(err))
		}
	}
	if cancelCalls.Load() != 0 {
		t.Fatal("malformed Abort reached cancellation")
	}
	if _, err := e.OnAbort(ctx, operationBinding(), &pb.AbortRequest{DebugletId: request.Id}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("foreign persisted owner code=%v", status.Code(err))
	}
	if cancelCalls.Load() != 1 {
		t.Fatalf("canonical Abort calls=%d", cancelCalls.Load())
	}
}

type schedulingBindingContextKey struct{}

// The private readiness gate models the armed/pre-ack interval while this test
// exercises real SQLite plus the actual Upload/Start/Abort/report path. It is
// not handshake evidence: the transport tests own real Bind negotiation.
func TestUploadBindingPersistsWhileSchedulingWaitsForReady(t *testing.T) {
	db := newFixtureDatabase(t)
	storage := newFixtureStorage(t, db, func(b controlsession.Binding) bool { return b == operationBinding() })
	peer := newOperationPeer()
	var allocations, runtimes atomic.Int32
	peer.allocate = func(context.Context, *pb.DebugletAllocateRequest) (*pb.DebugletAllocateResponse, error) {
		allocations.Add(1)
		return &pb.DebugletAllocateResponse{}, nil
	}
	e, client := newExecutorRPCFixture(t, peer, storage)
	e.newRuntime = func(scheduler.Spec) runtimeDebuglet { runtimes.Add(1); return &operationRuntime{} }
	original := e.clientFor
	entered, canceled, ready := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var enteredOnce, canceledOnce, readyOnce sync.Once
	open := func() { readyOnce.Do(func() { close(ready) }) }
	e.clientFor = func(ctx context.Context, binding controlsession.Binding) (pb.DispatcherServiceClient, error) {
		if binding != operationBinding() {
			return nil, errors.New("run retargeted its captured binding")
		}
		if ctx.Value(schedulingBindingContextKey{}) != nil {
			enteredOnce.Do(func() { close(entered) })
			select {
			case <-ctx.Done():
				canceledOnce.Do(func() { close(canceled) })
				return nil, context.Cause(ctx)
			case <-ready:
			}
		}
		return original(ctx, binding)
	}
	loopCtx, stopLoop := context.WithCancel(context.WithValue(context.Background(), schedulingBindingContextKey{}, true))
	loopDone := make(chan struct{})
	var loopErr error
	loopStarted := false
	abortCtx, cancelAbort := context.WithTimeout(context.Background(), 5*time.Second)
	abortDone := make(chan struct{})
	abortStarted := false
	var abortErr error
	t.Cleanup(func() {
		open()
		cancelAbort()
		stopLoop()
		if abortStarted {
			operationAwait(t, abortDone, "bound Abort caller")
		}
		if loopStarted {
			operationAwait(t, loopDone, "owned readiness scheduler loop")
		}
		ctx, end := context.WithTimeout(context.Background(), scheduler.CleanupTimeout)
		defer end()
		if err := storage.Shutdown(ctx); err != nil {
			t.Errorf("bound scheduling cleanup: %v", err)
		}
	})
	ctx, end := context.WithTimeout(context.Background(), 5*time.Second)
	defer end()
	id := uuid.New()
	if _, err := client.Upload(ctx, &pb.UploadRequest{Id: id.String(), ControlBinding: operationWireBinding(), Wasm: []byte("\x00asm\x01\x00\x00\x00"), Policy: &pb.DebugletPolicy{FloorBw: 64000, CeilBw: 1000000, TimeoutMs: 30000}}); err != nil {
		t.Fatal(err)
	}
	row, err := executordb.New(db).GetDebugletByUUID(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if row.DispatcherIncarnation != operationBinding().Incarnation || row.SessionID != operationBinding().SessionID {
		t.Fatal("persisted Upload lost its admitted binding")
	}
	loopStarted = true
	go func() { loopErr = storage.StartLoop(loopCtx); close(loopDone) }()
	if !operationAwait(t, entered, "owned pre-ack readiness wait") {
		return
	}
	if allocations.Load() != 0 || runtimes.Load() != 0 {
		t.Fatal("execution crossed readiness before confirmation")
	}
	abortStarted = true
	go func() {
		_, abortErr = client.Abort(abortCtx, &pb.AbortRequest{DebugletId: id.String()})
		close(abortDone)
	}()
	if !operationAwait(t, canceled, "readiness wait cancellation") {
		return
	}
	// Final reporting is a bounded, separately owned wait; expose readiness only
	// after proving the execution wait observed Abort's cancellation.
	open()
	if !operationAwait(t, abortDone, "Abort after owned readiness wait joined") {
		return
	}
	if abortErr != nil {
		t.Fatal(abortErr)
	}
	if allocations.Load() != 0 || runtimes.Load() != 0 || peer.reportCalls.Load() != 1 {
		t.Fatalf("pre-ack canceled flow allocate=%d runtime=%d reports=%d", allocations.Load(), runtimes.Load(), peer.reportCalls.Load())
	}
	if _, err := executordb.New(db).GetDebugletByUUID(ctx, id); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("accepted cancellation failed canonical finalization: %v", err)
	}
	stopLoop()
	if !operationAwait(t, loopDone, "scheduler return") {
		return
	}
	if !errors.Is(loopErr, context.Canceled) {
		t.Fatalf("loop result=%v", loopErr)
	}
}
