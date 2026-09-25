package executor

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/netsec-ethz/debuglet/internal/executor/scheduler"
	pb "github.com/netsec-ethz/debuglet/protocol"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type operationCall struct {
	cancel     context.CancelCauseFunc
	done       chan struct{}
	completion scheduler.Completion
}

func startOperationTest(t *testing.T, e *Executor, spec scheduler.Spec) *operationCall {
	t.Helper()
	ctx, cancel := context.WithCancelCause(context.Background())
	call := &operationCall{cancel: cancel, done: make(chan struct{})}
	go func() { call.completion = e.OnDebugletStart(ctx, spec); close(call.done) }()
	t.Cleanup(func() {
		cancel(context.Canceled)
		operationJoinCleanup(t, call.done, "owned executor callback cleanup")
	})
	return call
}

// The deterministic runtime owns the same limiter entry as a real Debuglet.
// Individual tests can hold Close without bypassing executor lifecycle code.
func installOperationRuntime(e *Executor, spec scheduler.Spec, runtime *operationRuntime) {
	closeRuntime := runtime.close
	runtime.close = func(ctx context.Context) error {
		var err error
		if closeRuntime != nil {
			err = closeRuntime(ctx)
		}
		e.limiter.RemoveDebuglet(spec.DebugletID)
		return err
	}
	e.newRuntime = func(scheduler.Spec) runtimeDebuglet { return runtime }
}

func TestOperationCancellationDuringAllocate(t *testing.T) {
	peer := newOperationPeer()
	allocateEntered, allocateJoined := make(chan struct{}), make(chan struct{})
	peer.allocate = func(ctx context.Context, _ *pb.DebugletAllocateRequest) (*pb.DebugletAllocateResponse, error) {
		close(allocateEntered)
		defer close(allocateJoined)
		<-ctx.Done()
		return nil, ctx.Err()
	}
	var reportContextOK atomic.Bool
	peer.exit = func(ctx context.Context, _ *pb.DebugletExitRequest) (*pb.DebugletExitResponse, error) {
		deadline, ok := ctx.Deadline()
		reportContextOK.Store(ctx.Err() == nil && ok && time.Until(deadline) > 0 && time.Until(deadline) <= scheduler.CleanupTimeout)
		return nil, status.Error(codes.Unavailable, "report transport fixture")
	}
	e, _ := newExecutorRPCFixture(t, peer, nil)
	var constructed atomic.Int32
	e.newRuntime = func(scheduler.Spec) runtimeDebuglet { constructed.Add(1); return &operationRuntime{} }
	spec := operationSpec()
	call := startOperationTest(t, e, spec)
	if !operationAwait(t, allocateEntered, "real Allocate RPC") {
		return
	}
	cause := errors.New("explicit cancellation cause")
	call.cancel(cause)
	if !operationAwait(t, call.done, "allocation cancellation") || !operationAwait(t, allocateJoined, "allocation handler") {
		return
	}
	if constructed.Load() != 0 || call.completion.CleanupErr != nil {
		t.Fatal("allocation cancellation launched a runtime or failed local cleanup")
	}
	report := operationRetriedReport(t, peer, spec.DebugletID)
	if report.ExitCode != -1 || report.GetErrorMessage() != cause.Error() || !reportContextOK.Load() {
		t.Fatalf("cancellation/report boundary lost: %+v context=%t", report, reportContextOK.Load())
	}
}

func TestOperationCompletionWaitsForClose(t *testing.T) {
	peer := newOperationPeer()
	e, _ := newExecutorRPCFixture(t, peer, nil)
	spec := operationSpec()
	entered, release := make(chan struct{}), make(chan struct{})
	closeErr := errors.New("held close result")
	runtime := &operationRuntime{close: func(ctx context.Context) error {
		if ctx.Err() != nil {
			return errors.New("resource close inherited execution cancellation")
		}
		close(entered)
		<-release
		return closeErr
	}}
	installOperationRuntime(e, spec, runtime)
	call := startOperationTest(t, e, spec)
	var once sync.Once
	t.Cleanup(func() { once.Do(func() { close(release) }) })
	if !operationAwait(t, entered, "owned close watcher") {
		return
	}
	if !e.mu.TryLock() {
		t.Fatal("executor mutex held across resource Close")
	}
	op := e.running[spec.DebugletID].operation
	e.mu.Unlock()
	select {
	case <-call.done:
		t.Fatal("callback completed before Close joined")
	default:
	}
	select {
	case <-op.resourceDone:
		t.Fatal("resource completion published before Close joined")
	default:
	}
	select {
	case <-peer.reports:
		t.Fatal("exit report preceded local resource completion")
	default:
	}
	once.Do(func() { close(release) })
	if !operationAwait(t, call.done, "close result and callback") {
		return
	}
	if !errors.Is(call.completion.CleanupErr, closeErr) || runtime.closes.Load() != 1 {
		t.Fatal("close error lost or Close repeated")
	}
	select {
	case <-op.resourceDone:
	default:
		t.Fatal("joined resource completion missing")
	}
	e.mu.Lock()
	remaining := len(e.running)
	e.mu.Unlock()
	if remaining != 0 {
		t.Fatal("completed executor diagnostic owner retained")
	}
	if report := operationReport(t, peer, spec.DebugletID); report.ExitCode != 0 || report.ErrorMessage != nil {
		t.Fatal("cleanup error replaced the guest outcome")
	}
}

func TestOperationStartedStateFailureJoinsOutput(t *testing.T) {
	peer := newOperationPeer()
	streamEntered := make(chan struct{})
	peer.state = func(ctx context.Context, req *pb.DebugletStateRequest) (*pb.DebugletStateResponse, error) {
		if req.State == pb.RunState_RUN_STATE_STARTED {
			select {
			case <-streamEntered:
			case <-ctx.Done():
				return nil, ctx.Err()
			}
			return nil, status.Error(codes.FailedPrecondition, "started state fixture")
		}
		return &pb.DebugletStateResponse{}, nil
	}
	streamJoined := make(chan struct{})
	peer.stream = func(stream grpc.BidiStreamingServer[pb.DebugletStreamRequest, pb.DebugletStreamResponse]) error {
		defer close(streamJoined)
		if _, err := stream.Recv(); err != nil {
			return err
		}
		close(streamEntered)
		for {
			if _, err := stream.Recv(); err != nil {
				return err
			}
		}
	}
	e, _ := newExecutorRPCFixture(t, peer, nil)
	spec, runtime := operationSpec(), &operationRuntime{}
	installOperationRuntime(e, spec, runtime)
	call := startOperationTest(t, e, spec)
	if !operationAwait(t, call.done, "pre-Run failure cleanup") || !operationAwait(t, streamJoined, "pre-Run stream handler") {
		return
	}
	if runtime.starts.Load() != 0 || runtime.closes.Load() != 1 || call.completion.CleanupErr != nil {
		t.Fatal("pre-Run failure did not clean exactly its owned resources")
	}
	if report := operationReport(t, peer, spec.DebugletID); report.ExitCode != -1 || !strings.Contains(report.GetErrorMessage(), "started state fixture") {
		t.Fatal("setup failure outcome lost")
	}
}

func TestOperationOutputSendFailureCancelsProducer(t *testing.T) {
	peer := newOperationPeer()
	producerStarted := make(chan struct{})
	peer.stream = func(stream grpc.BidiStreamingServer[pb.DebugletStreamRequest, pb.DebugletStreamResponse]) error {
		if _, err := stream.Recv(); err != nil {
			return err
		}
		select {
		case <-producerStarted:
		case <-stream.Context().Done():
			return stream.Context().Err()
		}
		return status.Error(codes.Unavailable, "output send fixture")
	}
	e, _ := newExecutorRPCFixture(t, peer, nil)
	spec := operationSpec()
	spec.Policy.Timeout = 10 * time.Second // The RPC failure must beat guest timeout.
	producerJoined := make(chan struct{})
	runtime := &operationRuntime{run: func(ctx context.Context, out chan<- []byte) error {
		close(producerStarted)
		defer close(producerJoined)
		payload := bytes.Repeat([]byte("x"), 64<<10)
		for {
			select {
			case out <- payload:
			case <-ctx.Done():
				return context.Cause(ctx)
			}
		}
	}}
	installOperationRuntime(e, spec, runtime)
	call := startOperationTest(t, e, spec)
	if !operationAwait(t, call.done, "Send failure cancellation") || !operationAwait(t, producerJoined, "cancelled output producer") {
		return
	}
	if runtime.closes.Load() != 1 || call.completion.CleanupErr != nil {
		t.Fatal("send failure lost local cleanup")
	}
	if report := operationReport(t, peer, spec.DebugletID); report.ExitCode != -1 || !strings.Contains(report.GetErrorMessage(), "output") {
		t.Fatal("Send failure did not become the single operation outcome")
	}
}

func TestOperationNaturalOutputDrainsBeforeReport(t *testing.T) {
	peer := newOperationPeer()
	var output []byte
	streamJoined := make(chan struct{})
	peer.stream = func(stream grpc.BidiStreamingServer[pb.DebugletStreamRequest, pb.DebugletStreamResponse]) error {
		defer close(streamJoined)
		identity, err := stream.Recv()
		if err != nil || identity.GetIdent() == nil {
			return status.Error(codes.InvalidArgument, "missing identity")
		}
		for {
			message, err := stream.Recv()
			if err == io.EOF {
				return nil
			}
			if err != nil {
				return err
			}
			if message.GetOutput() == nil {
				return status.Error(codes.InvalidArgument, "unexpected identity")
			}
			output = append(output, message.GetOutput().GetOutput()...)
		}
	}
	e, _ := newExecutorRPCFixture(t, peer, nil)
	spec := operationSpec()
	runtime := &operationRuntime{run: func(ctx context.Context, out chan<- []byte) error {
		for _, chunk := range []string{"first", "\x00second", "last\n"} {
			select {
			case out <- []byte(chunk):
			case <-ctx.Done():
				return context.Cause(ctx)
			}
		}
		return nil
	}}
	installOperationRuntime(e, spec, runtime)
	call := startOperationTest(t, e, spec)
	if !operationAwait(t, call.done, "natural stream drain") || !operationAwait(t, streamJoined, "natural stream handler") {
		return
	}
	if !bytes.Equal(output, []byte("first\x00secondlast\n")) || runtime.closes.Load() != 1 || call.completion.CleanupErr != nil {
		t.Fatal("natural output or cleanup incomplete")
	}
	if report := operationReport(t, peer, spec.DebugletID); report.ExitCode != 0 || report.ErrorMessage != nil {
		t.Fatal("natural completion became cancellation")
	}
}

func TestOperationRetainsOwnershipDuringUninterruptibleSetup(t *testing.T) {
	peer := newOperationPeer()
	e, _ := newExecutorRPCFixture(t, peer, nil)
	spec := operationSpec()
	setupEntered, setupRelease, closeJoined := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var closeContextOK, lateCleanup atomic.Bool
	lateErr := errors.New("late setup resource close failure")
	runtime := &operationRuntime{
		init: func(ctx context.Context) error {
			close(setupEntered)
			<-setupRelease
			lateCleanup.Store(true)
			return errors.Join(ctx.Err(), lateErr)
		},
		lateCloseError: func() error {
			if lateCleanup.Load() {
				return lateErr
			}
			return nil
		},
		close: func(ctx context.Context) error {
			closeContextOK.Store(ctx.Err() == nil)
			close(closeJoined)
			return nil
		},
	}
	installOperationRuntime(e, spec, runtime)
	call := startOperationTest(t, e, spec)
	var once sync.Once
	t.Cleanup(func() { once.Do(func() { close(setupRelease) }) })
	if !operationAwait(t, setupEntered, "held setup") {
		return
	}
	call.cancel(errors.New("cancel held setup"))
	if !operationAwait(t, closeJoined, "I/O closure before setup joins") {
		return
	}
	e.mu.Lock()
	op := e.running[spec.DebugletID].operation
	e.mu.Unlock()
	select {
	case <-call.done:
		t.Fatal("unjoined setup lost its callback owner")
	default:
	}
	select {
	case <-op.resourceDone:
		t.Fatal("unjoined setup was declared quiescent")
	default:
	}
	once.Do(func() { close(setupRelease) })
	if !operationAwait(t, call.done, "held setup release") {
		return
	}
	if !closeContextOK.Load() || runtime.starts.Load() != 0 || runtime.closes.Load() != 1 || !errors.Is(call.completion.CleanupErr, lateErr) {
		t.Fatal("setup cancellation/late cleanup error ownership was not preserved")
	}
	if report := operationReport(t, peer, spec.DebugletID); report.GetErrorMessage() != "cancel held setup" {
		t.Fatal("explicit cause was overwritten")
	}
}

func TestFailedOperationReportsWithoutAllocation(t *testing.T) {
	for _, name := range []string{"start_marker", "already_started", "cancelled"} {
		t.Run(name, func(t *testing.T) {
			peer := newOperationPeer()
			var allocations, states, constructed atomic.Int32
			peer.allocate = func(context.Context, *pb.DebugletAllocateRequest) (*pb.DebugletAllocateResponse, error) {
				allocations.Add(1)
				return nil, errors.New("failed callback attempted allocation")
			}
			peer.state = func(context.Context, *pb.DebugletStateRequest) (*pb.DebugletStateResponse, error) {
				states.Add(1)
				return nil, errors.New("failed callback attempted state update")
			}
			var reportContextOK atomic.Bool
			peer.exit = func(ctx context.Context, _ *pb.DebugletExitRequest) (*pb.DebugletExitResponse, error) {
				deadline, ok := ctx.Deadline()
				reportContextOK.Store(ctx.Err() == nil && ok && time.Until(deadline) > 0 && time.Until(deadline) <= scheduler.CleanupTimeout)
				return nil, status.Error(codes.Unavailable, "failed callback report fixture")
			}
			e, _ := newExecutorRPCFixture(t, peer, nil)
			e.newRuntime = func(scheduler.Spec) runtimeDebuglet { constructed.Add(1); return &operationRuntime{} }
			spec := operationSpec()
			ctx, cancel := context.WithCancelCause(context.Background())
			defer cancel(nil)
			failure := errors.New("SQLite start marker failure")
			if name == "already_started" {
				failure = scheduler.ErrDebugletAlreadyStarted
			}
			want := failure
			if name == "cancelled" {
				want = errors.New("cancel before scheduler callback")
				cancel(want)
			}
			done := make(chan struct{})
			var completion scheduler.Completion
			go func() { completion = e.OnDebugletFailed(ctx, spec, failure); close(done) }()
			t.Cleanup(func() { cancel(context.Canceled); operationJoinCleanup(t, done, "failed callback cleanup") })
			if !operationAwait(t, done, "failed callback report") {
				return
			}
			if completion.CleanupErr != nil || allocations.Load() != 0 || states.Load() != 0 || constructed.Load() != 0 {
				t.Fatal("failed callback replayed execution or mistook reporting for cleanup")
			}
			report := operationRetriedReport(t, peer, spec.DebugletID)
			if report.ExitCode != -1 || report.GetErrorMessage() != want.Error() || !reportContextOK.Load() {
				t.Fatalf("failed callback lost cause or detached report context: %+v context=%t", report, reportContextOK.Load())
			}
		})
	}
}
