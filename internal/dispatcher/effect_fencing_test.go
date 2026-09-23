package dispatcher

import (
	"context"
	"errors"
	"github.com/google/uuid"
	"github.com/netsec-ethz/debuglet/internal/controlsession"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/models"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/transport/rpc"
	pb "github.com/netsec-ethz/debuglet/protocol"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
	"io"
	"sync"
	"testing"
	"time"
)

func effectTestBinding(t *testing.T) controlsession.Binding {
	t.Helper()
	binding, err := controlsession.NewBinding("cd678a91-a1ba-4def-8192-123456789abc")
	if err != nil {
		t.Fatal(err)
	}
	return binding
}

func effectAdmit(ctx context.Context, d *Dispatcher, id string) (*rpc.Mutation, error) {
	d.mu.RLock()
	entry := d.executors[id]
	if d.closed || entry == nil {
		d.mu.RUnlock()
		return nil, rpc.ErrSessionUnavailable
	}
	mutation, err := entry.owner.AdmitMutation(ctx)
	d.mu.RUnlock()
	return mutation, err
}

func effectTestMutation(t *testing.T, d *Dispatcher, id string) *rpc.Mutation {
	t.Helper()
	mutation, err := effectAdmit(t.Context(), d, id)
	if err != nil {
		t.Fatalf("admit fixture mutation: %v", err)
	}
	t.Cleanup(mutation.Finish)
	return mutation
}

func TestDispatcherEffectsRequireOrdinaryOwnership(t *testing.T) {
	f := newTGFixture(t, nil)
	run := f.seedDirect(t, tgFloorA)
	before := f.snapshot(t)
	f.d.mu.RLock()
	owner := f.d.executors[tgExecutorID].owner
	f.d.mu.RUnlock()
	setup, err := owner.AdmitSetup(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer setup.Finish()
	finished := effectTestMutation(t, f.d, tgExecutorID)
	finished.Finish()
	for _, ticket := range []*rpc.Mutation{nil, setup, finished} {
		calls := []func() error{
			func() error {
				_, err := f.d.OnHeartbeat(f.ctx, ticket, &pb.HeartbeatRequest{ExecutorId: tgExecutorID})
				return err
			},
			func() error {
				_, err := f.d.OnResources(f.ctx, ticket, &pb.ResourcesRequest{ExecutorId: tgExecutorID, BandwidthCapacity: 1})
				return err
			},
			func() error {
				_, err := f.d.OnDebugletState(f.ctx, ticket, &pb.DebugletStateRequest{ExecutorId: tgExecutorID, DebugletId: run.id.String(), State: pb.RunState_RUN_STATE_STARTED})
				return err
			},
			func() error {
				_, err := f.d.OnDebugletAllocate(f.ctx, ticket, &pb.DebugletAllocateRequest{ExecutorId: tgExecutorID, DebugletId: run.id.String(), TransactionId: run.txID, Policy: &pb.DebugletPolicy{Addresses: []string{"192.0.2.1"}}})
				return err
			},
			func() error {
				_, err := f.d.OnDebugletExit(f.ctx, ticket, &pb.DebugletExitRequest{DebugletId: run.id.String()})
				return err
			},
		}
		for i, call := range calls {
			if err := call(); status.Code(err) != codes.FailedPrecondition {
				t.Fatalf("callback %d accepted invalid ordinary ownership: %v", i, err)
			}
		}
	}
	tgAssertSnapshot(t, f, before, "unadmitted ordinary callbacks")
}

func TestDispatcherEffectsRejectForeignRunAndTransaction(t *testing.T) {
	for _, sameID := range []bool{false, true} {
		name := "another_executor"
		if sameID {
			name = "replacement_session"
		}
		t.Run(name, func(t *testing.T) {
			f := newTGFixture(t, nil)
			run := f.seedDirect(t, tgFloorA)
			id := "other-executor"
			if sameID {
				id = tgExecutorID
				f.d.mu.RLock()
				old := f.d.executors[id].owner
				f.d.mu.RUnlock()
				old.Retire()
			}
			registryRegister(t, f.d, id)
			mutation := effectTestMutation(t, f.d, id)
			defer mutation.Finish()
			before := f.snapshot(t)
			calls := []func() error{
				func() error {
					_, err := f.d.OnDebugletState(f.ctx, mutation, &pb.DebugletStateRequest{ExecutorId: id, DebugletId: run.id.String(), State: pb.RunState_RUN_STATE_STARTED})
					return err
				},
				func() error {
					_, err := f.d.OnDebugletAllocate(f.ctx, mutation, &pb.DebugletAllocateRequest{ExecutorId: id, DebugletId: run.id.String(), TransactionId: run.txID, Policy: &pb.DebugletPolicy{Addresses: []string{"192.0.2.1"}, FloorBw: 10, CeilBw: 100}})
					return err
				},
				func() error {
					_, err := f.d.OnDebugletExit(f.ctx, mutation, &pb.DebugletExitRequest{DebugletId: run.id.String()})
					return err
				},
				func() error { return f.d.AbortDebuglet(f.ctx, id, run.id, "foreign abort") },
			}
			for i, call := range calls {
				if err := call(); status.Code(err) != codes.PermissionDenied {
					t.Fatalf("callback %d foreign run result: %v", i, err)
				}
			}
			tgAssertSnapshot(t, f, before, "foreign owner effects")
			f.d.mu.RLock()
			count := f.d.destinations.Len()
			f.d.mu.RUnlock()
			if count != 0 {
				t.Fatal("foreign allocation changed destinations")
			}
		})
	}
	t.Run("transaction_identity_before_payment", func(t *testing.T) {
		f := newTGFixture(t, nil)
		run := f.seedDirect(t, tgFloorA)
		mutation := effectTestMutation(t, f.d, tgExecutorID)
		defer mutation.Finish()
		before := f.snapshot(t)
		_, err := f.d.OnDebugletAllocate(f.ctx, mutation, &pb.DebugletAllocateRequest{ExecutorId: tgExecutorID, DebugletId: run.id.String(), TransactionId: "not-the-stored-transaction", Policy: &pb.DebugletPolicy{Addresses: []string{"192.0.2.2"}, FloorBw: 10, CeilBw: 100}})
		if status.Code(err) != codes.PermissionDenied {
			t.Fatalf("mismatched transaction: %v", err)
		}
		tgAssertSnapshot(t, f, before, "foreign transaction")
	})
}

// Unit stream adapter: actual frame processing and SQLite effects run, but
// this is not evidence of wire metadata admission or gRPC receive cancellation.
type effectStream struct {
	grpc.ServerStream
	ctx        context.Context
	frames     []*pb.DebugletStreamRequest
	beforeRecv func(int)
	calls      int
}

func (s *effectStream) Context() context.Context { return s.ctx }
func (s *effectStream) Recv() (*pb.DebugletStreamRequest, error) {
	index := s.calls
	s.calls++
	if s.beforeRecv != nil {
		s.beforeRecv(index)
	}
	if index >= len(s.frames) {
		return nil, io.EOF
	}
	return s.frames[index], nil
}
func (s *effectStream) Send(*pb.DebugletStreamResponse) error {
	return errors.New("unexpected stream response")
}
func effectIdent(id string) *pb.DebugletStreamRequest {
	return &pb.DebugletStreamRequest{Msg: &pb.DebugletStreamRequest_Ident{Ident: &pb.DebugletIdent{DebugletId: id}}}
}
func effectOutput() *pb.DebugletStreamRequest {
	return &pb.DebugletStreamRequest{Msg: &pb.DebugletStreamRequest_Output{Output: &pb.DebugletOutput{Timestamp: timestamppb.Now(), Output: []byte("owned-output")}}}
}

func TestDispatcherStreamRejectsProtocolWithoutTerminalEffects(t *testing.T) {
	cases := []string{"output_before_ident", "repeated_ident", "malformed_ident", "unknown_frame", "foreign_ident", "valid_output"}
	for _, name := range cases {
		t.Run(name, func(t *testing.T) {
			f := newTGFixture(t, nil)
			run := f.seedDirect(t, tgFloorA)
			f.d.mu.RLock()
			owner := f.d.executors[tgExecutorID].owner
			f.d.mu.RUnlock()
			frames := []*pb.DebugletStreamRequest{effectIdent(run.id.String())}
			want := codes.InvalidArgument
			switch name {
			case "output_before_ident":
				frames = []*pb.DebugletStreamRequest{effectOutput()}
			case "repeated_ident":
				frames = append(frames, effectIdent(run.id.String()), effectOutput())
			case "malformed_ident":
				frames = []*pb.DebugletStreamRequest{effectIdent("bad-run-id")}
			case "unknown_frame":
				frames = append(frames, &pb.DebugletStreamRequest{})
			case "foreign_ident":
				owner = registryRegister(t, f.d, "foreign-stream")
				want = codes.PermissionDenied
			case "valid_output":
				frames = append(frames, effectOutput())
				want = codes.OK
			}
			before := f.snapshot(t)
			err := f.d.OnDebugletStream(owner, &effectStream{ctx: f.ctx, frames: frames})
			if status.Code(err) != want {
				t.Fatalf("frame outcome: %v, want %s", err, want)
			}
			if want != codes.OK {
				tgAssertSnapshot(t, f, before, "rejected frame")
			}
			var logs int
			if err := f.db.QueryRow("SELECT count(*) FROM debuglet_logs").Scan(&logs); err != nil {
				t.Fatal(err)
			}
			expected := 0
			if want == codes.OK {
				expected = 1
			}
			if logs != expected {
				t.Fatalf("stored logs=%d, want %d", logs, expected)
			}
			tgAssertRow(t, f.row(t, run.id), models.RunStateUploaded, tgNull)
			tgAssertOrder(t, f, run, models.Outstanding)
		})
	}
}

func TestDispatcherIdleStreamDoesNotHoldMutationDrain(t *testing.T) {
	f := newTGFixture(t, nil)
	run := f.seedDirect(t, tgFloorA)
	f.d.mu.RLock()
	owner := f.d.executors[tgExecutorID].owner
	f.d.mu.RUnlock()
	entered, gate, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var once sync.Once
	release := func() { once.Do(func() { close(gate) }) }
	stream := &effectStream{ctx: f.ctx, frames: []*pb.DebugletStreamRequest{effectIdent(run.id.String()), effectOutput()}, beforeRecv: func(i int) {
		if i == 1 {
			close(entered)
			<-gate
		}
	}}
	var result error
	go func() { defer close(done); result = f.d.OnDebugletStream(owner, stream) }()
	t.Cleanup(func() { release(); registryWait(t, done) })
	registryWait(t, entered)
	owner.Retire()
	registryWait(t, owner.MutationsDrained())
	// The stream handler is really still blocked in its next receive; the
	// retired owner must nevertheless drain after its first frame completed.
	select {
	case <-done:
		t.Fatal("stream did not remain idle at its receive gate")
	default:
	}
	release()
	registryWait(t, done)
	if status.Code(result) != codes.FailedPrecondition {
		t.Fatalf("post-retirement frame result: %v", result)
	}
	var logs int
	if err := f.db.QueryRow("SELECT count(*) FROM debuglet_logs").Scan(&logs); err != nil {
		t.Fatal(err)
	}
	if logs != 0 {
		t.Fatal("retired stream wrote another output frame")
	}
	tgAssertRow(t, f.row(t, run.id), models.RunStateUploaded, tgNull)
}

func TestFairshareRetainsTicketsUntilLocalSenderJoins(t *testing.T) {
	d, _, _ := newRegistryFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	fairshareStartPeer(t, ctx, d, &fairsharePeer{})
	origin := effectTestMutation(t, d, fairshareExecutorID)
	owner := origin.Owner()
	id := uuid.New()
	destination := "192.0.2.70"
	d.mu.Lock()
	insertErr := d.destinations.Insert(id, destination, fairshareExecutorID, 10, 80)
	d.mu.Unlock()
	if insertErr != nil {
		t.Fatal(insertErr)
	}
	work, err := d.captureFairshare(ctx, origin, []string{destination})
	if err != nil {
		t.Fatal(err)
	}
	entered, gate, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var once sync.Once
	release := func() { once.Do(func() { close(gate) }) }
	core, _ := observer.New(zap.DebugLevel)
	d.logger = zap.New(core, zap.Hooks(func(entry zapcore.Entry) error {
		if entry.Message == "New fairshared update" {
			close(entered)
			<-gate
		}
		return nil
	}))
	var sendErr error
	go func() { defer close(done); sendErr = work.send(ctx) }()
	t.Cleanup(func() { release(); cancel(); registryWait(t, done) })
	registryWait(t, entered)
	origin.Finish()
	owner.Retire()
	select {
	case <-owner.MutationsDrained():
		t.Error("origin/recipient tickets drained while the actual local sender was held")
	case <-time.After(30 * time.Millisecond):
	}
	release()
	registryWait(t, done)
	registryWait(t, owner.MutationsDrained())
	// Retirement can cancel this exact client's call; completion proves only
	// dispatcher-local join, never a remote-handler drain acknowledgement.
	if sendErr != nil && !errors.Is(sendErr, context.Canceled) && status.Code(sendErr) != codes.Canceled && status.Code(sendErr) != codes.FailedPrecondition {
		t.Fatalf("unexpected retired delivery error: %v", sendErr)
	}
}
