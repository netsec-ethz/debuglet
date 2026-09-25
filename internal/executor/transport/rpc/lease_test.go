package rpc

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/netsec-ethz/debuglet/internal/controlrpc"
	"github.com/netsec-ethz/debuglet/internal/controlsession"
	pb "github.com/netsec-ethz/debuglet/protocol"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type leaseScriptClient struct {
	pb.DispatcherServiceClient
	calls  atomic.Int32
	renew  func(context.Context, *pb.RenewLeaseRequest) (*pb.RenewLeaseResponse, error)
	bind   func(context.Context, *pb.BindSessionRequest) (*pb.BindSessionResponse, error)
	stream *leaseScriptStream
}

func (c *leaseScriptClient) Heartbeat(context.Context, *pb.HeartbeatRequest, ...grpc.CallOption) (*pb.HeartbeatResponse, error) {
	c.calls.Add(1)
	return &pb.HeartbeatResponse{}, nil
}
func (c *leaseScriptClient) BindSession(ctx context.Context, in *pb.BindSessionRequest, _ ...grpc.CallOption) (*pb.BindSessionResponse, error) {
	c.calls.Add(1)
	return c.bind(ctx, in)
}
func (c *leaseScriptClient) RenewLease(ctx context.Context, in *pb.RenewLeaseRequest, _ ...grpc.CallOption) (*pb.RenewLeaseResponse, error) {
	c.calls.Add(1)
	return c.renew(ctx, in)
}
func (c *leaseScriptClient) DebugletStream(context.Context, ...grpc.CallOption) (grpc.BidiStreamingClient[pb.DebugletStreamRequest, pb.DebugletStreamResponse], error) {
	c.calls.Add(1)
	return c.stream, nil
}

type leaseScriptStream struct {
	grpc.BidiStreamingClient[pb.DebugletStreamRequest, pb.DebugletStreamResponse]
	sends, closes atomic.Int32
}

func (s *leaseScriptStream) Send(*pb.DebugletStreamRequest) error      { s.sends.Add(1); return nil }
func (s *leaseScriptStream) SendMsg(any) error                         { s.sends.Add(1); return nil }
func (s *leaseScriptStream) CloseSend() error                          { s.closes.Add(1); return nil }
func (s *leaseScriptStream) Recv() (*pb.DebugletStreamResponse, error) { return nil, io.EOF }

func newLeaseUnitClient(t *testing.T, now func() time.Time) (*BidiClient, controlsession.Binding) {
	t.Helper()
	b, err := NewBidiClient(BidiOptions{Address: "passthrough:///unused", Logger: zap.NewNop(), LeaseNow: now}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(b.Close)
	offer := negotiationOffer()
	binding := controlsession.Binding{Incarnation: offer.DispatcherIncarnation, SessionID: offer.SessionId}
	b.control = &controlrpc.Credentials{Binding: binding}
	copy(b.control.Token[:], offer.SessionToken)
	b.lease, _ = controlsession.NewLeaseTiming(time.Second)
	b.armed, b.negotiated = true, true
	b.deadline, b.bindDeadline = now().Add(time.Second), now().Add(time.Second)
	b.startupDeadline = now().Add(preOfferTimeout)
	return b, binding
}

func TestClientLeaseGuardsWithoutWatchdog(t *testing.T) {
	base := time.Now()
	var offset atomic.Int64
	b, binding := newLeaseUnitClient(t, func() time.Time { return base.Add(time.Duration(offset.Load())) })
	raw := &leaseScriptClient{stream: &leaseScriptStream{}}
	b.client = raw
	cached, err := b.ClientFor(binding)
	if err != nil {
		t.Fatal(err)
	}
	stream, err := cached.DebugletStream(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err = stream.Send(&pb.DebugletStreamRequest{}); err != nil {
		t.Fatal(err)
	}
	if _, err = cached.Heartbeat(context.Background(), &pb.HeartbeatRequest{}); err != nil {
		t.Fatal(err)
	}
	before := raw.calls.Load()
	offset.Store(int64(time.Second))
	committed := false
	if err = b.CommitLease(binding, func() { committed = true }); err == nil || committed {
		t.Fatal("expired lease admitted start without watchdog")
	}
	if err = b.CommitUpload(binding, func() { committed = true }); err == nil || committed {
		t.Fatal("expired lease admitted persistence without watchdog")
	}
	if _, err = cached.Heartbeat(context.Background(), &pb.HeartbeatRequest{}); err == nil {
		t.Fatal("cached unary escaped lease guard")
	}
	if _, err = cached.DebugletStream(context.Background()); err == nil {
		t.Fatal("cached stream open escaped lease guard")
	}
	if err = stream.Send(&pb.DebugletStreamRequest{}); err == nil {
		t.Fatal("cached stream Send escaped lease guard")
	}
	if err = stream.SendMsg(&pb.DebugletStreamRequest{}); err == nil {
		t.Fatal("cached stream SendMsg escaped lease guard")
	}
	if raw.calls.Load() != before || raw.stream.sends.Load() != 1 {
		t.Fatal("expired operation reached transport")
	}
	if err = stream.CloseSend(); err != nil {
		t.Fatal("loss prevented owned stream cleanup")
	}
	if _, err = stream.Recv(); !errors.Is(err, io.EOF) || raw.stream.closes.Load() != 1 {
		t.Fatal("loss prevented owned stream completion")
	}
	awaitNegotiation(t, b.Lost())
	selected := b.Cause()
	b.Stop(errors.New("later error"))
	var ended *controlsession.EndError
	if b.Cause() != selected || !errors.As(selected, &ended) || ended.Kind != controlsession.LeaseExpired {
		t.Fatal("loss cause was not immutable/typed")
	}
}

func TestClientPendingLeaseOnlyAdmitsUpload(t *testing.T) {
	base := time.Now()
	b, binding := newLeaseUnitClient(t, func() time.Time { return base })
	b.negotiated = false
	called := false
	if err := b.CommitUpload(binding, func() { called = true }); err != nil || !called {
		t.Fatal("live pending upload was refused")
	}
	called = false
	if err := b.CommitLease(binding, func() { called = true }); err == nil || called {
		t.Fatal("pending lease started work")
	}
	if _, err := b.ClientFor(binding); err == nil {
		t.Fatal("pending lease produced ordinary client")
	}
	if _, ok := b.Binding(); !ok {
		t.Fatal("pending upload lost its exact binding")
	}
	b.armed = false
	if err := b.CommitUpload(binding, func() { called = true }); err == nil || called {
		t.Fatal("Hello offer alone reserved work")
	}
}

func TestClientRenewalUsesRequestTime(t *testing.T) {
	base := time.Now()
	var offset atomic.Int64
	b, _ := newLeaseUnitClient(t, func() time.Time { return base.Add(time.Duration(offset.Load())) })
	offset.Store(int64(200 * time.Millisecond))
	b.client = &leaseScriptClient{renew: func(_ context.Context, in *pb.RenewLeaseRequest) (*pb.RenewLeaseResponse, error) {
		offset.Store(int64(600 * time.Millisecond))
		return &pb.RenewLeaseResponse{Sequence: in.Sequence, LeaseDurationMs: 1000}, nil
	}}
	if !b.renewOnce(context.Background()) || b.deadline != base.Add(1200*time.Millisecond) {
		t.Fatal("renewal extended from ACK receive instead of request send")
	}
	offset.Store(int64(800 * time.Millisecond))
	b.client = &leaseScriptClient{renew: func(_ context.Context, in *pb.RenewLeaseRequest) (*pb.RenewLeaseResponse, error) {
		offset.Store(int64(1200 * time.Millisecond))
		return &pb.RenewLeaseResponse{Sequence: in.Sequence, LeaseDurationMs: 1000}, nil
	}}
	if b.renewOnce(context.Background()) || b.deadline != base.Add(1200*time.Millisecond) {
		t.Fatal("late ACK revived old deadline without watchdog")
	}
	awaitNegotiation(t, b.Lost())
}

func TestClientRenewalRejectsInvalidAcknowledgement(t *testing.T) {
	for _, mode := range []string{"sequence", "duration", "context"} {
		t.Run(mode, func(t *testing.T) {
			base := time.Now()
			b, _ := newLeaseUnitClient(t, func() time.Time { return base })
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			b.client = &leaseScriptClient{renew: func(_ context.Context, in *pb.RenewLeaseRequest) (*pb.RenewLeaseResponse, error) {
				out := &pb.RenewLeaseResponse{Sequence: in.Sequence, LeaseDurationMs: 1000}
				switch mode {
				case "sequence":
					out.Sequence++
				case "duration":
					out.LeaseDurationMs++
				case "context":
					cancel()
				}
				return out, nil
			}}
			_ = b.renewOnce(ctx)
			if b.deadline != base.Add(time.Second) {
				t.Fatal("invalid/canceled ACK changed deadline")
			}
		})
	}
}

func TestBindOfferCannotOutlivePreArmDeadline(t *testing.T) {
	base := time.Now()
	var offset atomic.Int64
	b, _ := newLeaseUnitClient(t, func() time.Time { return base.Add(time.Duration(offset.Load())) })
	b.armed, b.negotiated = false, false
	b.hello = &pb.HelloResponse{ExecutorId: "executor"}
	close(b.offered)
	raw := &leaseScriptClient{bind: func(context.Context, *pb.BindSessionRequest) (*pb.BindSessionResponse, error) {
		return &pb.BindSessionResponse{LeaseDurationMs: 1000}, nil
	}}
	b.client = raw
	// A completed offer waits behind the actual Bidi guard before first Bind.
	b.mu.Lock()
	started, joined := make(chan struct{}), make(chan struct{})
	go func() {
		close(started)
		defer close(joined)
		b.confirmLease(context.Background(), context.Background())
	}()
	<-started
	offset.Store(int64(preOfferTimeout))
	b.mu.Unlock()
	awaitNegotiation(t, joined)
	if raw.calls.Load() != 0 {
		t.Fatal("expired pre-arm offer sent Bind")
	}
	awaitNegotiation(t, b.Lost())
	if b.armed {
		t.Fatal("expired pre-arm offer armed reverse admission")
	}
}

func TestWatchdogKeepsOfferToArmDeadline(t *testing.T) {
	base := time.Now()
	var offset atomic.Int64
	b, _ := newLeaseUnitClient(t, func() time.Time { return base.Add(time.Duration(offset.Load())) })
	b.armed, b.negotiated = false, false
	b.hello = &pb.HelloResponse{ExecutorId: "executor"}
	ticks := make(chan time.Time, 1)
	var stopped atomic.Int32
	b.newLeaseTicker = func(time.Duration) (<-chan time.Time, func()) { return ticks, func() { stopped.Add(1) } }
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	joined := make(chan struct{})
	go b.watchLease(ctx, joined)
	t.Cleanup(func() { cancel(); awaitNegotiation(t, joined) })
	offset.Store(int64(preOfferTimeout))
	ticks <- base
	awaitNegotiation(t, b.Lost())
	awaitNegotiation(t, joined)
	if stopped.Load() != 1 {
		t.Fatal("owned watchdog ticker did not stop once")
	}
}

func TestBidiPreOfferWatchdogInterruptsHandshake(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer lis.Close()
	base := time.Now()
	var offset atomic.Int64
	ticks := make(chan time.Time, 1)
	var stopped atomic.Int32
	b, err := NewBidiClient(BidiOptions{Address: lis.Addr().String(), Logger: zap.NewNop(), LeaseNow: func() time.Time { return base.Add(time.Duration(offset.Load())) }, NewLeaseTicker: func(time.Duration) (<-chan time.Time, func()) { return ticks, func() { stopped.Add(1) } }}, nil)
	if err != nil {
		t.Fatal(err)
	}
	ready, peerDone, clientDone := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var serveErr error
	go func() {
		defer close(peerDone)
		conn, err := lis.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		if _, err = io.ReadFull(conn, make([]byte, 12)); err != nil {
			return
		}
		close(ready)
		_, _ = io.Copy(io.Discard, conn)
	}()
	go func() { defer close(clientDone); serveErr = b.ConnectAndServe(ctx) }()
	t.Cleanup(func() {
		cancel()
		lis.Close()
		b.Close()
		awaitNegotiation(t, clientDone)
		awaitNegotiation(t, peerDone)
	})
	awaitNegotiation(t, ready)
	offset.Store(int64(preOfferTimeout))
	ticks <- base
	awaitNegotiation(t, b.Lost())
	var ended *controlsession.EndError
	if !errors.As(b.Cause(), &ended) || ended.Kind != controlsession.TransportUnavailable || !errors.Is(ended, context.DeadlineExceeded) {
		t.Fatalf("pre-offer timeout cause=%v", b.Cause())
	}
	// Neither peer teardown nor the parent deadline supplies the successful join.
	awaitNegotiation(t, clientDone)
	awaitNegotiation(t, peerDone)
	if !errors.Is(serveErr, context.DeadlineExceeded) || stopped.Load() != 1 {
		t.Fatal("pre-offer timeout did not join its actual lifetime")
	}
}

func TestControlProfileClassification(t *testing.T) {
	if !observedUnsupported(unsupportedProfile()) {
		t.Fatal("missing structured profile rejection")
	}
	for _, err := range []error{io.EOF, context.DeadlineExceeded, status.Error(codes.FailedPrecondition, "unsupported control profile"), status.Error(codes.Unavailable, "peer stopped")} {
		if observedUnsupported(err) {
			t.Fatal("generic status/text was classified incompatible")
		}
	}
}

// Keep the held-callback test's cleanup independent from a failed assertion.
func TestClientCommitExcludesStop(t *testing.T) {
	b, binding := newLeaseUnitClient(t, time.Now)
	entered, release, committed, stopped := make(chan struct{}), make(chan struct{}), make(chan struct{}), make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	t.Cleanup(func() { unblock(); awaitNegotiation(t, committed); awaitNegotiation(t, stopped) })
	go func() { defer close(committed); _ = b.CommitLease(binding, func() { close(entered); <-release }) }()
	awaitNegotiation(t, entered)
	requested := make(chan struct{})
	go func() { close(requested); defer close(stopped); b.Stop(nil) }()
	<-requested
	select {
	case <-b.Lost():
		t.Error("Stop crossed an admitted guarded commit")
	case <-time.After(20 * time.Millisecond):
	}
	unblock()
	awaitNegotiation(t, committed)
	awaitNegotiation(t, stopped)
	called := false
	if err := b.CommitLease(binding, func() { called = true }); err == nil || called {
		t.Fatal("retired client admitted a commit")
	}
}

func TestClientAcknowledgementContextAfterGuardWait(t *testing.T) {
	for _, mode := range []string{"bind", "renew"} {
		t.Run(mode, func(t *testing.T) {
			base := time.Now()
			b, _ := newLeaseUnitClient(t, func() time.Time { return base.Add(200 * time.Millisecond) })
			b.deadline = base.Add(time.Second)
			previous := b.deadline
			b.lease.RequestTimeout = 100 * time.Millisecond
			b.confirmationTimeout = 100 * time.Millisecond
			captured := make(chan context.Context, 1)
			locked := make(chan struct{})
			var releaseOnce sync.Once
			release := func() { releaseOnce.Do(func() { b.mu.Unlock() }) }
			lockAndCapture := func(ctx context.Context) { b.mu.Lock(); close(locked); captured <- ctx }
			raw := &leaseScriptClient{
				bind: func(ctx context.Context, _ *pb.BindSessionRequest) (*pb.BindSessionResponse, error) {
					lockAndCapture(ctx)
					return &pb.BindSessionResponse{LeaseDurationMs: 1000}, nil
				},
				renew: func(ctx context.Context, in *pb.RenewLeaseRequest) (*pb.RenewLeaseResponse, error) {
					lockAndCapture(ctx)
					return &pb.RenewLeaseResponse{Sequence: in.Sequence, LeaseDurationMs: 1000}, nil
				},
			}
			b.client = raw
			if mode == "bind" {
				b.armed, b.negotiated = false, false
				b.hello = &pb.HelloResponse{ExecutorId: "executor"}
				close(b.offered)
			}
			joined := make(chan struct{})
			parent, stop := context.WithCancel(context.Background())
			t.Cleanup(func() {
				stop()
				select {
				case <-locked:
					release()
				case <-joined:
					return
				case <-time.After(negotiationTestWait):
					t.Error("ACK fixture did not reach a releasable or joined state")
				}
				awaitNegotiation(t, joined)
			})
			go func() {
				defer close(joined)
				if mode == "bind" {
					b.confirmLease(parent, parent)
				} else {
					b.renewOnce(parent)
				}
			}()
			var request context.Context
			select {
			case request = <-captured:
			case <-time.After(negotiationTestWait):
				t.Fatal("ACK did not acquire real client guard")
			}
			// Parent remains live; only the bounded request expires behind the guard.
			// Expiry must be read after the mutex wait, not saved when RPC returned.
			awaitNegotiation(t, request.Done())
			if parent.Err() != nil {
				t.Fatal("parent supplied request timeout")
			}
			release()
			awaitNegotiation(t, joined)
			if mode == "bind" {
				select {
				case <-b.ready:
					t.Fatal("late Bind ACK published readiness after request expiry")
				default:
				}
				if b.negotiated {
					t.Fatal("late Bind ACK confirmed lease")
				}
			} else if b.deadline != previous {
				t.Fatal("late renewal ACK extended deadline after request expiry")
			}
		})
	}
}
