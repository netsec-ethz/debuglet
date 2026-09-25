package rpc

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hashicorp/yamux"
	"github.com/netsec-ethz/debuglet/internal/controlrpc"
	"github.com/netsec-ethz/debuglet/internal/controlsession"
	pb "github.com/netsec-ethz/debuglet/protocol"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

const negotiationTestWait = 10 * time.Second

type negotiationState struct {
	ExecutorState
	helloCalls atomic.Int32
	upload     func(context.Context, controlsession.Binding, *pb.UploadRequest) error
}

func (s *negotiationState) OnHello(_ context.Context, in *pb.HelloRequest) (*pb.HelloResponse, error) {
	s.helloCalls.Add(1)
	if len(in.SessionToken) != 0 {
		return nil, errors.New("transport exposed token to profile callback")
	}
	return &pb.HelloResponse{ExecutorId: "executor"}, nil
}
func (s *negotiationState) OnUpload(ctx context.Context, binding controlsession.Binding, in *pb.UploadRequest) (*pb.UploadResponse, error) {
	if s.upload != nil {
		if err := s.upload(ctx, binding, in); err != nil {
			return nil, err
		}
	}
	return &pb.UploadResponse{}, nil
}

type negotiationDispatcher struct {
	pb.UnimplementedDispatcherServiceServer
	bind func(context.Context, *pb.BindSessionRequest) (*pb.BindSessionResponse, error)
}

func (d *negotiationDispatcher) BindSession(ctx context.Context, in *pb.BindSessionRequest) (*pb.BindSessionResponse, error) {
	return d.bind(ctx, in)
}

type negotiationHello struct {
	client   pb.ExecutorServiceClient
	response *pb.HelloResponse
	err      error
}
type negotiationFixture struct {
	t                                   *testing.T
	ctx                                 context.Context
	cancel                              context.CancelFunc
	client                              *BidiClient
	direct                              *grpc.Server
	directLis, reverseLis               net.Listener
	directDone, reverseDone, clientDone chan struct{}
	hello                               chan negotiationHello
	result                              error
	releases                            []func()
	once                                sync.Once
}

func newNegotiationFixture(t *testing.T, state ExecutorState, offer *pb.HelloRequest, timeout time.Duration, bind func(context.Context, *pb.BindSessionRequest) (*pb.BindSessionResponse, error)) *negotiationFixture {
	t.Helper()
	direct, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	reverse, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		direct.Close()
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), negotiationTestWait)
	f := &negotiationFixture{t: t, ctx: ctx, cancel: cancel, directLis: direct, reverseLis: reverse, directDone: make(chan struct{}), reverseDone: make(chan struct{}), clientDone: make(chan struct{}), hello: make(chan negotiationHello, 1)}
	f.direct = grpc.NewServer(grpc.WaitForHandlers(true))
	pb.RegisterDispatcherServiceServer(f.direct, &negotiationDispatcher{bind: bind})
	f.client, err = NewBidiClient(BidiOptions{Address: direct.Addr().String(), YamuxAddress: reverse.Addr().String(), Logger: zap.NewNop()}, state)
	if err != nil {
		cancel()
		direct.Close()
		reverse.Close()
		f.direct.Stop()
		t.Fatal(err)
	}
	f.client.confirmationTimeout = timeout
	t.Cleanup(f.close)
	go func() { defer close(f.directDone); _ = f.direct.Serve(direct) }()
	go func() {
		defer close(f.reverseDone)
		conn, err := reverse.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		joined := make(chan struct{})
		local, stop := context.WithCancel(ctx)
		go func() { defer close(joined); <-local.Done(); conn.Close() }()
		defer func() { stop(); <-joined }()
		session, err := yamux.Server(conn, nil)
		if err != nil {
			f.hello <- negotiationHello{err: err}
			return
		}
		defer session.Close()
		gconn, err := grpc.NewClient("passthrough:///reverse", grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return session.Open() }))
		if err != nil {
			f.hello <- negotiationHello{err: err}
			return
		}
		defer gconn.Close()
		client := pb.NewExecutorServiceClient(gconn)
		response, err := client.Hello(ctx, offer)
		f.hello <- negotiationHello{client: client, response: response, err: err}
		if err != nil {
			return
		}
		select {
		case <-ctx.Done():
		case <-session.CloseChan():
		}
	}()
	go func() { defer close(f.clientDone); f.result = f.client.ConnectAndServe(ctx) }()
	return f
}
func (f *negotiationFixture) close() {
	f.once.Do(func() {
		f.cancel()
		for _, release := range f.releases {
			release()
		}
		f.client.Close()
		f.direct.Stop()
		f.directLis.Close()
		f.reverseLis.Close()
		awaitNegotiation(f.t, f.clientDone)
		awaitNegotiation(f.t, f.reverseDone)
		awaitNegotiation(f.t, f.directDone)
	})
}
func awaitNegotiation(t *testing.T, ch <-chan struct{}) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(negotiationTestWait):
		t.Fatal("negotiation fixture did not reach or join its owned boundary")
	}
}
func (f *negotiationFixture) helloResult() negotiationHello {
	f.t.Helper()
	select {
	case got := <-f.hello:
		return got
	case <-f.ctx.Done():
		f.t.Fatal("real Hello did not complete")
	}
	return negotiationHello{}
}
func negotiationOffer() *pb.HelloRequest {
	return &pb.HelloRequest{ControlVersion: controlsession.ProtocolVersion, LeaseDurationMs: time.Minute.Milliseconds(), DispatcherIncarnation: "00000000-0000-4000-8000-000000000001", SessionId: "00000000-0000-4000-8000-000000000002", SessionToken: []byte("0123456789abcdef0123456789abcdef")}
}

func TestBidiStrictHello(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(*pb.HelloRequest)
		code codes.Code
	}{
		{"legacy", func(p *pb.HelloRequest) { p.ControlVersion = 0 }, codes.FailedPrecondition},
		{"identity", func(p *pb.HelloRequest) { p.SessionId = "private-invalid-session" }, codes.InvalidArgument},
		{"token", func(p *pb.HelloRequest) { p.SessionToken = p.SessionToken[:31] }, codes.InvalidArgument},
	} {
		t.Run(tc.name, func(t *testing.T) {
			offer := negotiationOffer()
			tc.edit(offer)
			state := &negotiationState{}
			var binds atomic.Int32
			f := newNegotiationFixture(t, state, offer, time.Second, func(context.Context, *pb.BindSessionRequest) (*pb.BindSessionResponse, error) {
				binds.Add(1)
				return &pb.BindSessionResponse{LeaseDurationMs: time.Minute.Milliseconds()}, nil
			})
			if got := f.helloResult(); status.Code(got.err) != tc.code && !(tc.name == "legacy" && status.Code(got.err) == codes.Unavailable) {
				t.Fatalf("Hello status=%v want=%v", status.Code(got.err), tc.code)
			}
			awaitNegotiation(t, f.clientDone)
			if tc.name == "legacy" {
				var ended *controlsession.EndError
				if !errors.As(f.client.Cause(), &ended) || ended.Kind != controlsession.IncompatibleProfile {
					t.Fatal("observed legacy offer lost structured cause")
				}
			}
			if err := f.client.WaitReadyContext(f.ctx); err == nil {
				t.Fatal("failed negotiation reported ready")
			}
			if state.helloCalls.Load() != 0 || binds.Load() != 0 {
				t.Fatal("rejected offer reached profile or confirmation")
			}
			if _, ok := f.client.Binding(); ok {
				t.Fatal("rejected offer armed reverse admission")
			}
		})
	}
}

func TestBidiOneBindingLifetime(t *testing.T) {
	state := &negotiationState{}
	f := newNegotiationFixture(t, state, negotiationOffer(), time.Second, func(ctx context.Context, req *pb.BindSessionRequest) (*pb.BindSessionResponse, error) {
		if _, err := controlrpc.Read(ctx); err != nil {
			return nil, err
		}
		if req.ExecutorId != "executor" {
			return nil, controlrpc.Denied()
		}
		return &pb.BindSessionResponse{LeaseDurationMs: time.Minute.Milliseconds()}, nil
	})
	first := f.helloResult()
	if first.err != nil {
		t.Fatal(first.err)
	}
	if err := f.client.WaitReadyContext(f.ctx); err != nil {
		t.Fatal(err)
	}
	binding, ok := f.client.Binding()
	if !ok {
		t.Fatal("successful negotiation has no binding")
	}
	duplicate, err := first.client.Hello(f.ctx, negotiationOffer())
	if err != nil || duplicate.GetSessionId() != binding.SessionID {
		t.Fatalf("idempotent exact Hello: %v", err)
	}
	conflict := proto.Clone(negotiationOffer()).(*pb.HelloRequest)
	conflict.SessionId = "00000000-0000-4000-8000-000000000003"
	if _, err := first.client.Hello(f.ctx, conflict); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("conflicting Hello: %v", err)
	}
	if state.helloCalls.Load() != 1 {
		t.Fatal("repeated Hello reran profile effects")
	}
	if got, ok := f.client.Binding(); !ok || got != binding {
		t.Fatal("conflicting Hello changed binding")
	}
	if _, err := f.client.ClientFor(controlsession.Binding{}); err == nil {
		t.Fatal("invalid bound lookup returned ambient client")
	}
	f.close()
	if _, ok := f.client.Binding(); ok {
		t.Fatal("closed client retained live binding")
	}
	if _, err := f.client.ClientFor(binding); err == nil {
		t.Fatal("closed client returned bound client")
	}
	if err := f.client.ConnectAndServe(context.Background()); err == nil {
		t.Fatal("one-shot client admitted another lifetime")
	}
}

func TestBidiConfirmationTimeoutAndCancellation(t *testing.T) {
	for _, mode := range []string{"timeout", "caller_cancel"} {
		t.Run(mode, func(t *testing.T) {
			entered, joined := make(chan struct{}), make(chan struct{})
			var calls atomic.Int32
			timeout := 500 * time.Millisecond
			if mode == "caller_cancel" {
				timeout = bindConfirmationTimeout
			}
			f := newNegotiationFixture(t, &negotiationState{}, negotiationOffer(), timeout, func(ctx context.Context, _ *pb.BindSessionRequest) (*pb.BindSessionResponse, error) {
				calls.Add(1)
				close(entered)
				defer close(joined)
				<-ctx.Done()
				return nil, ctx.Err()
			})
			if got := f.helloResult(); got.err != nil {
				t.Fatal(got.err)
			}
			awaitNegotiation(t, entered)
			if mode == "caller_cancel" {
				f.cancel()
			}
			awaitNegotiation(t, f.clientDone)
			awaitNegotiation(t, joined)
			if f.result == nil {
				t.Fatal("withheld Bind response reported successful startup")
			}
			if mode == "caller_cancel" && !errors.Is(f.result, context.Canceled) {
				t.Fatalf("lost startup cancellation: %v", f.result)
			}
			if calls.Load() != 1 {
				t.Fatal("confirmation retried")
			}
			if _, ok := f.client.Binding(); ok {
				t.Fatal("failed confirmation left reverse binding active")
			}
			if err := f.client.WaitReadyContext(context.Background()); err == nil {
				t.Fatal("failed confirmation signaled ready")
			}
		})
	}
}

func TestBidiCloseJoinsAdmittedReverseHandler(t *testing.T) {
	entered, canceled, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	state := &negotiationState{upload: func(ctx context.Context, _ controlsession.Binding, _ *pb.UploadRequest) error {
		close(entered)
		<-ctx.Done()
		close(canceled)
		<-release
		return ctx.Err()
	}}
	offer := negotiationOffer()
	f := newNegotiationFixture(t, state, offer, time.Second, func(context.Context, *pb.BindSessionRequest) (*pb.BindSessionResponse, error) {
		return &pb.BindSessionResponse{LeaseDurationMs: time.Minute.Milliseconds()}, nil
	})
	f.releases = append(f.releases, unblock)
	hello := f.helloResult()
	if hello.err != nil {
		t.Fatal(hello.err)
	}
	if err := f.client.WaitReadyContext(f.ctx); err != nil {
		t.Fatal(err)
	}
	credentials := controlrpc.Credentials{Binding: controlsession.Binding{Incarnation: offer.DispatcherIncarnation, SessionID: offer.SessionId}}
	copy(credentials.Token[:], offer.SessionToken)
	called := make(chan struct{})
	go func() {
		defer close(called)
		_, _ = hello.client.Upload(credentials.Outgoing(f.ctx), &pb.UploadRequest{ControlBinding: &pb.ControlBinding{DispatcherIncarnation: offer.DispatcherIncarnation, SessionId: offer.SessionId}})
	}()
	// Release precedes every join, including assertions failing before Close.
	t.Cleanup(func() { unblock(); f.cancel(); f.client.Close(); awaitNegotiation(t, called) })
	awaitNegotiation(t, entered)
	closed := make(chan struct{})
	go func() { defer close(closed); f.client.Close() }()
	t.Cleanup(func() { unblock(); awaitNegotiation(t, closed) })
	awaitNegotiation(t, canceled)
	select {
	case <-closed:
		t.Error("Close returned before admitted handler joined")
	case <-f.clientDone:
		t.Error("ConnectAndServe returned before admitted handler joined")
	case <-time.After(20 * time.Millisecond):
	}
	unblock()
	awaitNegotiation(t, closed)
	awaitNegotiation(t, called)
	awaitNegotiation(t, f.clientDone)
}
