package rpc

import (
	"context"
	"encoding/base64"
	"github.com/hashicorp/yamux"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/netsec-ethz/debuglet/internal/controlrpc"
	"github.com/netsec-ethz/debuglet/internal/controlsession"
	pb "github.com/netsec-ethz/debuglet/protocol"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

func lifecycleDirectClient(t *testing.T, peer *lifecyclePeerOwner) pb.DispatcherServiceClient {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), sessionTestWait)
	defer cancel()
	if err := peer.client.WaitReadyContext(ctx); err != nil {
		t.Fatal(err)
	}
	binding, ok := peer.client.Binding()
	if !ok {
		t.Fatal("negotiated peer has no binding")
	}
	client, err := peer.client.ClientFor(binding)
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func TestControlMetadataBothChannels(t *testing.T) {
	state := newLifecycleState()
	f := newLifecycleFixture(t, state, nil)
	peer := &lifecyclePeer{id: "executor", version: "bound"}
	owned := f.peer(peer)
	owner := f.connected("bound")
	direct := lifecycleDirectClient(t, owned)
	ctx, cancel := context.WithTimeout(context.Background(), sessionTestWait)
	defer cancel()
	// Wrappers replace caller-supplied reserved keys without mutating its MD.
	polluted := metadata.Pairs(controlrpc.VersionKey, "bad", controlrpc.VersionKey, "duplicate", "unrelated", "kept")
	if _, err := direct.Heartbeat(metadata.NewOutgoingContext(ctx, polluted), &pb.HeartbeatRequest{ExecutorId: owner.ExecutorID()}); err != nil {
		t.Fatal(err)
	}
	if len(polluted.Get(controlrpc.VersionKey)) != 2 {
		t.Fatal("wrapper changed caller metadata")
	}
	f.b.mu.RLock()
	conn := f.b.clients[owner.ExecutorID()]
	credentials := conn.offer.credentials
	f.b.mu.RUnlock()
	rawConn, err := grpc.NewClient(f.direct.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	defer rawConn.Close()
	rawDirect, rawReverse := pb.NewDispatcherServiceClient(rawConn), pb.NewExecutorServiceClient(conn.gconn)
	if _, err := rawDirect.Heartbeat(ctx, &pb.HeartbeatRequest{}); status.Code(err) != codes.FailedPrecondition {
		t.Fatal("missing metadata bypassed the binding failure classification")
	}
	if _, err := rawDirect.Heartbeat(credentials.Outgoing(ctx), &pb.HeartbeatRequest{}); status.Code(err) != codes.PermissionDenied {
		t.Fatal("empty executor claim was accepted")
	}
	if _, err := rawDirect.BindSession(credentials.Outgoing(ctx), &pb.BindSessionRequest{ExecutorId: owner.ExecutorID()}); err != nil {
		t.Fatal("exact repeated confirmation failed")
	}
	if state.connectedCount() != 1 {
		t.Fatal("repeated confirmation reran registration")
	}

	valid, _ := metadata.FromOutgoingContext(credentials.Outgoing(ctx))
	cases := []struct {
		name string
		edit func(metadata.MD)
		code codes.Code
	}{
		{"missing", func(md metadata.MD) { md.Delete(controlrpc.TokenKey) }, codes.FailedPrecondition},
		{"duplicate", func(md metadata.MD) { md.Append(controlrpc.TokenKey, "private-extra") }, codes.InvalidArgument},
		{"version", func(md metadata.MD) { md.Set(controlrpc.VersionKey, "1") }, codes.FailedPrecondition},
		{"uuid", func(md metadata.MD) { md.Set(controlrpc.IncarnationKey, "private-malformed-uuid") }, codes.InvalidArgument},
		{"token_padding", func(md metadata.MD) {
			md.Set(controlrpc.TokenKey, base64.URLEncoding.EncodeToString(credentials.Token[:]))
		}, codes.InvalidArgument},
		{"token", func(md metadata.MD) {
			md.Set(controlrpc.TokenKey, base64.RawURLEncoding.EncodeToString(make([]byte, 32)))
		}, codes.FailedPrecondition},
		{"session", func(md metadata.MD) { md.Set(controlrpc.SessionIDKey, "00000000-0000-4000-8000-000000000099") }, codes.FailedPrecondition},
		{"incarnation", func(md metadata.MD) { md.Set(controlrpc.IncarnationKey, "00000000-0000-4000-8000-000000000099") }, codes.FailedPrecondition},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			md := valid.Copy()
			tc.edit(md)
			callCtx := metadata.NewOutgoingContext(ctx, md)
			_, err := rawDirect.Resources(callCtx, &pb.ResourcesRequest{ExecutorId: owner.ExecutorID()})
			checkControlStatus(t, err, tc.code, md)
			_, err = rawReverse.Abort(callCtx, &pb.AbortRequest{DebugletId: "fixture"})
			checkControlStatus(t, err, tc.code, md)
		})
	}
	if state.resources.Load() != 0 || peer.aborts.Load() != 0 {
		t.Fatal("rejected metadata reached an effect callback")
	}
	if _, err := rawDirect.Resources(credentials.Outgoing(ctx), &pb.ResourcesRequest{ExecutorId: "another-executor"}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("wrong claimed executor: %v", err)
	}
	if _, err := rawReverse.Bandwidth(credentials.Outgoing(ctx), &pb.BandwidthRequest{}); err != nil {
		t.Fatal(err)
	}
	if peer.bandwidths.Load() != 1 {
		t.Fatal("valid reverse mutation did not reach exact peer")
	}
}

func checkControlStatus(t *testing.T, err error, want codes.Code, md metadata.MD) {
	t.Helper()
	if status.Code(err) != want {
		t.Fatalf("status=%v want=%v", status.Code(err), want)
	}
	for _, key := range controlrpc.Keys() {
		for _, value := range md.Get(key) {
			if len(value) > 3 && strings.Contains(err.Error(), value) {
				t.Fatal("control status exposed supplied metadata")
			}
		}
	}
}

func TestControlBindingArmedBeforeAcknowledgement(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	interceptor := grpc.UnaryInterceptor(func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		out, err := handler(ctx, req)
		if info.FullMethod == pb.DispatcherService_BindSession_FullMethodName && err == nil {
			close(entered)
			select {
			case <-release:
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		return out, err
	})
	f := newLifecycleFixture(t, newLifecycleState(), nil, interceptor)
	f.releases = append(f.releases, unblock)
	received := make(chan controlsession.Binding, 1)
	peer := f.peer(&lifecyclePeer{id: "executor", version: "preack", upload: func(_ context.Context, binding controlsession.Binding, _ *pb.UploadRequest) error {
		received <- binding
		return nil
	}})
	owner := f.connected("preack")
	awaitSessionSignal(t, entered)
	binding, ok := peer.client.Binding()
	if !ok || binding != owner.Binding() {
		t.Fatal("reverse binding was not armed before acknowledgement")
	}
	if _, err := peer.client.ClientFor(binding); err == nil {
		t.Fatal("ordinary direct client escaped before acknowledgement")
	}
	short, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	if err := peer.client.WaitReadyContext(short); err == nil {
		cancel()
		t.Fatal("ready before acknowledgement")
	}
	cancel()
	client, ok := f.b.GetClientFor(owner)
	if !ok {
		t.Fatal("dispatcher did not activate confirmed candidate")
	}
	ctx, cancel := context.WithTimeout(context.Background(), sessionTestWait)
	defer cancel()
	if _, err := client.Upload(ctx, &pb.UploadRequest{Id: "fixture", ControlBinding: &pb.ControlBinding{DispatcherIncarnation: binding.Incarnation, SessionId: binding.SessionID}}); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-received:
		if got != binding {
			t.Fatal("pre-ack Upload changed binding")
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	unblock()
	lifecycleDirectClient(t, peer)
}

func TestControlReplacementRetainsAllPredecessors(t *testing.T) {
	state := newLifecycleState()
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	state.heartbeat = func(_ context.Context, ticket *Mutation, _ *pb.HeartbeatRequest) error {
		close(entered)
		<-release
		if !ticket.Live() {
			return controlrpc.Unavailable()
		}
		return nil
	}
	f := newLifecycleFixture(t, state, nil)
	f.releases = append(f.releases, unblock)
	first := f.peer(&lifecyclePeer{id: "same", version: "A"})
	a := f.connected("A")
	client := lifecycleDirectClient(t, first)
	ctx, cancel := context.WithTimeout(context.Background(), sessionTestWait)
	defer cancel()
	done := startLifecycleCall(t, unblock, func() { _, _ = client.Heartbeat(ctx, &pb.HeartbeatRequest{ExecutorId: "same"}) })
	awaitSessionSignal(t, entered)
	f.peer(&lifecyclePeer{id: "same", version: "B"})
	awaitSessionSignal(t, a.Done())
	// Publication retires A before any B callback can enter. Capture B from the
	// real lane after its publication, then use that retirement to order C.
	f.b.mu.RLock()
	b := f.b.clients["same"].owner
	f.b.mu.RUnlock()
	if b == nil || b == a {
		t.Fatal("replacement B was not published")
	}
	f.peer(&lifecyclePeer{id: "same", version: "C"})
	awaitSessionSignal(t, b.Done())
	f.b.mu.RLock()
	c := f.b.clients["same"].owner
	f.b.mu.RUnlock()
	if c == nil || c == b || c.Available() {
		t.Fatal("C did not retain A's outstanding mutation")
	}
	f.peer(&lifecyclePeer{id: "sibling", version: "sibling"})
	f.connected("sibling")
	select {
	case event := <-state.connected:
		t.Fatalf("replacement crossed A's actual handler: %s", event.version)
	default:
	}
	unblock()
	awaitSessionSignal(t, done)
	current := f.connected("C")
	if current != c {
		t.Fatal("wrong replacement activated")
	}
	if _, ok := f.b.GetClientFor(a); ok {
		t.Fatal("old exact owner acquired replacement client")
	}
	if _, ok := f.b.GetClientFor(b); ok {
		t.Fatal("intermediate owner acquired replacement client")
	}
	f.shutdown()
	f.b.mu.RLock()
	defer f.b.mu.RUnlock()
	if len(f.b.lanes) != 0 || len(f.b.offers) != 0 || len(f.b.clients) != 0 {
		t.Fatal("joined shutdown retained session tombstones")
	}
}

func reflectedControlStatus(ctx context.Context) error {
	md, _ := metadata.FromIncomingContext(ctx)
	token := md.Get(controlrpc.TokenKey)[0]
	st := status.New(codes.ResourceExhausted, "peer capacity exhausted; credential="+token)
	st, err := st.WithDetails(&errdetails.ErrorInfo{Reason: "private detail", Metadata: map[string]string{"credential": token}}, &errdetails.DebugInfo{Detail: "safe capacity diagnostic"})
	if err != nil {
		return status.Error(codes.Internal, "fixture could not construct status")
	}
	return st.Err()
}

func TestBoundClientsRedactReflectedPeerStatus(t *testing.T) {
	state := newLifecycleState()
	state.heartbeat = func(ctx context.Context, _ *Mutation, _ *pb.HeartbeatRequest) error {
		return reflectedControlStatus(ctx)
	}
	state.stream = func(_ *SessionOwner, stream grpc.BidiStreamingServer[pb.DebugletStreamRequest, pb.DebugletStreamResponse]) error {
		return reflectedControlStatus(stream.Context())
	}
	f := newLifecycleFixture(t, state, nil)
	peer := f.peer(&lifecyclePeer{id: "executor", version: "reflected", bandwidth: reflectedControlStatus})
	owner := f.connected("reflected")
	direct := lifecycleDirectClient(t, peer)
	f.b.mu.RLock()
	credential := f.b.clients[owner.ExecutorID()].offer.credentials
	f.b.mu.RUnlock()
	ctx, cancel := context.WithTimeout(context.Background(), sessionTestWait)
	defer cancel()
	_, directErr := direct.Heartbeat(ctx, &pb.HeartbeatRequest{ExecutorId: owner.ExecutorID()})
	reverse, ok := f.b.GetClientFor(owner)
	if !ok {
		t.Fatal("bound reverse client missing")
	}
	_, reverseErr := reverse.Bandwidth(ctx, &pb.BandwidthRequest{})
	stream, err := direct.DebugletStream(ctx)
	if err != nil {
		t.Fatal("stream did not open")
	}
	_, streamErr := stream.Recv()
	for _, got := range []error{directErr, reverseErr, streamErr} {
		if status.Code(got) != codes.ResourceExhausted {
			t.Fatalf("redaction changed status code: %v", status.Code(got))
		}
		if !strings.Contains(got.Error(), "peer capacity exhausted") || !strings.Contains(got.Error(), "[redacted]") {
			t.Fatal("redaction lost useful diagnostic or omitted marker")
		}
		encoded := base64.RawURLEncoding.EncodeToString(credential.Token[:])
		if strings.Contains(got.Error(), encoded) {
			t.Fatal("bound error exposed reflected credential")
		}
		st := status.Convert(got)
		if strings.Contains(st.Message(), encoded) || len(st.Details()) != 1 {
			t.Fatal("projected status retained credential or lost safe detail")
		}
		if detail, ok := st.Details()[0].(*errdetails.DebugInfo); !ok || detail.Detail != "safe capacity diagnostic" {
			t.Fatal("safe status detail changed")
		}
		if unwrap, ok := got.(interface{ Unwrap() error }); ok && unwrap.Unwrap() != nil {
			t.Fatal("sanitized error retained original credential through Unwrap")
		}
	}
}

type rejectedHelloPeer struct {
	pb.UnimplementedExecutorServiceServer
	version uint32
	entered chan struct{}
}

func (p *rejectedHelloPeer) Hello(_ context.Context, req *pb.HelloRequest) (*pb.HelloResponse, error) {
	close(p.entered)
	different := req.SessionId[:35] + "0"
	if different == req.SessionId {
		different = req.SessionId[:35] + "1"
	}
	return &pb.HelloResponse{ExecutorId: "same", ControlVersion: p.version, DispatcherIncarnation: req.DispatcherIncarnation, SessionId: different, LeaseDurationMs: req.LeaseDurationMs}, nil
}

func TestDispatcherRejectsUnboundHelloBeforeReplacement(t *testing.T) {
	for _, version := range []uint32{0, controlsession.ProtocolVersion} {
		t.Run(map[uint32]string{0: "legacy", controlsession.ProtocolVersion: "wrong_echo"}[version], func(t *testing.T) {
			f := newLifecycleFixture(t, newLifecycleState(), nil)
			healthy := &lifecyclePeer{id: "same", version: "healthy"}
			f.peer(healthy)
			owner := f.connected("healthy")
			raw, err := net.DialTimeout("tcp", f.lis.Addr().String(), time.Second)
			if err != nil {
				t.Fatal(err)
			}
			session, err := yamux.Client(raw, nil)
			if err != nil {
				raw.Close()
				t.Fatal(err)
			}
			peer := &rejectedHelloPeer{version: version, entered: make(chan struct{})}
			server := grpc.NewServer(grpc.WaitForHandlers(true))
			pb.RegisterExecutorServiceServer(server, peer)
			joined := make(chan struct{})
			t.Cleanup(func() { raw.Close(); session.Close(); server.Stop(); awaitSessionSignal(t, joined) })
			go func() { defer close(joined); _ = server.Serve(session) }()
			awaitSessionSignal(t, peer.entered)
			awaitSessionSignal(t, joined)
			if !owner.Available() || f.state.connectedCount() != 1 {
				t.Fatal("unsupported or mismatched Hello replaced a healthy owner")
			}
			f.abort("same", healthy)
		})
	}
}
