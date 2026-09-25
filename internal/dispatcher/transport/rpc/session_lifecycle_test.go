package rpc

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/netsec-ethz/debuglet/internal/controlsession"
	executorrpc "github.com/netsec-ethz/debuglet/internal/executor/transport/rpc"
	pb "github.com/netsec-ethz/debuglet/protocol"
	"go.uber.org/zap"
	"google.golang.org/grpc"
)

const sessionTestWait = 8 * time.Second

// The only intentionally permanent lock-cycle mutation runs in an owned child.
// Its timeout is a failure; the parent's Run joins the killed process and pipes.
func TestBidiDuplicateIDReplacement(t *testing.T) {
	if os.Getenv("DEBUGLET_SESSION_REPLACEMENT_HELPER") == "1" {
		testDuplicateIDReplacement(t)
		return
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, executable, "-test.run=^TestBidiDuplicateIDReplacement$", "-test.count=1", "-test.timeout=1m", "-test.v")
	cmd.Env = append(os.Environ(), "DEBUGLET_SESSION_REPLACEMENT_HELPER=1")
	cmd.WaitDelay = time.Second
	output := &sessionTestOutput{}
	cmd.Stdout, cmd.Stderr = output, output
	err = cmd.Run()
	if ctx.Err() != nil {
		t.Fatalf("duplicate-ID session scenario did not complete before parent deadline; owned child killed and waited: %v\n%s", err, output.String())
	}
	if err != nil {
		t.Fatalf("duplicate-ID session scenario failed: %v\n%s", err, output.String())
	}
}

func testDuplicateIDReplacement(t *testing.T) {
	state := newLifecycleState()
	var old, spare, siblingOwner atomic.Pointer[SessionOwner]
	var b *BidiServer
	reentered := make(chan error, 1)
	state.disconnect = func(owner *SessionOwner) {
		if owner != old.Load() {
			return
		}
		_, sibling := b.GetClientFor(siblingOwner.Load())
		removed := b.RemoveClient(spare.Load())
		if !sibling || !removed {
			reentered <- fmt.Errorf("reentrant lookup/removal=%v/%v", sibling, removed)
		} else {
			reentered <- nil
		}
	}
	f := newLifecycleFixture(t, state, nil)
	b = f.b
	f.peer(&lifecyclePeer{id: "sibling", version: "sibling"})
	siblingOwner.Store(f.connected("sibling"))
	f.peer(&lifecyclePeer{id: "spare", version: "spare"})
	spare.Store(f.connected("spare"))
	first := &lifecyclePeer{id: "duplicate", version: "A"}
	f.peer(first)
	old.Store(f.connected("A"))
	second := &lifecyclePeer{id: "duplicate", version: "B"}
	f.peer(second)
	current := f.connected("B")
	awaitSessionSignal(t, old.Load().Done())
	if old.Load().Available() || current == old.Load() {
		t.Fatal("replacement did not retire the distinct old owner")
	}
	if b.RemoveClient(old.Load()) {
		t.Fatal("stale removal matched replacement")
	}
	select {
	case err := <-reentered:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(sessionTestWait):
		t.Fatal("old disconnect callback did not complete its reentrant operations")
	}
	f.disconnected(old.Load())
	f.abort("duplicate", second)
	f.abort("sibling", nil)
	f.shutdown()
	if state.disconnectCount(old.Load()) != 1 || state.disconnectCount(current) != 1 {
		t.Fatal("published candidate disconnected more or less than once")
	}
}

func TestBidiDelayedHelloPublicationOrder(t *testing.T) {
	state := newLifecycleState()
	f := newLifecycleFixture(t, state, nil)
	entered, release := f.gate()
	first := &lifecyclePeer{id: "duplicate", version: "A", hello: func(ctx context.Context) error {
		close(entered)
		select {
		case <-release:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}}
	f.peer(first)
	awaitSessionSignal(t, entered)
	second := &lifecyclePeer{id: "duplicate", version: "B"}
	f.peer(second)
	ownerB := f.connected("B")
	f.abort("duplicate", second)
	f.releaseGate(release)
	ownerA := f.connected("A")
	awaitSessionSignal(t, ownerB.Done())
	if ownerA == ownerB || ownerB.Active() || !ownerA.Available() {
		t.Fatal("later successful Hello publication did not win")
	}
	f.abort("duplicate", first)
	f.disconnected(ownerB)
	if f.b.RemoveClient(ownerB) {
		t.Fatal("delayed old removal replaced the Hello winner")
	}

	// A separate real Hello is held until listener cancellation. It must never
	// acquire a published owner or leave the serving invocation unjoined.
	helloEntered, helloJoined := make(chan struct{}), make(chan struct{})
	f.peer(&lifecyclePeer{id: "unpublished", version: "held", hello: func(ctx context.Context) error {
		defer close(helloJoined)
		close(helloEntered)
		<-ctx.Done()
		return ctx.Err()
	}})
	awaitSessionSignal(t, helloEntered)
	f.shutdown()
	awaitSessionSignal(t, helloJoined)
	if state.connectedCount() != 2 {
		t.Fatal("canceled Hello acquired a published owner")
	}
}

func TestBidiHelloDeadline(t *testing.T) {
	state := newLifecycleState()
	f := newLifecycleFixture(t, state, nil)
	deadline := make(chan time.Duration, 1)
	joined := make(chan struct{})
	f.peer(&lifecyclePeer{id: "held", hello: func(ctx context.Context) error {
		defer close(joined)
		when, ok := ctx.Deadline()
		if !ok {
			deadline <- -1
		} else {
			deadline <- time.Until(when)
		}
		<-ctx.Done()
		return ctx.Err()
	}})
	select {
	case remaining := <-deadline:
		if remaining <= 0 || remaining > 5*time.Second {
			t.Fatalf("Hello deadline=%v", remaining)
		}
	case <-time.After(sessionTestWait):
		t.Fatal("real Hello was not invoked")
	}
	awaitSessionSignal(t, joined)
	f.shutdown()
	if state.connectedCount() != 0 {
		t.Fatal("failed Hello reached Connected")
	}
}

func TestBidiRejectedHelloDoesNotPublish(t *testing.T) {
	state := newLifecycleState()
	f := newLifecycleFixture(t, state, nil)
	peer := f.peer(&lifecyclePeer{version: "empty-ID"})
	awaitSessionSignal(t, peer.joined)
	if state.connectedCount() != 0 {
		t.Fatal("invalid Hello reached Connected")
	}
	if _, ok := f.b.GetClientFor(nil); ok {
		t.Fatal("invalid Hello published a client")
	}
}

func TestBidiClosedListenerAdmission(t *testing.T) {
	for _, mode := range []string{"grpc", "yamux"} {
		t.Run(mode, func(t *testing.T) {
			b := newTestBidiServer(t, zap.NewNop(), nil, "00000000-0000-4000-8000-000000000001")
			b.Close()
			lis, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer lis.Close()
			if mode == "grpc" {
				err = b.ServeGRPCListener(context.Background(), lis)
			} else {
				err = b.ServeYamux(context.Background(), lis)
			}
			if !errors.Is(err, net.ErrClosed) {
				t.Fatalf("post-close invocation=%v", err)
			}
			lis.(*net.TCPListener).SetDeadline(time.Now().Add(time.Second))
			if _, err := lis.Accept(); !errors.Is(err, net.ErrClosed) {
				t.Fatalf("rejected invocation retained listener: %v", err)
			}
		})
	}
}

func TestBidiRegistrationAvailabilityAndFailure(t *testing.T) {
	t.Run("held_callback_retirement", func(t *testing.T) {
		state := newLifecycleState()
		release := make(chan struct{})
		var releaseOnce sync.Once
		unblock := func() { releaseOnce.Do(func() { close(release) }) }
		canceled := make(chan struct{})
		state.connect = func(ctx context.Context, owner *SessionOwner, hello *pb.HelloResponse) error {
			if hello.Version != "held" {
				return nil
			}
			<-ctx.Done()
			close(canceled)
			<-release // Deliberately ignore cancellation until the test releases us.
			return nil
		}
		f := newLifecycleFixture(t, state, nil)
		f.releases = append(f.releases, unblock)
		f.peer(&lifecyclePeer{id: "duplicate", version: "held"})
		old := f.connectionEntered("held")
		if old.Available() {
			t.Fatal("callback entry made owner available")
		}
		if _, ok := f.b.GetClientFor(old); ok {
			t.Fatal("client became available before Connected returned")
		}
		currentPeer := &lifecyclePeer{id: "duplicate", version: "current"}
		f.peer(currentPeer)
		awaitSessionSignal(t, canceled)
		select {
		case event := <-state.connected:
			t.Fatalf("replacement crossed held predecessor setup: %s", event.version)
		default:
		}
		unblock()
		current := f.connected("current")
		f.abort("duplicate", currentPeer)
		if f.b.RemoveClient(old) || current == old {
			t.Fatal("retired callback owns current connection")
		}
		f.disconnected(old)
		select {
		case <-old.Registered():
			t.Fatal("retired successful callback marked registration")
		default:
		}
		if !current.Available() {
			t.Fatal("delayed old callback removed replacement")
		}
	})
	t.Run("callback_error", func(t *testing.T) {
		state := newLifecycleState()
		state.connect = func(context.Context, *SessionOwner, *pb.HelloResponse) error {
			return errors.New("scripted registration failure")
		}
		f := newLifecycleFixture(t, state, nil)
		f.peer(&lifecyclePeer{id: "rejected", version: "rejected"})
		owner := f.connectionEntered("rejected")
		f.disconnected(owner)
		if owner.Active() || owner.Available() {
			t.Fatal("failed callback retained active owner")
		}
		if _, ok := f.b.GetClientFor(owner); ok {
			t.Fatal("failed callback retained client")
		}
		select {
		case <-owner.Registered():
			t.Fatal("failed callback signaled registration")
		default:
		}
	})
}

func TestBidiHeldCloseDoesNotHoldRegistryLocks(t *testing.T) {
	state := newLifecycleState()
	closeEntered, closeRelease := make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(closeRelease) }) }
	var accepted atomic.Int32
	f := newLifecycleFixture(t, state, func(conn net.Conn) net.Conn {
		if accepted.Add(1) == 1 {
			return &heldSessionConn{Conn: conn, entered: closeEntered, release: closeRelease}
		}
		return conn
	})
	f.releases = append(f.releases, release)
	f.peer(&lifecyclePeer{id: "duplicate", version: "A"})
	old := f.connected("A")
	second := &lifecyclePeer{id: "duplicate", version: "B"}
	f.peer(second)
	awaitSessionSignal(t, closeEntered)
	current := f.connected("B")
	f.peer(&lifecyclePeer{id: "unrelated", version: "C"})
	f.connected("C")
	f.abort("duplicate", second)
	f.abort("unrelated", nil)
	if f.b.RemoveClient(old) || !current.Available() {
		t.Fatal("old held cleanup affected current session")
	}

	firstClose := startLifecycleCall(t, release, f.b.Close)
	awaitSessionSignal(t, f.b.stop)
	secondClose := startLifecycleCall(t, release, f.b.Close)
	select {
	case <-firstClose:
		t.Error("Close returned before owned resource Close joined")
	case <-secondClose:
		t.Error("concurrent Close did not join the first caller")
	case <-time.After(20 * time.Millisecond):
	}
	release()
	awaitSessionSignal(t, firstClose)
	awaitSessionSignal(t, secondClose)
	f.shutdown()
	if state.disconnectCount(old) != 1 || state.disconnectCount(current) != 1 {
		t.Fatal("held cleanup lost or repeated disconnected callback")
	}
}

func TestBidiCloseJoinsListenerInvocations(t *testing.T) {
	for _, mode := range []string{"grpc", "yamux"} {
		t.Run(mode, func(t *testing.T) {
			lis, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			entered, release := make(chan struct{}), make(chan struct{})
			var once sync.Once
			unblock := func() { once.Do(func() { close(release) }) }
			tracked := &heldSessionListener{Listener: lis, accepting: make(chan struct{}), entered: entered, release: release}
			b := newTestBidiServer(t, zap.NewNop(), nil, "00000000-0000-4000-8000-000000000001")
			rescue := func() { unblock(); b.Close() }
			served := startLifecycleCall(t, rescue, func() {
				var err error
				if mode == "grpc" {
					err = b.ServeGRPCListener(context.Background(), tracked)
				} else {
					err = b.ServeYamux(context.Background(), tracked)
				}
				if err != nil {
					t.Errorf("Serve returned %v", err)
				}
			})
			awaitSessionSignal(t, tracked.accepting)
			closed := startLifecycleCall(t, rescue, b.Close)
			awaitSessionSignal(t, entered)
			select {
			case <-closed:
				t.Error("Close omitted admitted listener invocation")
			case <-time.After(20 * time.Millisecond):
			}
			unblock()
			awaitSessionSignal(t, closed)
			awaitSessionSignal(t, served)
			if tracked.closes.Load() != 1 {
				t.Fatalf("listener release repeated %d times", tracked.closes.Load())
			}
			lis.(*net.TCPListener).SetDeadline(time.Now().Add(time.Second))
			if _, err := lis.Accept(); !errors.Is(err, net.ErrClosed) {
				t.Fatalf("listener survived joined Close: %v", err)
			}
		})
	}
}

type lifecycleEvent struct {
	owner       *SessionOwner
	version, ip string
}

type lifecycleState struct {
	DispatcherState
	connect     func(context.Context, *SessionOwner, *pb.HelloResponse) error
	heartbeat   func(context.Context, *Mutation, *pb.HeartbeatRequest) error
	stream      func(*SessionOwner, grpc.BidiStreamingServer[pb.DebugletStreamRequest, pb.DebugletStreamResponse]) error
	heartbeats  atomic.Int32
	resources   atomic.Int32
	disconnect  func(*SessionOwner)
	connected   chan lifecycleEvent
	mu          sync.Mutex
	connections int
	disconnects map[*SessionOwner]int
	changed     chan struct{}
}

func newLifecycleState() *lifecycleState {
	return &lifecycleState{connected: make(chan lifecycleEvent, 8), disconnects: make(map[*SessionOwner]int), changed: make(chan struct{})}
}
func (s *lifecycleState) OnExecutorConnected(ctx context.Context, owner *SessionOwner, hello *pb.HelloResponse, ip string) error {
	s.mu.Lock()
	s.connections++
	s.mu.Unlock()
	s.connected <- lifecycleEvent{owner: owner, version: hello.Version, ip: ip}
	if s.connect != nil {
		return s.connect(ctx, owner, hello)
	}
	return nil
}
func (s *lifecycleState) OnExecutorDisconnected(owner *SessionOwner) {
	if s.disconnect != nil {
		s.disconnect(owner)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.disconnects[owner]++
	close(s.changed)
	s.changed = make(chan struct{})
}
func (s *lifecycleState) disconnectCount(owner *SessionOwner) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.disconnects[owner]
}
func (s *lifecycleState) connectedCount() int { s.mu.Lock(); defer s.mu.Unlock(); return s.connections }

func (s *lifecycleState) OnHeartbeat(ctx context.Context, ticket *Mutation, req *pb.HeartbeatRequest) (*pb.HeartbeatResponse, error) {
	s.heartbeats.Add(1)
	if s.heartbeat != nil {
		if err := s.heartbeat(ctx, ticket, req); err != nil {
			return nil, err
		}
	}
	return &pb.HeartbeatResponse{}, nil
}
func (s *lifecycleState) OnDebugletStream(owner *SessionOwner, stream grpc.BidiStreamingServer[pb.DebugletStreamRequest, pb.DebugletStreamResponse]) error {
	if s.stream != nil {
		return s.stream(owner, stream)
	}
	return nil
}
func (s *lifecycleState) OnResources(context.Context, *Mutation, *pb.ResourcesRequest) (*pb.ResourcesResponse, error) {
	s.resources.Add(1)
	return &pb.ResourcesResponse{}, nil
}

type lifecyclePeer struct {
	executorrpc.ExecutorState
	id, version string
	token       string // Enrollment token this peer presents in its Hello.
	hello       func(context.Context) error
	aborts      atomic.Int32
	uploads     atomic.Int32
	bandwidths  atomic.Int32
	upload      func(context.Context, controlsession.Binding, *pb.UploadRequest) error
	bandwidth   func(context.Context) error
}

func (p *lifecyclePeer) OnHello(ctx context.Context, _ *pb.HelloRequest) (*pb.HelloResponse, error) {
	if p.hello != nil {
		if err := p.hello(ctx); err != nil {
			return nil, err
		}
	}
	out := &pb.HelloResponse{ExecutorId: p.id, Version: p.version, SourceIp: "192.0.2.77"}
	if p.token != "" {
		out.EnrollmentToken = &p.token
	}
	return out, nil
}
func (p *lifecyclePeer) OnAbort(context.Context, controlsession.Binding, *pb.AbortRequest) (*pb.AbortResponse, error) {
	p.aborts.Add(1)
	return &pb.AbortResponse{}, nil
}

func (p *lifecyclePeer) OnUpload(ctx context.Context, binding controlsession.Binding, req *pb.UploadRequest) (*pb.UploadResponse, error) {
	p.uploads.Add(1)
	if p.upload != nil {
		if err := p.upload(ctx, binding, req); err != nil {
			return nil, err
		}
	}
	return &pb.UploadResponse{}, nil
}
func (p *lifecyclePeer) OnBandwidth(ctx context.Context, _ controlsession.Binding, _ *pb.BandwidthRequest) (*pb.BandwidthResponse, error) {
	p.bandwidths.Add(1)
	if p.bandwidth != nil {
		if err := p.bandwidth(ctx); err != nil {
			return nil, err
		}
	}
	return &pb.BandwidthResponse{}, nil
}

type lifecyclePeerOwner struct {
	client *executorrpc.BidiClient
	joined chan struct{}
}
type lifecycleFixture struct {
	t            *testing.T
	b            *BidiServer
	state        *lifecycleState
	lis          net.Listener
	direct       net.Listener
	directServed chan struct{}
	directErr    error
	ctx          context.Context
	owners       map[string]*SessionOwner
	cancel       context.CancelFunc
	served       chan struct{}
	serveErr     error
	peers        []*lifecyclePeerOwner
	releases     []func()
	gates        map[<-chan struct{}]func()
	stopOnce     sync.Once
}

func newLifecycleFixture(t *testing.T, state *lifecycleState, transform func(net.Conn) net.Conn, options ...grpc.ServerOption) *lifecycleFixture {
	return newLeaseLifecycleFixture(t, state, time.Minute, time.Now, nil, transform, options...)
}

func newLeaseLifecycleFixture(t *testing.T, state *lifecycleState, duration time.Duration, now func() time.Time, directTransform, transform func(net.Conn) net.Conn, options ...grpc.ServerOption) *lifecycleFixture {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	direct, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		lis.Close()
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	transport, err := NewBidiServerWithClock(zap.NewNop(), state, "00000000-0000-4000-8000-000000000001", duration, now)
	if err != nil {
		cancel()
		lis.Close()
		direct.Close()
		t.Fatal(err)
	}
	f := &lifecycleFixture{t: t, b: transport, state: state, lis: lis, cancel: cancel, served: make(chan struct{}), gates: make(map[<-chan struct{}]func())}
	t.Cleanup(f.shutdown)
	f.ctx = ctx
	f.owners = make(map[string]*SessionOwner)
	f.direct = direct
	if len(options) != 0 {
		f.b.grpcServer.Stop()
		f.b.grpcServer = grpc.NewServer(append([]grpc.ServerOption{grpc.WaitForHandlers(true)}, options...)...)
		pb.RegisterDispatcherServiceServer(f.b.grpcServer, &server{state: state, bidi: f.b})
	}
	f.directServed = make(chan struct{})
	go func() {
		defer close(f.directServed)
		f.directErr = f.b.ServeGRPCListener(ctx, &sessionTransformListener{Listener: f.direct, transform: directTransform})
	}()
	go func() {
		defer close(f.served)
		f.serveErr = f.b.ServeYamux(ctx, &sessionTransformListener{Listener: lis, transform: transform})
	}()
	return f
}
func (f *lifecycleFixture) gate() (chan struct{}, <-chan struct{}) {
	entered, gate := make(chan struct{}), make(chan struct{})
	var once sync.Once
	release := func() { once.Do(func() { close(gate) }) }
	f.releases = append(f.releases, release)
	f.gates[gate] = release
	return entered, gate
}
func (f *lifecycleFixture) releaseGate(gate <-chan struct{}) { f.gates[gate]() }
func (f *lifecycleFixture) peer(peer *lifecyclePeer) *lifecyclePeerOwner {
	f.t.Helper()
	client, err := executorrpc.NewBidiClient(executorrpc.BidiOptions{Address: f.direct.Addr().String(), YamuxAddress: f.lis.Addr().String(), Logger: zap.NewNop()}, peer)
	if err != nil {
		f.t.Fatal(err)
	}
	owned := &lifecyclePeerOwner{client: client, joined: make(chan struct{})}
	f.peers = append(f.peers, owned)
	go func() { defer close(owned.joined); _ = client.ConnectAndServe(f.ctx) }()
	return owned
}
func (f *lifecycleFixture) connectionEntered(version string) *SessionOwner {
	f.t.Helper()
	select {
	case event := <-f.state.connected:
		if event.version != version || event.ip != "127.0.0.1" {
			f.t.Fatalf("Connected version/IP=%q/%q", event.version, event.ip)
		}
		f.owners[event.owner.ExecutorID()] = event.owner
		return event.owner
	case <-time.After(sessionTestWait):
		f.t.Fatalf("Connected(%s) did not enter", version)
	}
	return nil
}
func (f *lifecycleFixture) connected(version string) *SessionOwner {
	f.t.Helper()
	owner := f.connectionEntered(version)
	select {
	case <-owner.Registered():
	case <-owner.Done():
		f.t.Fatalf("owner %s retired before registration", version)
	case <-time.After(sessionTestWait):
		f.t.Fatalf("owner %s did not register", version)
	}
	if !owner.Available() {
		f.t.Fatalf("owner %s unavailable after registration", version)
	}
	return owner
}
func (f *lifecycleFixture) disconnected(owner *SessionOwner) {
	f.t.Helper()
	deadline := time.NewTimer(sessionTestWait)
	defer deadline.Stop()
	for {
		f.state.mu.Lock()
		count, changed := f.state.disconnects[owner], f.state.changed
		f.state.mu.Unlock()
		if count != 0 {
			if count != 1 {
				f.t.Errorf("owner disconnected %d times", count)
			}
			return
		}
		select {
		case <-changed:
		case <-deadline.C:
			f.t.Fatal("Disconnected did not complete")
		}
	}
}
func (f *lifecycleFixture) abort(id string, expected *lifecyclePeer) {
	f.t.Helper()
	client, ok := f.b.GetClientFor(f.owners[id])
	if !ok {
		f.t.Fatalf("client %s unavailable", id)
	}
	ctx, cancel := context.WithTimeout(context.Background(), sessionTestWait)
	defer cancel()
	// Server registration precedes the executor's Bind acknowledgement. Ordinary
	// reverse effects need that exact peer's confirmed lease; only Upload has a
	// pre-ack persistence exception. Do not replace this with a timing delay.
	confirmed := false
	for _, peer := range f.peers {
		binding, live := peer.client.Binding()
		if live && binding == f.owners[id].Binding() {
			if err := peer.client.WaitReadyContext(ctx); err != nil {
				f.t.Fatalf("exact peer confirmation: %v", err)
			}
			confirmed = true
			break
		}
	}
	if !confirmed {
		f.t.Fatal("ordinary reverse fixture has no exact owned peer")
	}

	var before int32
	if expected != nil {
		before = expected.aborts.Load()
	}
	if _, err := client.Abort(ctx, &pb.AbortRequest{DebugletId: "fixture"}); err != nil {
		f.t.Fatalf("actual reverse Abort: %v", err)
	}
	if expected != nil && expected.aborts.Load() != before+1 {
		f.t.Fatal("reverse RPC went to another session")
	}
}
func (f *lifecycleFixture) shutdown() {
	f.stopOnce.Do(func() {
		f.cancel()
		for _, release := range f.releases {
			release()
		}
		f.b.Close()
		for _, peer := range f.peers {
			peer.client.Close()
			awaitSessionSignal(f.t, peer.joined)
		}
		if f.directServed != nil {
			awaitSessionSignal(f.t, f.directServed)
			if f.directErr != nil {
				f.t.Errorf("ServeGRPC: %v", f.directErr)
			}
		}

		awaitSessionSignal(f.t, f.served)
		if f.serveErr != nil {
			f.t.Errorf("ServeYamux: %v", f.serveErr)
		}
	})
}

func awaitSessionSignal(t *testing.T, signal <-chan struct{}) {
	t.Helper()
	select {
	case <-signal:
	case <-time.After(sessionTestWait):
		t.Fatal("session fixture did not reach/join its owned boundary")
	}
}
func startLifecycleCall(t *testing.T, release func(), f func()) <-chan struct{} {
	t.Helper()
	joined := make(chan struct{})
	t.Cleanup(func() { release(); awaitSessionSignal(t, joined) })
	go func() { defer close(joined); f() }()
	return joined
}

type sessionTransformListener struct {
	net.Listener
	transform func(net.Conn) net.Conn
}

func (l *sessionTransformListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err == nil && l.transform != nil {
		conn = l.transform(conn)
	}
	return conn, err
}

type heldSessionConn struct {
	net.Conn
	once    sync.Once
	entered chan struct{}
	release <-chan struct{}
	err     error
}

func (c *heldSessionConn) Close() error {
	c.once.Do(func() { close(c.entered); <-c.release; c.err = c.Conn.Close() })
	return c.err
}

type heldSessionListener struct {
	net.Listener
	acceptOnce  sync.Once
	closeSignal sync.Once
	accepting   chan struct{}
	entered     chan struct{}
	release     <-chan struct{}
	closes      atomic.Int32
}

func (l *heldSessionListener) Accept() (net.Conn, error) {
	l.acceptOnce.Do(func() { close(l.accepting) })
	return l.Listener.Accept()
}
func (l *heldSessionListener) Close() error {
	l.closes.Add(1)
	l.closeSignal.Do(func() { close(l.entered) })
	<-l.release
	return l.Listener.Close()
}

type sessionTestOutput struct {
	mu   sync.Mutex
	data bytes.Buffer
}

func (o *sessionTestOutput) Write(p []byte) (int, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	n := len(p)
	if left := (64 << 10) - o.data.Len(); left > 0 {
		if len(p) > left {
			p = p[:left]
		}
		o.data.Write(p)
	}
	return n, nil
}
func (o *sessionTestOutput) String() string { o.mu.Lock(); defer o.mu.Unlock(); return o.data.String() }
