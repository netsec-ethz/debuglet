package dispatcher

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/netsec-ethz/debuglet/internal/dispatcher/models"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/resource"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/transport/rpc"
	erpc "github.com/netsec-ethz/debuglet/internal/executor/transport/rpc"
	"github.com/netsec-ethz/debuglet/internal/testpeer"
	pb "github.com/netsec-ethz/debuglet/protocol"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

const siBound = 5 * time.Second

// Gates surround the real callback, outside all production locks. They never
// replace registration, removal, expiry, or a transport with a mock.
type siPlan struct {
	before, after, beforeDisconnect <-chan struct{}
	entered                         chan *rpc.SessionOwner
	committed                       chan struct{}
	completed                       chan error
	disconnected                    chan struct{}
	control                         chan metadata.MD // Optional test-only observation of a real admitted call.
}

func siNewPlan() *siPlan {
	return &siPlan{entered: make(chan *rpc.SessionOwner, 1), committed: make(chan struct{}), completed: make(chan error, 1), disconnected: make(chan struct{})}
}

type siAdapter struct {
	rpc.DispatcherState
	plans  map[string]*siPlan // immutable after serving begins; keyed by version
	mu     sync.Mutex
	owners map[*rpc.SessionOwner]*siPlan
}

func (a *siAdapter) OnExecutorConnected(ctx context.Context, owner *rpc.SessionOwner, h *pb.HelloResponse, ip string) error {
	p := a.plans[h.GetVersion()]
	a.mu.Lock()
	a.owners[owner] = p
	a.mu.Unlock()
	p.entered <- owner
	if p.before != nil {
		<-p.before
	}
	err := a.DispatcherState.OnExecutorConnected(ctx, owner, h, ip)
	if err == nil {
		close(p.committed)
		if p.after != nil {
			<-p.after
		}
	}
	p.completed <- err
	return err
}

func (a *siAdapter) OnExecutorDisconnected(owner *rpc.SessionOwner) {
	a.mu.Lock()
	p := a.owners[owner]
	a.mu.Unlock()
	// A published candidate may retire while waiting for a predecessor, before
	// Connected ever entered this adapter. It still needs real registry cleanup.
	if p == nil {
		a.DispatcherState.OnExecutorDisconnected(owner)
		return
	}
	if p.beforeDisconnect != nil {
		<-p.beforeDisconnect
	}
	a.DispatcherState.OnExecutorDisconnected(owner)
	close(p.disconnected) // callback observation; harness shutdown joins its return
}

func (a *siAdapter) OnHeartbeat(ctx context.Context, mutation *rpc.Mutation, req *pb.HeartbeatRequest) (*pb.HeartbeatResponse, error) {
	resp, err := a.DispatcherState.OnHeartbeat(ctx, mutation, req)
	if err == nil {
		a.mu.Lock()
		plan := a.owners[mutation.Owner()]
		a.mu.Unlock()
		if plan != nil && plan.control != nil {
			md, _ := metadata.FromIncomingContext(ctx)
			select {
			case plan.control <- md.Copy():
			default:
			}
		}
	}
	return resp, err
}

type siPeer struct {
	pb.UnimplementedExecutorServiceServer
	id, version string
	client      *erpc.BidiClient
	bandwidth   chan struct{}
	joined      chan struct{}
}

func (p *siPeer) Hello(context.Context, *pb.HelloRequest) (*pb.HelloResponse, error) {
	return &pb.HelloResponse{ExecutorId: p.id, Version: p.version, Currency: "TEST", PricePerBwS: 1}, nil
}

func (p *siPeer) Bandwidth(context.Context, *pb.BandwidthRequest) (*pb.BandwidthResponse, error) {
	p.bandwidth <- struct{}{}
	return &pb.BandwidthResponse{}, nil
}

type siHarness struct {
	t             *testing.T
	d             *Dispatcher
	ctx           context.Context
	cancel        context.CancelFunc
	lis           net.Listener
	directAddress string
	direct        *grpc.ClientConn
	rpc           pb.DispatcherServiceClient
	peers         []*siPeer
	releases      []func()
	serves        sync.WaitGroup
	close         sync.Once
}

func siAwait(t *testing.T, ch <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(siBound):
		t.Fatalf("%s did not complete", what)
	}
}

func siNewHarness(t *testing.T, plans map[string]*siPlan, releases ...func()) *siHarness {
	t.Helper()
	return siNewHarnessFor(t, newTerminalPeerDispatcher(t), plans, releases...)
}

func siNewHarnessFor(t *testing.T, d *Dispatcher, plans map[string]*siPlan, releases ...func()) *siHarness {
	t.Helper()
	d.Bidi.Close() // replace only the original unused transport
	a := &siAdapter{DispatcherState: d, plans: plans, owners: make(map[*rpc.SessionOwner]*siPlan)}
	replacement, err := rpc.NewBidiServerWithClock(d.logger, a, d.ControlIncarnation(), d.ControlLeaseDuration(), d.now)
	if err != nil {
		t.Fatal(err)
	}
	d.Bidi = replacement
	ctx, cancel := context.WithCancel(context.Background())
	f := &siHarness{t: t, d: d, ctx: ctx, cancel: cancel, releases: releases}
	t.Cleanup(f.shutdown)
	f.lis, err = net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f.serves.Add(1)
	go func() {
		defer f.serves.Done()
		if err := d.Bidi.ServeYamux(ctx, f.lis); err != nil {
			t.Errorf("session fixture ServeYamux: %v", err)
		}
	}()
	grpcLis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f.serves.Add(1)
	go func() {
		defer f.serves.Done()
		if err := d.Bidi.ServeGRPCListener(ctx, grpcLis); err != nil && !errors.Is(err, grpc.ErrServerStopped) {
			t.Errorf("session fixture ServeGRPC: %v", err)
		}
	}()
	f.directAddress = grpcLis.Addr().String()
	f.direct, err = grpc.NewClient(f.directAddress, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	f.rpc = pb.NewDispatcherServiceClient(f.direct)
	return f
}

func siGate() (<-chan struct{}, func()) {
	ch := make(chan struct{})
	var once sync.Once
	release := func() { once.Do(func() { close(ch) }) }
	return ch, release
}

func (f *siHarness) shutdown() {
	f.close.Do(func() {
		// Release test-owned callbacks before joining any lifetime or database.
		for _, release := range f.releases {
			release()
		}
		f.cancel()
		if f.direct != nil {
			_ = f.direct.Close()
		}
		for _, p := range f.peers {
			p.client.Close()
			<-p.joined
		}
		f.d.Close()
		f.serves.Wait()
	})
}

func (f *siHarness) connect(id, version string) *siPeer {
	f.t.Helper()
	p := &siPeer{id: id, version: version, joined: make(chan struct{}), bandwidth: make(chan struct{}, 8)}
	var err error
	p.client, err = erpc.NewBidiClient(erpc.BidiOptions{Logger: f.d.logger, Address: f.directAddress, YamuxAddress: f.lis.Addr().String()}, testpeer.ExecutorState{Service: p})
	if err != nil {
		f.t.Fatal(err)
	}
	f.peers = append(f.peers, p)
	go func() { defer close(p.joined); _ = p.client.ConnectAndServe(f.ctx) }()
	return p
}

func (f *siHarness) boundClient(version string) pb.DispatcherServiceClient {
	f.t.Helper()
	for _, p := range f.peers {
		if p.version != version {
			continue
		}
		ctx, cancel := context.WithTimeout(f.ctx, siBound)
		defer cancel()
		if err := p.client.WaitReadyContext(ctx); err != nil {
			f.t.Fatal(err)
		}
		binding, ok := p.client.Binding()
		if !ok {
			f.t.Fatal("peer has no armed binding")
		}
		client, err := p.client.ClientFor(binding)
		if err != nil {
			f.t.Fatal(err)
		}
		return client
	}
	f.t.Fatal("no matching peer")
	return nil
}

func siEntered(t *testing.T, p *siPlan) *rpc.SessionOwner {
	t.Helper()
	select {
	case owner := <-p.entered:
		return owner
	case <-time.After(siBound):
		t.Fatal("real Connected callback did not enter")
		return nil
	}
}

func siAvailable(t *testing.T, p *siPlan, owner *rpc.SessionOwner) {
	t.Helper()
	select {
	case err := <-p.completed:
		if err != nil {
			t.Fatalf("real Connected callback: %v", err)
		}
	case <-time.After(siBound):
		t.Fatal("real Connected callback did not finish")
	}
	siAwait(t, owner.Registered(), "transport registration")
	if !owner.Available() {
		t.Fatal("registered owner is not available")
	}
}

func (f *siHarness) checkPeer(id, version string) {
	f.t.Helper()
	executor, ok := f.d.GetExecutor(id)
	if !ok || executor.Version != version {
		f.t.Fatalf("registry %s = %+v, exists=%v; want %s", id, executor, ok, version)
	}
	f.d.mu.RLock()
	owner := f.d.executors[id].owner
	f.d.mu.RUnlock()
	client, ok := f.d.Bidi.GetClientFor(owner)
	if !ok {
		f.t.Fatalf("no exact reverse client for %s", id)
	}
	ctx, cancel := context.WithTimeout(f.ctx, siBound)
	defer cancel()
	for _, p := range f.peers {
		if p.id == id && p.version == version {
			// Server registration precedes receipt of the client's Bind ACK.
			// Ordinary reverse methods require that exact peer to confirm it.
			if err := p.client.WaitReadyContext(ctx); err != nil {
				f.t.Fatal(err)
			}
			if _, err := client.Bandwidth(ctx, &pb.BandwidthRequest{}); err != nil {
				f.t.Fatal(err)
			}
			siAwait(f.t, p.bandwidth, "actual reverse Bandwidth")
			return
		}
	}
	f.t.Fatal("expected reverse recipient missing")
}

func TestDispatcherDelayedConnectedCannotRepublish(t *testing.T) {
	for _, removeReplacement := range []bool{false, true} {
		name := "replacement_present"
		if removeReplacement {
			name = "replacement_removed"
		}
		t.Run(name, func(t *testing.T) {
			a, b, unrelated := siNewPlan(), siNewPlan(), siNewPlan()
			var release func()
			a.before, release = siGate()
			f := siNewHarness(t, map[string]*siPlan{"a": a, "b": b, "unrelated": unrelated}, release)
			f.connect("same", "a")
			old := siEntered(t, a) // transport published A; registry callback is held
			f.connect("same", "b")
			siAwait(t, old.Done(), "old owner retirement")
			select {
			case <-b.entered:
				t.Fatal("replacement entered Connected before predecessor setup joined")
			default:
			}
			// Replacement drain must not stall a different executor.
			f.connect("sentinel", "unrelated")
			siAvailable(t, unrelated, siEntered(t, unrelated))
			f.checkPeer("sentinel", "unrelated")
			release()
			next := siEntered(t, b)
			siAvailable(t, b, next)
			f.checkPeer("same", "b")
			if removeReplacement {
				if !f.d.Bidi.RemoveClient(next) {
					t.Fatal("current owner removal failed")
				}
				siAwait(t, b.disconnected, "replacement disconnect callback")
			}
			release()
			select {
			case err := <-a.completed:
				if err == nil {
					t.Error("retired delayed Connected succeeded")
				}
			case <-time.After(siBound):
				t.Fatal("released delayed callback did not finish")
			}
			siAwait(t, a.disconnected, "retired callback cleanup")
			if removeReplacement {
				if _, ok := f.d.GetExecutor("same"); ok {
					t.Error("delayed old callback resurrected a removed registry entry")
				}
				if _, ok := f.d.Bidi.GetClientFor(next); ok {
					t.Error("removed owner still has an available client")
				}
			} else {
				f.checkPeer("same", "b")
			}
			f.checkPeer("sentinel", "unrelated")
		})
	}
}

func TestDispatcherOldDisconnectAndExpiry(t *testing.T) {
	a, b, unrelated := siNewPlan(), siNewPlan(), siNewPlan()
	var release func()
	a.beforeDisconnect, release = siGate()
	d := newTerminalPeerDispatcher(t)
	var clock atomic.Int64
	base := time.Unix(1700000000, 0)
	clock.Store(base.UnixNano())
	d.now = func() time.Time { return time.Unix(0, clock.Load()) }
	// Hold the expiry worker so the stale-candidate and exact-current checks
	// below observe the transition before any fixture cleanup can repair it.
	ticker := &registryTestTicker{ticks: make(chan time.Time), started: make(chan struct{}), stopped: make(chan struct{})}
	d.newExpiryTicker = func(time.Duration) expiryTicker { return ticker }
	f := siNewHarnessFor(t, d, map[string]*siPlan{"a": a, "b": b, "unrelated": unrelated}, release)
	f.connect("same", "a")
	old := siEntered(t, a)
	siAvailable(t, a, old)
	f.connect("same", "b")
	next := siEntered(t, b)
	siAvailable(t, b, next)
	f.checkPeer("same", "b") // Confirm the client received Bind before expiring its owner.
	siAwait(t, old.Done(), "replaced owner retirement")
	clock.Store(base.Add(2 * d.ControlLeaseDuration()).UnixNano())
	f.connect("sentinel", "unrelated")
	siAvailable(t, unrelated, siEntered(t, unrelated))
	// B is deadline-expired but still retained; stale A must not remove it.
	if f.d.expireOwner(old) {
		t.Error("stale expiry candidate removed a replacement")
	}
	if f.d.Bidi.RemoveClient(old) {
		t.Error("stale transport removal matched a replacement")
	}
	release()
	siAwait(t, a.disconnected, "old actual Disconnected callback")
	f.d.mu.RLock()
	entry := f.d.executors["same"]
	f.d.mu.RUnlock()
	if entry == nil || entry.owner != next || !next.Active() {
		t.Fatal("old cleanup removed or retired the exact replacement")
	}
	f.checkPeer("sentinel", "unrelated")
	if !f.d.expireOwner(next) {
		t.Fatal("deadline-eligible current owner did not expire")
	}
	siAwait(t, b.disconnected, "current owner expiry cleanup")
	if _, ok := f.d.GetExecutor("same"); ok {
		t.Error("expired current owner remains discoverable")
	}
	f.checkPeer("sentinel", "unrelated")
}

func TestRegistrationAvailabilityAcrossRealTransport(t *testing.T) {
	p := siNewPlan()
	gate, release := siGate()
	// A wrapper signals registry publication before holding callback completion.
	p.after = gate
	f := siNewHarness(t, map[string]*siPlan{"held": p}, release)
	f.connect("held", "held")
	owner := siEntered(t, p)
	siAwait(t, p.committed, "real registry publication")
	ctx, cancel := context.WithTimeout(f.ctx, siBound)
	defer cancel()
	if _, err := f.rpc.Resources(ctx, &pb.ResourcesRequest{ExecutorId: "held", BandwidthCapacity: int64(resource.Megabit)}); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("unbound Resources before callback completion: %v", err)
	}
	if _, err := f.rpc.Heartbeat(ctx, &pb.HeartbeatRequest{ExecutorId: "held", TeslaKeyEpoch: 1, TeslaKey: []byte("local-key")}); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("unbound Heartbeat before callback completion: %v", err)
	}
	if owner.Available() {
		t.Fatal("owner became available before Connected returned")
	}
	if _, ok := f.d.GetExecutor("held"); ok {
		t.Error("GetExecutor exposed incomplete registration")
	}
	if len(f.d.ListExecutors()) != 0 {
		t.Error("ListExecutors exposed incomplete registration")
	}
	if _, ok := f.d.GetExecutorByIPFull("127.0.0.1"); ok {
		t.Error("by-IP lookup exposed incomplete registration")
	}
	if _, ok := f.d.Bidi.GetClientFor(owner); ok {
		t.Error("GetClient exposed incomplete registration")
	}
	validate := func() error {
		spec := models.DebugletSpec{ExecutorID: "held", Policy: models.DebugletPolicy{
			FloorBW: 1000, CeilBW: 1000, Timeout: time.Second,
		}}
		f.d.mu.Lock()
		defer f.d.mu.Unlock()
		_, err := f.d.validateDebugletSpec(&spec)
		return err
	}
	if err := validate(); err == nil {
		t.Error("admission exposed incomplete registration with known capacity")
	}
	release()
	siAvailable(t, p, owner)
	f.checkPeer("held", "held")
	client := f.boundClient("held")
	if _, err := client.Resources(ctx, &pb.ResourcesRequest{ExecutorId: "held", BandwidthCapacity: int64(resource.Megabit)}); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Heartbeat(ctx, &pb.HeartbeatRequest{ExecutorId: "held", TeslaKeyEpoch: 1, TeslaKey: []byte("local-key")}); err != nil {
		t.Fatal(err)
	}
	if err := validate(); err != nil {
		t.Fatalf("admission after callback completion: %v", err)
	}
	snapshot, _ := f.d.GetExecutor("held")
	if !snapshot.Ready || snapshot.capacity != resource.Megabit {
		t.Fatalf("bound updates after availability were lost: %+v", snapshot)
	}
}
