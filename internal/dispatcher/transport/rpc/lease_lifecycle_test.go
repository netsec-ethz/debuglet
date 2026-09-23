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
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
)

// The proxy blocks actual bytes in one direction only. Close interrupts its
// gate before closing the owned socket, so test teardown never strands Read or
// Write behind an in-process failure fixture.
type leasePartition struct {
	enabled     atomic.Bool
	read        bool
	entered     chan struct{}
	release     chan struct{}
	enterOnce   sync.Once
	releaseOnce sync.Once
}

func newLeasePartition(read bool) *leasePartition {
	return &leasePartition{read: read, entered: make(chan struct{}), release: make(chan struct{})}
}
func (p *leasePartition) unblock() { p.releaseOnce.Do(func() { close(p.release) }) }
func (p *leasePartition) wrap(conn net.Conn) net.Conn {
	return &leasePartitionConn{Conn: conn, partition: p, closed: make(chan struct{})}
}

type leasePartitionConn struct {
	net.Conn
	partition *leasePartition
	closed    chan struct{}
	once      sync.Once
	err       error
}

func (c *leasePartitionConn) gate() error {
	if !c.partition.enabled.Load() {
		return nil
	}
	c.partition.enterOnce.Do(func() { close(c.partition.entered) })
	select {
	case <-c.partition.release:
		return nil
	case <-c.closed:
		return net.ErrClosed
	}
}
func (c *leasePartitionConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if c.partition.read && n > 0 {
		if blocked := c.gate(); blocked != nil {
			return 0, blocked
		}
	}
	return n, err
}
func (c *leasePartitionConn) Write(p []byte) (int, error) {
	if !c.partition.read {
		if err := c.gate(); err != nil {
			return 0, err
		}
	}
	return c.Conn.Write(p)
}
func (c *leasePartitionConn) Close() error {
	c.once.Do(func() { close(c.closed); c.err = c.Conn.Close() })
	return c.err
}

func TestLeaseBothChannelPartitions(t *testing.T) {
	for _, tc := range []struct {
		name         string
		direct, read bool
	}{
		{"direct_request", true, true}, {"direct_response", true, false}, {"reverse_request", false, false}, {"reverse_response", false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			partition := newLeasePartition(tc.read)
			var directTransform, reverseTransform func(net.Conn) net.Conn
			if tc.direct {
				directTransform = partition.wrap
			} else {
				reverseTransform = partition.wrap
			}
			f := newLeaseLifecycleFixture(t, newLifecycleState(), 2*time.Second, time.Now, directTransform, reverseTransform)
			f.releases = append(f.releases, partition.unblock)
			peer := &lifecyclePeer{id: "executor", version: "partition"}
			connected := f.peer(peer)
			owner := f.connected("partition")
			direct := lifecycleDirectClient(t, connected)
			partition.enabled.Store(true)
			// Traffic on the other channel still performs a real, admitted operation.
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if tc.direct {
				client, ok := f.b.GetClientFor(owner)
				if !ok {
					t.Fatal("lost reverse client before partition")
				}
				if _, err := client.Abort(ctx, &pb.AbortRequest{DebugletId: "probe"}); err != nil {
					t.Fatalf("healthy reverse path: %v", err)
				}
				if peer.aborts.Load() != 1 {
					t.Fatal("healthy reverse path did not reach handler")
				}
			} else {
				if _, err := direct.Heartbeat(ctx, &pb.HeartbeatRequest{ExecutorId: owner.ExecutorID()}); err != nil {
					t.Fatalf("healthy direct path: %v", err)
				}
			}
			awaitSessionSignal(t, partition.entered)
			awaitSessionSignal(t, connected.client.Lost())
			var ended *controlsession.EndError
			if !errors.As(connected.client.Cause(), &ended) || ended.Kind != controlsession.LeaseExpired {
				t.Fatalf("partition did not expire lease: %v", connected.client.Cause())
			}
			if _, ok := connected.client.Binding(); ok {
				t.Fatal("expired partition retained reverse admission")
			}
			if _, err := connected.client.ClientFor(owner.Binding()); err == nil {
				t.Fatal("expired partition returned ordinary client")
			}
			// Observe actual invocation join before releasing the proxy. Its owned
			// socket Close must break the gate; emergency fixture release is not proof.
			awaitSessionSignal(t, connected.joined)
			// Buffered proxy reads can outlive their remote peer. Release this test
			// transport only after the local lease and join verdict, then join the
			// remote fixture; this is not evidence of remote lease enforcement.
			partition.unblock()
			f.disconnected(owner)
		})
	}
}

func TestLeaseRenewalTraversesBothChannels(t *testing.T) {
	committed := make(chan uint64, 16)
	observe := grpc.UnaryInterceptor(func(ctx context.Context, in any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		out, err := handler(ctx, in)
		if info.FullMethod == pb.DispatcherService_RenewLease_FullMethodName && err == nil {
			select {
			case committed <- out.(*pb.RenewLeaseResponse).Sequence:
			default:
			}
		}
		return out, err
	})
	f := newLeaseLifecycleFixture(t, newLifecycleState(), time.Second, time.Now, nil, nil, observe)
	peer := f.peer(&lifecyclePeer{id: "executor", version: "renewed"})
	owner := f.connected("renewed")
	_ = lifecycleDirectClient(t, peer)
	owner.mu.Lock()
	initial := owner.deadline
	owner.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), sessionTestWait)
	defer cancel()
	for want := uint64(1); want <= 6; want++ {
		select {
		case got := <-committed:
			if got != want {
				t.Fatalf("renewal sequence=%d want=%d", got, want)
			}
		case <-ctx.Done():
			t.Fatal("real two-channel renewals stopped")
		}
	}
	owner.mu.Lock()
	deadline := owner.deadline
	owner.mu.Unlock()
	if !deadline.After(initial) || !owner.Available() {
		t.Fatal("valid probes did not extend live server authority")
	}
	if err := peer.client.CheckLease(owner.Binding()); err != nil {
		t.Fatalf("client lease not renewed: %v", err)
	}
}

func TestLeaseRenewalContextCheckedInsideOwnerGuard(t *testing.T) {
	owner := newTestOwner(t, "executor")
	owner.MarkRegistered()
	before := owner.deadline
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	holder := startOwnerTestCall(t, unblock, func() bool { return owner.CommitActive(func() { close(entered); <-release }) })
	awaitOwnerSignal(t, entered)
	ctx, cancel := context.WithCancel(context.Background())
	// Cancel while the real owner guard is held. The caller must recheck inside
	// that guard even if its containing transport made an earlier live check.
	requested := make(chan struct{})
	renewed := startOwnerTestCall(t, unblock, func() bool { close(requested); return owner.commitLease(ctx, 1) })
	awaitOwnerSignal(t, requested)
	cancel()
	unblock()
	if !holder.wait(t) || renewed.wait(t) {
		t.Fatal("canceled renewal committed after waiting for owner guard")
	}
	if owner.sequence != 0 || owner.deadline != before {
		t.Fatal("canceled renewal changed sequence/deadline")
	}
	owner.Retire()
}

// This bounded peer exposes independent observations of the reverse control
// method; counting direct ACKs alone would miss an accidentally omitted probe.
type observedLeasePeer struct {
	pb.UnimplementedExecutorServiceServer
	offered chan *pb.HelloRequest
	calls   atomic.Int32
	mode    atomic.Int32
}

func (p *observedLeasePeer) Hello(_ context.Context, in *pb.HelloRequest) (*pb.HelloResponse, error) {
	p.offered <- in
	return &pb.HelloResponse{ExecutorId: "observed-probe", Version: "observed", ControlVersion: controlsession.ProtocolVersion, DispatcherIncarnation: in.DispatcherIncarnation, SessionId: in.SessionId, LeaseDurationMs: in.LeaseDurationMs}, nil
}
func (p *observedLeasePeer) ProbeSession(ctx context.Context, in *pb.ProbeSessionRequest) (*pb.ProbeSessionResponse, error) {
	if _, err := controlrpc.Read(ctx); err != nil {
		return nil, err
	}
	p.calls.Add(1)
	switch p.mode.Load() {
	case 1:
		return &pb.ProbeSessionResponse{Sequence: in.Sequence + 1}, nil
	case 2:
		return nil, status.Error(codes.Unavailable, "probe unavailable")
	}
	return &pb.ProbeSessionResponse{Sequence: in.Sequence}, nil
}

func TestRenewLeaseRequiresMatchingReverseProbe(t *testing.T) {
	f := newLifecycleFixture(t, newLifecycleState(), nil)
	raw, err := net.DialTimeout("tcp", f.lis.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	session, err := yamux.Client(raw, nil)
	if err != nil {
		raw.Close()
		t.Fatal(err)
	}
	peer := &observedLeasePeer{offered: make(chan *pb.HelloRequest, 1)}
	callback := grpc.NewServer(grpc.WaitForHandlers(true))
	pb.RegisterExecutorServiceServer(callback, peer)
	served := make(chan struct{})
	go func() { defer close(served); _ = callback.Serve(session) }()
	t.Cleanup(func() { raw.Close(); session.Close(); callback.Stop(); awaitSessionSignal(t, served) })
	ctx, cancel := context.WithTimeout(context.Background(), sessionTestWait)
	defer cancel()
	var offer *pb.HelloRequest
	select {
	case offer = <-peer.offered:
	case <-ctx.Done():
		t.Fatal("real lease offer did not reach peer")
	}
	credentials := controlrpc.Credentials{Binding: controlsession.Binding{Incarnation: offer.DispatcherIncarnation, SessionID: offer.SessionId}}
	copy(credentials.Token[:], offer.SessionToken)
	directConn, err := grpc.NewClient(f.direct.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	defer directConn.Close()
	direct := pb.NewDispatcherServiceClient(directConn)
	if ack, err := direct.BindSession(credentials.Outgoing(ctx), &pb.BindSessionRequest{ExecutorId: "observed-probe"}); err != nil || ack.GetLeaseDurationMs() != time.Minute.Milliseconds() {
		t.Fatalf("real bind failed: %v", err)
	}
	owner := f.connected("observed")
	if ack, err := direct.RenewLease(credentials.Outgoing(ctx), &pb.RenewLeaseRequest{Sequence: 1}); err != nil || ack.GetSequence() != 1 {
		t.Fatalf("valid probe renewal failed: %v", err)
	}
	if peer.calls.Load() != 1 {
		t.Fatal("renewal ACK was produced without one actual reverse probe")
	}
	owner.mu.Lock()
	deadline := owner.deadline
	owner.mu.Unlock()
	for _, mode := range []int32{1, 2} {
		peer.mode.Store(mode)
		if _, err := direct.RenewLease(credentials.Outgoing(ctx), &pb.RenewLeaseRequest{Sequence: uint64(mode + 1)}); err == nil {
			t.Fatal("mismatched/failed reverse probe renewed lease")
		}
		owner.mu.Lock()
		changed := owner.deadline != deadline || owner.sequence != 1
		owner.mu.Unlock()
		if changed {
			t.Fatal("rejected reverse proof changed lease authority")
		}
	}
	if peer.calls.Load() != 3 {
		t.Fatal("renewal did not traverse captured reverse connection")
	}
	if _, err := direct.RenewLease(credentials.Outgoing(ctx), &pb.RenewLeaseRequest{}); err == nil || peer.calls.Load() != 3 {
		t.Fatal("zero sequence admitted a probe")
	}
}
