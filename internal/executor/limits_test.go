package executor

import (
	"net"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/netsec-ethz/debuglet/internal/executor/debuglet/socket/netutil"
	"github.com/netsec-ethz/debuglet/internal/executor/ratelimit/app"
	pb "github.com/netsec-ethz/debuglet/protocol"
)

// recordingPacketCount keeps the last limit applied to each active connection.
type recordingPacketCount struct {
	mu          sync.Mutex
	executor    map[uuid.UUID]app.Bitrate
	destination map[string]app.Bitrate
}

func newRecordingPacketCount() *recordingPacketCount {
	return &recordingPacketCount{executor: make(map[uuid.UUID]app.Bitrate), destination: make(map[string]app.Bitrate)}
}

func (c *recordingPacketCount) Attach(conn net.Conn, _ uuid.UUID, _ string) (net.Conn, error) {
	return conn, nil
}
func (c *recordingPacketCount) SetLimit(addr string, id uuid.UUID, limit app.Bitrate) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.destination[addr+"|"+id.String()] = limit
	return nil
}
func (c *recordingPacketCount) SetExecLimit(id uuid.UUID, limit app.Bitrate) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.executor[id] = limit
	return nil
}
func (c *recordingPacketCount) DeleteLimit(netutil.IPv6, uuid.UUID) error    { return nil }
func (c *recordingPacketCount) DeleteExecLimit(uuid.UUID) error              { return nil }
func (c *recordingPacketCount) Detach(string, uuid.UUID, netutil.IPv6) error { return nil }
func (c *recordingPacketCount) Close() error                                 { return nil }
func (c *recordingPacketCount) Type() string                                 { return "recording" }
func (c *recordingPacketCount) appliedExecutor(id uuid.UUID) app.Bitrate {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.executor[id]
}
func (c *recordingPacketCount) appliedDestination(addr string, id uuid.UUID) app.Bitrate {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.destination[addr+"|"+id.String()]
}

// A capacity change reaches the connections that are already running, without
// waiting for another run to be inserted.
func TestChangedCapacityReachesActiveRuns(t *testing.T) {
	counter := newRecordingPacketCount()
	e := newFixtureExecutor(t, fixtureConfig(), counter, newFixtureMemoryStorage(t))

	const addr = "203.0.113.30"
	id := uuid.New()
	if err := e.limiter.InsertDebuglet(id, 0, 1000, []string{addr}); err != nil {
		t.Fatal(err)
	}
	e.running[id] = RunningDebuglet{id: id}

	binding := operationBinding()
	apply := func(limit int64) {
		t.Helper()
		req := &pb.BandwidthRequest{Limits: []*pb.DestinationLimit{{Address: addr, BitsLimit: limit}}}
		if _, err := e.applyBandwidth(binding, req); err != nil {
			t.Fatal(err)
		}
	}
	apply(800)
	if got := counter.appliedDestination(addr, id); got != 800 {
		t.Fatalf("destination limit applied %d, want 800", got)
	}
	if got := counter.appliedExecutor(id); got != 1000 {
		t.Fatalf("executor limit applied %d, want 1000", got)
	}

	// Lowering the same destination must move the active connection again.
	apply(200)
	if got := counter.appliedDestination(addr, id); got != 200 {
		t.Fatalf("lowered destination limit applied %d, want 200", got)
	}

	// So must lowering the executor capacity, which names no destination.
	e.limiter.SetExecutorCapacity(400)
	e.publishLimits(nil)
	if got := counter.appliedExecutor(id); got != 400 {
		t.Fatalf("lowered executor limit applied %d, want 400", got)
	}
	if got := counter.appliedDestination(addr, id); got != 200 {
		t.Fatalf("executor capacity change moved the destination limit to %d", got)
	}
}
