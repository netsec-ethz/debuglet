package executor

import (
	"context"
	"errors"
	"github.com/netsec-ethz/debuglet/internal/controlsession"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/netsec-ethz/debuglet/internal/executor/config"
	pb "github.com/netsec-ethz/debuglet/protocol"
	"go.uber.org/zap"
	"google.golang.org/grpc"
)

type resourcesClient struct {
	pb.DispatcherServiceClient
	resources func(context.Context, *pb.ResourcesRequest) (*pb.ResourcesResponse, error)
}

func (c resourcesClient) Resources(ctx context.Context, in *pb.ResourcesRequest, _ ...grpc.CallOption) (*pb.ResourcesResponse, error) {
	return c.resources(ctx, in)
}

func TestResourcesReady(t *testing.T) {
	t.Run("pending before positive capacity acknowledgement", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		entered, ack := make(chan struct{}), make(chan struct{})
		cfg := fixtureConfig()
		cfg.Identity.ExecutorID = "ready-test"
		e := newFixtureExecutor(t, cfg, nil, newFixtureMemoryStorage(t))
		client := resourcesClient{resources: func(ctx context.Context, in *pb.ResourcesRequest) (*pb.ResourcesResponse, error) {
			if in.BandwidthCapacity <= 0 || in.ExecutorId != "ready-test" {
				t.Errorf("invalid announcement: %+v", in)
			}
			close(entered)
			select {
			case <-ack:
				return &pb.ResourcesResponse{}, nil
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}}
		e.clientFor = func(_ context.Context, binding controlsession.Binding) (pb.DispatcherServiceClient, error) {
			if binding != operationBinding() {
				return nil, errors.New("resource fixture received wrong binding")
			}
			return client, nil
		}
		done := make(chan struct{})
		go func() { defer close(done); e.resolveResources(e.announceResources(ctx, operationBinding())) }()
		defer func() { cancel(); <-done }()
		select {
		case <-entered:
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
		select {
		case <-e.resourcesDone:
			t.Fatal("ready before acknowledgement")
		default:
		}
		var waiters sync.WaitGroup
		results := make(chan error, 8)
		for i := 0; i < 8; i++ {
			waiters.Go(func() { results <- e.WaitResourcesReady(ctx) })
		}
		close(ack)
		waiters.Wait()
		close(results)
		for err := range results {
			if err != nil {
				t.Fatal(err)
			}
		}
		e.resolveResources(errors.New("later failure"))
		if err := e.WaitResourcesReady(ctx); err != nil {
			t.Fatalf("one-shot success changed: %v", err)
		}
	})
	t.Run("failed connection resolves and joins waiter", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		// A real session owning the real transport, whose configured dispatcher
		// address refuses the connection.
		node, db, _ := newSessionFixture(t)
		s, err := NewSession(node, db)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { stopAndWaitSession(t, s) })
		e := s.executor
		result := make(chan error, 1)
		go func() { result <- e.WaitResourcesReady(ctx) }()
		listenErr := e.Listen(ctx)
		if listenErr == nil {
			t.Fatal("connection unexpectedly succeeded")
		}
		readyErr := <-result
		var end *controlsession.EndError
		var dial *net.OpError
		if !errors.Is(readyErr, listenErr) || !errors.As(readyErr, &end) || end.Kind != controlsession.TransportUnavailable || !errors.As(readyErr, &dial) || dial.Op != "dial" {
			t.Fatalf("readiness lost typed connection failure: %v; Listen: %v", readyErr, listenErr)
		}
	})
	t.Run("retry exhaustion preserves last error", func(t *testing.T) {
		e := newFixtureExecutor(t, fixtureConfig(), nil, newFixtureMemoryStorage(t))
		sentinel := errors.New("not registered")
		attempts, waits := 0, 0
		err := e.announceResourcesWith(context.Background(), func(context.Context) error { attempts++; return sentinel }, func(context.Context) error { waits++; return nil })
		e.resolveResources(err)
		if attempts != 10 || waits != 9 || !errors.Is(e.WaitResourcesReady(context.Background()), sentinel) {
			t.Fatalf("attempts=%d waits=%d err=%v", attempts, waits, err)
		}
	})
	t.Run("retry success", func(t *testing.T) {
		e := newFixtureExecutor(t, fixtureConfig(), nil, newFixtureMemoryStorage(t))
		attempts, waits := 0, 0
		err := e.announceResourcesWith(context.Background(), func(context.Context) error {
			attempts++
			if attempts == 3 {
				return nil
			}
			return errors.New("not registered")
		}, func(context.Context) error { waits++; return nil })
		if err != nil || attempts != 3 || waits != 2 {
			t.Fatalf("attempts=%d waits=%d err=%v", attempts, waits, err)
		}
	})
	t.Run("caller cancellation leaves latch pending", func(t *testing.T) {
		e := newFixtureExecutor(t, fixtureConfig(), nil, newFixtureMemoryStorage(t))
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if err := e.WaitResourcesReady(ctx); !errors.Is(err, context.Canceled) {
			t.Fatalf("cancellation: %v", err)
		}
		e.resolveResources(nil)
		if err := e.WaitResourcesReady(context.Background()); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("retry wait cancellation", func(t *testing.T) {
		e := newFixtureExecutor(t, fixtureConfig(), nil, newFixtureMemoryStorage(t))
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		attempts := 0
		err := e.announceResourcesWith(ctx, func(context.Context) error { attempts++; return errors.New("not registered") }, func(ctx context.Context) error { cancel(); return ctx.Err() })
		if attempts != 1 || !errors.Is(err, context.Canceled) {
			t.Fatalf("attempts=%d err=%v", attempts, err)
		}
	})
}

// The counter is a daemon resource, so its selection belongs to node
// construction: fallback mode ignores the named interface, an unknown mode is
// refused, and auto still requires the interface it was given to exist.
func TestFallbackPacketCounter(t *testing.T) {
	cfg := &config.ExecutorConfig{
		Identity:   config.IdentityConfig{ExecutorID: "fallback-test"},
		Dispatcher: config.DispatcherConfig{Addr: "127.0.0.1:1"},
		TLS:        config.TLSConfig{Disable: true}, Tesla: config.TeslaConfig{Delay: 1, ChainLength: 10},
		Network: config.NetworkConfig{PacketCounter: "fallback", Interface: "deliberately-nonexistent-interface"},
	}
	db := newFixtureDatabase(t)
	node, err := NewNode(cfg, zap.NewNop(), db)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := node.Close(); err != nil {
			t.Errorf("close node: %v", err)
		}
	}()
	if node.iface != nil || node.packetCount.Type() != "fallback" {
		t.Fatalf("fallback selected iface=%v counter=%s", node.iface, node.packetCount.Type())
	}
	cfg.Network.PacketCounter = "unknown"
	if _, err := NewNode(cfg, zap.NewNop(), db); err == nil {
		t.Fatal("direct config bypassed mode validation")
	}
	cfg.Network.PacketCounter = "auto"
	if _, err := NewNode(cfg, zap.NewNop(), db); err == nil {
		t.Fatal("auto ignored supplied invalid interface")
	}
}
