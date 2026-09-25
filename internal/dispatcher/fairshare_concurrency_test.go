package dispatcher

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/database"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/models"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/resource"
	pb "github.com/netsec-ethz/debuglet/protocol"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
)

const fairshareExecutorID = "fairshare-executor"

type fairsharePeer struct {
	pb.UnimplementedExecutorServiceServer
	mu        sync.Mutex
	requests  []*pb.BandwidthRequest
	bandwidth func() error
}

func (p *fairsharePeer) Hello(context.Context, *pb.HelloRequest) (*pb.HelloResponse, error) {
	return &pb.HelloResponse{ExecutorId: fairshareExecutorID, Currency: "TEST", PricePerBwS: 1}, nil
}

func (p *fairsharePeer) Bandwidth(_ context.Context, req *pb.BandwidthRequest) (*pb.BandwidthResponse, error) {
	if p.bandwidth != nil {
		if err := p.bandwidth(); err != nil {
			return nil, err
		}
	}
	p.mu.Lock()
	p.requests = append(p.requests, req)
	p.mu.Unlock()
	return &pb.BandwidthResponse{}, nil
}

func (p *fairsharePeer) recorded() []*pb.BandwidthRequest {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]*pb.BandwidthRequest(nil), p.requests...)
}

func fairshareStartPeer(t *testing.T, ctx context.Context, d *Dispatcher, peer *fairsharePeer) {
	t.Helper()
	stop, err := startTerminalPeer(ctx, d, resource.Gigabit, peer)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := stop(cleanupCtx); err != nil {
			t.Error(err)
		}
	})
}

func TestFairshareComputationWaitsForDestinationLock(t *testing.T) {
	d, _, _ := newRegistryFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	registryRegister(t, d, "fairshare-origin")
	origin := effectTestMutation(t, d, "fairshare-origin")
	defer origin.Finish()
	// A read lock must also exclude computation: even an empty destination
	// causes Fairshare to create its tree before returning the lazy iterator.
	d.mu.RLock()
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(d.mu.RUnlock) }
	started, done := make(chan struct{}), make(chan struct{})
	var result error
	go func() {
		defer close(done)
		close(started)
		result = d.sendFairshare(ctx, origin, []string{"previously-unseen"})
	}()
	t.Cleanup(func() {
		release()
		cancel()
		registryWait(t, done)
	})
	registryWait(t, started)
	premature := false
	select {
	case <-done:
		premature = true
	case <-time.After(40 * time.Millisecond):
	}
	// Always release and join before reporting the missing-lock control's
	// assertion, so a failing test leaves neither a lock nor a caller behind.
	release()
	registryWait(t, done)
	if premature {
		t.Error("fairshare computation completed while destination lock was held")
	}
	if result != nil {
		t.Fatal(result)
	}
}

func TestFairshareDetachesBeforeLoggingAndRPC(t *testing.T) {
	d, _, _ := newRegistryFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	id := uuid.New()
	dests := []string{"192.0.2.1", "192.0.2.2"}
	d.mu.Lock()
	for _, dest := range dests {
		d.destinations.SetLimit(dest, 100)
		if err := d.destinations.Insert(id, dest, fairshareExecutorID, 10, 80); err != nil {
			d.mu.Unlock()
			t.Fatal(err)
		}
	}
	d.mu.Unlock()
	var logCalls, rpcCalls atomic.Int32
	var logHeldLock atomic.Bool
	var removeOnce sync.Once
	core, _ := observer.New(zap.DebugLevel)
	d.logger = zap.New(core, zap.Hooks(func(entry zapcore.Entry) error {
		if entry.Message != "New fairshared update" {
			return nil
		}
		logCalls.Add(1)
		if !d.mu.TryLock() {
			logHeldLock.Store(true)
			return nil
		}
		// Change both source allocations during the first log callback. The
		// subsequent real RPC must still receive the complete prior snapshot.
		removeOnce.Do(func() {
			for _, dest := range dests {
				d.destinations.Remove(id, dest)
				d.destinations.SetLimit(dest, 1)
			}
		})
		d.mu.Unlock()
		return nil
	}))
	peer := &fairsharePeer{bandwidth: func() error {
		rpcCalls.Add(1)
		if !d.mu.TryLock() {
			return fmt.Errorf("fairshare RPC ran while destination lock was held")
		}
		d.mu.Unlock()
		return nil
	}}
	fairshareStartPeer(t, ctx, d, peer)
	origin := effectTestMutation(t, d, fairshareExecutorID)
	defer origin.Finish()
	if err := d.sendFairshare(ctx, origin, dests); err != nil {
		t.Fatal(err)
	}
	if logHeldLock.Load() || logCalls.Load() != 2 || rpcCalls.Load() != 1 {
		t.Fatalf("publication lock/counts: logging held lock=%t, logs=%d, RPCs=%d", logHeldLock.Load(), logCalls.Load(), rpcCalls.Load())
	}
	requests := peer.recorded()
	if len(requests) != 1 || len(requests[0].Limits) != len(dests) {
		t.Fatalf("detached updates = %v", requests)
	}
	for i, limit := range requests[0].Limits {
		if limit.Address != dests[i] || limit.BitsLimit != 80 {
			t.Fatalf("detached update %d = %v, want %s at 80", i, limit, dests[i])
		}
	}
	d.mu.Lock()
	remaining := d.destinations.Len()
	d.mu.Unlock()
	if remaining != 0 {
		t.Fatalf("logging callback did not remove source allocations: %d remain", remaining)
	}
}

func TestFairshareConcurrentAllocationRemovalAndLimits(t *testing.T) {
	d, _, _ := newRegistryFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	t.Cleanup(cancel)
	peer := &fairsharePeer{}
	fairshareStartPeer(t, ctx, d, peer)
	origin := effectTestMutation(t, d, fairshareExecutorID)
	defer origin.Finish()
	const transactionID = "fairshare-paid-transaction"
	if _, err := d.Payment.CreatePaymentIntent(transactionID, 0, "TEST", "fairshare-fixture", ctx); err != nil {
		t.Fatal(err)
	}
	dests := []string{"192.0.2.10", "192.0.2.11"}
	for _, dest := range dests {
		d.SetDestinationLimit(dest, 4096)
	}
	const allocators, iterations = 4, 12
	const workers = allocators + 3
	start := make(chan struct{})
	ready := make(chan struct{}, workers)
	errors := make(chan error, workers)
	var group sync.WaitGroup
	var allocations atomic.Int32
	launch := func(work func() error) {
		group.Add(1)
		go func() {
			defer group.Done()
			ready <- struct{}{}
			<-start
			if err := work(); err != nil {
				errors <- err
			}
		}()
	}
	for range allocators {
		launch(func() error {
			for range iterations {
				id := uuid.New()
				_, err := database.New(d.db).CreateDebuglet(ctx, database.CreateDebugletParams{Uuid: id, StartTime: models.NewUTCTime(time.Now()), EndTime: models.NewUTCTime(time.Now().Add(time.Minute)), ExecutorID: fairshareExecutorID, TransactionID: transactionID, Usage: 10, CeilBw: 80, Addresses: dests, State: models.RunStateUploaded, DispatcherIncarnation: origin.Owner().Binding().Incarnation, SessionID: origin.Owner().Binding().SessionID})
				if err != nil {
					return err
				}
				_, err = d.OnDebugletAllocate(ctx, origin, &pb.DebugletAllocateRequest{
					DebugletId: id.String(), ExecutorId: fairshareExecutorID, TransactionId: transactionID,
					Policy: &pb.DebugletPolicy{Addresses: dests, FloorBw: 10, CeilBw: 80},
				})
				if err != nil {
					return fmt.Errorf("allocate: %w", err)
				}
				allocations.Add(1)
				// Exercise the same resource removal and lock as the terminal
				// path, without starting its separately scoped async notifier.
				d.mu.Lock()
				for _, dest := range dests {
					d.destinations.Remove(id, dest)
				}
				d.mu.Unlock()
			}
			return nil
		})
	}
	for range 2 {
		launch(func() error {
			for i := range 4 * iterations {
				// Both senders also encounter previously unseen empty trees.
				addresses := append([]string{fmt.Sprintf("unused-%d", i)}, dests...)
				if err := d.sendFairshare(ctx, origin, addresses); err != nil {
					return fmt.Errorf("fairshare: %w", err)
				}
			}
			return nil
		})
	}
	launch(func() error {
		for i := range 4 * iterations {
			for _, dest := range dests {
				d.SetDestinationLimit(dest, resource.Bitrate(4096+i%2))
			}
		}
		return nil
	})
	done := make(chan struct{})
	go func() { group.Wait(); close(done) }()
	var startOnce sync.Once
	release := func() { startOnce.Do(func() { close(start) }) }
	t.Cleanup(func() {
		release()
		cancel()
		registryWait(t, done)
	})
	for range workers {
		select {
		case <-ready:
		case <-ctx.Done():
			t.Fatal("concurrent fairshare callers did not reach start gate")
		}
	}
	release()
	select {
	case <-done:
	case <-ctx.Done():
		t.Fatal("concurrent fairshare callers did not join before deadline")
	}
	close(errors)
	for err := range errors {
		t.Error(err)
	}
	if got := allocations.Load(); got != allocators*iterations {
		t.Errorf("successful allocations = %d, want %d", got, allocators*iterations)
	}
	requests := peer.recorded()
	if len(requests) == 0 {
		t.Fatal("real peer received no bandwidth updates")
	}
	for _, req := range requests {
		seen := make(map[string]bool)
		for _, limit := range req.Limits {
			if (limit.Address != dests[0] && limit.Address != dests[1]) || seen[limit.Address] || limit.BitsLimit < 10 || limit.BitsLimit > allocators*80 {
				t.Fatalf("invalid concurrent bandwidth snapshot: %v", req)
			}
			seen[limit.Address] = true
		}
	}
	d.mu.Lock()
	remaining := d.destinations.Len()
	for _, dest := range dests {
		if err := d.destinations.CheckCapacity(dest, d.destinations.Cap(dest)); err != nil {
			t.Errorf("capacity not fully recovered after joined removals: %v", err)
		}
	}
	d.mu.Unlock()
	if remaining != 0 {
		t.Fatalf("%d destination allocations remain after joined removals", remaining)
	}
	if err := d.sendFairshare(ctx, origin, dests); err != nil {
		t.Fatal(err)
	}
	if len(peer.recorded()) != len(requests) {
		t.Fatal("empty destinations produced an executor update after all removals")
	}
}
