package dispatcher

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/netsec-ethz/debuglet/internal/bitrate"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/database"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/models"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/resource"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/resource/schedule"
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
	stop, err := startTerminalPeer(ctx, d, bitrate.Gigabit, peer)
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
	// A run holding both destinations throughout makes every update, the
	// asynchronous exit ones included, a delivery to the same executor.
	holder := uuid.New()
	d.mu.Lock()
	for _, dest := range dests {
		d.destinations.SetLimit(dest, 4096)
		if err := d.destinations.Insert(holder, dest, fairshareExecutorID, 10, 80); err != nil {
			d.mu.Unlock()
			t.Fatal(err)
		}
	}
	d.mu.Unlock()
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
				row, err := database.New(d.db).CreateDebuglet(ctx, database.CreateDebugletParams{Uuid: id, StartTime: models.NewUTCTime(time.Now()), EndTime: models.NewUTCTime(time.Now().Add(time.Minute)), ExecutorID: fairshareExecutorID, TransactionID: transactionID, Usage: 10, CeilBw: 80, Addresses: dests, State: models.RunStateUploaded, DispatcherIncarnation: origin.Owner().Binding().Incarnation, SessionID: origin.Owner().Binding().SessionID})
				if err != nil {
					return err
				}
				// Reserve the window the terminal release returns, as admission does.
				d.mu.Lock()
				d.reserveFloor(id, schedule.Request{Executor: fairshareExecutorID, Destination: dests, From: row.StartTime.Time, To: row.EndTime.Time, Use: 10})
				d.mu.Unlock()
				_, err = d.OnDebugletAllocate(ctx, origin, &pb.DebugletAllocateRequest{
					DebugletId: id.String(), ExecutorId: fairshareExecutorID, TransactionId: transactionID,
					Policy: &pb.DebugletPolicy{Addresses: dests, FloorBw: 10, CeilBw: 80},
				})
				if err != nil {
					return fmt.Errorf("allocate: %w", err)
				}
				allocations.Add(1)
				// The terminal path releases the allocation and captures its
				// update before delivering it asynchronously.
				if _, err := d.OnDebugletExit(ctx, origin, &pb.DebugletExitRequest{DebugletId: id.String(), ExitCode: 1}); err != nil {
					return fmt.Errorf("exit: %w", err)
				}
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
				d.SetDestinationLimit(dest, bitrate.Bitrate(4096+i%2))
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
	// Every update was captured before this last change; delivered in capture
	// order, the last one to arrive for each destination is the current share.
	for _, dest := range dests {
		if err := d.SetDestinationLimit(dest, 4096); err != nil {
			t.Fatal(err)
		}
	}
	requests := peer.recorded()
	if len(requests) == 0 {
		t.Fatal("real peer received no bandwidth updates")
	}
	for _, req := range requests {
		seen := make(map[string]bool)
		for _, limit := range req.Limits {
			if (limit.Address != dests[0] && limit.Address != dests[1]) || seen[limit.Address] || limit.BitsLimit < 10 || limit.BitsLimit > (allocators+1)*80 {
				t.Fatalf("invalid concurrent bandwidth snapshot: %v", req)
			}
			seen[limit.Address] = true
		}
	}
	for _, dest := range dests {
		arrived := dlArrived(requests, dest)
		if want := allocationFairshare(t, d, dest)[fairshareExecutorID]; len(arrived) == 0 || arrived[len(arrived)-1] != want {
			t.Fatalf("the last update for %s to arrive was not the current share %s: %v", dest, want, arrived)
		}
	}
	d.mu.Lock()
	for _, dest := range dests {
		d.destinations.Remove(holder, dest)
	}
	remaining := d.destinations.Len()
	if reserved := len(d.reservations); reserved != 0 {
		t.Errorf("%d run reservations remain after joined removals", reserved)
	}
	for _, dest := range dests {
		if reserved := d.scheduler.QueryMaxDest(dest, d.now(), maxReservableTime); reserved != 0 {
			t.Errorf("destination %s retains %s of scheduled floor after joined removals", dest, reserved)
		}
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

// TestDestinationFloorConcurrentAdmissionReductionAndExit races admission,
// allocation and exit of runs on one destination against limits set at and
// just above the floors admitted there. A limit is only ever accepted at or
// above the reserved floors, so every admitted run allocates, and at rest the
// destination and the scheduler hold exactly what the remaining run holds.
func TestDestinationFloorConcurrentAdmissionReductionAndExit(t *testing.T) {
	f := newTGFixture(t, &tgPeer{})
	const destination = "192.0.2.12"
	const floor = tgFloorA
	if err := f.d.SetDestinationLimit(destination, 4*floor); err != nil {
		t.Fatal(err)
	}
	client := allocationClient(t, f.d)
	ctx := f.ctx
	allocate := func(deb tgDebuglet) error {
		_, err := client.DebugletAllocate(ctx, &pb.DebugletAllocateRequest{
			DebugletId: deb.id.String(), ExecutorId: tgExecutorID, TransactionId: deb.txID,
			Policy: &pb.DebugletPolicy{Addresses: []string{destination}, FloorBw: int64(floor), CeilBw: int64(2 * floor)},
		})
		return err
	}
	held, err := dlAdmit(f, dlSpec(t, f, floor, destination))
	if err != nil {
		t.Fatal(err)
	}
	if err := allocate(held); err != nil {
		t.Fatal(err)
	}

	const admitters, iterations = 2, 8
	specs := make([][]models.DebugletSpec, admitters)
	for i := range specs {
		for range iterations {
			specs[i] = append(specs[i], dlSpec(t, f, floor, destination))
		}
	}
	start := make(chan struct{})
	failures := make(chan error, admitters+1)
	var group sync.WaitGroup
	var mu sync.Mutex
	var exited []tgDebuglet
	for i := range admitters {
		group.Go(func() {
			<-start
			for _, spec := range specs[i] {
				deb, err := dlAdmit(f, spec)
				if errors.Is(err, resource.ErrCapacityFull) {
					continue
				}
				if err != nil {
					failures <- fmt.Errorf("admission: %w", err)
					return
				}
				if err := allocate(deb); err != nil {
					failures <- fmt.Errorf("allocation of an admitted run: %w", err)
					return
				}
				if _, err := client.DebugletExit(ctx, &pb.DebugletExitRequest{DebugletId: deb.id.String()}); err != nil {
					failures <- fmt.Errorf("exit: %w", err)
					return
				}
				mu.Lock()
				exited = append(exited, deb)
				mu.Unlock()
			}
		})
	}
	group.Go(func() {
		<-start
		for i := range 4 * iterations {
			level := bitrate.Bitrate(2+i%2) * floor
			for _, limit := range []bitrate.Bitrate{level, level + 1} {
				if err := f.d.SetDestinationLimit(destination, limit); err != nil && !errors.Is(err, resource.ErrCapacityFull) {
					failures <- fmt.Errorf("limit %s: %w", limit, err)
					return
				}
			}
		}
	})
	done := make(chan struct{})
	go func() { group.Wait(); close(done) }()
	close(start)
	select {
	case <-done:
	case <-ctx.Done():
		t.Fatal("concurrent admission, reduction and exit did not join before the deadline")
	}
	close(failures)
	for err := range failures {
		t.Error(err)
	}
	if len(exited) == 0 {
		t.Fatal("no run was admitted while the limit changed")
	}

	allocationCharged(t, f.d, destination, floor)
	if limit := dlCap(f.d, destination); limit < floor {
		t.Fatalf("limit %s is below the charged floor %s", limit, floor)
	}
	if reserved := f.d.scheduler.QueryMaxDest(destination, time.Now(), maxReservableTime); reserved != floor {
		t.Fatalf("reserved floors on the destination are %s, want the remaining run's %s", reserved, floor)
	}
	for _, deb := range exited {
		tgAssertReserved(t, f, deb, floor)
	}
	if _, err := client.DebugletExit(ctx, &pb.DebugletExitRequest{DebugletId: held.id.String()}); err != nil {
		t.Fatal(err)
	}
	allocationCharged(t, f.d, destination, 0)
	tgAssertReserved(t, f, held, 0)
}
