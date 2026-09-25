package dispatcher

import (
	"context"
	pb "github.com/netsec-ethz/debuglet/protocol"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestExpiryRechecksCurrentLease(t *testing.T) {
	d, _, _ := newRegistryFixture(t)
	var clock atomic.Int64
	base := time.Unix(1700000000, 0)
	clock.Store(base.UnixNano())
	d.now = func() time.Time { return time.Unix(0, clock.Load()) }
	owner := registryRegister(t, d, "expiry")
	candidates := d.expiryCandidates()
	if len(candidates) != 1 || candidates[0] != owner {
		t.Fatal("missing expiry candidate")
	}
	clock.Store(base.Add(40 * time.Second).UnixNano())
	// This registry unit fixture explicitly commits a renewal. Actual binding,
	// reverse-probe and sequence validation are transport integration gates.
	if !owner.CommitLease(1) {
		t.Fatal("live owner refused renewal")
	}
	clock.Store(base.Add(61 * time.Second).UnixNano())
	if d.expireOwner(candidates[0]) {
		t.Fatal("expiry used the deadline saved before renewal")
	}
	clock.Store(base.Add(100*time.Second - time.Nanosecond).UnixNano())
	if d.expireOwner(owner) {
		t.Fatal("unexpired lease retired")
	}
	clock.Add(1)
	if !d.expireOwner(owner) || owner.Active() {
		t.Fatal("owner at its exact lease deadline was not retired")
	}
	if _, ok := d.GetExecutor("expiry"); ok {
		t.Fatal("expired record remained visible")
	}
	replacement := registryRegister(t, d, "expiry")
	clock.Add(int64(2 * time.Minute))
	if d.expireOwner(owner) {
		t.Fatal("old expiry removed new owner")
	}
	d.mu.RLock()
	entry := d.executors["expiry"]
	d.mu.RUnlock()
	if entry == nil || entry.owner != replacement || !replacement.Active() {
		t.Fatal("stale candidate retired or removed replacement")
	}
}

func TestHeartbeatDoesNotRenewControlLease(t *testing.T) {
	d, _, _ := newRegistryFixture(t)
	var clock atomic.Int64
	base := time.Unix(1700000000, 0)
	clock.Store(base.UnixNano())
	d.now = func() time.Time { return time.Unix(0, clock.Load()) }
	owner := registryRegister(t, d, "telemetry")
	clock.Store(base.Add(59 * time.Second).UnixNano())
	mutation, err := owner.AdmitMutation(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	_, err = d.OnHeartbeat(mutation.Context(), mutation, &pb.HeartbeatRequest{ExecutorId: "telemetry", TimestampNs: 1 << 62})
	mutation.Finish()
	if err != nil {
		t.Fatal(err)
	}
	clock.Store(base.Add(time.Minute).UnixNano())
	if !d.expireOwner(owner) {
		t.Fatal("recent heartbeat or peer timestamp extended execution authority")
	}
}

func TestDispatcherCloseJoinsExpiry(t *testing.T) {
	t.Run("empty", func(t *testing.T) {
		d, _, ticker := newRegistryFixture(t)
		d.Close()
		d.Close()
		if ticker.calls.Load() != 0 {
			t.Fatal("empty dispatcher started expiry")
		}
	})
	t.Run("idle", func(t *testing.T) {
		d, _, ticker := newRegistryFixture(t)
		registryRegister(t, d, "idle")
		registryWait(t, ticker.started)
		d.Close()
		registryWait(t, ticker.stopped)
		if ticker.calls.Load() != 1 {
			t.Fatal("idle worker start count changed")
		}
	})

	t.Run("reserved_worker", func(t *testing.T) {
		d, _, ticker := newRegistryFixture(t)
		factory := d.newExpiryTicker
		entered, release := make(chan struct{}), make(chan struct{})
		var once sync.Once
		unblock := func() { once.Do(func() { close(release) }) }
		t.Cleanup(unblock)
		d.newExpiryTicker = func(period time.Duration) expiryTicker { close(entered); <-release; return factory(period) }
		registryRegister(t, d, "reserved")
		registryWait(t, entered)
		done := make(chan struct{})
		go func() { d.Close(); close(done) }()
		t.Cleanup(func() { unblock(); registryWait(t, done) })
		registryWait(t, d.expiryStop)
		select {
		case <-done:
			t.Fatal("Close omitted reserved worker join")
		case <-time.After(20 * time.Millisecond):
		}
		unblock()
		registryWait(t, done)
		registryWait(t, ticker.stopped)
		if ticker.calls.Load() != 1 {
			t.Fatal("expiry start reservation duplicated")
		}
	})
	t.Run("active_expiry_and_concurrent_close", func(t *testing.T) {
		d, _, ticker := newRegistryFixture(t)
		var clock atomic.Int64
		base := time.Unix(1700000000, 0)
		clock.Store(base.UnixNano())
		d.now = func() time.Time { return time.Unix(0, clock.Load()) }
		stopping, release := make(chan struct{}), make(chan struct{})
		var once sync.Once
		unblock := func() { once.Do(func() { close(release) }) }
		t.Cleanup(unblock)
		ticker.beforeStop = func() { close(stopping); <-release }
		expired := registryRegister(t, d, "expires")
		registryRegister(t, d, "other")
		registryWait(t, ticker.started)
		clock.Store(base.Add(2 * time.Minute).UnixNano())
		ticker.ticks <- time.Now()
		registryWait(t, expired.Done())
		done := make(chan struct{})
		var callers sync.WaitGroup
		for i := 0; i < 8; i++ {
			callers.Add(1)
			go func() { defer callers.Done(); d.Close() }()
		}
		go func() { callers.Wait(); close(done) }()
		t.Cleanup(func() { unblock(); registryWait(t, done) })
		registryWait(t, stopping)
		select {
		case <-done:
			t.Fatal("Close returned before ticker Stop joined")
		case <-time.After(20 * time.Millisecond):
		}
		unblock()
		registryWait(t, done)
		registryWait(t, ticker.stopped)
		if ticker.calls.Load() != 1 {
			t.Fatalf("expiry workers=%d", ticker.calls.Load())
		}
		if len(d.ListExecutors()) != 0 {
			t.Fatal("closed registry retained visible owner")
		}
	})
}
