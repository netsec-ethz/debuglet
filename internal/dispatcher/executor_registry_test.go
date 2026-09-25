package dispatcher

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/config"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/models"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/payments"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/testutil"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/transport/rpc"
	pb "github.com/netsec-ethz/debuglet/protocol"
	"go.uber.org/zap"
	_ "modernc.org/sqlite"
)

type registryTestTicker struct {
	ticks      chan time.Time
	started    chan struct{}
	stopped    chan struct{}
	calls      atomic.Int32
	once       sync.Once
	beforeStop func()
}

func (t *registryTestTicker) C() <-chan time.Time { return t.ticks }
func (t *registryTestTicker) Stop() {
	t.once.Do(func() {
		if t.beforeStop != nil {
			t.beforeStop()
		}
		close(t.stopped)
	})
}

func newRegistryFixture(t *testing.T) (*Dispatcher, *sql.DB, *registryTestTicker) {
	t.Helper()
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "registry.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Error(err)
		}
	})
	db.SetMaxOpenConns(1)
	testutil.ApplyMigrations(t, db, "database/migrations")
	cfg := &config.DispatcherConfig{}
	cfg.Sui.Disabled = true
	d, err := New(zap.NewNop(), db, "registry-test", time.Minute, time.Second, payments.NewPaymentHandler(db, cfg, zap.NewNop()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		d.Close()
		// Join the actual worker even when a negative control removes Close's
		// join. Tests assert premature completion before this failure cleanup;
		// their later-registered cleanups release every owned gate first.
		d.mu.RLock()
		done := d.expiryDone
		d.mu.RUnlock()
		if done != nil {
			registryWait(t, done)
		}
	})
	ticker := &registryTestTicker{ticks: make(chan time.Time, 1), started: make(chan struct{}), stopped: make(chan struct{})}
	d.newExpiryTicker = func(time.Duration) expiryTicker {
		if ticker.calls.Add(1) == 1 {
			close(ticker.started)
		}
		return ticker
	}
	return d, db, ticker
}
func registryWait(t *testing.T, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("registry fixture worker did not join or reach its observed gate")
	}
}
func registryOwner(t *testing.T, id string) *rpc.SessionOwner {
	t.Helper()
	owner, err := rpc.NewSessionOwner(id, effectTestBinding(t), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	return owner
}
func registryHello(id string) *pb.HelloResponse {
	host := "127.0.0.1"
	return &pb.HelloResponse{ExecutorId: id, Version: "registry-v1", SourceIp: "203.0.113.8", PublicHost: &host, TeslaAnchorKey: bytes.Repeat([]byte{7}, 32), Currency: "TEST", PricePerBwS: 3, TeslaDelaySec: 2}
}

// registryRegisterWithSetup registers an executor the way the control transport
// does: it admits the one setup operation the registration runs under, so that
// retirement cancels the call, and finishes that operation once the call has
// returned.
func registryRegisterWithSetup(ctx context.Context, d *Dispatcher, owner *rpc.SessionOwner, hello *pb.HelloResponse, sourceIP string) error {
	setup, err := owner.AdmitSetup(ctx)
	if err != nil {
		return err
	}
	defer setup.Finish()
	return d.RegisterExecutor(setup.Context(), owner, hello, sourceIP)
}

func registryRegister(t *testing.T, d *Dispatcher, id string) *rpc.SessionOwner {
	t.Helper()
	o, err := rpc.NewSessionOwnerWithClock(id, effectTestBinding(t), d.ControlLeaseDuration(), d.now)
	if err != nil {
		t.Fatal(err)
	}
	if err := registryRegisterWithSetup(context.Background(), d, o, registryHello(id), "127.0.0.1"); err != nil {
		t.Fatal(err)
	}
	if !o.MarkRegistered() {
		t.Fatal("fresh registration was retired")
	}
	return o
}

func TestRegistrySnapshotsAreDetached(t *testing.T) {
	d, _, _ := newRegistryFixture(t)
	fixed := time.Unix(1700000000, 0)
	d.now = func() time.Time { return fixed }
	owner := registryOwner(t, "a")
	hello := registryHello("a")
	if err := registryRegisterWithSetup(context.Background(), d, owner, hello, "127.0.0.1"); err != nil {
		t.Fatal(err)
	}
	owner.MarkRegistered()
	first, second := uuid.New(), uuid.New()
	d.mu.Lock()
	d.executors["a"].AppendDebugletID(first)
	d.executors["a"].capacity = 23
	d.executors["a"].Ready = true
	d.mu.Unlock()
	got, ok := d.GetExecutor("a")
	if !ok {
		t.Fatal("missing registered executor")
	}
	list := d.ListExecutors()
	byIP, ok := d.GetExecutorByIPFull("127.0.0.1")
	if !ok || len(list) != 1 {
		t.Fatal("snapshot lookup failed")
	}
	hello.TeslaAnchorKey[0] = 99
	*hello.PublicHost = "changed-input"
	got.TeslaAnchorKey[1] = 88
	*got.publicHost = "changed-output"
	got.AppendDebugletID(second)
	current, _ := d.GetExecutor("a")
	if current.TeslaAnchorKey[0] != 7 || current.TeslaAnchorKey[1] != 7 || current.PublicHost() != "127.0.0.1" || len(current.RecentDebugletIDs(10)) != 1 {
		t.Fatal("caller mutation changed live registry")
	}
	d.mu.Lock()
	d.executors["a"].AppendDebugletID(second)
	d.mu.Unlock()
	for _, snapshot := range []*RegisteredExecutor{&list[0], &byIP} {
		if snapshot.TeslaAnchorKey[0] != 7 || snapshot.PublicHost() != "127.0.0.1" || len(snapshot.RecentDebugletIDs(10)) != 1 || snapshot.capacity != 23 {
			t.Fatal("prior snapshot followed live mutation")
		}
	}
	owner.Retire()
	replacement := registryOwner(t, "a")
	empty := registryHello("a")
	empty.TeslaAnchorKey = nil
	empty.PublicHost = nil
	if err := registryRegisterWithSetup(context.Background(), d, replacement, empty, "127.0.0.1"); err != nil {
		t.Fatal(err)
	}
	replacement.MarkRegistered()
	current, _ = d.GetExecutor("a")
	if current.Ready || current.capacity != 0 || len(current.TeslaAnchorKey) != 0 || current.PublicHost() != "" || len(current.RecentDebugletIDs(10)) != 2 {
		t.Fatal("replacement inherited stale metadata or lost copied history")
	}
	d.OnExecutorDisconnected(owner)
	if current, ok = d.GetExecutor("a"); !ok || current.ID != "a" {
		t.Fatal("old disconnect removed replacement")
	}
	registryRegister(t, d, "z")
	tie, ok := d.GetExecutorByIPFull("127.0.0.1")
	if !ok || tie.ID != "a" {
		t.Fatalf("unstable IP tie: %s", tie.ID)
	}
	if _, ok := d.GetExecutorByIPFull(""); ok {
		t.Fatal("empty IP matched")
	}
	d.Close()
	if _, ok := d.GetExecutor("a"); ok || len(d.ListExecutors()) != 0 {
		t.Fatal("closed registry exposed entries")
	}
}

func TestHeartbeatUsesReceiptTime(t *testing.T) {
	d, _, _ := newRegistryFixture(t)
	var clock atomic.Int64
	clock.Store(time.Unix(1700000000, 0).UnixNano())
	d.now = func() time.Time { return time.Unix(0, clock.Load()) }
	owner := registryRegister(t, d, "clock")
	for _, sender := range []int64{1, 1 << 62} {
		clock.Add(int64(time.Second))
		mutation := effectTestMutation(t, d, "clock")
		_, err := d.OnHeartbeat(context.Background(), mutation, &pb.HeartbeatRequest{ExecutorId: "clock", TimestampNs: sender})
		mutation.Finish()
		if err != nil {
			t.Fatal(err)
		}
		snapshot, _ := d.GetExecutor("clock")
		if snapshot.LastSeen.UnixNano() != clock.Load() || !snapshot.Ready {
			t.Fatal("sender time controlled local liveness")
		}
	}
	owner.Retire()
	if _, err := d.OnHeartbeat(context.Background(), nil, &pb.HeartbeatRequest{ExecutorId: "clock"}); err == nil {
		t.Fatal("retired-only heartbeat succeeded")
	}
	replacement := registryRegister(t, d, "clock")
	clock.Add(int64(time.Second))
	// The replacement requires its own freshly admitted ticket.
	if _, err := d.OnHeartbeat(context.Background(), effectTestMutation(t, d, "clock"), &pb.HeartbeatRequest{ExecutorId: "clock", TimestampNs: 1}); err != nil {
		t.Fatal(err)
	}
	if !replacement.Available() {
		t.Fatal("bound update retired replacement")
	}
	snapshot, _ := d.GetExecutor("clock")
	if snapshot.LastSeen.UnixNano() != clock.Load() {
		t.Fatal("replacement did not receive its admitted heartbeat")
	}
	if _, err := d.OnResources(context.Background(), nil, &pb.ResourcesRequest{ExecutorId: "missing"}); err == nil {
		t.Fatal("unknown Resources succeeded")
	}
}

func TestRegistrationAvailabilityAndClose(t *testing.T) {
	t.Run("availability", func(t *testing.T) {
		d, _, _ := newRegistryFixture(t)
		owner := registryOwner(t, "staged")
		if err := registryRegisterWithSetup(context.Background(), d, owner, registryHello("staged"), "127.0.0.1"); err != nil {
			t.Fatal(err)
		}
		if _, err := d.OnHeartbeat(context.Background(), nil, &pb.HeartbeatRequest{ExecutorId: "staged"}); err == nil {
			t.Fatal("staged heartbeat accepted without ordinary admission")
		}
		if _, err := d.OnResources(context.Background(), nil, &pb.ResourcesRequest{ExecutorId: "staged", BandwidthCapacity: 100}); err == nil {
			t.Fatal("staged resources accepted without ordinary admission")
		}
		if _, ok := d.GetExecutor("staged"); ok || len(d.ListExecutors()) != 0 {
			t.Fatal("registry became available before callback completion")
		}
		if _, ok := d.GetExecutorByIPFull("127.0.0.1"); ok {
			t.Fatal("IP lookup exposed staged owner")
		}
		d.mu.Lock()
		_, err := d.validateDebugletSpec(&models.DebugletSpec{ExecutorID: "staged"})
		d.mu.Unlock()
		if err == nil {
			t.Fatal("staged owner admitted work")
		}
		if !owner.MarkRegistered() {
			t.Fatal("mark registration failed")
		}
		mutation := effectTestMutation(t, d, "staged")
		if _, err := d.OnHeartbeat(context.Background(), mutation, &pb.HeartbeatRequest{ExecutorId: "staged"}); err != nil {
			t.Fatal(err)
		}
		if _, err := d.OnResources(context.Background(), mutation, &pb.ResourcesRequest{ExecutorId: "staged", BandwidthCapacity: 100}); err != nil {
			t.Fatal(err)
		}
		mutation.Finish()
		snapshot, ok := d.GetExecutor("staged")
		if !ok || !snapshot.Ready || snapshot.capacity != 100 {
			t.Fatal("shared availability lost staged updates")
		}
	})
	t.Run("owned_SQL_call", func(t *testing.T) {
		d, db, _ := newRegistryFixture(t)
		original := d.initializeEarnings
		entered, canceled, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
		var releaseOnce sync.Once
		unblock := func() { releaseOnce.Do(func() { close(release) }) }
		var calls atomic.Int32
		d.initializeEarnings = func(ctx context.Context, e *RegisteredExecutor) {
			calls.Add(1)
			original(ctx, e)
			close(entered)
			<-ctx.Done()
			close(canceled)
			<-release
		}
		result := make(chan error, 1)
		joined := make(chan struct{})
		closed := make(chan struct{})
		owner := registryOwner(t, "held")
		go func() {
			defer close(joined)
			result <- registryRegisterWithSetup(context.Background(), d, owner, registryHello("held"), "")
		}()
		var closeOnce sync.Once
		startClose := func() { closeOnce.Do(func() { go func() { d.Close(); close(closed) }() }) }
		t.Cleanup(func() { startClose(); unblock(); registryWait(t, joined); registryWait(t, closed) })
		registryWait(t, entered)
		var rows int
		if err := db.QueryRow("SELECT count(*) FROM earnings WHERE executor_id = 'held'").Scan(&rows); err != nil || rows != 1 {
			t.Fatalf("actual earnings helper rows=%d err=%v", rows, err)
		}
		startClose()
		registryWait(t, canceled)
		select {
		case <-closed:
			t.Fatal("Close returned before admitted registration joined")
		case <-time.After(20 * time.Millisecond):
		}
		unblock()
		registryWait(t, joined)
		registryWait(t, closed)
		if err := <-result; !errors.Is(err, ErrDispatcherClosed) {
			t.Fatalf("held registration result=%v", err)
		}
		if err := registryRegisterWithSetup(context.Background(), d, registryOwner(t, "after"), registryHello("after"), ""); !errors.Is(err, ErrDispatcherClosed) {
			t.Fatalf("post-close registration=%v", err)
		}
		if calls.Load() != 1 {
			t.Fatal("post-close registration issued earnings work")
		}
	})
	t.Run("retirement_cancels_registration", func(t *testing.T) {
		d, _, _ := newRegistryFixture(t)
		original := d.initializeEarnings
		entered, canceled, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
		var once sync.Once
		unblock := func() { once.Do(func() { close(release) }) }
		d.initializeEarnings = func(ctx context.Context, e *RegisteredExecutor) {
			original(ctx, e)
			close(entered)
			<-ctx.Done()
			close(canceled)
			<-release
		}
		owner := registryOwner(t, "retired")
		result := make(chan error, 1)
		joined := make(chan struct{})
		go func() {
			defer close(joined)
			result <- registryRegisterWithSetup(context.Background(), d, owner, registryHello("retired"), "")
		}()
		t.Cleanup(func() { owner.Retire(); unblock(); registryWait(t, joined) })
		registryWait(t, entered)
		owner.Retire()
		registryWait(t, canceled)
		select {
		case <-owner.MutationsDrained():
			t.Fatal("retirement discarded registration setup SQL ownership")
		default:
		}
		unblock()
		registryWait(t, joined)
		registryWait(t, owner.MutationsDrained())
		if err := <-result; !errors.Is(err, ErrSessionRetired) {
			t.Fatalf("retirement result=%v", err)
		}
		d.mu.RLock()
		entry := d.executors["retired"]
		started := d.expiryDone
		pending := len(d.registrations)
		d.mu.RUnlock()
		if entry != nil || started != nil || pending != 0 {
			t.Fatal("retired registration retained publication or workers")
		}
	})

	t.Run("cancellation_before_commit", func(t *testing.T) {
		d, _, _ := newRegistryFixture(t)
		original := d.initializeEarnings
		entered, release, approaching := make(chan struct{}), make(chan struct{}), make(chan struct{})
		var once sync.Once
		unblock := func() { once.Do(func() { close(release) }) }
		d.initializeEarnings = func(ctx context.Context, e *RegisteredExecutor) { original(ctx, e); close(entered); <-release }
		d.now = func() time.Time { close(approaching); return time.Now() }
		ctx, cancel := context.WithCancel(context.Background())
		result := make(chan error, 1)
		joined := make(chan struct{})
		owner := registryOwner(t, "expired")
		go func() {
			defer close(joined)
			result <- registryRegisterWithSetup(ctx, d, owner, registryHello("expired"), "")
		}()
		t.Cleanup(func() { cancel(); unblock(); registryWait(t, joined) })
		registryWait(t, entered)
		d.mu.Lock()
		unblock()
		// The clock call is immediately before lock acquisition, outside all locks.
		// No sleep is used to infer registration progress.
		select {
		case <-approaching:
		case <-time.After(3 * time.Second):
			d.mu.Unlock()
			t.Fatal("registration never approached commit")
		}
		cancel()
		d.mu.Unlock()
		registryWait(t, joined)
		if err := <-result; !errors.Is(err, context.Canceled) {
			t.Fatalf("expired publication=%v", err)
		}
		d.mu.RLock()
		entry := d.executors["expired"]
		started := d.expiryDone
		d.mu.RUnlock()
		if entry != nil || started != nil {
			t.Fatal("canceled registration published or started expiry")
		}
	})
}

// TestRegistryRejectsInvalidAdmission drives registration directly, without the
// transport's setup operation around it, because these are the guards
// registration applies to what it is handed.
func TestRegistryRejectsInvalidAdmission(t *testing.T) {
	d, _, _ := newRegistryFixture(t)
	var calls atomic.Int32
	original := d.initializeEarnings
	d.initializeEarnings = func(ctx context.Context, e *RegisteredExecutor) { calls.Add(1); original(ctx, e) }
	owner := registryOwner(t, "valid")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := d.RegisterExecutor(ctx, owner, registryHello("valid"), ""); !errors.Is(err, context.Canceled) {
		t.Fatal("pre-canceled registration accepted")
	}
	if err := d.RegisterExecutor(context.Background(), owner, registryHello("other"), ""); err == nil {
		t.Fatal("identity alias accepted")
	}
	owner.Retire()
	if err := d.RegisterExecutor(context.Background(), owner, registryHello("valid"), ""); !errors.Is(err, ErrSessionRetired) {
		t.Fatal("retired registration accepted")
	}
	if invalid, err := New(zap.NewNop(), d.db, "invalid", 0, time.Second, d.Payment); err == nil || invalid != nil {
		t.Fatal("zero control lease accepted during construction")
	}
	if calls.Load() != 0 {
		t.Fatal("invalid registration performed SQL")
	}
}

func TestRegistryUpdatesAndReplacement(t *testing.T) {
	d, _, _ := newRegistryFixture(t)
	initial := registryRegister(t, d, "race")
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	var workers sync.WaitGroup
	done := make(chan struct{})
	workers.Add(4)
	go func() {
		defer workers.Done()
		old := initial
		for i := 0; i < 24; i++ {
			old.Retire()
			next, err := rpc.NewSessionOwner("race", effectTestBinding(t), time.Minute)
			if err != nil {
				t.Error(err)
				return
			}
			if err := registryRegisterWithSetup(ctx, d, next, registryHello("race"), "127.0.0.1"); err != nil {
				t.Error(err)
				return
			}
			next.MarkRegistered()
			d.OnExecutorDisconnected(old)
			old = next
		}
	}()
	go func() {
		defer workers.Done()
		for i := 0; i < 96; i++ {
			mutation, err := effectAdmit(ctx, d, "race")
			if err == nil {
				_, _ = d.OnResources(ctx, mutation, &pb.ResourcesRequest{ExecutorId: "race", BandwidthCapacity: int64(i)})
				mutation.Finish()
			}
		}
	}()
	go func() {
		defer workers.Done()
		for i := 0; i < 48; i++ {
			mutation, err := effectAdmit(ctx, d, "race")
			if err == nil {
				_, _ = d.OnHeartbeat(ctx, mutation, &pb.HeartbeatRequest{ExecutorId: "race", TimestampNs: int64(i)})
				mutation.Finish()
			}
		}
	}()
	go func() {
		defer workers.Done()
		for i := 0; i < 96; i++ {
			if e, ok := d.GetExecutor("race"); ok {
				e.AppendDebugletID(uuid.New())
				if len(e.TeslaAnchorKey) > 0 {
					e.TeslaAnchorKey[0] = 99
				}
			}
			d.ListExecutors()
			d.GetExecutorByIPFull("127.0.0.1")
		}
	}()
	go func() { workers.Wait(); close(done) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Error("registry producers did not join")
		}
	})
	select {
	case <-done:
	case <-ctx.Done():
		t.Fatal("registry concurrent producers timed out")
	}
	snapshot, ok := d.GetExecutor("race")
	if !ok || len(snapshot.RecentDebugletIDs(10)) != 0 || snapshot.TeslaAnchorKey[0] != 7 {
		t.Fatal("concurrent snapshot mutation escaped into live state")
	}
}
