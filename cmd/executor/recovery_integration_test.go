package main

import (
	"bufio"
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/netsec-ethz/debuglet/internal/dispatcher"
	dconfig "github.com/netsec-ethz/debuglet/internal/dispatcher/config"
	ddb "github.com/netsec-ethz/debuglet/internal/dispatcher/database"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/models"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/payments"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/testutil"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/transport/api"
	drpc "github.com/netsec-ethz/debuglet/internal/dispatcher/transport/rpc"
	"github.com/netsec-ethz/debuglet/internal/executor/config"
	edb "github.com/netsec-ethz/debuglet/internal/executor/database"
	"github.com/netsec-ethz/debuglet/internal/readiness"
	"github.com/netsec-ethz/debuglet/pkg/client"
	pb "github.com/netsec-ethz/debuglet/protocol"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"modernc.org/sqlite"
	sqlite3 "modernc.org/sqlite/lib"
)

const (
	// commandRowWait bounds a canonical-row read whose caller has no shorter
	// window of its own. The database's busy timeout is shorter, so a
	// contended read is retried several times inside it.
	commandRowWait = 5 * time.Second
	// commandRowMargin is left to a caller that reads inside a window it still
	// needs afterwards, and commandRowMinimum keeps one attempt in a window
	// that is already spent: an observation must fail with what it read.
	commandRowMargin  = 500 * time.Millisecond
	commandRowMinimum = 250 * time.Millisecond
	// commandBusyTimeoutMS is the busy timeout the services' own DSNs carry.
	commandBusyTimeoutMS = 1000
	// commandRequestTimeout bounds each request of the fixture's client. A
	// TEST submission makes two, the payment intent and then the submission
	// the dispatcher admits, so a submission that succeeds was admitted within
	// twice this bound; a slower one fails on its own.
	commandRequestTimeout = 5 * time.Second
	// commandRetireMargin bounds how long before the queued start the first
	// transport is retired. The successor sends its Bind only after that, and
	// its registration is held until the start, so the hold delays the Bind's
	// acknowledgement by at most this much: the rest of the executor's fixed
	// five-second Bind bound is left to the dispatcher's own registration.
	commandRetireMargin = 3 * time.Second
)

// This is the actual command function, dispatcher and guest path. The only
// callback adapter observes registration and holds its second invocation; it
// delegates every application effect to the real dispatcher. It does not model
// a process crash, remote quiescence or recovery of an old terminal outcome.
func TestExecutorCommandReconnectWithRealGuest(t *testing.T) {
	dir, err := os.MkdirTemp("", "debuglet-command-recovery-")
	if err != nil {
		t.Fatal(err)
	}
	var f *commandRecovery
	t.Cleanup(func() {
		if f != nil && f.retained {
			t.Log("failed command retains its state directory until the outer test-process/container boundary")
			return
		}
		if err := os.RemoveAll(dir); err != nil {
			t.Error(err)
		}
	})
	guest := commandRecoveryGuest(t, dir)
	// This budget covers everything after the guest build: the queued start's
	// window, which is derived from bounds and so costs about fourteen seconds
	// on any host, the reconnect with its held registration, the fresh guest run
	// and the join. It only decides how quickly a genuine hang is reported, and
	// stays well inside the package timeout.
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	f = &commandRecovery{t: t, ctx: ctx, cancel: cancel, ready: filepath.Join(dir, "ready.json"), done: make(chan struct{})}
	t.Cleanup(f.close)
	f.open(dir)
	first := f.connected()
	f.awaitReady(first)

	blocked := f.target("blocked")
	active := f.submit(guest, blocked, nil)
	f.await(blocked.ack, "first real guest ACK before withholding EOF")
	if state, err := f.sdk.Status(ctx, active.IDs[0]); err != nil || state.State != models.RunStateStarted.String() {
		t.Fatalf("first guest is not actually started: state=%s error=%v", state.State, err)
	}
	select {
	case <-blocked.done:
		t.Fatal("first target completed before transport retirement")
	default:
	}

	queuedTarget := f.target("queued")
	// Submit after real guest entry so its compilation does not consume this
	// interval. The queued start is fixed before the submission, and each part
	// of its window stands for a bound, not for an expected duration:
	//   - admission: the dispatcher drops a start that has already passed, so
	//     the start lies beyond the longest submission that can succeed, two
	//     requests of commandRequestTimeout, plus the second that truncation
	//     to a whole Unix timestamp can take off;
	//   - retirement: the first transport is retired while the run is still
	//     queued, so commandRetireMargin is kept beyond the admission bound for
	//     the read and the retirement that follow even the longest submission;
	//   - Bind: the next registration is held until this timestamp is due, and
	//     the retirement waits until no more than commandRetireMargin remains,
	//     so that hold stays under the fixed five-second Bind bound however
	//     quickly the submission completes.
	future := time.Now().Add(2*commandRequestTimeout + time.Second + commandRetireMargin).Unix()
	queued := f.submit(guest, queuedTarget, &future)
	// This read happens inside the window the queued start is still due in, so
	// it may not spend the part of it that the retirement below needs.
	before := f.executorRow(queued.IDs[0], commandRowBound(time.Until(time.Unix(future, 0))))
	if !before.StartedAt.IsZero() || before.DispatcherIncarnation != first.Binding().Incarnation || before.SessionID != first.Binding().SessionID {
		t.Fatal("queued row did not retain the first negotiated binding")
	}
	if !before.StartTime.Equal(time.Unix(future, 0)) {
		t.Fatal("queued canonical start time differs from the observed due-time boundary")
	}
	if !bytes.Equal(before.Wasm, guest) || !reflect.DeepEqual([]string(before.Args), []string{queuedTarget.addr(), queuedTarget.nonce}) {
		t.Fatal("queued canonical bytes/arguments differ from the submitted guest")
	}
	// Retire at an observed distance from the start, not as soon as the row
	// was read: after a quick submission the rest of the window is longer than
	// the held registration may take.
	if delay := time.Until(time.Unix(future, 0)) - commandRetireMargin; delay > 0 {
		timer := time.NewTimer(delay)
		select {
		case <-timer.C:
		case <-ctx.Done():
			timer.Stop()
			t.Fatal("queued retirement observation exceeded the owned runtime budget")
		}
	}
	if !time.Now().Before(time.Unix(future, 0)) {
		t.Fatal("queued start elapsed before retirement; no future-queue control was established")
	}
	if !f.dispatcher.Bidi.RemoveClient(first) {
		t.Fatal("failed to retire the exact first transport owner")
	}
	f.await(blocked.done, "old guest socket closure from transport loss")
	if blocked.err != nil {
		t.Fatalf("old target did not observe clean guest socket closure: %v", blocked.err)
	}
	second := f.connected()
	if first == second || first.Binding() == second.Binding() || first.Binding().Incarnation != second.Binding().Incarnation {
		t.Fatal("command retry did not negotiate a distinct session in the same dispatcher")
	}
	if err := f.adapter.readyObservation; err != nil {
		t.Fatalf("second Connected saw stale readiness: %v", err)
	}
	if second.Available() {
		t.Fatal("second owner became available while its real registration was held")
	}
	if delay := time.Until(time.Unix(future, 0)); delay > 0 {
		timer := time.NewTimer(delay)
		select {
		case <-timer.C:
		case <-ctx.Done():
			timer.Stop()
			t.Fatal("queued due-time observation exceeded the owned runtime budget")
		}
	}
	f.adapter.unblock()
	f.awaitReady(second)
	if after := f.executorRow(queued.IDs[0], commandRowWait); !reflect.DeepEqual(before, after) {
		t.Fatal("successor changed or started the old queued row after its due time")
	}

	freshTarget := f.target("fresh")
	fresh := f.submit(guest, freshTarget, nil)
	if fresh.IDs[0] == active.IDs[0] || fresh.IDs[0] == queued.IDs[0] || fresh.TransactionID == active.TransactionID {
		t.Fatal("new submission reused an earlier identity")
	}
	f.await(freshTarget.done, "fresh guest nonce/ACK/normal EOF exchange")
	if freshTarget.err != nil {
		t.Fatal(freshTarget.err)
	}
	f.awaitResult(fresh.IDs[0], freshTarget.nonce)
	row, err := ddb.New(f.dispatcherDB).GetDebugletByUUID(ctx, uuid.MustParse(fresh.IDs[0]))
	if err != nil || row.DispatcherIncarnation != second.Binding().Incarnation || row.SessionID != second.Binding().SessionID || row.State != models.RunStateExited || row.Error.String != "" {
		t.Fatalf("fresh terminal row did not retain the successor binding: %v", err)
	}
	select {
	case <-queuedTarget.accepted:
		t.Fatal("quarantined guest reached its target after becoming due")
	default:
	}
	if f.adapter.count.Load() != 2 {
		t.Fatal("unexpected extra command session; retries cannot substitute for the observed successor")
	}
	// Observe the actual command join and readiness withdrawal before teardown
	// closes target listeners or dispatcher transports. No old terminal result
	// is required: the lost binding's report remains unconfirmed. Do not read
	// executor SQLite while the fresh callback may still be finalizing: this
	// independent observer must not introduce a rollback-journal reader lock.
	cancel()
	f.await(f.done, "actual runExecutor return after parent cancellation")
	if f.runErr != nil {
		t.Fatalf("actual command cleanup: %v", f.runErr)
	}
	if _, err := os.Lstat(f.ready); !os.IsNotExist(err) {
		t.Fatalf("joined command retained readiness: %v", err)
	}
	if after := f.executorRow(queued.IDs[0], commandRowWait); !reflect.DeepEqual(before, after) {
		t.Fatal("joined command changed the quarantined queued row")
	}
	select {
	case <-queuedTarget.accepted:
		t.Fatal("old queued target accepted before the actual command joined")
	default:
	}
	t.Log("actual command reconnected once; old socket closed, readiness withdrawn, due queue retained, fresh real guest output and terminal verified")
}

type commandRegistration struct {
	drpc.DispatcherState
	readyPath        string
	owners           chan *drpc.SessionOwner
	release          chan struct{}
	once             sync.Once
	count            atomic.Int32
	readyObservation error // Published before the second owners send.
}

func (a *commandRegistration) unblock() { a.once.Do(func() { close(a.release) }) }
func (a *commandRegistration) OnExecutorConnected(ctx context.Context, owner *drpc.SessionOwner, hello *pb.HelloResponse, ip string) error {
	count := a.count.Add(1)
	if count == 2 {
		if _, err := os.Lstat(a.readyPath); !os.IsNotExist(err) {
			a.readyObservation = fmt.Errorf("previous readiness path is not absent: %w", err)
		}
	}
	select {
	case a.owners <- owner:
	case <-ctx.Done():
		return ctx.Err()
	}
	if count == 2 {
		select {
		case <-a.release:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return a.DispatcherState.OnExecutorConnected(ctx, owner, hello, ip)
}

type commandRecovery struct {
	t            *testing.T
	ctx          context.Context
	cancel       context.CancelFunc
	ready        string
	id           string
	dispatcherDB *sql.DB
	executorDB   *sql.DB // Independent observer; runExecutor owns its actual pool.
	dispatcher   *dispatcher.Dispatcher
	adapter      *commandRegistration
	sdk          *client.Client
	http         *httptest.Server
	listeners    []net.Listener
	serves       sync.WaitGroup
	targets      []*commandGuestTarget
	started      bool
	retained     bool
	done         chan struct{}
	runErr       error
}

func (f *commandRecovery) open(dir string) {
	f.t.Helper()
	open := func(name, migrations string) *sql.DB {
		f.t.Helper()
		// Only the executor's database is read beside a service that writes to
		// it. The dispatcher's handle is that service's own, and is left as the
		// dispatcher opens it.
		dsn := filepath.Join(dir, name)
		if name == "executor.sqlite" {
			dsn = commandDSN(dsn)
		}
		db, err := sql.Open("sqlite", dsn)
		if err != nil {
			f.t.Fatal(err)
		}
		db.SetMaxOpenConns(1)
		// Publish ownership before migrations can fail.
		if name == "dispatcher.sqlite" {
			f.dispatcherDB = db
		} else {
			f.executorDB = db
		}
		testutil.ApplyMigrations(f.t, db, migrations)
		return db
	}
	open("dispatcher.sqlite", "../../internal/dispatcher/database/migrations")
	open("executor.sqlite", "../../internal/executor/database/migrations")
	logger := zap.NewNop()
	ph := payments.NewPaymentHandler(f.dispatcherDB, &dconfig.DispatcherConfig{Sui: dconfig.SuiConfig{Disabled: true}}, logger)
	var err error
	f.dispatcher, err = dispatcher.New(logger, f.dispatcherDB, "command-recovery", time.Minute, time.Second, ph)
	if err != nil {
		f.t.Fatal(err)
	}
	f.dispatcher.Bidi.Close() // Replace only the unused transport, before serving.
	f.adapter = &commandRegistration{DispatcherState: f.dispatcher, readyPath: f.ready, owners: make(chan *drpc.SessionOwner, 4), release: make(chan struct{})}
	replacement, err := drpc.NewBidiServer(logger, f.adapter, f.dispatcher.ControlIncarnation(), f.dispatcher.ControlLeaseDuration())
	if err != nil {
		f.t.Fatal(err)
	}
	f.dispatcher.Bidi = replacement
	listen := func(serve func(context.Context, net.Listener) error) string {
		f.t.Helper()
		lis, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			f.t.Fatal(err)
		}
		f.listeners = append(f.listeners, lis)
		f.serves.Add(1)
		go func() {
			defer f.serves.Done()
			if err := serve(f.ctx, lis); err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, grpc.ErrServerStopped) && !errors.Is(err, net.ErrClosed) {
				f.t.Errorf("actual dispatcher listener: %v", err)
			}
		}()
		return lis.Addr().String()
	}
	direct, reverse := listen(f.dispatcher.Bidi.ServeGRPCListener), listen(f.dispatcher.Bidi.ServeYamux)
	e := echo.New()
	e.HideBanner = true
	api.NewHandler(f.dispatcher, f.dispatcherDB, logger, api.LocalDevelopment(true)).RegisterRoutes(e)
	f.http = httptest.NewServer(e)
	f.sdk, err = client.New(f.http.URL, client.Options{HTTPClient: f.http.Client(), RequestTimeout: commandRequestTimeout})
	if err != nil {
		f.t.Fatal(err)
	}
	f.id = uuid.NewString()
	// The guest measures against a target on this machine, so this executor
	// says so; the default policy reaches no loopback service.
	localTargets := true
	cfg := &config.ExecutorConfig{
		Identity:   config.IdentityConfig{ExecutorID: f.id, Version: "command-recovery"},
		Dispatcher: config.DispatcherConfig{Addr: direct, YamuxAddr: reverse}, TLS: config.TLSConfig{Disable: true},
		Resources: config.ResourcesConfig{Capacity: 1000000000, MaxDebuglets: 8},
		Tesla:     config.TeslaConfig{Seed: "owned-command-recovery", Delay: 2, ChainLength: 64},
		Network: config.NetworkConfig{PacketCounter: "fallback", DisableSCIONEnvironment: true,
			Policy: config.PolicyConfig{LocalTargets: &localTargets}},
		Database: config.DatabaseConfig{Path: filepath.Join(dir, "executor.sqlite")},
		Pricing:  config.PricingConfig{PricePerBwS: 1, Currency: "TEST"},
	}
	f.started = true
	go func() { defer close(f.done); f.runErr = runExecutor(f.ctx, cfg, f.ready, logger) }()
}

func (f *commandRecovery) connected() *drpc.SessionOwner {
	f.t.Helper()
	select {
	case owner := <-f.adapter.owners:
		return owner
	case <-f.done:
		f.t.Fatalf("command ended before real Connected: %v", f.runErr)
	case <-f.ctx.Done():
		f.t.Fatal("real Connected was not observed within the runtime budget")
	}
	return nil
}

func (f *commandRecovery) await(done <-chan struct{}, what string) {
	f.t.Helper()
	timer := time.NewTimer(10 * time.Second)
	defer timer.Stop()
	select {
	case <-done:
	case <-timer.C:
		f.t.Fatalf("did not observe %s within its bound", what)
	}
}

func (f *commandRecovery) poll() {
	f.t.Helper()
	timer := time.NewTimer(20 * time.Millisecond)
	defer timer.Stop()
	select {
	case <-timer.C:
	case <-f.ctx.Done():
		f.t.Fatal("actual command traversal exceeded its runtime budget")
	case <-f.done:
		f.t.Fatalf("actual command ended during traversal: %v", f.runErr)
	}
}

func (f *commandRecovery) awaitReady(owner *drpc.SessionOwner) {
	f.t.Helper()
	for {
		data, err := commandReadReady(f.ready)
		if err != nil && !os.IsNotExist(err) {
			f.t.Fatal(err)
		}
		if err == nil {
			var record readiness.Record
			if len(data) > 4096 || json.Unmarshal(data, &record) != nil || record.SchemaVersion != 1 || record.PID != os.Getpid() || record.ExecutorID != f.id {
				f.t.Fatal("actual command readiness record is malformed or has a different identity")
			}
			nodes, err := f.sdk.Nodes(f.ctx)
			if err != nil {
				f.t.Fatal(err)
			}
			if owner.Available() && len(nodes) == 1 && nodes[0].ID == f.id && nodes[0].Ready {
				return
			}
		}
		f.poll()
	}
}

func (f *commandRecovery) submit(wasm []byte, target *commandGuestTarget, start *int64) client.Submission {
	f.t.Helper()
	batch, err := client.Prepare([]client.Request{{OrderID: 1, ExecutorID: f.id, StartTimestamp: start, Wasm: wasm,
		Args: []string{target.addr(), target.nonce}, Policy: client.Policy{FloorBW: 64000, CeilBW: 1000000, TimeoutMS: 30000, Addresses: []string{"127.0.0.1"}}}})
	if err != nil {
		f.t.Fatal(err)
	}
	submission, err := f.sdk.SubmitTEST(f.ctx, batch)
	if err != nil || len(submission.IDs) != 1 {
		f.t.Fatalf("actual TEST submission: %v", err)
	}
	transaction, err := ddb.New(f.dispatcherDB).GetTransactionByID(f.ctx, submission.TransactionID)
	if err != nil || transaction.Method != "TEST" || transaction.Status != int64(models.Paid) || transaction.Price != 0 || transaction.Currency != "" {
		f.t.Fatalf("actual TEST transaction bookkeeping: %v", err)
	}
	return submission
}

// commandDSN is the observer's connection to the executor's database, which
// the actual command writes to throughout. A file URI keeps filename
// characters separate from the connection options, and the busy timeout is the
// one the services' own DSNs carry (internal/demo/schema.go,
// internal/storagecheck): a lock this reader can wait out is not an
// observation. The daemons' own handles are untouched.
func commandDSN(path string) string {
	dsn := url.URL{Scheme: "file", Path: filepath.ToSlash(path)}
	dsn.RawQuery = url.Values{"_pragma": {fmt.Sprintf("busy_timeout(%d)", commandBusyTimeoutMS)}}.Encode()
	return dsn.String()
}

// commandRowPending reports whether a failed read can still succeed: the live
// command holds the database lock, or the canonical row it writes has not
// appeared yet.
func commandRowPending(err error) bool {
	var busy *sqlite.Error
	// Extended result codes keep the primary code in their low byte.
	return errors.Is(err, sql.ErrNoRows) || errors.As(err, &busy) && busy.Code()&0xff == sqlite3.SQLITE_BUSY
}

// awaitCanonicalRow reads the canonical row for id while the actual command
// owns the same database, waiting out a locked database or a row that has not
// been written yet. It returns what the reads found when neither resolves
// inside ctx, and reports how long the read had to wait.
func awaitCanonicalRow(ctx context.Context, db *sql.DB, id uuid.UUID) (edb.Debuglet, time.Duration, error) {
	queries, started := edb.New(db), time.Now()
	var pending error // The last read this wait could still resolve.
	for {
		row, err := queries.GetDebugletByUUID(ctx, id)
		switch {
		case err == nil:
			return row, time.Since(started), nil
		case commandRowPending(err):
			pending = err
		case pending != nil && ctx.Err() != nil:
			// The expiring bound cancels the read in flight, whether the driver
			// reports that as the context's error or as its own interruption.
			// Report what the reads that did complete found.
			return edb.Debuglet{}, time.Since(started), pending
		default:
			return edb.Debuglet{}, time.Since(started), err
		}
		timer := time.NewTimer(20 * time.Millisecond)
		select {
		case <-timer.C:
		case <-ctx.Done():
			timer.Stop()
			return edb.Debuglet{}, time.Since(started), pending
		}
		timer.Stop()
	}
}

// commandRowBound is the share of a caller's remaining window that a canonical
// row read may spend, so a slow read fails with its own diagnostic instead of
// consuming the window the caller still needs.
func commandRowBound(remaining time.Duration) time.Duration {
	return max(remaining-commandRowMargin, commandRowMinimum)
}

func (f *commandRecovery) executorRow(id string, bound time.Duration) edb.Debuglet {
	f.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), bound)
	defer cancel()
	row, waited, err := awaitCanonicalRow(ctx, f.executorDB, uuid.MustParse(id))
	if err != nil {
		f.t.Fatalf("canonical queued row: %v", err)
	}
	if waited > 20*time.Millisecond {
		// A wait is part of this observation's cost, which the test's own
		// timing assertions have to account for.
		f.t.Logf("canonical row %s was read after %s", id, waited)
	}
	return row
}

// The fixture reads a database the actual command writes to, so it carries the
// services' busy timeout. A canonical row that never appears must still fail
// inside the caller's bound, with the read's own diagnostic.
func TestCanonicalRowWaitIsBounded(t *testing.T) {
	db, err := sql.Open("sqlite", commandDSN(filepath.Join(t.TempDir(), "executor.sqlite")))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Error(err)
		}
	})
	db.SetMaxOpenConns(1)
	testutil.ApplyMigrations(t, db, "../../internal/executor/database/migrations")
	var timeout int64
	if err := db.QueryRow("PRAGMA busy_timeout").Scan(&timeout); err != nil || timeout != commandBusyTimeoutMS {
		t.Fatalf("fixture busy timeout is %d: %v", timeout, err)
	}
	bound := 300 * time.Millisecond
	started := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), bound)
	defer cancel()
	_, waited, err := awaitCanonicalRow(ctx, db, uuid.New())
	elapsed := time.Since(started)
	if !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("absent canonical row reported %v, want the read's own diagnostic", err)
	}
	if elapsed < bound || elapsed > commandRowWait || waited > elapsed {
		t.Fatalf("absent canonical row failed after %s (waited %s), want its %s bound", elapsed, waited, bound)
	}
}

func (f *commandRecovery) awaitResult(id, nonce string) {
	f.t.Helper()
	var output []byte
	var cursor int64
	marker := []byte("DEBUGLET_DEMO_OK " + nonce + "\n")
	for {
		state, err := f.sdk.Status(f.ctx, id)
		if err != nil || state.ExecutorID != f.id || state.Error != "" {
			f.t.Fatalf("fresh guest status: error=%v workload=%q", err, state.Error)
		}
		page, err := f.sdk.Logs(f.ctx, id, client.LogOptions{After: cursor, Limit: 100})
		if err != nil || page.Error != "" {
			f.t.Fatalf("fresh guest output: error=%v workload=%q", err, page.Error)
		}
		for _, entry := range page.Logs {
			if len(output)+len(entry.Output) > 64<<10 {
				f.t.Fatal("fresh guest output exceeded its bound")
			}
			output = append(output, entry.Output...)
		}
		cursor = page.After
		if state.State == client.StateExited && bytes.Equal(output, marker) {
			return
		}
		// Terminal state does not certify that every output frame has arrived.
		if !page.HasMore {
			f.poll()
		}
	}
}

func (f *commandRecovery) close() {
	f.cancel()
	if f.adapter != nil {
		f.adapter.unblock()
	}
	for _, target := range f.targets {
		target.stop()
	}
	if f.started {
		f.cleanupJoin(f.done, "owned command")
		if f.runErr != nil {
			f.t.Errorf("owned command returned a cleanup error: %v", f.runErr)
			// A failed command may retain an unjoined private Session, for which
			// the command API exposes no later join. Never remove its database
			// or label this failed path complete. The enclosing test process and
			// bounded container remain its last containment boundary.
			f.retained = true
		}
	}
	if f.http != nil {
		f.http.CloseClientConnections()
		f.http.Close()
	}
	if f.dispatcher != nil {
		f.dispatcher.Close()
	}
	for _, listener := range f.listeners {
		listener.Close()
	}
	f.serves.Wait()
	for _, target := range f.targets {
		f.cleanupJoin(target.done, "owned TCP target")
		if target.mode != "queued" && target.err != nil && !f.t.Failed() {
			f.t.Errorf("target ended without the required exchange: %v", target.err)
		}
	}
	for _, db := range []*sql.DB{f.executorDB, f.dispatcherDB} {
		if f.retained && db == f.executorDB {
			continue
		}
		if db != nil {
			if err := db.Close(); err != nil {
				f.t.Error(err)
			}
		}
	}
}

func (f *commandRecovery) cleanupJoin(done <-chan struct{}, what string) {
	timer := time.NewTimer(10 * time.Second)
	defer timer.Stop()
	select {
	case <-done:
	case <-timer.C:
		f.t.Errorf("%s did not join within the cleanup observation bound", what)
		// A failed observation cannot authorize TempDir/SQL destruction. Keep
		// the actual caller owned; the package/container deadline still bounds
		// a permanently broken implementation and is never counted as a pass.
		<-done
	}
}

func commandReadReady(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > 4096 {
		return nil, errors.New("readiness is not a bounded regular file")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	actual, err := file.Stat()
	if err != nil || !os.SameFile(info, actual) || !actual.Mode().IsRegular() || actual.Size() > 4096 {
		return nil, errors.New("readiness changed during bounded observation")
	}
	return io.ReadAll(io.LimitReader(file, 4097))
}

type commandGuestTarget struct {
	lis      net.Listener
	nonce    string
	mode     string
	mu       sync.Mutex
	conn     net.Conn
	stopped  bool
	accepted chan struct{}
	ack      chan struct{}
	done     chan struct{}
	err      error
}

func (f *commandRecovery) target(mode string) *commandGuestTarget {
	f.t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		f.t.Fatal(err)
	}
	target := &commandGuestTarget{lis: lis, nonce: strings.ReplaceAll(uuid.NewString(), "-", ""), mode: mode,
		accepted: make(chan struct{}), ack: make(chan struct{}), done: make(chan struct{})}
	f.targets = append(f.targets, target)
	go func() { defer close(target.done); target.err = target.exchange(f.ctx) }()
	return target
}

func (target *commandGuestTarget) addr() string { return target.lis.Addr().String() }
func (target *commandGuestTarget) exchange(ctx context.Context) error {
	conn, err := target.lis.Accept()
	if err != nil {
		return err
	}
	defer conn.Close()
	close(target.accepted)
	target.mu.Lock()
	if target.stopped {
		target.mu.Unlock()
		return errors.New("target interrupted after accept")
	}
	target.conn = conn
	target.mu.Unlock()
	deadline, _ := ctx.Deadline()
	if err := conn.SetDeadline(deadline); err != nil {
		return err
	}
	if target.mode == "queued" {
		return errors.New("quarantined queued guest connected")
	}
	if _, err := io.WriteString(conn, "DEBUGLET/1 "+target.nonce+"\n"); err != nil {
		return err
	}
	line, err := bufio.NewReader(io.LimitReader(conn, 129)).ReadString('\n')
	if err != nil || line != "ACK "+target.nonce+"\n" {
		return errors.New("real guest did not return the exact bounded acknowledgement")
	}
	close(target.ack)
	if target.mode == "blocked" {
		var extra [1]byte
		n, err := conn.Read(extra[:])
		if n != 0 || !errors.Is(err, io.EOF) || ctx.Err() != nil {
			return fmt.Errorf("old guest socket did not close independently of fixture cancellation: bytes=%d error=%v", n, err)
		}
		return nil
	}
	// Success owns the normal EOF. Cleanup may close a failed target but cannot
	// turn it into this successful exchange.
	target.mu.Lock()
	defer target.mu.Unlock()
	if target.stopped || ctx.Err() != nil {
		return errors.New("fresh target interrupted before normal EOF")
	}
	return conn.Close()
}

func (target *commandGuestTarget) stop() {
	target.mu.Lock()
	defer target.mu.Unlock()
	target.stopped = true
	target.lis.Close()
	if target.conn != nil {
		target.conn.Close()
	}
}

// The guest is built from this committed checkout. Missing tooling,
// build errors and an empty artifact fail the test; there is no skip or binary
// fixture copied from a different candidate.
func commandRecoveryGuest(t *testing.T, dir string) []byte {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	out := filepath.Join(dir, "command-demo.wasm")
	cmd := exec.CommandContext(ctx, "go", "build", "-mod=readonly", "-trimpath", "-o", out, "../../local/wasm_samples/go/demo")
	cmd.Env = append(os.Environ(), "GOOS=wasip1", "GOARCH=wasm", "CGO_ENABLED=0", "GOTOOLCHAIN=local", "GOFLAGS=")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL); errors.Is(err, syscall.ESRCH) {
			return os.ErrProcessDone
		} else {
			return err
		}
	}
	cmd.WaitDelay = 2 * time.Second
	var output commandBuildOutput
	cmd.Stdout, cmd.Stderr = &output, &output
	if err := cmd.Run(); err != nil {
		t.Fatalf("build tracked demo guest: %v\n%s", err, output.buffer.String())
	}
	guest, err := os.ReadFile(out)
	if err != nil || len(guest) == 0 {
		t.Fatalf("read tracked demo guest: %v", err)
	}
	return guest
}

type commandBuildOutput struct{ buffer bytes.Buffer }

func (output *commandBuildOutput) Write(data []byte) (int, error) {
	size := min(len(data), max(0, (64<<10)-output.buffer.Len()))
	output.buffer.Write(data[:size])
	return len(data), nil
}
