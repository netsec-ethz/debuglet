package dispatcher

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/netsec-ethz/debuglet/internal/controlsession"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/config"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/database"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/models"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/payments"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/resource"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/testutil"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/transport/rpc"
	pb "github.com/netsec-ethz/debuglet/protocol"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	_ "modernc.org/sqlite"
)

// Fixture constants. One order costs tgPrice * floor * (tgTimeout in seconds),
// see Handler.LockPrice; the two floors differ so the remaining executor
// reservation after one exit is a distinct, nonzero value.
const (
	tgExecutorID = "tg-executor"
	tgCurrency   = "TEST"
	tgPrice      = int64(1)
	tgCapacity   = resource.Megabit
	tgTimeout    = 10 * time.Second
	tgFloorA     = resource.Bitrate(1000)
	tgFloorB     = resource.Bitrate(3000)
	tgBound      = 30 * time.Second
	tgCallBound  = 10 * time.Second
	tgMigrations = "database/migrations"
	tgTrigger    = "tg_reject_state_write"
	tgSentinel   = "tg_sentinel_state_write"
	tgBadTime    = "tg-not-a-timestamp"
)

var (
	tgWasm         = []byte("\x00asm\x01\x00\x00\x00")
	tgNull         = sql.NullString{}
	tgErrCompleteQ = errors.New("sentinel: CompleteDebuglet failed")
	tgErrClassifyQ = errors.New("sentinel: GetOwnedDebugletByUUID failed")
	tgMockBinding  = controlsession.Binding{Incarnation: "cd678a91-a1ba-4def-8192-123456789abc", SessionID: "92ab28aa-189a-4fd0-9924-abcdef123456"}

	// Generated query texts (internal/dispatcher/database/debuglet.sql.go) for
	// the checked sqlmock fixtures; sqlmock collapses whitespace before
	// matching.
	tgCompleteQuery = regexp.QuoteMeta(
		"UPDATE debuglets SET state = ?1, error = ?2 WHERE uuid = ?3 AND state <> ?1 AND executor_id = ?4 AND dispatcher_incarnation = ?5 AND session_id = ?6 AND dispatcher_incarnation <> '' AND session_id <> '' RETURNING id, uuid, start_time, end_time, usage, ceil_bw, executor_id, addresses, state, error, transaction_id, order_id, dispatcher_incarnation, session_id",
	)
	tgGetQuery = regexp.QuoteMeta(
		"SELECT id, uuid, start_time, end_time, usage, ceil_bw, executor_id, addresses, state, error, transaction_id, order_id, dispatcher_incarnation, session_id FROM debuglets WHERE uuid = ?",
	)
	tgOwnedGetQuery   = regexp.QuoteMeta("SELECT id, uuid, start_time, end_time, usage, ceil_bw, executor_id, addresses, state, error, transaction_id, order_id, dispatcher_incarnation, session_id FROM debuglets WHERE uuid = ?1 AND executor_id = ?2 AND dispatcher_incarnation = ?3 AND session_id = ?4 AND dispatcher_incarnation <> '' AND session_id <> ''")
	tgIdentityQuery   = regexp.QuoteMeta("SELECT executor_id, dispatcher_incarnation, session_id FROM debuglets WHERE uuid = ?")
	tgDebugletColumns = []string{
		"id", "uuid", "start_time", "end_time", "usage", "ceil_bw",
		"executor_id", "addresses", "state", "error", "transaction_id", "order_id", "dispatcher_incarnation", "session_id",
	}
)

func tgStr(s string) *string { return &s }

func tgText(s string) sql.NullString { return sql.NullString{String: s, Valid: true} }

func tgOrderPrice(floor resource.Bitrate) int64 {
	return tgPrice * int64(floor) * int64(tgTimeout/time.Second)
}

// ============================================================
// ==================== SCRIPTED PEER =========================
// ============================================================

// tgPeer is the scripted executor. Hello is deterministic;
// Upload records the exact payload and may run a hook (which can call the
// dispatcher's callbacks) before replying; Abort acknowledges or fails as
// scripted; Bandwidth records limits. All state is mutex-protected because
// the RPC handlers run on the peer's gRPC server goroutines.
type tgPeer struct {
	pb.UnimplementedExecutorServiceServer
	mu           sync.Mutex
	uploads      []*pb.UploadRequest
	aborts       []*pb.AbortRequest
	bandwidth    []*pb.BandwidthRequest
	beforeUpload func(ctx context.Context, req *pb.UploadRequest) error
	abortErr     error
}

func (p *tgPeer) Hello(context.Context, *pb.HelloRequest) (*pb.HelloResponse, error) {
	return &pb.HelloResponse{ExecutorId: tgExecutorID, Version: "tg-peer", Currency: tgCurrency, PricePerBwS: tgPrice}, nil
}

func (p *tgPeer) Upload(ctx context.Context, req *pb.UploadRequest) (*pb.UploadResponse, error) {
	p.mu.Lock()
	p.uploads = append(p.uploads, req)
	hook := p.beforeUpload
	p.mu.Unlock()
	if hook != nil {
		if err := hook(ctx, req); err != nil {
			return nil, err
		}
	}
	return &pb.UploadResponse{}, nil
}

func (p *tgPeer) Abort(_ context.Context, req *pb.AbortRequest) (*pb.AbortResponse, error) {
	p.mu.Lock()
	p.aborts = append(p.aborts, req)
	err := p.abortErr
	p.mu.Unlock()
	if err != nil {
		return nil, err
	}
	return &pb.AbortResponse{}, nil
}

func (p *tgPeer) Bandwidth(_ context.Context, req *pb.BandwidthRequest) (*pb.BandwidthResponse, error) {
	p.mu.Lock()
	p.bandwidth = append(p.bandwidth, req)
	p.mu.Unlock()
	return &pb.BandwidthResponse{}, nil
}

func (p *tgPeer) scriptUpload(hook func(ctx context.Context, req *pb.UploadRequest) error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.beforeUpload = hook
}

func (p *tgPeer) scriptAbort(err error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.abortErr = err
}

func (p *tgPeer) recordedUploads() []*pb.UploadRequest {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]*pb.UploadRequest(nil), p.uploads...)
}

func (p *tgPeer) recordedAborts() []*pb.AbortRequest {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]*pb.AbortRequest(nil), p.aborts...)
}

// ============================================================
// ======================== FIXTURE ===========================
// ============================================================

// tgFixture is a real Dispatcher on a fresh migrated SQLite file with the
// real disabled PaymentHandler. With a peer, the executor is registered by
// startTerminalPeer and Upload/Abort reach the peer; without
// one, the executor is registered directly so callback-only subtests run
// without the transport.
type tgFixture struct {
	ctx   context.Context
	db    *sql.DB
	q     *database.Queries
	ph    *payments.PaymentHandler
	d     *Dispatcher
	peer  *tgPeer
	start time.Time
}

type tgDebuglet struct {
	id      uuid.UUID
	txID    string
	orderID int64
	floor   resource.Bitrate
	row     database.Debuglet
}

func newTGFixture(t *testing.T, peer *tgPeer) *tgFixture {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), tgBound)
	t.Cleanup(cancel)

	// synchronous(OFF) only skips fsync, which dominates fixture cost on the
	// CI container's overlay filesystem; locking and journaling are unchanged.
	db, err := sql.Open("sqlite", fmt.Sprintf("file:%s?_pragma=synchronous(OFF)", filepath.Join(t.TempDir(), "guards.sqlite")))
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Errorf("close sqlite: %v", err)
		}
	})
	testutil.ApplyMigrations(t, db, tgMigrations)

	logger := zap.NewNop()
	ph := payments.NewPaymentHandler(db, &config.DispatcherConfig{Sui: config.SuiConfig{Disabled: true}}, logger)
	d, err := New(logger, db, "tg-test", time.Minute, time.Minute, ph)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(d.Close)
	f := &tgFixture{
		ctx:  ctx,
		db:   db,
		q:    database.New(db),
		ph:   ph,
		d:    d,
		peer: peer,
		// A fixed future start keeps validateDebugletSpec from resetting it, so
		// every debuglet of a fixture occupies the same admission window.
		start: time.Now().Add(time.Hour).Truncate(time.Second),
	}

	if peer != nil {
		stop, err := startTerminalPeer(ctx, d, tgCapacity, peer)
		if err != nil {
			t.Fatalf("startTerminalPeer: %v", err)
		}
		t.Cleanup(func() {
			stopCtx, cancelStop := context.WithTimeout(context.Background(), tgBound)
			defer cancelStop()
			if err := stop(stopCtx); err != nil {
				t.Errorf("stop peer: %v", err)
			}
		})
	} else {
		owner, err := rpc.NewSessionOwner(tgExecutorID, effectTestBinding(t), time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		if err := registryRegisterWithSetup(ctx, d, owner, &pb.HelloResponse{
			ExecutorId: tgExecutorID, Version: "tg-direct", PricePerBwS: tgPrice, Currency: tgCurrency,
		}, "127.0.0.1"); err != nil {
			t.Fatalf("register direct executor: %v", err)
		}
		if !owner.MarkRegistered() {
			t.Fatal("direct executor owner retired before registration completed")
		}
		mutation := effectTestMutation(t, d, tgExecutorID)
		_, err = d.OnResources(ctx, mutation, &pb.ResourcesRequest{ExecutorId: tgExecutorID, BandwidthCapacity: int64(tgCapacity)})
		mutation.Finish()
		if err != nil {
			t.Fatalf("set capacity: %v", err)
		}
	}
	if _, ok := d.GetExecutor(tgExecutorID); !ok {
		t.Fatal("executor not registered")
	}
	if earning := f.earnings(t); earning.TotalIncome != 0 || earning.CurrentBalance != 0 {
		t.Fatalf("fresh earnings %+v, want zero", earning)
	}
	return f
}

// spec pays for one TEST order and returns the matching submission spec.
func (f *tgFixture) spec(t *testing.T, floor resource.Bitrate) models.DebugletSpec {
	t.Helper()
	txID, err := f.ph.NewTransactionID()
	if err != nil {
		t.Fatalf("transaction id: %v", err)
	}
	if _, err := f.ph.CreatePaymentIntent(txID, tgOrderPrice(floor), "TEST", "tg-hash", f.ctx); err != nil {
		t.Fatalf("TEST intent: %v", err)
	}
	if _, err := f.q.CreateDebugletOrder(f.ctx, database.CreateDebugletOrderParams{
		TransactionID: txID, OrderID: 1, ExecutorID: tgExecutorID, Price: tgOrderPrice(floor),
		Currency: tgCurrency, RefundAddress: "", State: int64(models.Outstanding),
	}); err != nil {
		t.Fatalf("TEST order: %v", err)
	}
	start := f.start
	return models.DebugletSpec{
		StartTime:     &start,
		Wasm:          tgWasm,
		Args:          []string{"tg"},
		ExecutorID:    tgExecutorID,
		TransactionID: txID,
		OrderID:       1,
		Policy:        models.DebugletPolicy{FloorBW: floor, CeilBW: 2 * floor, Timeout: tgTimeout},
	}
}

// seedDirect creates a debuglet the way SubmitDebuglets does up to the Upload
// RPC (admission, row, executor history, scheduler reservation) and then
// applies the guarded Uploaded write a successful upload performs. It lets
// the callback subtests run without the peer transport.
func (f *tgFixture) seedDirect(t *testing.T, floor resource.Bitrate) tgDebuglet {
	t.Helper()
	spec := f.spec(t, floor)
	id := uuid.New()
	mutation := effectTestMutation(t, f.d, tgExecutorID)
	defer mutation.Finish()
	owner := mutation.Owner()

	f.d.mu.Lock()
	r, err := f.d.validateDebugletSpec(&spec)
	if err != nil {
		f.d.mu.Unlock()
		t.Fatalf("validate spec: %v", err)
	}
	_, err = f.q.CreateDebuglet(f.ctx, database.CreateDebugletParams{
		Uuid:                  id,
		StartTime:             models.NewUTCTime(r.From),
		EndTime:               models.NewUTCTime(r.To),
		ExecutorID:            spec.ExecutorID,
		Usage:                 int64(spec.Policy.FloorBW),
		CeilBw:                int64(spec.Policy.CeilBW),
		State:                 models.RunStateUploading,
		Addresses:             spec.Policy.Addresses,
		TransactionID:         spec.TransactionID,
		OrderID:               spec.OrderID,
		DispatcherIncarnation: owner.Binding().Incarnation, SessionID: owner.Binding().SessionID,
	})
	if err != nil {
		f.d.mu.Unlock()
		t.Fatalf("create debuglet: %v", err)
	}
	f.d.executors[spec.ExecutorID].AppendDebugletID(id)
	f.d.scheduler.Submit(*r)
	f.d.mu.Unlock()

	row, err := f.q.UpdateDebugletState(f.ctx, database.UpdateDebugletStateParams{
		State: models.RunStateUploaded, StateRank: models.RunStateUploaded.SemanticRank(), Uuid: id, ExitedState: models.RunStateExited,
		ExecutorID: owner.ExecutorID(), DispatcherIncarnation: owner.Binding().Incarnation, SessionID: owner.Binding().SessionID,
	})
	if err != nil {
		t.Fatalf("mark uploaded: %v", err)
	}
	return tgDebuglet{id: id, txID: spec.TransactionID, orderID: spec.OrderID, floor: floor, row: row}
}

// submit pays for and submits one debuglet through the real SubmitDebuglets
// path, so the Upload RPC reaches the peer.
func (f *tgFixture) submit(t *testing.T, floor resource.Bitrate) (tgDebuglet, error) {
	t.Helper()
	spec := f.spec(t, floor)
	deb := tgDebuglet{txID: spec.TransactionID, orderID: spec.OrderID, floor: floor}
	ids, err := f.d.SubmitDebuglets(f.ctx, []models.DebugletSpec{spec}, nil)
	if err != nil {
		if ids != nil {
			t.Errorf("SubmitDebuglets returned ids %v alongside error %v", ids, err)
		}
		return deb, err
	}
	if len(ids) != 1 {
		t.Fatalf("SubmitDebuglets returned %d ids, want 1", len(ids))
	}
	deb.id = ids[0]
	deb.row = f.row(t, deb.id)
	return deb, nil
}

func (f *tgFixture) exit(t *testing.T, id uuid.UUID, code int32, msg *string) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(f.ctx, tgCallBound)
	defer cancel()
	mutation := effectTestMutation(t, f.d, tgExecutorID)
	defer mutation.Finish()
	resp, err := f.d.OnDebugletExit(ctx, mutation, &pb.DebugletExitRequest{DebugletId: id.String(), ExitCode: code, ErrorMessage: msg})
	if err == nil && resp == nil {
		t.Errorf("OnDebugletExit(%s, %d) returned neither response nor error", id, code)
	}
	if err != nil && resp != nil {
		t.Errorf("OnDebugletExit(%s, %d) returned a response alongside error %v", id, code, err)
	}
	return err
}

func (f *tgFixture) state(t *testing.T, id uuid.UUID, state pb.RunState) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(f.ctx, tgCallBound)
	defer cancel()
	mutation := effectTestMutation(t, f.d, tgExecutorID)
	defer mutation.Finish()
	resp, err := f.d.OnDebugletState(ctx, mutation, &pb.DebugletStateRequest{DebugletId: id.String(), ExecutorId: tgExecutorID, State: state})
	if err == nil && resp == nil {
		t.Errorf("OnDebugletState(%s, %s) returned neither response nor error", id, state)
	}
	return err
}

func (f *tgFixture) abort(t *testing.T, id uuid.UUID, reason string) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(f.ctx, tgCallBound)
	defer cancel()
	return f.d.AbortDebuglet(ctx, tgExecutorID, id, reason)
}

func (f *tgFixture) row(t *testing.T, id uuid.UUID) database.Debuglet {
	t.Helper()
	row, err := f.q.GetDebugletByUUID(f.ctx, id)
	if err != nil {
		t.Fatalf("get debuglet %s: %v", id, err)
	}
	return row
}

// rawRow reads state and error without scanning the other columns, for rows
// whose timestamps have been deliberately corrupted.
func (f *tgFixture) rawRow(t *testing.T, id uuid.UUID) (models.DebugletRunState, sql.NullString) {
	t.Helper()
	var state models.DebugletRunState
	var errText sql.NullString
	if err := f.db.QueryRow("SELECT state, error FROM debuglets WHERE uuid = ?", id).Scan(&state, &errText); err != nil {
		t.Fatalf("raw row %s: %v", id, err)
	}
	return state, errText
}

func (f *tgFixture) orderState(t *testing.T, deb tgDebuglet) models.TransactionState {
	t.Helper()
	order, err := f.q.GetDebugletOrder(f.ctx, database.GetDebugletOrderParams{TransactionID: deb.txID, OrderID: deb.orderID})
	if err != nil {
		t.Fatalf("get order of %s: %v", deb.id, err)
	}
	return models.TransactionState(order.State)
}

func (f *tgFixture) earnings(t *testing.T) database.Earning {
	t.Helper()
	earning, err := f.q.GetEarningsIn(f.ctx, database.GetEarningsInParams{ExecutorID: tgExecutorID, Currency: tgCurrency})
	if err != nil {
		t.Fatalf("TEST earnings: %v", err)
	}
	return earning
}

// reserved is the executor's maximum scheduled usage over the debuglet's
// window: the scheduler reservation that a winning exit releases exactly once.
func (f *tgFixture) reserved(t *testing.T, deb tgDebuglet) resource.Bitrate {
	t.Helper()
	return f.d.scheduler.QueryMaxExec(tgExecutorID, deb.row.StartTime.Time, deb.row.EndTime.Time)
}

// snapshot renders every effect-relevant table so "no effects" is one
// string comparison.
func (f *tgFixture) snapshot(t *testing.T) string {
	t.Helper()
	var b strings.Builder
	for _, query := range []string{
		"SELECT uuid, state, error FROM debuglets ORDER BY id",
		"SELECT transaction_id, order_id, state FROM debuglet_order ORDER BY transaction_id, order_id",
		"SELECT executor_id, currency, total_income, current_balance FROM earnings ORDER BY executor_id, currency",
	} {
		rows, err := f.db.Query(query)
		if err != nil {
			t.Fatalf("snapshot %q: %v", query, err)
		}
		cols, err := rows.Columns()
		if err != nil {
			rows.Close()
			t.Fatalf("snapshot columns: %v", err)
		}
		for rows.Next() {
			vals := make([]any, len(cols))
			ptrs := make([]any, len(cols))
			for i := range vals {
				ptrs[i] = &vals[i]
			}
			if err := rows.Scan(ptrs...); err != nil {
				rows.Close()
				t.Fatalf("snapshot scan: %v", err)
			}
			for i, v := range vals {
				if bs, ok := v.([]byte); ok {
					vals[i] = string(bs)
				}
			}
			fmt.Fprintf(&b, "%v\n", vals)
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			t.Fatalf("snapshot rows: %v", err)
		}
		rows.Close()
	}
	return b.String()
}

// installTrigger makes every state write on debuglets fail with tgSentinel
// until the returned drop function runs (also registered as cleanup).
func (f *tgFixture) installTrigger(t *testing.T) (drop func()) {
	t.Helper()
	if _, err := f.db.Exec(fmt.Sprintf(
		"CREATE TRIGGER %s BEFORE UPDATE OF state ON debuglets BEGIN SELECT RAISE(ABORT, '%s'); END", tgTrigger, tgSentinel)); err != nil {
		t.Fatalf("create trigger: %v", err)
	}
	installed := true
	drop = func() {
		if installed {
			installed = false
			if _, err := f.db.Exec("DROP TRIGGER " + tgTrigger); err != nil {
				t.Errorf("drop trigger: %v", err)
			}
		}
	}
	t.Cleanup(drop)
	return drop
}

func tgAssertRow(t *testing.T, row database.Debuglet, state models.DebugletRunState, errText sql.NullString) {
	t.Helper()
	if row.State != state {
		t.Fatalf("debuglet %s state is %s, want %s", row.Uuid, row.State, state)
	}
	if row.Error != errText {
		t.Fatalf("debuglet %s error is %+v, want %+v", row.Uuid, row.Error, errText)
	}
}

func tgAssertReserved(t *testing.T, f *tgFixture, deb tgDebuglet, want resource.Bitrate) {
	t.Helper()
	if got := f.reserved(t, deb); got != want {
		t.Fatalf("executor reservation over the window of %s is %s, want %s", deb.id, got, want)
	}
}

func tgAssertOrder(t *testing.T, f *tgFixture, deb tgDebuglet, want models.TransactionState) {
	t.Helper()
	if got := f.orderState(t, deb); got != want {
		t.Fatalf("order of %s is %s, want %s", deb.id, got, want)
	}
}

func tgAssertEarnings(t *testing.T, f *tgFixture, want int64) {
	t.Helper()
	if e := f.earnings(t); e.TotalIncome != want || e.CurrentBalance != want {
		t.Fatalf("TEST earnings income=%d balance=%d, want both %d", e.TotalIncome, e.CurrentBalance, want)
	}
}

func tgAssertSnapshot(t *testing.T, f *tgFixture, before string, what string) {
	t.Helper()
	if after := f.snapshot(t); after != before {
		t.Fatalf("%s changed rows:\nbefore:\n%s\nafter:\n%s", what, before, after)
	}
}

// ============================================================
// ========================== TESTS ===========================
// ============================================================

// TestTerminalResultGuards proves the terminal-result contract at the
// dispatcher boundary: normalization, one in-process winner per debuglet with
// effects exactly once (payment on real SQLite orders/earnings, scheduler
// release), missing IDs, result-write and classification failures with no
// effects, late ordinary states after exit, and an Upload that replies after
// a terminal callback without turning the submission into a failure.
func TestTerminalResultGuards(t *testing.T) {
	t.Run("normalization", func(t *testing.T) {
		cases := []struct {
			name     string
			code     int32
			msg      *string
			want     sql.NullString
			credited bool
		}{
			{"zero exit and nil message store NULL", 0, nil, tgNull, true},
			{"zero exit and empty message store NULL", 0, tgStr(""), tgNull, true},
			{"zero exit and nonempty message store the message verbatim", 0, tgStr("finished with warnings"), tgText("finished with warnings"), true},
			{"nonzero exit and nil message store the exit code text", 3, nil, tgText("debuglet exited with code 3"), false},
			{"nonzero exit and empty message store the exit code text", -1, tgStr(""), tgText("debuglet exited with code -1"), false},
			{"nonzero exit and nonempty message store the message verbatim", 5, tgStr("crashed: segfault at 0x0"), tgText("crashed: segfault at 0x0"), false},
		}
		f := newTGFixture(t, nil)
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				deb := f.seedDirect(t, tgFloorA)
				tgAssertRow(t, deb.row, models.RunStateUploaded, tgNull)
				tgAssertReserved(t, f, deb, tgFloorA)
				income := f.earnings(t).TotalIncome

				if err := f.exit(t, deb.id, tc.code, tc.msg); err != nil {
					t.Fatalf("OnDebugletExit: %v", err)
				}
				tgAssertRow(t, f.row(t, deb.id), models.RunStateExited, tc.want)
				tgAssertReserved(t, f, deb, 0)
				// The payment decision stays exit-code based, also for a zero
				// exit with an error message; TEST refunds are unsupported and
				// leave the order Outstanding.
				if tc.credited {
					tgAssertOrder(t, f, deb, models.Credited)
					tgAssertEarnings(t, f, income+tgOrderPrice(tgFloorA))
				} else {
					tgAssertOrder(t, f, deb, models.Outstanding)
					tgAssertEarnings(t, f, income)
				}
			})
		}
	})

	t.Run("sequential duplicate exits", func(t *testing.T) {
		t.Run("zero exit then late failure: first wins, effects once", func(t *testing.T) {
			f := newTGFixture(t, nil)
			a, b := f.seedDirect(t, tgFloorA), f.seedDirect(t, tgFloorB)
			tgAssertReserved(t, f, a, tgFloorA+tgFloorB)

			if err := f.exit(t, a.id, 0, nil); err != nil {
				t.Fatalf("first exit: %v", err)
			}
			tgAssertRow(t, f.row(t, a.id), models.RunStateExited, tgNull)
			tgAssertOrder(t, f, a, models.Credited)
			tgAssertEarnings(t, f, tgOrderPrice(tgFloorA))
			tgAssertReserved(t, f, a, tgFloorB)
			after := f.snapshot(t)

			if err := f.exit(t, a.id, 9, tgStr("late failure")); err != nil {
				t.Fatalf("duplicate exit: %v", err)
			}
			tgAssertRow(t, f.row(t, a.id), models.RunStateExited, tgNull)
			tgAssertSnapshot(t, f, after, "duplicate exit")
			tgAssertReserved(t, f, a, tgFloorB)
			tgAssertRow(t, f.row(t, b.id), models.RunStateUploaded, tgNull)
			tgAssertOrder(t, f, b, models.Outstanding)
		})

		t.Run("nonzero exit then late success: failure stays, no credit", func(t *testing.T) {
			f := newTGFixture(t, nil)
			a, b := f.seedDirect(t, tgFloorA), f.seedDirect(t, tgFloorB)
			tgAssertReserved(t, f, b, tgFloorA+tgFloorB)

			if err := f.exit(t, b.id, 2, nil); err != nil {
				t.Fatalf("first exit: %v", err)
			}
			tgAssertRow(t, f.row(t, b.id), models.RunStateExited, tgText("debuglet exited with code 2"))
			// The refund attempt fails for TEST and rolls back: order unchanged.
			tgAssertOrder(t, f, b, models.Outstanding)
			tgAssertEarnings(t, f, 0)
			tgAssertReserved(t, f, b, tgFloorA)
			after := f.snapshot(t)

			if err := f.exit(t, b.id, 0, nil); err != nil {
				t.Fatalf("duplicate exit: %v", err)
			}
			tgAssertRow(t, f.row(t, b.id), models.RunStateExited, tgText("debuglet exited with code 2"))
			tgAssertOrder(t, f, b, models.Outstanding)
			tgAssertEarnings(t, f, 0)
			tgAssertSnapshot(t, f, after, "duplicate exit")
			tgAssertReserved(t, f, b, tgFloorA)
			tgAssertRow(t, f.row(t, a.id), models.RunStateUploaded, tgNull)
		})
	})

	t.Run("concurrent duplicate exits: one winner, effects once, all acknowledged", func(t *testing.T) {
		f := newTGFixture(t, nil)
		a, _ := f.seedDirect(t, tgFloorA), f.seedDirect(t, tgFloorB)
		tgAssertReserved(t, f, a, tgFloorA+tgFloorB)

		const callers = 6
		results := make([]error, callers)
		start := make(chan struct{})
		done := make(chan struct{})
		var wg sync.WaitGroup
		for i := 0; i < callers; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				<-start
				if i%2 == 0 {
					results[i] = f.exit(t, a.id, 0, nil)
				} else {
					results[i] = f.exit(t, a.id, 4, tgStr("concurrent failure"))
				}
			}(i)
		}
		go func() {
			wg.Wait()
			close(done)
		}()
		close(start)
		select {
		case <-done:
		case <-f.ctx.Done():
			t.Fatalf("concurrent exits did not finish within %s", tgBound)
		}
		for i, err := range results {
			if err != nil {
				t.Fatalf("concurrent caller %d returned %v, want nil (loser gets an empty success)", i, err)
			}
		}

		row := f.row(t, a.id)
		switch row.Error {
		case tgNull:
			tgAssertRow(t, row, models.RunStateExited, tgNull)
			tgAssertOrder(t, f, a, models.Credited)
			tgAssertEarnings(t, f, tgOrderPrice(tgFloorA))
		case tgText("concurrent failure"):
			tgAssertRow(t, row, models.RunStateExited, tgText("concurrent failure"))
			tgAssertOrder(t, f, a, models.Outstanding)
			tgAssertEarnings(t, f, 0)
		default:
			t.Fatalf("row error %+v belongs to no caller", row.Error)
		}
		tgAssertReserved(t, f, a, tgFloorB)
	})

	t.Run("missing id: does-not-exist error, no effects", func(t *testing.T) {
		f := newTGFixture(t, nil)
		a := f.seedDirect(t, tgFloorA)
		before := f.snapshot(t)
		missing := uuid.New()

		for _, tc := range []struct {
			code int32
			msg  *string
		}{{0, nil}, {7, tgStr("gone")}} {
			err := f.exit(t, missing, tc.code, tc.msg)
			want := "debuglet does not exist"
			if err == nil || !strings.Contains(err.Error(), want) {
				t.Fatalf("exit of a missing id returned %v, want an error containing %q", err, want)
			}
		}
		if _, err := f.d.OnDebugletExit(f.ctx, effectTestMutation(t, f.d, tgExecutorID), &pb.DebugletExitRequest{DebugletId: "not-a-uuid"}); err == nil || !strings.Contains(err.Error(), "invalid debuglet ID") {
			t.Fatalf("exit with an unparsable id returned %v", err)
		}
		tgAssertSnapshot(t, f, before, "missing-id exits")
		tgAssertReserved(t, f, a, tgFloorA)
		tgAssertRow(t, f.row(t, a.id), models.RunStateUploaded, tgNull)
	})

	t.Run("query failures", func(t *testing.T) {
		t.Run("terminal write failure: wrapped error, no effects", func(t *testing.T) {
			f := newTGFixture(t, nil)
			a, _ := f.seedDirect(t, tgFloorA), f.seedDirect(t, tgFloorB)
			before := f.snapshot(t)
			drop := f.installTrigger(t)

			for _, tc := range []struct {
				code int32
				msg  *string
			}{{0, nil}, {3, tgStr("failed")}} {
				err := f.exit(t, a.id, tc.code, tc.msg)
				if err == nil || !strings.Contains(err.Error(), tgSentinel) || !strings.Contains(err.Error(), "failed to mark debuglet exited") {
					t.Fatalf("exit with a failing terminal write returned %v, want a wrapped %q", err, tgSentinel)
				}
				tgAssertSnapshot(t, f, before, "failed terminal write")
				tgAssertReserved(t, f, a, tgFloorA+tgFloorB)
			}
			tgAssertRow(t, f.row(t, a.id), models.RunStateUploaded, tgNull)

			// Once the write succeeds again the same debuglet still completes.
			drop()
			if err := f.exit(t, a.id, 0, nil); err != nil {
				t.Fatalf("exit after dropping the trigger: %v", err)
			}
			tgAssertRow(t, f.row(t, a.id), models.RunStateExited, tgNull)
			tgAssertOrder(t, f, a, models.Credited)
			tgAssertReserved(t, f, a, tgFloorB)
		})

		t.Run("owned corrupt terminal row returns bounded integrity error", func(t *testing.T) {
			f := newTGFixture(t, nil)
			a, _ := f.seedDirect(t, tgFloorA), f.seedDirect(t, tgFloorB)
			if err := f.exit(t, a.id, 0, nil); err != nil {
				t.Fatalf("first exit: %v", err)
			}
			tgAssertReserved(t, f, a, tgFloorB)
			before := f.snapshot(t)

			// The guard rejects the duplicate (terminal row) and the classifying
			// read then fails: an unparsable timestamp makes GetDebugletByUUID
			// fail while CompleteDebuglet still returns sql.ErrNoRows.
			if _, err := f.db.Exec("UPDATE debuglets SET start_time = ? WHERE uuid = ?", tgBadTime, a.id); err != nil {
				t.Fatalf("corrupt start_time: %v", err)
			}
			if _, err := f.q.GetDebugletByUUID(f.ctx, a.id); err == nil || errors.Is(err, sql.ErrNoRows) {
				t.Fatalf("GetDebugletByUUID on the corrupted row returned %v, want a scan failure", err)
			}
			if _, err := f.d.ownedDebuglet(f.ctx, f.d.executors[tgExecutorID].owner, a.id); status.Code(err) != codes.Internal || status.Convert(err).Message() != "stored debuglet data is invalid" {
				t.Fatalf("owned corrupt lookup returned %v, want bounded Internal integrity error", err)
			}
			err := f.exit(t, a.id, 5, tgStr("late"))
			if err == nil || !strings.Contains(err.Error(), "stored debuglet data is invalid") || strings.Contains(err.Error(), tgBadTime) {
				t.Fatalf("exit with corrupt owned data returned %v, want bounded Internal integrity error", err)
			}
			tgAssertSnapshot(t, f, before, "failed classification")
			tgAssertReserved(t, f, a, tgFloorB)
			if state, errText := f.rawRow(t, a.id); state != models.RunStateExited || errText != tgNull {
				t.Fatalf("row after failed classification is state=%s error=%+v", state, errText)
			}
		})

		t.Run("foreign corrupt row is permission denied without repair", func(t *testing.T) {
			f := newTGFixture(t, nil)
			a := f.seedDirect(t, tgFloorA)
			if _, err := f.db.Exec("UPDATE debuglets SET start_time = ?, addresses = ? WHERE uuid = ?", tgBadTime, 17, a.id); err != nil {
				t.Fatalf("corrupt foreign row: %v", err)
			}
			foreign := registryRegister(t, f.d, "foreign-corrupt")
			if _, err := f.d.ownedDebuglet(f.ctx, foreign, a.id); status.Code(err) != codes.PermissionDenied {
				t.Fatalf("foreign corrupt row returned %v, want PermissionDenied", err)
			}
			var start, addresses any
			if err := f.db.QueryRow("SELECT start_time, addresses FROM debuglets WHERE uuid = ?", a.id).Scan(&start, &addresses); err != nil {
				t.Fatalf("read raw corrupt row: %v", err)
			}
			if fmt.Sprint(start) != tgBadTime || fmt.Sprint(addresses) != "17" {
				t.Fatalf("ownership classification changed corrupt content: start=%v addresses=%v", start, addresses)
			}
			if _, err := f.d.ownedDebuglet(f.ctx, foreign, uuid.New()); status.Code(err) != codes.NotFound {
				t.Fatalf("absent row returned %v, want NotFound", err)
			}
		})

		t.Run("sqlmock: classification outcomes are bounded and perform no effects", func(t *testing.T) {
			id := uuid.New()
			terminalRow := func(state models.DebugletRunState) *sqlmock.Rows {
				return sqlmock.NewRows(tgDebugletColumns).AddRow(
					int64(1), id, time.Now(), time.Now().Add(time.Minute), int64(tgFloorA), int64(2*tgFloorA),
					tgExecutorID, nil, int64(state), nil, "tx", int64(1), tgMockBinding.Incarnation, tgMockBinding.SessionID,
				)
			}
			cases := []struct {
				name    string
				expect  func(mock sqlmock.Sqlmock)
				wantErr error
				wantMsg string
				wantOK  bool
			}{
				{
					name: "terminal write failure is wrapped",
					expect: func(mock sqlmock.Sqlmock) {
						mock.ExpectQuery(tgCompleteQuery).
							WithArgs(int64(models.RunStateExited), "debuglet exited with code 4", id.String(), tgExecutorID, tgMockBinding.Incarnation, tgMockBinding.SessionID).
							WillReturnError(tgErrCompleteQ)
					},
					wantErr: tgErrCompleteQ,
				},
				{
					name: "classification failure is wrapped",
					expect: func(mock sqlmock.Sqlmock) {
						mock.ExpectQuery(tgCompleteQuery).
							WithArgs(int64(models.RunStateExited), "debuglet exited with code 4", id.String(), tgExecutorID, tgMockBinding.Incarnation, tgMockBinding.SessionID).
							WillReturnError(sql.ErrNoRows)
						mock.ExpectQuery(tgOwnedGetQuery).WithArgs(id.String(), tgExecutorID, tgMockBinding.Incarnation, tgMockBinding.SessionID).WillReturnError(tgErrClassifyQ)
					},
					wantMsg: "stored debuglet data is invalid",
				},
				{
					name: "missing row keeps the does-not-exist error",
					expect: func(mock sqlmock.Sqlmock) {
						mock.ExpectQuery(tgCompleteQuery).
							WithArgs(int64(models.RunStateExited), "debuglet exited with code 4", id.String(), tgExecutorID, tgMockBinding.Incarnation, tgMockBinding.SessionID).
							WillReturnError(sql.ErrNoRows)
						mock.ExpectQuery(tgOwnedGetQuery).WithArgs(id.String(), tgExecutorID, tgMockBinding.Incarnation, tgMockBinding.SessionID).WillReturnError(sql.ErrNoRows)
						mock.ExpectQuery(tgIdentityQuery).WithArgs(id.String()).WillReturnError(sql.ErrNoRows)
					},
					wantMsg: "debuglet does not exist",
				},
				{
					name: "nonterminal row after a missed guard is an error",
					expect: func(mock sqlmock.Sqlmock) {
						mock.ExpectQuery(tgCompleteQuery).
							WithArgs(int64(models.RunStateExited), "debuglet exited with code 4", id.String(), tgExecutorID, tgMockBinding.Incarnation, tgMockBinding.SessionID).
							WillReturnError(sql.ErrNoRows)
						mock.ExpectQuery(tgOwnedGetQuery).WithArgs(id.String(), tgExecutorID, tgMockBinding.Incarnation, tgMockBinding.SessionID).WillReturnRows(terminalRow(models.RunStateStarted))
					},
					wantMsg: "rejected although it is in state RunStateStarted",
				},
				{
					name: "terminal row is acknowledged without effects",
					expect: func(mock sqlmock.Sqlmock) {
						mock.ExpectQuery(tgCompleteQuery).
							WithArgs(int64(models.RunStateExited), "debuglet exited with code 4", id.String(), tgExecutorID, tgMockBinding.Incarnation, tgMockBinding.SessionID).
							WillReturnError(sql.ErrNoRows)
						mock.ExpectQuery(tgOwnedGetQuery).WithArgs(id.String(), tgExecutorID, tgMockBinding.Incarnation, tgMockBinding.SessionID).WillReturnRows(terminalRow(models.RunStateExited))
					},
					wantOK: true,
				},
			}
			for _, tc := range cases {
				t.Run(tc.name, func(t *testing.T) {
					db, mock, err := sqlmock.New()
					if err != nil {
						t.Fatalf("sqlmock: %v", err)
					}
					t.Cleanup(func() {
						mock.ExpectClose()
						if err := db.Close(); err != nil {
							t.Errorf("close mock db: %v", err)
						}
					})
					logger := zap.NewNop()
					ph := payments.NewPaymentHandler(db, &config.DispatcherConfig{Sui: config.SuiConfig{Disabled: true}}, logger)
					d, err := New(logger, db, "tg-mock", time.Minute, time.Minute, ph)
					if err != nil {
						t.Fatal(err)
					}
					t.Cleanup(d.Close)
					tc.expect(mock)
					owner, err := rpc.NewSessionOwner(tgExecutorID, tgMockBinding, time.Minute)
					if err != nil {
						t.Fatal(err)
					}
					owner.MarkRegistered()
					mutation, err := owner.AdmitMutation(t.Context())
					if err != nil {
						t.Fatal(err)
					}
					defer mutation.Finish()
					resp, err := d.OnDebugletExit(t.Context(), mutation, &pb.DebugletExitRequest{DebugletId: id.String(), ExitCode: 4})
					switch {
					case tc.wantOK:
						if err != nil || resp == nil {
							t.Fatalf("got (%v, %v), want an empty success", resp, err)
						}
					case tc.wantErr != nil:
						if !errors.Is(err, tc.wantErr) {
							t.Fatalf("got %v, want an error wrapping %v", err, tc.wantErr)
						}
						if resp != nil {
							t.Fatalf("got response %v alongside error", resp)
						}
					default:
						if err == nil || !strings.Contains(err.Error(), tc.wantMsg) {
							t.Fatalf("got %v, want an error containing %q", err, tc.wantMsg)
						}
						if resp != nil {
							t.Fatalf("got response %v alongside error", resp)
						}
					}
					// No payment transaction, no further queries: the fixture is
					// exact, so any effect would be an unexpected call.
					if err := mock.ExpectationsWereMet(); err != nil {
						t.Fatalf("unmet sqlmock expectations: %v", err)
					}
				})
			}
		})
	})

	t.Run("late ordinary state after terminal", func(t *testing.T) {
		f := newTGFixture(t, nil)
		a, b := f.seedDirect(t, tgFloorA), f.seedDirect(t, tgFloorB)
		if err := f.exit(t, a.id, 2, tgStr("failed early")); err != nil {
			t.Fatalf("exit: %v", err)
		}
		tgAssertRow(t, f.row(t, a.id), models.RunStateExited, tgText("failed early"))
		before := f.snapshot(t)

		for _, late := range []pb.RunState{pb.RunState_RUN_STATE_STARTED, pb.RunState_RUN_STATE_INITIALIZING} {
			if err := f.state(t, a.id, late); err != nil {
				t.Fatalf("late state %s after exit returned %v, want acknowledgement", late, err)
			}
			tgAssertRow(t, f.row(t, a.id), models.RunStateExited, tgText("failed early"))
		}
		if err := f.state(t, uuid.New(), pb.RunState_RUN_STATE_STARTED); err != nil {
			t.Fatalf("state for a missing id returned %v, want acknowledgement", err)
		}
		tgAssertSnapshot(t, f, before, "late states")

		// Positive control: an ordinary state on a nonterminal row still lands.
		if err := f.state(t, b.id, pb.RunState_RUN_STATE_INITIALIZING); err != nil {
			t.Fatalf("ordinary state on a running debuglet: %v", err)
		}
		tgAssertRow(t, f.row(t, b.id), models.RunStateInitializing, tgNull)

		// A database failure is returned, not logged as success; a terminal
		// row is still acknowledged because its guarded write touches no row.
		drop := f.installTrigger(t)
		err := f.state(t, b.id, pb.RunState_RUN_STATE_STARTED)
		if err == nil || !strings.Contains(err.Error(), tgSentinel) {
			t.Fatalf("state with a failing write returned %v, want a wrapped %q", err, tgSentinel)
		}
		tgAssertRow(t, f.row(t, b.id), models.RunStateInitializing, tgNull)
		if err := f.state(t, a.id, pb.RunState_RUN_STATE_STARTED); err != nil {
			t.Fatalf("late state on a terminal row with the trigger installed returned %v", err)
		}
		drop()
	})

	t.Run("upload replying after a terminal callback", func(t *testing.T) {
		t.Run("started before the upload reply stays started", func(t *testing.T) {
			peer := &tgPeer{}
			f := newTGFixture(t, peer)
			peer.scriptUpload(func(ctx context.Context, req *pb.UploadRequest) error {
				_, err := f.d.OnDebugletState(ctx, effectTestMutation(t, f.d, tgExecutorID), &pb.DebugletStateRequest{
					DebugletId: req.GetId(), ExecutorId: tgExecutorID, State: pb.RunState_RUN_STATE_STARTED,
				})
				return err
			})

			deb, err := f.submit(t, tgFloorA)
			if err != nil {
				t.Fatalf("SubmitDebuglets after Started: %v", err)
			}
			tgAssertRow(t, deb.row, models.RunStateStarted, tgNull)
		})

		t.Run("duplicate reordered and unsupported states", func(t *testing.T) {
			f := newTGFixture(t, &tgPeer{})
			deb, err := f.submit(t, tgFloorA)
			if err != nil {
				t.Fatalf("submit: %v", err)
			}
			if err := f.state(t, deb.id, pb.RunState_RUN_STATE_STARTED); err != nil {
				t.Fatalf("Started: %v", err)
			}
			for _, state := range []pb.RunState{pb.RunState_RUN_STATE_STARTED, pb.RunState_RUN_STATE_INITIALIZING} {
				if err := f.state(t, deb.id, state); err != nil {
					t.Fatalf("duplicate/reordered %s: %v", state, err)
				}
				tgAssertRow(t, f.row(t, deb.id), models.RunStateStarted, tgNull)
			}
			for _, state := range []pb.RunState{pb.RunState_RUN_STATE_UNSPECIFIED, pb.RunState(99)} {
				if err := f.state(t, deb.id, state); status.Code(err) != codes.InvalidArgument {
					t.Fatalf("unsupported %d returned %v, want InvalidArgument", state, err)
				}
				tgAssertRow(t, f.row(t, deb.id), models.RunStateStarted, tgNull)
			}
		})

		t.Run("zero exit before the upload reply keeps the submission successful", func(t *testing.T) {
			peer := &tgPeer{}
			f := newTGFixture(t, peer)
			peer.scriptUpload(func(ctx context.Context, req *pb.UploadRequest) error {
				_, err := f.d.OnDebugletExit(ctx, effectTestMutation(t, f.d, tgExecutorID), &pb.DebugletExitRequest{DebugletId: req.GetId(), ExitCode: 0})
				return err
			})

			deb, err := f.submit(t, tgFloorA)
			if err != nil {
				t.Fatalf("SubmitDebuglets after an early exit: %v", err)
			}
			// The terminal result was not overwritten by the guarded Uploaded
			// write, and the winner's effects ran once.
			tgAssertRow(t, deb.row, models.RunStateExited, tgNull)
			tgAssertOrder(t, f, deb, models.Credited)
			tgAssertEarnings(t, f, tgOrderPrice(tgFloorA))
			tgAssertReserved(t, f, deb, 0)

			uploads := peer.recordedUploads()
			if len(uploads) != 1 {
				t.Fatalf("peer recorded %d uploads, want 1", len(uploads))
			}
			up := uploads[0]
			if up.GetId() != deb.id.String() || up.GetTransactionId() != deb.txID || !bytes.Equal(up.GetWasm(), tgWasm) ||
				len(up.GetArgs()) != 1 || up.GetArgs()[0] != "tg" ||
				up.GetPolicy().GetFloorBw() != int64(tgFloorA) || up.GetPolicy().GetCeilBw() != int64(2*tgFloorA) ||
				up.GetPolicy().GetTimeoutMs() != tgTimeout.Milliseconds() ||
				!up.GetStartTime().AsTime().Equal(f.start) {
				t.Fatalf("peer recorded upload %+v, want the submitted spec for %s", up, deb.id)
			}

			// Later ordinary states and duplicate exits keep the result.
			if err := f.state(t, deb.id, pb.RunState_RUN_STATE_STARTED); err != nil {
				t.Fatalf("late state: %v", err)
			}
			if err := f.exit(t, deb.id, 1, tgStr("late")); err != nil {
				t.Fatalf("duplicate exit: %v", err)
			}
			tgAssertRow(t, f.row(t, deb.id), models.RunStateExited, tgNull)
			tgAssertEarnings(t, f, tgOrderPrice(tgFloorA))
		})

		t.Run("state and failed exit before the upload reply store the failure", func(t *testing.T) {
			peer := &tgPeer{}
			f := newTGFixture(t, peer)
			peer.scriptUpload(func(ctx context.Context, req *pb.UploadRequest) error {
				if _, err := f.d.OnDebugletState(ctx, effectTestMutation(t, f.d, tgExecutorID), &pb.DebugletStateRequest{DebugletId: req.GetId(), ExecutorId: tgExecutorID, State: pb.RunState_RUN_STATE_STARTED}); err != nil {
					return err
				}
				_, err := f.d.OnDebugletExit(ctx, effectTestMutation(t, f.d, tgExecutorID), &pb.DebugletExitRequest{DebugletId: req.GetId(), ExitCode: 3, ErrorMessage: tgStr("crash")})
				return err
			})

			deb, err := f.submit(t, tgFloorA)
			if err != nil {
				t.Fatalf("SubmitDebuglets after an early failure: %v", err)
			}
			tgAssertRow(t, deb.row, models.RunStateExited, tgText("crash"))
			tgAssertOrder(t, f, deb, models.Outstanding)
			tgAssertEarnings(t, f, 0)
			tgAssertReserved(t, f, deb, 0)
		})

		t.Run("plain upload, then exit and abort through the peer", func(t *testing.T) {
			peer := &tgPeer{}
			f := newTGFixture(t, peer)

			a, err := f.submit(t, tgFloorA)
			if err != nil {
				t.Fatalf("submit A: %v", err)
			}
			tgAssertRow(t, a.row, models.RunStateUploaded, tgNull)
			tgAssertReserved(t, f, a, tgFloorA)
			b, err := f.submit(t, tgFloorB)
			if err != nil {
				t.Fatalf("submit B: %v", err)
			}
			tgAssertRow(t, b.row, models.RunStateUploaded, tgNull)
			tgAssertReserved(t, f, a, tgFloorA+tgFloorB)
			if n := len(peer.recordedUploads()); n != 2 {
				t.Fatalf("peer recorded %d uploads, want 2", n)
			}

			// AbortDebuglet acknowledges through the peer and reports the exit
			// itself; a duplicate abort is acknowledged with no further effect.
			if err := f.abort(t, a.id, "operator abort"); err != nil {
				t.Fatalf("abort A: %v", err)
			}
			tgAssertRow(t, f.row(t, a.id), models.RunStateExited, tgText("operator abort"))
			tgAssertOrder(t, f, a, models.Outstanding)
			tgAssertReserved(t, f, a, tgFloorB)
			after := f.snapshot(t)
			if err := f.abort(t, a.id, "second abort"); err != nil {
				t.Fatalf("duplicate abort A: %v", err)
			}
			tgAssertRow(t, f.row(t, a.id), models.RunStateExited, tgText("operator abort"))
			tgAssertSnapshot(t, f, after, "duplicate abort")
			tgAssertReserved(t, f, a, tgFloorB)
			if aborts := peer.recordedAborts(); len(aborts) != 2 || aborts[0].GetDebugletId() != a.id.String() || aborts[0].GetReason() != "operator abort" {
				t.Fatalf("peer recorded aborts %+v", aborts)
			}

			// A failing Abort RPC performs no terminal write.
			peer.scriptAbort(errors.New("executor refused the abort"))
			if err := f.abort(t, b.id, "refused"); err == nil || !strings.Contains(err.Error(), "executor refused the abort") {
				t.Fatalf("abort with a failing RPC returned %v", err)
			}
			tgAssertRow(t, f.row(t, b.id), models.RunStateUploaded, tgNull)
			tgAssertReserved(t, f, a, tgFloorB)
			peer.scriptAbort(nil)

			if err := f.exit(t, b.id, 0, nil); err != nil {
				t.Fatalf("exit B: %v", err)
			}
			tgAssertRow(t, f.row(t, b.id), models.RunStateExited, tgNull)
			tgAssertOrder(t, f, b, models.Credited)
			tgAssertEarnings(t, f, tgOrderPrice(tgFloorB))
			tgAssertReserved(t, f, a, 0)
		})
	})
}
