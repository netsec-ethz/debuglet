package dispatcher

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/config"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/database"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/models"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/payments"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/testutil"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/transport/rpc"
	pb "github.com/netsec-ethz/debuglet/protocol"
	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
	"modernc.org/sqlite"
)

// The connector wraps the real SQLite driver without global registration or a
// production dependency seam. A selected generated query executes normally;
// its first actual result row is held before returning to database/sql. Caller
// cancellation cannot pretend that this owned database operation has joined.
type fencingSQLGate struct {
	query   string
	entered chan struct{}
	release <-chan struct{}
	once    sync.Once
}
type fencingConnector struct {
	path string
	gate *fencingSQLGate
}

func (c fencingConnector) Driver() driver.Driver { return &sqlite.Driver{} }
func (c fencingConnector) Connect(ctx context.Context) (driver.Conn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	conn, err := c.Driver().Open(c.path)
	if err != nil {
		return nil, err
	}
	return &fencingConn{Conn: conn, gate: c.gate}, nil
}

type fencingConn struct {
	driver.Conn
	gate *fencingSQLGate
}

func (c *fencingConn) QueryContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	q, ok := c.Conn.(driver.QueryerContext)
	if !ok {
		return nil, driver.ErrSkip
	}
	rows, err := q.QueryContext(ctx, query, args)
	if err != nil || !strings.HasPrefix(query, "-- name: "+c.gate.query+" ") {
		return rows, err
	}
	return &fencingRows{Rows: rows, gate: c.gate}, nil
}
func (c *fencingConn) ExecContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Result, error) {
	e, ok := c.Conn.(driver.ExecerContext)
	if !ok {
		return nil, driver.ErrSkip
	}
	return e.ExecContext(ctx, query, args)
}

type fencingRows struct {
	driver.Rows
	gate *fencingSQLGate
}

func (r *fencingRows) Next(values []driver.Value) error {
	err := r.Rows.Next(values)
	if err == nil {
		r.gate.once.Do(func() { close(r.gate.entered); <-r.gate.release })
	}
	return err
}

func fencingDispatcher(t *testing.T, gate *fencingSQLGate) *Dispatcher {
	t.Helper()
	db := sql.OpenDB(fencingConnector{path: filepath.Join(t.TempDir(), "fencing.sqlite"), gate: gate})
	db.SetMaxOpenConns(1)
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Error(err)
		}
	})
	testutil.ApplyMigrations(t, db, "database/migrations")
	logger := zap.NewNop()
	ph := payments.NewPaymentHandler(db, &config.DispatcherConfig{Sui: config.SuiConfig{Disabled: true}}, logger)
	d, err := New(logger, db, "fencing-test", time.Minute, time.Minute, ph)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(d.Close)
	return d
}

func fencingRun(t *testing.T, d *Dispatcher, owner *rpc.SessionOwner) database.Debuglet {
	t.Helper()
	now := time.Now()
	row, err := database.New(d.db).CreateDebuglet(t.Context(), database.CreateDebugletParams{
		Uuid: uuid.New(), ExecutorID: owner.ExecutorID(), DispatcherIncarnation: owner.Binding().Incarnation, SessionID: owner.Binding().SessionID,
		StartTime: models.NewUTCTime(now), EndTime: models.NewUTCTime(now.Add(time.Minute)), State: models.RunStateUploaded,
		TransactionID: "fencing-unpaid", OrderID: 1, Usage: 1000, CeilBw: 2000, Addresses: models.CommaSeparatedList{"127.0.0.1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	return row
}

// Each case crosses direct gRPC, the actual dispatcher, generated SQL and real
// SQLite. A->B->C replacement must retain A's counted operation even after B's
// own canceled startup joins. A second executor remains usable over its actual
// reverse channel. Neither RPC cancellation nor a wait deadline releases SQL.
func TestControlMutationSQLDrainAcrossSuccessiveReplacements(t *testing.T) {
	for _, tc := range []struct{ name, query string }{
		{"state", "UpdateDebugletState"}, {"allocate", "GetOwnedDebugletByUUID"},
		{"exit", "CompleteDebuglet"}, {"log", "CreateDebugletLog"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			release, open := siGate()
			gate := &fencingSQLGate{query: tc.query, entered: make(chan struct{}), release: release}
			d := fencingDispatcher(t, gate)
			a, b, c, unrelated := siNewPlan(), siNewPlan(), siNewPlan(), siNewPlan()
			f := siNewHarnessFor(t, d, map[string]*siPlan{"a": a, "b": b, "c": c, "unrelated": unrelated}, open)
			f.connect("same", "a")
			old := siEntered(t, a)
			siAvailable(t, a, old)
			client := f.boundClient("a")
			f.connect("sentinel", "unrelated")
			siAvailable(t, unrelated, siEntered(t, unrelated))
			run := fencingRun(t, d, old)
			callCtx, cancelCall := context.WithTimeout(f.ctx, siBound)
			callDone := make(chan struct{})
			var callErr error
			// Registered after harness cleanup: release and join the caller before
			// joining server handlers, then only afterwards close the database.
			t.Cleanup(func() { open(); cancelCall(); siAwait(t, callDone, "original RPC caller") })
			go func() {
				defer close(callDone)
				switch tc.name {
				case "state":
					_, callErr = client.DebugletState(callCtx, &pb.DebugletStateRequest{ExecutorId: "same", DebugletId: run.Uuid.String(), State: pb.RunState_RUN_STATE_STARTED})
				case "allocate":
					_, callErr = client.DebugletAllocate(callCtx, &pb.DebugletAllocateRequest{ExecutorId: "same", DebugletId: run.Uuid.String(), TransactionId: run.TransactionID, Policy: &pb.DebugletPolicy{FloorBw: 1000, CeilBw: 2000}})
				case "exit":
					_, callErr = client.DebugletExit(callCtx, &pb.DebugletExitRequest{DebugletId: run.Uuid.String(), ExitCode: 1})
				case "log":
					stream, err := client.DebugletStream(callCtx)
					if err != nil {
						callErr = err
						return
					}
					if err = stream.Send(&pb.DebugletStreamRequest{Msg: &pb.DebugletStreamRequest_Ident{Ident: &pb.DebugletIdent{DebugletId: run.Uuid.String()}}}); err != nil {
						callErr = err
						return
					}
					if err = stream.Send(&pb.DebugletStreamRequest{Msg: &pb.DebugletStreamRequest_Output{Output: &pb.DebugletOutput{Timestamp: timestamppb.Now(), Output: []byte("owned frame")}}}); err != nil {
						callErr = err
						return
					}
					_ = stream.CloseSend()
					_, callErr = stream.Recv()
				}
			}()
			siAwait(t, gate.entered, "actual generated SQL row")
			middle := f.connect("same", "b")
			siAwait(t, old.Done(), "A retirement")
			latest := f.connect("same", "c")
			siAwait(t, middle.joined, "superseded B client lifetime")
			short, cancel := context.WithTimeout(f.ctx, 100*time.Millisecond)
			err := latest.client.WaitReadyContext(short)
			cancel()
			if !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("C readiness while A SQL held = %v", err)
			}
			select {
			case <-old.MutationsDrained():
				t.Fatal("retired owner drained before actual SQL returned")
			default:
			}
			select {
			case <-c.entered:
				t.Fatal("C Connected bypassed A's retained predecessor barrier")
			default:
			}
			f.checkPeer("sentinel", "unrelated")
			open()
			siAwait(t, callDone, "original RPC return")
			_ = callErr // cancellation/EOF is not itself the local completion oracle
			siAwait(t, old.MutationsDrained(), "actual SQL/effect and descendant completion")
			next := siEntered(t, c)
			siAvailable(t, c, next)
			f.checkPeer("same", "c")
			stored, err := database.New(d.db).GetDebugletByUUID(t.Context(), run.Uuid)
			if err != nil || stored.SessionID != old.Binding().SessionID || stored.DispatcherIncarnation != old.Binding().Incarnation {
				t.Fatalf("original run was rebound or removed: session=%q err=%v", stored.SessionID, err)
			}
		})
	}
}

func TestControlCurrentSessionCannotClaimRetainedRun(t *testing.T) {
	a, b := siNewPlan(), siNewPlan()
	a.control = make(chan metadata.MD, 1)
	f := siNewHarness(t, map[string]*siPlan{"a": a, "b": b})
	oldPeer := f.connect("same", "a")
	old := siEntered(t, a)
	siAvailable(t, a, old)
	oldClient := f.boundClient("a")
	row := fencingRun(t, f.d, old)
	ctx, cancel := context.WithTimeout(f.ctx, siBound)
	defer cancel()
	// Capture the actual admitted wire envelope. The profile Hello intentionally
	// omits possession tokens; it cannot provide a valid stale-server fixture.
	if _, err := oldClient.Heartbeat(ctx, &pb.HeartbeatRequest{ExecutorId: "same"}); err != nil {
		t.Fatal(err)
	}
	var captured metadata.MD
	select {
	case captured = <-a.control:
	case <-ctx.Done():
		t.Fatal("no actual admitted credential envelope observed")
	}
	stale := metadata.NewOutgoingContext(ctx, captured)
	if _, err := f.rpc.Heartbeat(stale, &pb.HeartbeatRequest{ExecutorId: "same"}); err != nil {
		t.Fatal("captured credential envelope did not succeed while current")
	}
	f.connect("same", "b")
	next := siEntered(t, b)
	siAvailable(t, b, next)
	client := f.boundClient("b")
	assertStatus := func(name string, err error, want codes.Code) {
		t.Helper()
		if status.Code(err) != want {
			t.Fatalf("%s: status=%v want=%v", name, status.Code(err), want)
		}
	}
	// v3 rejects a cached client locally once its loss is observed. Independently
	// send the captured stale offer over the harness's direct connection to keep
	// the actual server admission oracle exercised as well.
	siAwait(t, oldPeer.client.Lost(), "old client loss before fresh mutation")
	_, err := oldClient.DebugletState(ctx, &pb.DebugletStateRequest{ExecutorId: "same", DebugletId: row.Uuid.String(), State: pb.RunState_RUN_STATE_STARTED})
	if err == nil || !errors.Is(err, oldPeer.client.Cause()) {
		t.Fatal("cached old client did not preserve its selected loss cause")
	}
	_, err = f.rpc.DebugletState(stale, &pb.DebugletStateRequest{ExecutorId: "same", DebugletId: row.Uuid.String(), State: pb.RunState_RUN_STATE_STARTED})
	assertStatus("server rejects retired session", err, codes.FailedPrecondition)
	_, err = client.DebugletState(ctx, &pb.DebugletStateRequest{ExecutorId: "same", DebugletId: row.Uuid.String(), State: pb.RunState_RUN_STATE_STARTED})
	assertStatus("replacement state", err, codes.PermissionDenied)
	_, err = client.DebugletAllocate(ctx, &pb.DebugletAllocateRequest{ExecutorId: "same", DebugletId: row.Uuid.String(), TransactionId: row.TransactionID, Policy: &pb.DebugletPolicy{FloorBw: 1000, CeilBw: 2000, Addresses: []string{"127.0.0.1"}}})
	assertStatus("replacement allocation before payment", err, codes.PermissionDenied)
	_, err = client.DebugletExit(ctx, &pb.DebugletExitRequest{DebugletId: row.Uuid.String(), ExitCode: 0})
	assertStatus("replacement terminal result", err, codes.PermissionDenied)
	err = f.d.AbortDebuglet(ctx, "same", row.Uuid, "must not retarget")
	assertStatus("operator cancellation of old run", err, codes.PermissionDenied)
	stream, err := client.DebugletStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err = stream.Send(&pb.DebugletStreamRequest{Msg: &pb.DebugletStreamRequest_Ident{Ident: &pb.DebugletIdent{DebugletId: row.Uuid.String()}}}); err != nil {
		t.Fatal(err)
	}
	_ = stream.CloseSend()
	_, err = stream.Recv()
	assertStatus("replacement output identity", err, codes.PermissionDenied)
	queries := database.New(f.d.db)
	stored, err := queries.GetDebugletByUUID(ctx, row.Uuid)
	if err != nil || !reflect.DeepEqual(stored, row) {
		t.Fatalf("rejected calls changed original run: err=%v", err)
	}
	logs, err := queries.ListDebugletLogs(ctx, database.ListDebugletLogsParams{Uuid: row.Uuid, Limit: 10})
	if err != nil || len(logs) != 0 {
		t.Fatalf("rejected calls created logs: count=%d err=%v", len(logs), err)
	}
	f.d.mu.RLock()
	destinations := f.d.destinations.Len()
	f.d.mu.RUnlock()
	if destinations != 0 {
		t.Fatal("rejected allocation changed destination accounting")
	}
	var orders int
	if err := f.d.db.QueryRowContext(ctx, "SELECT count(*) FROM debuglet_order").Scan(&orders); err != nil || orders != 0 {
		t.Fatalf("rejected callbacks changed orders: count=%d err=%v", orders, err)
	}
	f.checkPeer("same", "b")
}
