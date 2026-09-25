package api

import (
	"bufio"
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/netsec-ethz/debuglet/internal/dispatcher"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/config"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/database"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/models"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/payments"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/resource"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/testutil"
	"github.com/netsec-ethz/debuglet/pkg/client"
	pb "github.com/netsec-ethz/debuglet/protocol"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"go.uber.org/zap"

	_ "modernc.org/sqlite"
)

const (
	ccExecutorID    = "cc-executor"
	ccPricePerBwS   = int64(1)
	ccFloorBW       = int64(1000)
	ccDurationMS    = int64(2000)
	ccCapacity      = resource.Megabit
	ccBuildTimeout  = 120 * time.Second
	ccRequestBound  = 10 * time.Second
	ccCommandBound  = 20 * time.Second
	ccCleanupBound  = 15 * time.Second
	ccMigrationsDir = "../../database/migrations"
)

// ccGuest is the bytes submitted as the guest. The dispatcher only decodes
// them; no execution happens with the scripted peer.
var ccGuest = []byte("\x00asm\x01\x00\x00\x00client-contract")

// ccFixture is the real dispatcher HTTP surface backed by SQLite, the
// disabled payment handler and the scripted executor peer, served by two
// httptest servers: one at the root and one behind an explicit /api prefix.
type ccFixture struct {
	t       *testing.T
	ctx     context.Context
	db      *sql.DB
	queries *database.Queries
	d       *dispatcher.Dispatcher
	peer    *cpPeer
	root    *httptest.Server
	// routes lists every registered route as "METHOD path", for the tests
	// that check a decision was made for each of them.
	routes []string
	prefix *httptest.Server
	dbl    string
}

func ccBuildCLI(t *testing.T) string {
	t.Helper()
	goBin, err := exec.LookPath("go")
	if err != nil {
		t.Fatalf("go toolchain is required to build dbl: %v", err)
	}
	moduleRoot, err := filepath.Abs("../../../..")
	if err != nil {
		t.Fatalf("module root: %v", err)
	}
	out := filepath.Join(t.TempDir(), "dbl")
	ctx, cancel := context.WithTimeout(context.Background(), ccBuildTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, goBin, "build", "-mod=readonly", "-o", out, "./cmd/dbl")
	cmd.Dir = moduleRoot
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOTOOLCHAIN=local")
	start := time.Now()
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("building dbl failed after %s: %v\n%s", time.Since(start), err, output)
	}
	t.Logf("built dbl in %s", time.Since(start))
	return out
}

// ccNewFixture builds the fixture in the local development profile, which is
// the one the wallet-free local flow uses. ccNewFixtureWith builds the same
// stack in any profile; the enforced one is exercised by auth_test.go.
func ccNewFixture(t *testing.T) *ccFixture {
	t.Helper()
	return ccNewFixtureWith(t, LocalDevelopment(true))
}

func ccNewFixtureWith(t *testing.T, options ...Option) *ccFixture {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "dispatcher.sqlite"))
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Errorf("close sqlite: %v", err)
		}
	})
	db.SetMaxOpenConns(1)
	testutil.ApplyMigrations(t, db, ccMigrationsDir)

	logger := zap.NewNop()
	ph := payments.NewPaymentHandler(db, &config.DispatcherConfig{Sui: config.SuiConfig{Disabled: true}}, logger)
	d, err := dispatcher.New(logger, db, "cc-version", time.Minute, time.Minute, ph)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(d.Close)
	peer := &cpPeer{id: ccExecutorID, price: ccPricePerBwS, currency: "TEST"}
	stop, err := startClientPeer(ctx, d, ccCapacity, peer)
	if err != nil {
		t.Fatalf("startClientPeer: %v", err)
	}
	t.Cleanup(func() {
		cancel()
		cleanupCtx, cancelCleanup := context.WithTimeout(context.Background(), ccCleanupBound)
		defer cancelCleanup()
		if err := stop(cleanupCtx); err != nil {
			t.Errorf("stop client peer: %v", err)
		}
	})

	e := echo.New()
	e.HideBanner = true
	NewHandler(d, db, logger, options...).RegisterRoutes(e)
	var routes []string
	for _, route := range e.Routes() {
		routes = append(routes, route.Method+" "+route.Path)
	}
	// LIFO cleanup stops fixture traffic, then joins peer callbacks,
	// then closes SQLite. Register each resource as it is acquired.
	root := httptest.NewServer(e)
	t.Cleanup(func() {
		root.CloseClientConnections()
		root.Close()
	})
	prefix := httptest.NewServer(http.StripPrefix("/api", e))
	t.Cleanup(func() {
		prefix.CloseClientConnections()
		prefix.Close()
	})

	f := &ccFixture{t: t, ctx: ctx, db: db, queries: database.New(db), d: d, peer: peer, root: root, prefix: prefix, routes: routes}
	return f
}

func (f *ccFixture) client(base string, allowRemote bool) *client.Client {
	f.t.Helper()
	c, err := client.New(base, client.Options{RequestTimeout: ccRequestBound, AllowRemoteTEST: allowRemote})
	if err != nil {
		f.t.Fatalf("client.New(%s): %v", base, err)
	}
	return c
}

func (f *ccFixture) requestCtx() (context.Context, context.CancelFunc) {
	return context.WithTimeout(f.ctx, ccRequestBound)
}

func ccRequest(args []string) client.Request {
	return client.Request{
		OrderID:    0,
		ExecutorID: ccExecutorID,
		Args:       args,
		Wasm:       ccGuest,
		Policy: client.Policy{
			FloorBW:   ccFloorBW,
			CeilBW:    ccFloorBW,
			TimeoutMS: ccDurationMS,
			Addresses: []string{"127.0.0.1"},
		},
	}
}

// submit prepares one request and submits it through the SDK, returning the
// accepted submission.
func (f *ccFixture) submit(c *client.Client, args []string) client.Submission {
	f.t.Helper()
	batch, err := client.Prepare([]client.Request{ccRequest(args)})
	if err != nil {
		f.t.Fatalf("Prepare: %v", err)
	}
	ctx, cancel := f.requestCtx()
	defer cancel()
	sub, err := c.SubmitTEST(ctx, batch)
	if err != nil {
		f.t.Fatalf("SubmitTEST: %v", err)
	}
	if len(sub.IDs) != 1 || sub.TransactionID == "" {
		f.t.Fatalf("unexpected submission %+v", sub)
	}
	if _, err := uuid.Parse(sub.IDs[0]); err != nil {
		f.t.Fatalf("submission id %q is not a UUID: %v", sub.IDs[0], err)
	}
	return sub
}

// exitHook returns an upload hook that reports the given exit through the
// real callbacks before acknowledging the upload.
func (f *ccFixture) exitHook(code int32, message *string) func(context.Context, *pb.UploadRequest) error {
	return func(ctx context.Context, req *pb.UploadRequest) error {
		if _, err := f.peer.direct.DebugletState(ctx, &pb.DebugletStateRequest{
			DebugletId: req.GetId(), ExecutorId: ccExecutorID, State: pb.RunState_RUN_STATE_STARTED,
		}); err != nil {
			return err
		}
		_, err := f.peer.direct.DebugletExit(ctx, &pb.DebugletExitRequest{DebugletId: req.GetId(), ExitCode: code, ErrorMessage: message})
		return err
	}
}

// seedLogs stores output chunks for id through the real query, returning the
// stored entry IDs in order.
func (f *ccFixture) seedLogs(id string, chunks [][]byte) []int64 {
	f.t.Helper()
	u, err := uuid.Parse(id)
	if err != nil {
		f.t.Fatalf("parse id: %v", err)
	}
	var ids []int64
	base := time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)
	for i, chunk := range chunks {
		row, err := f.queries.CreateDebugletLog(f.ctx, database.CreateDebugletLogParams{
			ExecutorID: f.peer.owner.ExecutorID(), DispatcherIncarnation: f.peer.owner.Binding().Incarnation, SessionID: f.peer.owner.Binding().SessionID,
			Uuid: u, Timestamp: models.NewUTCTime(base.Add(time.Duration(i) * time.Second)), Output: chunk,
		})
		if err != nil {
			f.t.Fatalf("seed log %d: %v", i, err)
		}
		ids = append(ids, row.ID)
	}
	return ids
}

// runCLI executes the built dbl with a bounded context and returns its exit
// code, stdout and stderr.
func (f *ccFixture) runCLI(args ...string) (int, []byte, []byte) {
	f.t.Helper()
	ctx, cancel := context.WithTimeout(f.ctx, ccCommandBound)
	defer cancel()
	cmd := exec.CommandContext(ctx, f.dbl, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	cmd.Env = append(os.Environ(), "GOTOOLCHAIN=local")
	err := cmd.Run()
	code := 0
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		code = exitErr.ExitCode()
	} else if err != nil {
		f.t.Fatalf("dbl %v: %v", args, err)
	}
	if ctx.Err() != nil {
		f.t.Fatalf("dbl %v did not finish within %s; stdout=%s stderr=%s", args, ccCommandBound, stdout.Bytes(), stderr.Bytes())
	}
	return code, stdout.Bytes(), stderr.Bytes()
}

func ccDecode(t *testing.T, what string, data []byte, v any) {
	t.Helper()
	dec := json.NewDecoder(bytes.NewReader(data))
	if err := dec.Decode(v); err != nil {
		t.Fatalf("%s: decode %q: %v", what, data, err)
	}
	// A second decode must report a clean end of stream: trailing JSON or an
	// invalid trailing delimiter is a second document, not parseable output.
	var trailing json.RawMessage
	if err := dec.Decode(&trailing); !errors.Is(err, io.EOF) {
		t.Fatalf("%s: stdout does not end after one JSON document (%v): %s", what, err, data)
	}
}

func ccAssertNoAuthKey(t *testing.T, what string, outputs ...[]byte) {
	t.Helper()
	for _, o := range outputs {
		if strings.Contains(string(o), "auth_key") {
			t.Fatalf("%s leaked an auth key field: %s", what, o)
		}
	}
}

// TestClientHTTPContract drives the public SDK and the built dbl binary
// against the real Echo routes, the disabled PaymentHandler, a fresh
// SQLite file and the scripted executor peer: node discovery, TEST
// submission through the server's hash check, terminal success and failure
// reported by the real callbacks, binary paginated logs seeded through the
// database, cancellation acknowledgement and rejection, and the explicit
// /api prefix. It proves the HTTP, SQLite, upload-RPC and client contracts
// with scripted executor behaviour, not guest execution.
func TestClientHTTPContract(t *testing.T) {
	f := ccNewFixture(t)
	f.dbl = ccBuildCLI(t)
	rootClient := f.client(f.root.URL, false)

	t.Run("nodes", func(t *testing.T) {
		ctx, cancel := f.requestCtx()
		defer cancel()
		nodes, err := rootClient.Nodes(ctx)
		if err != nil {
			t.Fatalf("Nodes: %v", err)
		}
		if len(nodes) != 1 || nodes[0].ID != ccExecutorID || nodes[0].Ready || nodes[0].Currency != "TEST" || nodes[0].PricePerBw != ccPricePerBwS || nodes[0].Version != "client-peer" {
			t.Fatalf("unexpected nodes: %+v", nodes)
		}
		code, stdout, stderr := f.runCLI("--endpoint", f.root.URL, "--output", "json", "nodes")
		if code != 0 {
			t.Fatalf("dbl nodes exit %d: %s", code, stderr)
		}
		var cliNodes []client.Node
		ccDecode(t, "dbl nodes", stdout, &cliNodes)
		if len(cliNodes) != 1 || cliNodes[0].ID != ccExecutorID {
			t.Fatalf("dbl nodes: %+v", cliNodes)
		}
	})

	t.Run("submission passes the server hash check and reaches the peer", func(t *testing.T) {
		f.peer.setUploadHook(nil)
		before := f.peer.uploadCount()
		sub := f.submit(rootClient, []string{"127.0.0.1:12345", "two words"})
		up := f.peer.lastUpload()
		if f.peer.uploadCount() != before+1 || up == nil || up.GetId() != sub.IDs[0] || up.GetTransactionId() != sub.TransactionID {
			t.Fatalf("upload not observed for %+v: %+v", sub, up)
		}
		if !bytes.Equal(up.GetWasm(), ccGuest) || len(up.GetArgs()) != 2 || up.GetArgs()[1] != "two words" ||
			up.GetPolicy().GetFloorBw() != ccFloorBW || up.GetPolicy().GetTimeoutMs() != ccDurationMS {
			t.Fatalf("upload payload differs from the request: %+v", up)
		}
		tx, err := f.queries.GetTransactionByID(f.ctx, sub.TransactionID)
		if err != nil || tx.Method != "TEST" || tx.Status != int64(models.Paid) || tx.AuthKey != "" {
			t.Fatalf("transaction row %+v (err %v)", tx, err)
		}

		// A deliberately changed request under the same transaction must fail
		// the real hash check; the SDK never sends a changed array, so use a
		// raw request with the frozen keys.
		altered := wfDebuglets()
		altered[0].ExecutorID = ccExecutorID
		altered[0].Args = []string{"changed"}
		raw := &wfClient{t: t, base: f.root.URL, http: f.root.Client()}
		status, body := raw.do(http.MethodPut, "/debuglet", SubmitDebugletsRequest{Debuglets: altered, TransactionId: sub.TransactionID, AuthKey: ""})
		if status != http.StatusBadRequest || !strings.Contains(string(body), "does not match the intent") {
			t.Fatalf("altered request: status %d body %s", status, body)
		}

		ctx, cancel := f.requestCtx()
		defer cancel()
		st, err := rootClient.Status(ctx, sub.IDs[0])
		if err != nil || st.State != "RunStateUploaded" || st.ExecutorID != ccExecutorID || st.Error != "" {
			t.Fatalf("status after upload: %+v (err %v)", st, err)
		}
	})

	t.Run("terminal success and failure through the real callbacks", func(t *testing.T) {
		f.peer.setUploadHook(f.exitHook(0, nil))
		ok := f.submit(rootClient, nil)
		ctx, cancel := f.requestCtx()
		defer cancel()
		st, err := rootClient.Status(ctx, ok.IDs[0])
		if err != nil || st.State != client.StateExited || st.Error != "" {
			t.Fatalf("success status: %+v (err %v)", st, err)
		}

		f.peer.setUploadHook(f.exitHook(7, nil))
		failed := f.submit(rootClient, nil)
		st, err = rootClient.Status(ctx, failed.IDs[0])
		if err != nil || st.State != client.StateExited || st.Error != "debuglet exited with code 7" {
			t.Fatalf("failure status: %+v (err %v)", st, err)
		}

		code, stdout, stderr := f.runCLI("--endpoint", f.root.URL, "--output", "json", "status", failed.IDs[0])
		if code != 0 {
			t.Fatalf("dbl status exit %d: %s", code, stderr)
		}
		var cliState struct {
			ID         string `json:"id"`
			State      string `json:"state"`
			Error      string `json:"error"`
			ExecutorID string `json:"executor_id"`
		}
		ccDecode(t, "dbl status", stdout, &cliState)
		if cliState.ID != failed.IDs[0] || cliState.State != client.StateExited || cliState.Error != "debuglet exited with code 7" || cliState.ExecutorID != ccExecutorID {
			t.Fatalf("dbl status: %+v", cliState)
		}
	})

	t.Run("binary paginated logs", func(t *testing.T) {
		f.peer.setUploadHook(f.exitHook(0, nil))
		sub := f.submit(rootClient, nil)
		chunks := [][]byte{{0x00, 0xff, 0x0a}, []byte("second\n"), {0x7f, 0x00}}
		ids := f.seedLogs(sub.IDs[0], chunks)

		ctx, cancel := f.requestCtx()
		defer cancel()
		var got [][]byte
		after := int64(0)
		for i := 0; i < len(chunks); i++ {
			page, err := rootClient.Logs(ctx, sub.IDs[0], client.LogOptions{After: after, Limit: 1})
			if err != nil {
				t.Fatalf("Logs page %d: %v", i, err)
			}
			if len(page.Logs) != 1 || page.Logs[0].ID != ids[i] || !page.HasMore || page.After != ids[i] || page.State != client.StateExited {
				t.Fatalf("page %d: %+v", i, page)
			}
			got = append(got, page.Logs[0].Output)
			after = page.After
		}
		// The last full page reported has_more; the following page is empty.
		empty, err := rootClient.Logs(ctx, sub.IDs[0], client.LogOptions{After: after, Limit: 1})
		if err != nil || len(empty.Logs) != 0 || empty.HasMore || empty.After != after {
			t.Fatalf("trailing empty page: %+v (err %v)", empty, err)
		}
		for i := range chunks {
			if !bytes.Equal(got[i], chunks[i]) {
				t.Fatalf("chunk %d: got %x want %x", i, got[i], chunks[i])
			}
		}

		code, stdout, stderr := f.runCLI("--endpoint", f.root.URL, "--output", "json", "logs", "--follow", "--limit", "1", sub.IDs[0])
		if code != 0 {
			t.Fatalf("dbl logs --follow exit %d: %s", code, stderr)
		}
		var pages []client.LogPage
		scanner := bufio.NewScanner(bytes.NewReader(stdout))
		for scanner.Scan() {
			var page client.LogPage
			if err := json.Unmarshal(scanner.Bytes(), &page); err != nil {
				t.Fatalf("NDJSON line %q: %v", scanner.Text(), err)
			}
			pages = append(pages, page)
		}
		var joined []byte
		for _, p := range pages {
			for _, e := range p.Logs {
				joined = append(joined, e.Output...)
			}
		}
		if !bytes.Equal(joined, bytes.Join(chunks, nil)) {
			t.Fatalf("dbl logs --follow output %x want %x (pages %+v)", joined, bytes.Join(chunks, nil), pages)
		}

		code, stdout, _ = f.runCLI("--endpoint", f.root.URL, "logs", "--limit", "1", sub.IDs[0])
		if code != 0 || !bytes.Equal(stdout, chunks[0]) {
			t.Fatalf("dbl logs human: exit %d stdout %x want %x", code, stdout, chunks[0])
		}
	})

	t.Run("CLI run, wait and receipts", func(t *testing.T) {
		wasm := filepath.Join(t.TempDir(), "guest.wasm")
		if err := os.WriteFile(wasm, ccGuest, 0o600); err != nil {
			t.Fatalf("write guest: %v", err)
		}
		f.peer.setUploadHook(nil)
		code, stdout, stderr := f.runCLI("--endpoint", f.root.URL, "--output", "json", "run",
			"--wasm", wasm, "--executor", ccExecutorID, "--allow", "127.0.0.1", "--duration", "2s",
			"--floor-bps", fmt.Sprint(ccFloorBW), "--ceil-bps", fmt.Sprint(ccFloorBW), "--", "127.0.0.1:12345", "two words")
		if code != 0 {
			t.Fatalf("dbl run exit %d: %s", code, stderr)
		}
		ccAssertNoAuthKey(t, "dbl run", stdout, stderr)
		var receipt struct {
			ID            string `json:"id"`
			TransactionID string `json:"transaction_id"`
			ExecutorID    string `json:"executor_id"`
			State         string `json:"state"`
			Error         string `json:"error"`
		}
		ccDecode(t, "dbl run", stdout, &receipt)
		if receipt.State != "submitted" || receipt.ID == "" || receipt.TransactionID == "" || receipt.ExecutorID != ccExecutorID {
			t.Fatalf("receipt %+v", receipt)
		}
		if up := f.peer.lastUpload(); up == nil || up.GetId() != receipt.ID || len(up.GetArgs()) != 2 || up.GetArgs()[1] != "two words" {
			t.Fatalf("upload for CLI run: %+v", up)
		}

		f.peer.setUploadHook(f.exitHook(0, nil))
		code, stdout, stderr = f.runCLI("--endpoint", f.root.URL, "--output", "json", "run", "--wait",
			"--wasm", wasm, "--executor", ccExecutorID, "--duration", "2s", "--floor-bps", "0", "--ceil-bps", "0")
		if code != 0 {
			t.Fatalf("dbl run --wait success exit %d: %s", code, stderr)
		}
		ccDecode(t, "dbl run --wait", stdout, &receipt)
		if receipt.State != client.StateExited || receipt.Error != "" || receipt.ID == "" {
			t.Fatalf("wait receipt %+v", receipt)
		}

		f.peer.setUploadHook(f.exitHook(7, nil))
		code, stdout, stderr = f.runCLI("--endpoint", f.root.URL, "--output", "json", "run", "--wait",
			"--wasm", wasm, "--executor", ccExecutorID, "--duration", "2s", "--floor-bps", "0", "--ceil-bps", "0")
		if code != 3 {
			t.Fatalf("dbl run --wait failure exit %d (want 3): stdout %s stderr %s", code, stdout, stderr)
		}
		ccDecode(t, "dbl run --wait failure", stdout, &receipt)
		if receipt.State != client.StateExited || receipt.Error != "debuglet exited with code 7" {
			t.Fatalf("wait failure receipt %+v", receipt)
		}
	})

	t.Run("cancellation acknowledgement and rejection", func(t *testing.T) {
		f.peer.setUploadHook(nil)
		f.peer.setAbortHook(nil)
		sub := f.submit(rootClient, nil)
		aborts := f.peer.abortCount()
		ctx, cancel := f.requestCtx()
		defer cancel()
		if err := rootClient.Cancel(ctx, sub.IDs[0], ccExecutorID); err != nil {
			t.Fatalf("Cancel: %v", err)
		}
		if f.peer.abortCount() != aborts+1 {
			t.Fatal("abort RPC did not reach the peer")
		}
		st, err := rootClient.Status(ctx, sub.IDs[0])
		if err != nil || st.State != client.StateExited || st.Error != "cancelled via API" {
			t.Fatalf("status after cancel: %+v (err %v)", st, err)
		}

		var httpErr *client.HTTPError
		if err := rootClient.Cancel(ctx, sub.IDs[0], "no-such-executor"); !errors.As(err, &httpErr) || httpErr.StatusCode != http.StatusBadRequest {
			t.Fatalf("Cancel with unknown executor: %v", err)
		}

		f.peer.setAbortHook(func(context.Context, *pb.AbortRequest) error { return errors.New("executor refused") })
		refused := f.submit(rootClient, nil)
		if err := rootClient.Cancel(ctx, refused.IDs[0], ccExecutorID); !errors.As(err, &httpErr) || httpErr.StatusCode != http.StatusBadRequest {
			t.Fatalf("Cancel with refusing peer: %v", err)
		}
		f.peer.setAbortHook(nil)

		acked := f.submit(rootClient, nil)
		code, stdout, stderr := f.runCLI("--endpoint", f.root.URL, "--output", "json", "cancel", acked.IDs[0])
		if code != 0 {
			t.Fatalf("dbl cancel exit %d: %s", code, stderr)
		}
		var ack struct {
			ID           string `json:"id"`
			Acknowledged bool   `json:"acknowledged"`
		}
		ccDecode(t, "dbl cancel", stdout, &ack)
		if ack.ID != acked.IDs[0] || !ack.Acknowledged {
			t.Fatalf("dbl cancel: %+v", ack)
		}
		f.peer.setAbortHook(func(context.Context, *pb.AbortRequest) error { return errors.New("executor refused") })
		rejected := f.submit(rootClient, nil)
		code, stdout, stderr = f.runCLI("--endpoint", f.root.URL, "--output", "json", "cancel", rejected.IDs[0])
		if code != 1 || strings.Contains(string(stdout), "true") {
			t.Fatalf("dbl cancel rejection: exit %d stdout %s stderr %s", code, stdout, stderr)
		}
		f.peer.setAbortHook(nil)
	})

	t.Run("version", func(t *testing.T) {
		ctx, cancel := f.requestCtx()
		defer cancel()
		v, err := rootClient.Version(ctx)
		if err != nil || v.Version != "cc-version" {
			t.Fatalf("Version: %+v (err %v)", v, err)
		}
		code, stdout, stderr := f.runCLI("--endpoint", f.root.URL, "--output", "json", "version", "--server")
		if code != 0 {
			t.Fatalf("dbl version --server exit %d: %s", code, stderr)
		}
		var info struct {
			Module   string               `json:"module"`
			Version  string               `json:"version"`
			Revision string               `json:"revision"`
			Modified bool                 `json:"modified"`
			Server   client.ServerVersion `json:"server"`
		}
		ccDecode(t, "dbl version", stdout, &info)
		if info.Server.Version != "cc-version" {
			t.Fatalf("dbl version --server: %+v", info)
		}
	})

	t.Run("explicit /api prefix", func(t *testing.T) {
		prefixClient := f.client(f.prefix.URL+"/api", false)
		f.peer.setUploadHook(f.exitHook(0, nil))
		sub := f.submit(prefixClient, nil)
		ctx, cancel := f.requestCtx()
		defer cancel()
		nodes, err := prefixClient.Nodes(ctx)
		if err != nil || len(nodes) != 1 {
			t.Fatalf("prefix Nodes: %+v (err %v)", nodes, err)
		}
		st, err := prefixClient.Status(ctx, sub.IDs[0])
		if err != nil || st.State != client.StateExited {
			t.Fatalf("prefix Status: %+v (err %v)", st, err)
		}
		if _, err := prefixClient.Logs(ctx, sub.IDs[0], client.LogOptions{}); err != nil {
			t.Fatalf("prefix Logs: %v", err)
		}
		if v, err := prefixClient.Version(ctx); err != nil || v.Version != "cc-version" {
			t.Fatalf("prefix Version: %+v (err %v)", v, err)
		}
		if err := prefixClient.Cancel(ctx, sub.IDs[0], ccExecutorID); err != nil {
			t.Fatalf("prefix Cancel: %v", err)
		}
		code, stdout, stderr := f.runCLI("--endpoint", f.prefix.URL+"/api", "--output", "json", "nodes")
		if code != 0 {
			t.Fatalf("dbl nodes via prefix exit %d: %s", code, stderr)
		}
		var cliNodes []client.Node
		ccDecode(t, "dbl nodes via prefix", stdout, &cliNodes)
		if len(cliNodes) != 1 {
			t.Fatalf("dbl nodes via prefix: %+v", cliNodes)
		}
		// The root server does not serve /api; the prefix must never be guessed.
		rootMisused := f.client(f.root.URL+"/api", false)
		var httpErr *client.HTTPError
		if _, err := rootMisused.Version(ctx); !errors.As(err, &httpErr) || httpErr.StatusCode != http.StatusNotFound {
			t.Fatalf("root server with /api prefix: %v", err)
		}
	})
}
