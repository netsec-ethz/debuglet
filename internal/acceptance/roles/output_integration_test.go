//go:build linux && roles_integration

// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package roles

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/netsec-ethz/debuglet/internal/acceptance/procinventory"
	"github.com/netsec-ethz/debuglet/internal/demo"
	dispatcherdb "github.com/netsec-ethz/debuglet/internal/dispatcher/database"
	executordb "github.com/netsec-ethz/debuglet/internal/executor/database"
	"github.com/netsec-ethz/debuglet/internal/executor/outputstore"
	"github.com/netsec-ethz/debuglet/internal/readiness"
	"github.com/netsec-ethz/debuglet/internal/sqlitedb"
	"github.com/netsec-ethz/debuglet/internal/testtls"
	"github.com/netsec-ethz/debuglet/pkg/client"
	pb "github.com/netsec-ethz/debuglet/protocol"
	"github.com/pelletier/go-toml/v2"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// TestInstalledOutput loses a committed receipt, then kills both installed
// daemons with output still queued. The forwarding peer holds only transport;
// admission, spooling, accounting and replay all belong to the installed code.
func TestInstalledOutput(t *testing.T) {
	root, source, evidence := os.Getenv("DEBUGLET_LOCAL_INSTALL_ROOT"), os.Getenv("DEBUGLET_LOCAL_SOURCE_ROOT"), os.Getenv("DEBUGLET_ROLE_EVIDENCE_DIR")
	if !filepath.IsAbs(root) || !filepath.IsAbs(source) || !filepath.IsAbs(evidence) {
		t.Fatal("absolute installed, source and evidence directories required")
	}
	assets, err := demo.ResolveAssets(filepath.Join(root, "bin", "dbl"))
	if err != nil || assets.Manifest.SourceSHA != os.Getenv("DEBUGLET_LOCAL_SOURCE_SHA") {
		t.Fatalf("installed/source identity: %v", err)
	}
	const policyTimeout = 4 * time.Minute
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Minute)
	defer cancel()
	work, err := os.MkdirTemp("", "debuglet-output-")
	if err != nil {
		t.Fatal(err)
	}
	// Private keys and account credentials stay outside uploaded evidence.
	// Preserve failed state locally for diagnosis; owned processes are still joined.
	t.Cleanup(func() {
		if !t.Failed() {
			if err := os.RemoveAll(work); err != nil {
				t.Error(err)
			}
		}
	})
	ca, err := testtls.NewAuthority(work, "ca")
	if err != nil {
		t.Fatal(err)
	}
	server, err := ca.Issue("server", testtls.Options{Hosts: []string{"127.0.0.1"}, Server: true})
	if err != nil {
		t.Fatal(err)
	}
	identity, err := ca.Issue("executor", testtls.Options{Client: true})
	if err != nil {
		t.Fatal(err)
	}
	dispatcherPath, executorPath := filepath.Join(work, "dispatcher.sqlite"), filepath.Join(work, "executor.sqlite")
	for _, role := range []string{"dispatcher", "executor"} {
		path := filepath.Join(work, role+".sqlite")
		db, err := sqlitedb.Open(path, sqlitedb.Create())
		if err != nil {
			t.Fatal(err)
		}
		migrations := dispatcherdb.MigrationFS()
		if role == "executor" {
			migrations = executordb.MigrationFS()
		}
		_, err = sqlitedb.Migrate(ctx, db, migrations, sqlitedb.Latest)
		closeErr := db.Close()
		if err != nil || closeErr != nil {
			t.Fatal(errors.Join(err, closeErr))
		}
	}
	dispatcherConfig := filepath.Join(work, "dispatcher.toml")
	writeOutputConfig(t, dispatcherConfig, map[string]any{
		"server":    map[string]any{"bind_host": "127.0.0.1", "http_port": 0, "grpc_port": 0},
		"tls":       map[string]any{"cert_file": server.CertFile, "key_file": server.KeyFile, "ca_file": ca.CertFile, "require_client_cert": true},
		"logging":   map[string]any{"log_level": "error", "json_logs": true},
		"scheduler": map[string]any{"executor_timeout": 60, "scheduler_granularity_ms": 1000},
		"database":  map[string]any{"path": dispatcherPath}, "sui": map[string]any{"disabled": true},
	})
	executorID := uuid.NewString()
	enrollment, _, err := runCommand(ctx, assets.Dispatcher, work, isolatedEnvironment(work), "-config", dispatcherConfig, "-enroll-executor", executorID)
	if err != nil {
		t.Fatal("installed enrollment:", err)
	}
	lines := strings.Split(strings.TrimSpace(string(enrollment)), "\n")
	token := lines[len(lines)-1]
	if token == "" || strings.Contains(token, " ") {
		t.Fatal("invalid enrollment response")
	}
	d := startOutputDaemon(t, ctx, assets.Dispatcher, work, dispatcherConfig, "dispatcher-1")

	transport := &http.Transport{TLSClientConfig: ca.ClientConfig(nil, "")}
	t.Cleanup(transport.CloseIdleConnections)
	newClient := func() *client.Client {
		c, err := client.New("https://"+d.ready.HTTPAddr, client.Options{HTTPClient: &http.Client{Transport: transport}, RequestTimeout: 5 * time.Second})
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	account, err := newClient().CreateAccount(ctx, "output owner")
	if err != nil {
		t.Fatal(err)
	}
	login := func() *client.Client {
		c := newClient()
		session, err := c.Login(ctx, account.AccountKey)
		if err != nil || session.ID != account.ID || session.Role != "user" {
			t.Fatalf("same owner login: %v", err)
		}
		c, err = c.WithCredential(session.Token)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	c := login()
	// The guest signals only after its whole stdout write has been accepted.
	target, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	emitted := make(chan struct{})
	targetDone := make(chan struct{})
	targetCtx, targetCancel := context.WithCancel(ctx)
	go func() {
		defer close(targetDone)
		conn, err := target.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		joined := make(chan struct{})
		go func() { defer close(joined); <-targetCtx.Done(); conn.Close() }()
		defer func() { targetCancel(); <-joined }()
		marker := make([]byte, 5)
		if _, err = io.ReadFull(conn, marker); err == nil && string(marker) == "ready" {
			close(emitted)
		}
		var b [1]byte
		_, _ = conn.Read(b[:])
	}()
	t.Cleanup(func() { targetCancel(); target.Close(); <-targetDone })
	guest := buildOutputGuest(t, ctx, source, work)
	peer := &outputForwarder{emitted: emitted, tail: make(chan struct{}), endSeen: make(chan struct{}), end: make(chan struct{})}
	peer.connect(t, ca, identity, d.ready.GRPCAddr)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	proxy := grpc.NewServer(grpc.Creds(credentials.NewTLS(ca.ServerConfig(server, true))), grpc.WaitForHandlers(true))
	pb.RegisterDispatcherServiceServer(proxy, peer)
	proxyDone := make(chan struct{})
	go func() { defer close(proxyDone); _ = proxy.Serve(listener) }()
	t.Cleanup(func() { peer.release(); proxy.Stop(); <-proxyDone; peer.close() })
	executorConfig := filepath.Join(work, "executor.toml")
	configureExecutor := func() {
		writeOutputConfig(t, executorConfig, map[string]any{
			"identity":    map[string]any{"executor_id": executorID},
			"dispatcher":  map[string]any{"addr": listener.Addr().String(), "yamux_addr": d.ready.HTTPAddr},
			"credentials": map[string]any{"ca_cert": ca.CertFile, "client_cert": identity.CertFile, "client_key": identity.KeyFile, "enrollment_token": token},
			"resources":   map[string]any{"capacity": 1000000000, "max_debuglets": 4}, "tesla": map[string]any{"delay": 30},
			"network": map[string]any{"packet_counter": "fallback", "disable_scion_environment": true, "policy": map[string]any{"local_targets": true}},
			"logging": map[string]any{"log_level": "error", "json_logs": true}, "database": map[string]any{"path": executorPath},
			"pricing": map[string]any{"price_per_bw_s": 1, "currency": "TEST"},
		})
	}
	configureExecutor()
	e := startOutputDaemon(t, ctx, assets.Executor, work, executorConfig, "executor-1")
	if e.ready.ExecutorID != executorID {
		t.Fatal("unexpected executor identity")
	}
	executorDB, err := sqlitedb.Open(executorPath, sqlitedb.ReadOnly())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { executorDB.Close() })
	dispatcherDB, err := sqlitedb.Open(dispatcherPath, sqlitedb.ReadOnly())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { dispatcherDB.Close() })
	spool, err := outputstore.New(executorDB, outputstore.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	submit := func(wasm []byte, args []string, start *int64) uuid.UUID {
		batch, err := client.Prepare([]client.Request{{OrderID: 1, ExecutorID: executorID, Wasm: wasm, Args: args, StartTimestamp: start, Policy: client.Policy{FloorBW: 1000000, CeilBW: 1000000, TimeoutMS: policyTimeout.Milliseconds(), Addresses: []string{"127.0.0.1"}}}})
		if err != nil {
			t.Fatal(err)
		}
		receipt, err := c.SubmitTEST(ctx, batch)
		if err != nil || len(receipt.IDs) != 1 {
			t.Fatalf("owned acknowledged submission: %v", err)
		}
		return uuid.MustParse(receipt.IDs[0])
	}
	first := submit(guest, []string{target.Addr().String(), "65536"}, nil)
	var savedA outputstore.Run
	outputEventually(t, ctx, "first producer joined", func() bool { savedA, err = spool.Get(ctx, first); return err == nil && savedA.End != nil })
	if savedA.End.Status != pb.DebugletOutputStatus_DEBUGLET_OUTPUT_STATUS_COMPLETE || savedA.LastSequence < 2 || savedA.AcknowledgedSequence != 0 {
		t.Fatalf("lost-ACK producer prefix: %+v", savedA)
	}
	wantA := outputFrames(t, ctx, spool, first)
	if !bytes.Equal(wantA, bytes.Repeat([]byte("x"), 65536)) {
		t.Fatalf("accepted output: %d bytes", len(wantA))
	}
	var stateA client.State
	outputEventually(t, ctx, "terminal before delayed tail", func() bool {
		stateA, err = c.Status(ctx, first.String())
		return err == nil && stateA.State == client.StateExited
	})
	page, err := c.Logs(ctx, first.String(), client.LogOptions{Limit: 1})
	if err != nil || page.Output.State != "pending" || len(page.Logs) != 1 || page.Output.FinalCursor != nil {
		t.Fatalf("committed first frame is pending: %v %+v", err, page.Output)
	}
	recordedA, err := dispatcherdb.New(dispatcherDB).GetDebugletOutput(ctx, first)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint := sha256.Sum256(identity.Certificate.Certificate[0])
	if recordedA.OwnerFingerprint != hex.EncodeToString(fingerprint[:]) || recordedA.DispatcherIncarnation != savedA.Binding.Incarnation || recordedA.SessionID != savedA.Binding.SessionID {
		t.Fatal("original enrolled certificate/binding not recorded")
	}
	second := submit(guest, []string{target.Addr().String(), "524288"}, nil)
	var savedB outputstore.Run
	outputEventually(t, ctx, "second producer has a durable open prefix", func() bool {
		savedB, err = spool.Get(ctx, second)
		return err == nil && savedB.End == nil && savedB.LastSequence > 0
	})
	wantB := outputFrames(t, ctx, spool, second)
	if len(wantB) == 0 || len(wantB) >= 524288 {
		t.Fatal("no interrupted partial prefix")
	}
	executionB, err := executordb.New(executorDB).GetDebugletIdentity(ctx, second)
	if err != nil {
		t.Fatal(err)
	}
	if executionB.StartedAt.IsZero() {
		t.Fatal("second workload has not actually started")
	}
	stateB, err := c.Status(ctx, second.String())
	if err != nil {
		t.Fatal(err)
	}
	e.kill(t, ctx)
	d.kill(t, ctx)
	d = startOutputDaemon(t, ctx, assets.Dispatcher, work, dispatcherConfig, "dispatcher-2")
	peer.connect(t, ca, identity, d.ready.GRPCAddr)
	configureExecutor()
	e = startOutputDaemon(t, ctx, assets.Executor, work, executorConfig, "executor-2")
	if e.ready.ExecutorID != executorID {
		t.Fatal("restart changed executor identity")
	}
	c = login()
	interrupted, err := spool.Get(ctx, second)
	if err != nil || interrupted.End == nil || interrupted.End.Status != pb.DebugletOutputStatus_DEBUGLET_OUTPUT_STATUS_TRUNCATED || interrupted.End.Reason != pb.OutputReasonExecutorInterrupted || interrupted.LastSequence != savedB.LastSequence || interrupted.Binding != savedB.Binding {
		t.Fatalf("restart interrupted prefix: %v %+v", err, interrupted)
	}
	recovery, err := c.Recovery(ctx, second.String())
	if err != nil || recovery.Observation.Observer == nil || recovery.Observation.Observer.Binding.SessionID == savedB.Binding.SessionID || recovery.Observation.Classification != "started_unknown" {
		t.Fatalf("new control did not preserve old execution provenance: %v %+v", err, recovery)
	}

	cliConfig := filepath.Join(work, "client.json")
	keyPath := filepath.Join(work, "account-key")
	if err := os.WriteFile(keyPath, []byte(account.AccountKey), 0600); err != nil {
		t.Fatal(err)
	}
	cliEnv := append(isolatedEnvironment(work), "SSL_CERT_FILE="+ca.CertFile)
	for _, args := range [][]string{{"connect", "https://" + d.ready.HTTPAddr, "--name", "output"}, {"login", "--account-key-file", keyPath}} {
		if _, _, err := runCommand(ctx, assets.CLI, work, cliEnv, append([]string{"--config", cliConfig}, args...)...); err != nil {
			t.Fatal("installed owner connection:", err)
		}
	}
	capture := new(capture)
	follower, err := demo.StartChild(demo.ChildSpec{Path: assets.CLI, Dir: work, Env: cliEnv, Args: []string{"--config", cliConfig, "--output", "json", "logs", "--follow", "--limit", "1", first.String()}, Stdout: captureWriter{capture, true}, Stderr: captureWriter{capture, false}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		phase, done := context.WithTimeout(context.Background(), 5*time.Second)
		defer done()
		_ = follower.Stop(phase)
		if !follower.CleanupComplete() {
			t.Error("follower cleanup incomplete")
		}
	})
	peer.tailOnce.Do(func() { close(peer.tail) })
	select {
	case <-peer.endSeen:
	case <-ctx.Done():
		t.Fatal("delayed End not reached:", ctx.Err())
	}
	tail, tailPage := readInstalledOutput(t, ctx, c, first)
	if !bytes.Equal(tail, wantA) || tailPage.Output.State != "pending" {
		t.Fatalf("terminal run lost delayed bytes before End: %d %+v", len(tail), tailPage.Output)
	}
	outputEventually(t, ctx, "installed follower observes pending tail", func() bool {
		out, _, overflow := capture.snapshot()
		if overflow {
			t.Fatal("installed follower exceeded capture bound")
		}
		lines := bytes.Split(out, []byte("\n"))
		for _, line := range lines[:len(lines)-1] {
			var page client.LogPage
			if err := json.Unmarshal(line, &page); err != nil {
				t.Fatal("installed pending page:", err)
			}
			if page.State == client.StateExited && page.Output.State == "pending" && page.After == tailPage.After {
				return true
			}
		}
		return false
	})
	select {
	case <-follower.Done():
		t.Fatal("follower stopped on workload terminal before output End")
	default:
	}
	peer.endOnce.Do(func() { close(peer.end) })
	phase, done := context.WithTimeout(ctx, 20*time.Second)
	err = follower.Wait(phase)
	stopErr := follower.Stop(phase)
	done()
	out, diag, _ := capture.snapshot()
	if err != nil || stopErr != nil || !follower.CleanupComplete() {
		t.Fatalf("installed complete follower: %v %v stderr=%q", err, stopErr, diag)
	}
	assertInstalledCompleteFollow(t, out, wantA)
	outputEventually(t, ctx, "interrupted output committed", func() bool {
		page, err = c.Logs(ctx, second.String(), client.LogOptions{Limit: 1})
		return err == nil && page.Output.State == "truncated"
	})
	gotB, finalB := readInstalledOutput(t, ctx, c, second)
	if !bytes.Equal(gotB, wantB) || finalB.Output.LossReason != pb.OutputReasonExecutorInterrupted || finalB.Output.FinalCursor == nil || *finalB.Output.FinalCursor != finalB.After {
		t.Fatalf("interrupted exact prefix: %d %+v", len(gotB), finalB.Output)
	}
	out, diag, err = runCommand(ctx, assets.CLI, work, cliEnv, "--config", cliConfig, "--output", "json", "logs", "--follow", "--limit", "1", second.String())
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 1 || !bytes.Contains(diag, []byte("executor_interrupted")) {
		t.Fatalf("installed incomplete follower: %v stderr=%q", err, diag)
	}
	assertInstalledIncompleteFollow(t, out, wantB, "truncated", pb.OutputReasonExecutorInterrupted)
	outputEventually(t, ctx, "both receipts persisted", func() bool {
		a, ea := spool.Get(ctx, first)
		b, eb := spool.Get(ctx, second)
		return ea == nil && eb == nil && a.EndAcknowledged && b.EndAcknowledged && a.QueuedFrames == 0 && b.QueuedFrames == 0
	})
	afterA, err := c.Status(ctx, first.String())
	if err != nil || afterA != stateA {
		t.Fatal("output delivery changed immutable terminal")
	}
	afterB, err := c.Status(ctx, second.String())
	if err != nil || afterB != stateB {
		t.Fatal("output delivery invented a terminal after restart")
	}
	if !time.Now().Before(executionB.StartedAt.Add(policyTimeout)) {
		t.Fatal("interrupted work expired before the no-replay observation")
	}
	retainedB, err := executordb.New(executorDB).GetDebugletIdentity(ctx, second)
	if err != nil || !reflect.DeepEqual(retainedB, executionB) {
		t.Fatal("restart replayed or changed interrupted execution")
	}
	for _, entry := range []struct {
		id    uuid.UUID
		saved outputstore.Run
		bytes []byte
	}{{first, savedA, wantA}, {second, savedB, wantB}} {
		row, err := dispatcherdb.New(dispatcherDB).GetDebugletOutput(ctx, entry.id)
		if err != nil || row.CommittedSequence != entry.saved.LastSequence || row.FrameCount != entry.saved.LastSequence || row.ByteCount != int64(len(entry.bytes)) || row.OwnerFingerprint != recordedA.OwnerFingerprint || row.DispatcherIncarnation != entry.saved.Binding.Incarnation || row.SessionID != entry.saved.Binding.SessionID {
			t.Fatalf("replay changed identity or charged duplicate data: %v", err)
		}
	}
	frames := savedA.LastSequence + savedB.LastSequence
	charged := 2*pb.OutputRunCharge + int64(len(wantA)+len(wantB)) + frames*pb.OutputFrameCharge
	accountUsage, err := dispatcherdb.New(dispatcherDB).GetOutputAccountUsage(ctx, recordedA.AccountID)
	if err != nil || accountUsage.ChargedBytes != charged || accountUsage.FrameCount != frames {
		t.Fatalf("replay charged account more than its exact prefix: %+v %v", accountUsage, err)
	}
	nodeUsage, err := dispatcherdb.New(dispatcherDB).GetOutputNodeUsage(ctx)
	if err != nil || nodeUsage.ChargedBytes != charged || nodeUsage.FrameCount != frames {
		t.Fatalf("replay charged node more than its exact prefix: %+v %v", nodeUsage, err)
	}
	helloGuest, err := os.ReadFile(filepath.Join(root, "share", "debuglet", "hello.wasm"))
	if err != nil {
		t.Fatal(err)
	}
	fresh := submit(helloGuest, []string{"after-output-restart"}, nil)
	awaitOutput(t, ctx, c, fresh.String(), hello+"after-output-restart\n")
	// Cancellation must finalize an empty output independently of execution exit.
	due := time.Now().Add(time.Minute).Unix()
	queued := submit(helloGuest, []string{"must-not-start"}, &due)
	if err := c.Cancel(ctx, queued.String(), executorID); err != nil {
		t.Fatal("queued cancellation:", err)
	}
	outputEventually(t, ctx, "queued cancellation output final", func() bool {
		page, err = c.Logs(ctx, queued.String(), client.LogOptions{Limit: 1})
		return err == nil && page.Output.State == "complete"
	})
	if page.After != 0 || len(page.Logs) != 0 || page.Output.FinalCursor == nil || *page.Output.FinalCursor != 0 {
		t.Fatal("queued cancellation fabricated output")
	}
	out, diag, err = runCommand(ctx, assets.CLI, work, cliEnv, "--config", cliConfig, "--output", "json", "logs", "--follow", queued.String())
	if err != nil {
		t.Fatalf("queued installed follow: %v stderr=%q", err, diag)
	}
	assertInstalledCompleteFollow(t, out, nil)
	t.Logf("installed output: source=%s lost_receipt_run=%s interrupted_run=%s complete_bytes=%d interrupted_bytes=%d", assets.Manifest.SourceSHA, first, second, len(wantA), len(wantB))
}

func writeOutputConfig(t *testing.T, path string, value any) {
	t.Helper()
	b, err := toml.Marshal(value)
	if err == nil {
		err = os.WriteFile(path, b, 0600)
	}
	if err != nil {
		t.Fatal(err)
	}
}

func outputEventually(t *testing.T, ctx context.Context, what string, ready func() bool) {
	t.Helper()
	phase, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	tick := time.NewTicker(20 * time.Millisecond)
	defer tick.Stop()
	for !ready() {
		select {
		case <-phase.Done():
			t.Fatalf("%s: %v", what, phase.Err())
		case <-tick.C:
		}
	}
}

func outputFrames(t *testing.T, ctx context.Context, store *outputstore.Store, id uuid.UUID) []byte {
	t.Helper()
	frames, err := store.Frames(ctx, id, 0, 64)
	if err != nil {
		t.Fatal(err)
	}
	var data []byte
	for _, frame := range frames {
		data = append(data, frame.Output...)
	}
	return data
}

func readInstalledOutput(t *testing.T, ctx context.Context, c *client.Client, id uuid.UUID) ([]byte, client.LogPage) {
	t.Helper()
	var data []byte
	var page client.LogPage
	var after int64
	for n := 0; n < 64; n++ {
		var err error
		page, err = c.Logs(ctx, id.String(), client.LogOptions{After: after, Limit: 1})
		if err != nil {
			t.Fatal(err)
		}
		for _, entry := range page.Logs {
			if entry.ID <= after {
				t.Fatal("duplicate log cursor")
			}
			after = entry.ID
			data = append(data, entry.Output...)
		}
		if page.After != after || len(data) > 1<<20 {
			t.Fatal("invalid log page")
		}
		if !page.HasMore {
			return data, page
		}
	}
	t.Fatal("unbounded log pages")
	return nil, page
}

func buildOutputGuest(t *testing.T, ctx context.Context, source, work string) []byte {
	t.Helper()
	path := filepath.Join(work, "output-guest.go")
	wasm := filepath.Join(work, "output-guest.wasm")
	const program = `package main
import("fmt";"os";"strconv";"strings";"github.com/netsec-ethz/debuglet/pkg/debuglet")
func main(){n,_:=strconv.Atoi(os.Args[1]);if _,err:=fmt.Print(strings.Repeat("x",n));err!=nil{return};c,err:=debuglet.ConnectTCP(os.Args[0]);if err!=nil{return};defer c.Close();if err=c.Write([]byte("ready"));err!=nil{return};var b [1]byte;c.Read(b[:])}
`
	if err := os.WriteFile(path, []byte(program), 0600); err != nil {
		t.Fatal(err)
	}
	goPath := os.Getenv("GO")
	if goPath == "" {
		goPath = "go"
	}
	goPath, err := exec.LookPath(goPath)
	if err != nil {
		t.Fatal(err)
	}
	_, diag, err := runCommand(ctx, goPath, source, append(os.Environ(), "GOOS=wasip1", "GOARCH=wasm", "CGO_ENABLED=0"), "build", "-mod=readonly", "-o", wasm, path)
	if err != nil {
		t.Fatalf("compile fixture guest: %v %q", err, diag)
	}
	data, err := os.ReadFile(wasm)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

type outputDaemon struct {
	child    *demo.Child
	output   *capture
	ready    readiness.Record
	identity procinventory.Process
	stopped  bool
}

func startOutputDaemon(t *testing.T, ctx context.Context, binary, work, config, name string) *outputDaemon {
	t.Helper()
	r := &outputDaemon{output: new(capture)}
	readyPath := filepath.Join(work, name+".ready.json")
	var err error
	r.child, err = demo.StartChild(demo.ChildSpec{Path: binary, Dir: work, Env: isolatedEnvironment(work), Args: []string{"-config", config, "-ready-file", readyPath}, Stdout: captureWriter{r.output, true}, Stderr: captureWriter{r.output, false}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if !r.stopped {
			phase, cancel := context.WithTimeout(context.Background(), 8*time.Second)
			defer cancel()
			if err := r.child.Stop(phase); err != nil {
				t.Error("daemon stop:", err)
			}
			r.stopped = true
		}
		if !r.child.CleanupComplete() {
			t.Error("daemon cleanup incomplete")
		}
	})
	outputEventually(t, ctx, name+" readiness", func() bool {
		select {
		case <-r.child.Done():
			_, diagnostics, overflow := r.output.snapshot()
			t.Fatalf("%s exited before readiness (diagnostics truncated=%t): %q", name, overflow, diagnostics)
		default:
		}
		data, err := os.ReadFile(readyPath)
		if err != nil {
			return false
		}
		if len(data) > 4096 || json.Unmarshal(data, &r.ready) != nil || r.ready.SchemaVersion != 1 || r.ready.PID != r.child.PID() {
			t.Fatal("invalid installed readiness record")
		}
		r.identity, err = procinventory.Read(r.child.PID())
		if err != nil {
			t.Fatal(err)
		}
		if r.identity.Executable != binary || r.identity.Parent != os.Getpid() || !procinventory.Live(r.identity) {
			t.Fatal("unexpected owned daemon identity")
		}
		return true
	})
	return r
}
func (r *outputDaemon) kill(t *testing.T, ctx context.Context) {
	t.Helper()
	current, err := procinventory.Read(r.child.PID())
	if err != nil || !procinventory.Same(r.identity, current) || !procinventory.Live(current) {
		t.Fatal("refusing termination of unowned daemon")
	}
	if err := syscall.Kill(current.PID, syscall.SIGKILL); err != nil {
		t.Fatal(err)
	}
	phase, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	err = r.child.Wait(phase)
	var exit *exec.ExitError
	if !errors.As(err, &exit) {
		t.Fatalf("owned SIGKILL wait: %v", err)
	}
	status, ok := exit.Sys().(syscall.WaitStatus)
	if !ok || !status.Signaled() || status.Signal() != syscall.SIGKILL {
		t.Fatalf("unexpected exit: %v", err)
	}
	stopErr := r.child.Stop(phase)
	if errors.Is(stopErr, demo.ErrForcedKill) || errors.Is(stopErr, context.DeadlineExceeded) || !r.child.CleanupComplete() {
		t.Fatalf("owned killed daemon not joined: %v", stopErr)
	}
	r.stopped = true
}

// Every forwarded request retains the original session metadata and enrolled
// executor certificate. Only the two output boundaries below are delayed.
type outputForwarder struct {
	pb.UnimplementedDispatcherServiceServer
	mu                          sync.Mutex
	conn                        *grpc.ClientConn
	client                      pb.DispatcherServiceClient
	ids                         []string
	emitted                     <-chan struct{}
	tail, endSeen, end          chan struct{}
	tailOnce, endOnce, seenOnce sync.Once
}

func (p *outputForwarder) connect(t *testing.T, ca *testtls.Authority, identity *testtls.Identity, address string) {
	t.Helper()
	conn, err := grpc.NewClient(address, grpc.WithTransportCredentials(credentials.NewTLS(ca.ClientConfig(identity, ""))))
	if err != nil {
		t.Fatal(err)
	}
	p.mu.Lock()
	old := p.conn
	p.conn = conn
	p.client = pb.NewDispatcherServiceClient(conn)
	p.mu.Unlock()
	if old != nil {
		old.Close()
	}
}
func (p *outputForwarder) close() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.conn != nil {
		p.conn.Close()
	}
}
func (p *outputForwarder) release() {
	p.tailOnce.Do(func() { close(p.tail) })
	p.endOnce.Do(func() { close(p.end) })
}
func (p *outputForwarder) upstream(ctx context.Context) (context.Context, pb.DispatcherServiceClient) {
	md, _ := metadata.FromIncomingContext(ctx)
	p.mu.Lock()
	defer p.mu.Unlock()
	return metadata.NewOutgoingContext(ctx, md.Copy()), p.client
}
func (p *outputForwarder) DebugletStream(down pb.DispatcherService_DebugletStreamServer) error {
	first, err := down.Recv()
	if err != nil {
		return err
	}
	ident := first.GetIdent()
	if ident == nil {
		return status.Error(codes.InvalidArgument, "identity required")
	}
	p.mu.Lock()
	index := -1
	initial := false
	for i, id := range p.ids {
		if id == ident.DebugletId {
			index = i
			break
		}
	}
	if index < 0 {
		index = len(p.ids)
		p.ids = append(p.ids, ident.DebugletId)
		initial = true
	}
	p.mu.Unlock()
	wait := func(ch <-chan struct{}) error {
		select {
		case <-ch:
			return nil
		case <-down.Context().Done():
			return down.Context().Err()
		}
	}
	if index < 2 && !initial {
		if err := wait(p.tail); err != nil {
			return err
		}
	}
	ctx, client := p.upstream(down.Context())
	up, err := client.DebugletStream(ctx)
	if err != nil {
		return err
	}
	defer up.CloseSend()
	request := first
	for {
		if request.GetOutput() != nil && index == 1 && initial {
			if err := wait(p.tail); err != nil {
				return err
			}
		}
		if request.GetEnd() != nil && index == 0 {
			p.seenOnce.Do(func() { close(p.endSeen) })
			if err := wait(p.end); err != nil {
				return err
			}
		}
		if err := up.Send(request); err != nil {
			return err
		}
		ack, err := up.Recv()
		if err != nil {
			return err
		}
		if request.GetOutput() != nil && index == 0 && initial {
			if err := wait(p.emitted); err != nil {
				return err
			}
			return status.Error(codes.Unavailable, "receipt delivery interrupted")
		}
		if err := down.Send(ack); err != nil {
			return err
		}
		if request.GetEnd() != nil {
			return nil
		}
		request, err = down.Recv()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
	}
}
func (p *outputForwarder) Heartbeat(ctx context.Context, in *pb.HeartbeatRequest) (*pb.HeartbeatResponse, error) {
	ctx, c := p.upstream(ctx)
	return c.Heartbeat(ctx, in)
}
func (p *outputForwarder) Resources(ctx context.Context, in *pb.ResourcesRequest) (*pb.ResourcesResponse, error) {
	ctx, c := p.upstream(ctx)
	return c.Resources(ctx, in)
}
func (p *outputForwarder) DebugletState(ctx context.Context, in *pb.DebugletStateRequest) (*pb.DebugletStateResponse, error) {
	ctx, c := p.upstream(ctx)
	return c.DebugletState(ctx, in)
}
func (p *outputForwarder) DebugletAllocate(ctx context.Context, in *pb.DebugletAllocateRequest) (*pb.DebugletAllocateResponse, error) {
	ctx, c := p.upstream(ctx)
	return c.DebugletAllocate(ctx, in)
}
func (p *outputForwarder) DebugletExit(ctx context.Context, in *pb.DebugletExitRequest) (*pb.DebugletExitResponse, error) {
	ctx, c := p.upstream(ctx)
	return c.DebugletExit(ctx, in)
}
func (p *outputForwarder) BindSession(ctx context.Context, in *pb.BindSessionRequest) (*pb.BindSessionResponse, error) {
	ctx, c := p.upstream(ctx)
	return c.BindSession(ctx, in)
}
func (p *outputForwarder) RenewLease(ctx context.Context, in *pb.RenewLeaseRequest) (*pb.RenewLeaseResponse, error) {
	ctx, c := p.upstream(ctx)
	return c.RenewLease(ctx, in)
}

func assertInstalledIncompleteFollow(t *testing.T, data, want []byte, state, reason string) {
	t.Helper()
	decoder := json.NewDecoder(bytes.NewReader(data))
	var actual []byte
	var last client.LogPage
	for n := 0; n < 256; n++ {
		var page client.LogPage
		err := decoder.Decode(&page)
		if errors.Is(err, io.EOF) {
			if !bytes.Equal(actual, want) || last.Output.State != state || last.Output.LossReason != reason {
				t.Fatal("incomplete follower did not drain retained bytes")
			}
			return
		}
		if err != nil {
			t.Fatal(err)
		}
		for _, entry := range page.Logs {
			actual = append(actual, entry.Output...)
		}
		last = page
	}
	t.Fatal("excessive follower pages")
}
func assertInstalledCompleteFollow(t *testing.T, output, want []byte) {
	t.Helper()
	decoder := json.NewDecoder(bytes.NewReader(output))
	var collected []byte
	var cursor int64
	var last client.LogPage
	pages := 0
	for {
		var page client.LogPage
		err := decoder.Decode(&page)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal("installed follow JSONL", err)
		}
		pages++
		if pages > 256 {
			t.Fatal("excessive sample pages")
		}
		for _, entry := range page.Logs {
			if entry.ID <= cursor {
				t.Fatal("duplicate or backward installed cursor")
			}
			cursor = entry.ID
			collected = append(collected, entry.Output...)
			if len(collected) > 64<<10 {
				t.Fatal("excessive sample output")
			}
		}
		if page.After != cursor {
			t.Fatal("installed page cursor differs from bytes")
		}
		last = page
	}
	if pages == 0 || !bytes.Equal(collected, want) || last.Output.State != "complete" || last.Output.FinalCursor == nil || *last.Output.FinalCursor != cursor || last.Output.LossReason != "" {
		t.Fatalf("installed follower did not drain declared complete prefix: pages=%d cursor=%d output=%q last=%+v", pages, cursor, collected, last)
	}
}
