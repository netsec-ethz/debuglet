//go:build linux && roles_integration

// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package roles

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"syscall"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/netsec-ethz/debuglet/internal/acceptance/procinventory"
	"github.com/netsec-ethz/debuglet/internal/demo"
	dispatcherdb "github.com/netsec-ethz/debuglet/internal/dispatcher/database"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/models"
	executordb "github.com/netsec-ethz/debuglet/internal/executor/database"
	"github.com/netsec-ethz/debuglet/internal/sqlitedb"
	"github.com/netsec-ethz/debuglet/pkg/client"
)

// TestInstalledRecovery starts the installed payload twice against the same
// databases. SIGKILL here means owned daemon process termination, not power loss.
func TestInstalledRecovery(t *testing.T) {
	root, evidence := os.Getenv("DEBUGLET_LOCAL_INSTALL_ROOT"), os.Getenv("DEBUGLET_ROLE_EVIDENCE_DIR")
	if !filepath.IsAbs(root) || !filepath.IsAbs(evidence) {
		t.Fatal("absolute installed and evidence directories are required")
	}
	assets, err := demo.ResolveAssets(filepath.Join(root, "bin", "dbl"))
	if err != nil || assets.Manifest.SourceSHA != os.Getenv("DEBUGLET_LOCAL_SOURCE_SHA") {
		t.Fatalf("installed/source identity: %v", err)
	}
	guest, err := os.ReadFile(filepath.Join(root, "share", "debuglet", "hello.wasm"))
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"graceful", "terminated"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
			defer cancel()
			work, err := os.MkdirTemp(evidence, "recovery-"+mode+"-")
			if err != nil {
				t.Fatal(err)
			}
			var running []*role
			t.Cleanup(func() {
				clean := true
				for i := len(running) - 1; i >= 0; i-- {
					r := running[i]
					if !r.stopped {
						if err := r.stop(); err != nil {
							t.Error("role cleanup:", err)
						}
					}
					clean = clean && r.clean
				}
				if clean {
					if err := os.RemoveAll(work); err != nil {
						t.Error(err)
					}
				} else {
					t.Log("preserving state after incomplete cleanup:", work)
				}
			})
			start := func(kind, endpoint string) *role {
				t.Helper()
				state := filepath.Join(work, kind)
				args := []string{"--config", filepath.Join(work, kind+"-client.json"), "--output", "json", kind, "up", "--name", "recovery", "--state-dir", state}
				if kind == "dispatcher" {
					args = append(args, "--port", "0", "--grpc-port", "0")
				} else {
					args = append(args, "--dispatcher", endpoint)
				}
				r, err := startRole(assets, work, kind, "recovery", state, args)
				if err != nil {
					t.Fatal(err)
				}
				running = append(running, r)
				phase, done := context.WithTimeout(ctx, 20*time.Second)
				defer done()
				if err := r.ready(phase); err != nil {
					_, diag, _ := r.output.snapshot()
					t.Fatalf("%s ready: %v; %q", kind, err, diag)
				}
				return r
			}
			d := start("dispatcher", "")
			e := start("executor", d.record.Endpoint)
			account, err := sdk(t, d.record.Endpoint).CreateAccount(ctx, "recovery owner")
			if err != nil {
				t.Fatal(err)
			}
			login := func(endpoint string) *client.Client {
				t.Helper()
				c := sdk(t, endpoint)
				session, err := c.Login(ctx, account.AccountKey)
				if err != nil || session.ID != account.ID || session.Role != "user" {
					t.Fatalf("same-account login: %v", err)
				}
				c, err = c.WithCredential(session.Token)
				if err != nil {
					t.Fatal(err)
				}
				return c
			}
			c := login(d.record.Endpoint)
			keyFile := filepath.Join(work, "account-key.txt")
			if err := os.WriteFile(keyFile, []byte(account.AccountKey), 0600); err != nil {
				t.Fatal(err)
			}
			due := time.Now().Add(30 * time.Second).Truncate(time.Second)
			startTime := due.Unix()
			request := client.Request{OrderID: 1, ExecutorID: e.record.ExecutorID, StartTimestamp: &startTime, Wasm: guest, Args: []string{"must-not-replay"}, Policy: client.Policy{FloorBW: 1000, CeilBW: 1000, TimeoutMS: 120000}}
			prepared, err := client.Prepare([]client.Request{request})
			if err != nil {
				t.Fatal(err)
			}
			submitted, err := c.SubmitTEST(ctx, prepared)
			if err != nil || len(submitted.IDs) != 1 {
				t.Fatalf("acknowledged submission: %+v %v", submitted, err)
			}
			id := uuid.MustParse(submitted.IDs[0])
			before := recoverySnapshot(t, ctx, d.state, e.state, id)
			if before.Owner.String() != account.ID || before.Run.State != models.RunStateUploaded || !before.Executor.StartedAt.IsZero() || before.Run.TransactionID != submitted.TransactionID || before.Executor.TransactionID != submitted.TransactionID || before.Run.DispatcherIncarnation == "" || before.Run.SessionID == "" || before.Run.DispatcherIncarnation != before.Executor.DispatcherIncarnation || before.Run.SessionID != before.Executor.SessionID {
				t.Fatalf("owned committed queued rows not established: state=%q started=%v", before.Run.State, !before.Executor.StartedAt.IsZero())
			}
			dbIdentity := make(map[string]os.FileInfo)
			for _, r := range []*role{d, e} {
				path := filepath.Join(r.state, r.kind+".sqlite")
				info, err := os.Stat(path)
				if err != nil {
					t.Fatal(err)
				}
				dbIdentity[path] = info
			}
			for _, r := range []*role{e, d} {
				if mode == "graceful" {
					if err := r.stop(); err != nil {
						t.Fatal("graceful stop:", err)
					}
				} else {
					terminateRecoveryRole(t, ctx, r)
				}
			}
			if !time.Now().Before(due) {
				t.Fatal("queued due time passed before both first processes stopped")
			}
			timer := time.NewTimer(time.Until(due.Add(100 * time.Millisecond)))
			select {
			case <-ctx.Done():
				timer.Stop()
				t.Fatal(ctx.Err())
			case <-timer.C:
			}
			d = start("dispatcher", "")
			e = start("executor", d.record.Endpoint)
			if e.record.ExecutorID != request.ExecutorID {
				t.Fatal("restart replaced executor identity")
			}
			for path, old := range dbIdentity {
				info, err := os.Stat(path)
				if err != nil || !os.SameFile(old, info) {
					t.Fatalf("restart replaced retained database %s: %v", path, err)
				}
			}
			c = login(d.record.Endpoint)
			restarted := recoverySnapshot(t, ctx, d.state, e.state, id)
			if !reflect.DeepEqual(before, restarted) {
				t.Fatal("restart changed the retained run or its accounting")
			}
			doc, err := c.Recovery(ctx, id.String())
			if err != nil {
				t.Fatal(err)
			}
			if doc.ControlStatus != "unavailable" || doc.Observation.Classification != "retained_unstarted" || doc.Observation.Observer == nil || doc.Observation.CurrentAtCheck == nil || !*doc.Observation.CurrentAtCheck || doc.Observation.ReceivedAt == nil || doc.Observation.Retained == nil || doc.Observation.Retained.Started {
				t.Fatalf("restart not conservatively classified: %+v", doc)
			}
			if doc.OriginalBinding.DispatcherIncarnation != before.Run.DispatcherIncarnation || doc.OriginalBinding.SessionID != before.Run.SessionID || doc.Observation.Observer.Binding.DispatcherIncarnation == before.Run.DispatcherIncarnation || doc.Observation.Observer.Binding.SessionID == before.Run.SessionID {
				t.Fatalf("restart failed to distinguish control identities: %+v", doc)
			}
			clientConfig := filepath.Join(work, "client", "config.json")
			for _, args := range [][]string{
				{"connect", d.record.Endpoint, "--name", "recovery"},
				{"login", "--account-key-file", keyFile},
			} {
				args = append([]string{"--config", clientConfig}, args...)
				if _, _, err := runCommand(ctx, assets.CLI, work, isolatedEnvironment(work), args...); err != nil {
					t.Fatalf("installed owner connection: %v", err)
				}
			}
			out, diag, err := runCommand(ctx, assets.CLI, work, isolatedEnvironment(work), "--config", clientConfig, "--output", "json", "recovery", id.String())
			var cliDoc client.RecoveryDocument
			if err != nil || decode(out, &cliDoc) != nil || cliDoc.Observation.Classification != "retained_unstarted" {
				t.Fatalf("installed recovery CLI: %v; stdout=%q stderr=%q", err, out, diag)
			}
			if after := recoverySnapshot(t, ctx, d.state, e.state, id); !reflect.DeepEqual(restarted, after) {
				t.Fatal("inspection changed stored state, metadata, logs, orders or payments")
			}
			request.StartTimestamp = nil
			request.Args = []string{"after-recovery"}
			request.Policy.TimeoutMS = 2000
			prepared, err = client.Prepare([]client.Request{request})
			if err != nil {
				t.Fatal(err)
			}
			fresh, err := c.SubmitTEST(ctx, prepared)
			if err != nil || len(fresh.IDs) != 1 || fresh.IDs[0] == id.String() {
				t.Fatalf("fresh submission: %+v %v", fresh, err)
			}
			awaitOutput(t, ctx, c, fresh.IDs[0], hello+"after-recovery\n")
			final := recoverySnapshot(t, ctx, d.state, e.state, id)
			if !reflect.DeepEqual(final.Run, before.Run) || !reflect.DeepEqual(final.Executor, before.Executor) || final.DispatcherLogs != 0 || final.ExecutorLogs != 0 || final.ExecutorExits != 0 {
				t.Fatal("old run replayed or changed after fresh work")
			}
			for _, r := range []*role{e, d} {
				if err := r.stop(); err != nil {
					t.Fatal(err)
				}
			}
			report := struct {
				SourceSHA, Mode, RetainedID, FreshID string
				Observation                          client.RecoveryDocument
				Passed                               bool
			}{assets.Manifest.SourceSHA, mode, id.String(), fresh.IDs[0], doc, true}
			data, err := json.MarshalIndent(report, "", "  ")
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(evidence, "recovery-"+mode+".json"), append(data, '\n'), 0600); err != nil {
				t.Fatal(err)
			}
			t.Logf("%s: acknowledged run %s retained without replay, fresh run %s completed, all children joined", mode, id, fresh.IDs[0])
		})
	}
}

type recoveryStored struct {
	Owner                                       uuid.UUID
	Run                                         dispatcherdb.Debuglet
	Executor                                    executordb.GetDebugletIdentityRow
	Transaction                                 dispatcherdb.Transaction
	Orders                                      []dispatcherdb.DebugletOrder
	Earnings                                    []dispatcherdb.Earning
	DispatcherLogs, ExecutorLogs, ExecutorExits int
}

func recoverySnapshot(t *testing.T, ctx context.Context, dispatcherState, executorState string, id uuid.UUID) recoveryStored {
	t.Helper()
	db, err := sqlitedb.Open(filepath.Join(dispatcherState, "dispatcher.sqlite"), sqlitedb.ReadOnly())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	eb, err := sqlitedb.Open(filepath.Join(executorState, "executor.sqlite"), sqlitedb.ReadOnly())
	if err != nil {
		t.Fatal(err)
	}
	defer eb.Close()
	q := dispatcherdb.New(db)
	var result recoveryStored
	result.Owner, err = q.GetDebugletOwnerUUID(ctx, id)
	if err != nil {
		t.Fatal("retained run owner:", err)
	}
	result.Run, err = q.GetDebugletByUUID(ctx, id)
	if err != nil {
		t.Fatal("dispatcher retained row:", err)
	}
	result.Executor, err = executordb.New(eb).GetDebugletIdentity(ctx, id)
	if err != nil {
		t.Fatal("executor retained row:", err)
	}
	result.Transaction, err = q.GetTransactionByID(ctx, result.Run.TransactionID)
	if err != nil {
		t.Fatal(err)
	}
	result.Orders, err = q.GetTransactionOrders(ctx, result.Run.TransactionID)
	if err != nil {
		t.Fatal(err)
	}
	result.Earnings, err = q.GetEarnings(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRowContext(ctx, "SELECT count(*) FROM debuglet_logs WHERE debuglet_id=?", result.Run.ID).Scan(&result.DispatcherLogs); err != nil {
		t.Fatal(err)
	}
	if err := eb.QueryRowContext(ctx, "SELECT count(*) FROM debuglet_logs l JOIN debuglets d ON l.debuglet_id=d.id WHERE d.uuid=?", id).Scan(&result.ExecutorLogs); err != nil {
		t.Fatal(err)
	}
	if err := eb.QueryRowContext(ctx, "SELECT count(*) FROM debuglet_exits WHERE debuglet_id=?", id.String()).Scan(&result.ExecutorExits); err != nil {
		t.Fatal(err)
	}
	return result
}

// terminateRecoveryRole kills only the daemon identity recorded at readiness.
// Its live CLI must reap it and exit; this is not a cleanup fallback signal.
func terminateRecoveryRole(t *testing.T, ctx context.Context, r *role) {
	t.Helper()
	if len(r.owned) != 1 {
		t.Fatal("termination needs exactly one independently observed daemon")
	}
	for _, owned := range r.owned {
		current, err := procinventory.Read(owned.PID)
		if err != nil || !procinventory.Same(owned, current) || !procinventory.Live(current) {
			t.Fatalf("daemon ownership changed before termination: %v", err)
		}
		if err := syscall.Kill(owned.PID, syscall.SIGKILL); err != nil {
			t.Fatal(err)
		}
	}
	phase, done := context.WithTimeout(ctx, 10*time.Second)
	defer done()
	err := r.child.Wait(phase)
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 1 {
		t.Fatalf("supervisor did not report the terminated daemon: %v", err)
	}
	cleanup := r.child.Stop(phase)
	if cleanup != nil && (errors.Is(cleanup, demo.ErrForcedKill) || errors.Is(cleanup, context.DeadlineExceeded) || !errors.As(cleanup, &exit) || exit.ExitCode() != 1) {
		t.Fatalf("join terminated role: %v", cleanup)
	}
	if !r.child.CleanupComplete() {
		t.Fatal("terminated role supervisor was not reaped")
	}
	for _, owned := range r.owned {
		if alive(owned) || !errors.Is(syscall.Kill(-owned.Group, 0), syscall.ESRCH) {
			t.Fatal("terminated daemon was not reaped")
		}
	}
	for _, name := range []string{"ready.json", "child-ready.json"} {
		if _, err := os.Lstat(filepath.Join(r.state, name)); !os.IsNotExist(err) {
			t.Fatal("terminated role retained readiness")
		}
	}
	if r.kind == "dispatcher" {
		for _, address := range []string{r.record.YamuxAddress, r.record.GRPCAddress} {
			conn, err := net.DialTimeout("tcp", address, 100*time.Millisecond)
			if err == nil {
				conn.Close()
				t.Fatal("terminated dispatcher listener remains")
			}
		}
	}
	r.stopped, r.clean = true, true
}
