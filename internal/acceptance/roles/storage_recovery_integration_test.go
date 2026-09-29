// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

//go:build linux && roles_integration

package roles

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/netsec-ethz/debuglet/internal/demo"
	executordb "github.com/netsec-ethz/debuglet/internal/executor/database"
	"github.com/netsec-ethz/debuglet/internal/storagecheck"
	"github.com/netsec-ethz/debuglet/pkg/client"
	"golang.org/x/sys/unix"
)

// This is an installed backup-destination failure drill, not a live database
// fault. The dedicated runner must provide a private bounded tmpfs.
func TestInstalledStorageRecovery(t *testing.T) {
	for _, attempt := range []string{"first", "second", "third"} {
		if !t.Run(attempt, storageRecoveryDrill) {
			break
		}
	}
}

func storageRecoveryDrill(t *testing.T) {
	install := os.Getenv("DEBUGLET_LOCAL_INSTALL_ROOT")
	assets, err := demo.ResolveAssets(filepath.Join(install, "bin", "dbl"))
	if !filepath.IsAbs(install) || err != nil || assets.Manifest.SourceSHA != os.Getenv("DEBUGLET_LOCAL_SOURCE_SHA") {
		t.Fatalf("exact installed package required: %v", err)
	}
	volume := os.Getenv("DEBUGLET_STORAGE_DRILL_ROOT")
	var fs unix.Statfs_t
	if !filepath.IsAbs(volume) || unix.Statfs(volume, &fs) != nil || fs.Type != unix.TMPFS_MAGIC || fs.Bsize <= 0 || fs.Blocks > (16<<20)/uint64(fs.Bsize) {
		t.Fatal("DEBUGLET_STORAGE_DRILL_ROOT must be an owned private tmpfs of at most 16 MiB")
	}
	backups, err := os.MkdirTemp(volume, "storage-recovery-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(backups); err != nil {
			t.Error(err)
		}
	})
	ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	defer cancel()
	work := t.TempDir()
	if err := os.Chmod(work, 0700); err != nil {
		t.Fatal(err)
	}
	cliArgs := func(args ...string) []string {
		return append([]string{"--config", filepath.Join(work, "client.json"), "--output", "json"}, args...)
	}
	cli := func(args ...string) []byte {
		t.Helper()
		out, diagnostic, err := runCommand(ctx, assets.CLI, work, isolatedEnvironment(work), cliArgs(args...)...)
		if err != nil {
			t.Fatalf("%s: %v; stdout=%q stderr=%q", args[0], err, out, diagnostic)
		}
		return out
	}
	var owned []*role
	start := func(kind, state, endpoint string) *role {
		t.Helper()
		args := []string{"--config", filepath.Join(work, kind+".json"), "--output", "json", kind, "up", "--name", kind, "--state-dir", state}
		if kind == "dispatcher" {
			args = append(args, "--port", "0", "--grpc-port", "0")
		} else {
			args = append(args, "--dispatcher", endpoint)
		}
		r, err := startRole(assets, work, kind, kind, state, args)
		if err != nil {
			t.Fatal(err)
		}
		owned = append(owned, r)
		t.Cleanup(func() {
			if !r.stopped {
				if err := r.stop(); err != nil {
					t.Error("role cleanup:", err)
				}
			}
		})
		phase, done := context.WithTimeout(ctx, 20*time.Second)
		defer done()
		if err := r.ready(phase); err != nil {
			_, diagnostic, _ := r.output.snapshot()
			t.Fatalf("%s startup: %v; %s", kind, err, diagnostic)
		}
		return r
	}
	stop := func(r *role) {
		t.Helper()
		if err := r.stop(); err != nil {
			t.Fatal(err)
		}
	}
	submit := func(endpoint, argument string) uuid.UUID {
		t.Helper()
		var receipt struct {
			ID            string `json:"id"`
			TransactionID string `json:"transaction_id"`
			ExecutorID    string `json:"executor_id"`
			State         string `json:"state"`
			Error         string `json:"error"`
		}
		if err := decode(cli("run", "--sample", "hello", "--wait", "--", argument), &receipt); err != nil || !validID(receipt.ID) || receipt.State != client.StateExited || receipt.Error != "" {
			t.Fatalf("fresh measurement: %+v, %v", receipt, err)
		}
		awaitOutput(t, ctx, sdk(t, endpoint), receipt.ID, hello+argument+"\n")
		return uuid.MustParse(receipt.ID)
	}

	d := start("dispatcher", filepath.Join(work, "original-dispatcher"), "")
	cli("connect", d.record.Endpoint, "--name", "drill")
	e := start("executor", filepath.Join(work, "original-executor"), d.record.Endpoint)
	first := submit(d.record.Endpoint, "before-snapshot")
	wasm, err := os.ReadFile(filepath.Join(install, "share", "debuglet", "hello.wasm"))
	if err != nil {
		t.Fatal(err)
	}
	queuedAt := time.Now().Add(10 * time.Second).Unix()
	batch, err := client.Prepare([]client.Request{{ExecutorID: e.record.ExecutorID, StartTimestamp: &queuedAt, Wasm: wasm,
		Policy: client.Policy{FloorBW: 1, CeilBW: 10, TimeoutMS: 120000, Addresses: []string{"127.0.0.1"}}}})
	if err != nil {
		t.Fatal(err)
	}
	accepted, err := sdk(t, d.record.Endpoint).SubmitTEST(ctx, batch)
	if err != nil || len(accepted.IDs) != 1 {
		t.Fatalf("real queued submission: %+v, %v", accepted, err)
	}
	queuedID := uuid.MustParse(accepted.IDs[0])
	stop(e)
	stop(d)
	oldBinding := storedBinding(t, d.state, first)
	retained := seedRetained(t, e.state, oldBinding, wasm)
	db := backupDB(t, e.state, storagecheck.Executor)
	queued, err := executordb.New(db).GetDebugletByUUID(ctx, queuedID)
	closeErr := db.Close()
	if err != nil || closeErr != nil || !queued.StartedAt.IsZero() || queued.DispatcherIncarnation != oldBinding.Incarnation || queued.SessionID != oldBinding.SessionID {
		t.Fatalf("accepted queued row did not remain queued at shutdown: %v, %v", err, closeErr)
	}
	retained.runs = append(retained.runs, queued)
	assertRetained(t, e.state, retained)
	snapshotAt := time.Now()
	for _, original := range []*role{d, e} {
		var manifest demo.BackupManifest
		if err := decode(cli("backup", "--state-dir", original.state, "--destination", filepath.Join(backups, original.kind), "--offline"), &manifest); err != nil {
			t.Fatal(err)
		}
		if original == d || manifest.ObservedAt.Before(snapshotAt) {
			snapshotAt = manifest.ObservedAt
		}
	}
	goodFiles := storageDrillFiles(t, backups)
	d1 := start("dispatcher", d.state, "")
	cli("connect", d1.record.Endpoint, "--name", "drill")
	e1 := start("executor", e.state, d1.record.Endpoint)
	afterSnapshot := submit(d1.record.Endpoint, "after-snapshot")
	stop(e1)
	stop(d1)
	// Only this disposable source database grows. The copy fails on the private
	// tmpfs after the previous backups have already been published there.
	db = backupDB(t, e.state, storagecheck.Executor)
	_, writeErr := db.ExecContext(ctx, "CREATE TABLE recovery_pressure(data BLOB); INSERT INTO recovery_pressure VALUES(zeroblob(?))", fs.Blocks*uint64(fs.Bsize)+4096)
	closeErr = db.Close()
	if writeErr != nil || closeErr != nil {
		t.Fatalf("prepare bounded storage pressure: %v, %v", writeErr, closeErr)
	}
	failureStart := time.Now()
	out, diagnostic, err := runCommand(ctx, assets.CLI, work, isolatedEnvironment(work), cliArgs("backup", "--state-dir", e.state, "--destination", filepath.Join(backups, "failed"), "--offline")...)
	detectedAt := time.Now()
	if !storageDrillExitFailure(err) || len(out) != 0 || !bytes.Contains(diagnostic, []byte("write ")) || !bytes.Contains(diagnostic, []byte("no space left on device")) {
		t.Fatalf("wanted joined CLI backup-copy ENOSPC: %v; stdout=%q stderr=%q", err, out, diagnostic)
	}
	if !reflect.DeepEqual(goodFiles, storageDrillFiles(t, backups)) {
		t.Fatal("failed backup changed the last-valid backups or left staging")
	}
	restoreStart := time.Now()
	for _, kind := range []string{"dispatcher", "executor"} {
		cli("restore", "--backup", filepath.Join(backups, kind), "--state-dir", filepath.Join(work, "restored-"+kind))
	}
	copyElapsed := time.Since(restoreStart)
	d2 := start("dispatcher", filepath.Join(work, "restored-dispatcher"), "")
	cli("connect", d2.record.Endpoint, "--name", "drill")
	e2 := start("executor", filepath.Join(work, "restored-executor"), d2.record.Endpoint)
	if e2.record.ExecutorID != e.record.ExecutorID {
		t.Fatal("restoration changed persistent executor identity")
	}
	c := sdk(t, d2.record.Endpoint)
	assertStatus(t, ctx, c, first.String(), e2.record.ExecutorID)
	awaitOutput(t, ctx, c, first.String(), hello+"before-snapshot\n")
	var unavailable *client.HTTPError
	if _, err := c.Status(ctx, afterSnapshot.String()); !errors.As(err, &unavailable) || unavailable.StatusCode != 404 {
		t.Fatalf("post-snapshot run unexpectedly restored: %v", err)
	}
	fresh := submit(d2.record.Endpoint, "after-restore")
	restoreElapsed := time.Since(restoreStart)
	// Observe the accepted run after its scheduled start while the restored
	// executor is still serving. This wait is outside the recovery timing.
	if remaining := time.Until(time.Unix(queuedAt, 0)); remaining > 0 {
		timer := time.NewTimer(remaining)
		defer timer.Stop()
		select {
		case <-timer.C:
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
	}
	submit(d2.record.Endpoint, "quarantine-checkpoint")
	stop(e2)
	stop(d2)
	assertRetained(t, e.state, retained)
	assertRetained(t, e2.state, retained)
	newBinding := storedBinding(t, d2.state, fresh)
	if newBinding.Incarnation == oldBinding.Incarnation || newBinding.SessionID == oldBinding.SessionID {
		t.Fatal("restored measurement reused old control authority")
	}
	for _, r := range owned {
		if !r.stopped || !r.clean {
			t.Fatal("owned role did not join")
		}
	}
	report := map[string]any{
		"source_sha": assets.Manifest.SourceSHA, "version": assets.Manifest.Version,
		"failure": "backup_destination_enospc", "detection_ms": detectedAt.Sub(failureStart).Milliseconds(),
		"snapshot_age_ms": detectedAt.Sub(snapshotAt).Milliseconds(), "restore_copy_ms": copyElapsed.Milliseconds(),
		"restored_measurement_ms": restoreElapsed.Milliseconds(), "first_run": first.String(),
		"accepted_queued_run": queuedID.String(), "lost_post_snapshot_run": afterSnapshot.String(),
		"fresh_run": fresh.String(), "roles_joined": true,
	}
	data, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("storage_recovery %s", data)
}

func storageDrillExitFailure(err error) bool {
	if joined, ok := err.(interface{ Unwrap() []error }); ok {
		for _, cause := range joined.Unwrap() {
			if !storageDrillExitFailure(cause) {
				return false
			}
		}
		return true
	}
	var exit *exec.ExitError
	return errors.As(err, &exit) && exit.ExitCode() == 1
}

func storageDrillFiles(t *testing.T, root string) map[string][32]byte {
	t.Helper()
	files := make(map[string][32]byte)
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			if path != root {
				files[path] = [32]byte{}
			}
			return nil
		}
		data, err := os.ReadFile(path)
		if err == nil {
			files[path] = sha256.Sum256(data)
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return files
}
