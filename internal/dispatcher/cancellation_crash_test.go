// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package dispatcher

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/config"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/database"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/models"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/payments"
	"github.com/netsec-ethz/debuglet/internal/sqlitedb"
	"go.uber.org/zap"
)

// The child uses the real control peer and synchronous SQLite. The parent kills
// it at each persisted boundary and opens its file in a new dispatcher lifetime.
func TestCancellationCrashBoundaries(t *testing.T) {
	type checkpoint struct {
		File    string
		Run     uuid.UUID
		Request string
		Aborts  int
	}
	if phase := os.Getenv("DEBUGLET_CANCELLATION_PHASE"); phase != "" {
		peer := &tgPeer{}
		f := newTGFixture(t, peer)
		cleanupExec(t, f, "PRAGMA synchronous=FULL")
		run, err := f.submit(t, tgFloorA)
		if err != nil {
			t.Fatal(err)
		}
		switch phase {
		case "requested":
			cleanupExec(t, f, `CREATE TRIGGER cancel_boundary BEFORE UPDATE OF attempted_at ON debuglet_cancellations BEGIN SELECT RAISE(ABORT, 'stop before delivery'); END`)
		case "reply_not_recorded":
			cleanupExec(t, f, `CREATE TRIGGER cancel_boundary BEFORE UPDATE OF acknowledged_at ON debuglet_cancellations BEGIN SELECT RAISE(ABORT, 'stop before ACK commit'); END`)
		case "acknowledged":
			f.installTrigger(t)
		default:
			t.Fatal("unknown phase")
		}
		if err := f.abort(t, run.id, "original cancellation"); err == nil {
			t.Fatal("expected boundary failure")
		}
		record, err := f.q.GetCancellation(f.ctx, run.row.ID)
		if err != nil {
			t.Fatal(err)
		}
		var seq int64
		var name, file string
		if err := f.db.QueryRowContext(f.ctx, "PRAGMA database_list").Scan(&seq, &name, &file); err != nil {
			t.Fatal(err)
		}
		data, _ := json.Marshal(checkpoint{file, run.id, record.RequestID, len(peer.recordedAborts())})
		if err := os.WriteFile(os.Getenv("DEBUGLET_CANCELLATION_CHECKPOINT"), data, 0600); err != nil {
			t.Fatal(err)
		}
		fmt.Println("cancellation checkpoint committed")
		<-f.ctx.Done()
		t.Fatal("parent did not kill checkpoint child")
	}
	for _, phase := range []string{"requested", "reply_not_recorded", "acknowledged"} {
		t.Run(phase, func(t *testing.T) {
			dir := t.TempDir()
			marker := filepath.Join(dir, "checkpoint.json")
			ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestCancellationCrashBoundaries$", "-test.timeout=25s")
			cmd.Env = append(os.Environ(), "TMPDIR="+dir, "DEBUGLET_CANCELLATION_PHASE="+phase, "DEBUGLET_CANCELLATION_CHECKPOINT="+marker)
			output, err := cmd.StdoutPipe()
			if err != nil {
				t.Fatal(err)
			}
			cmd.Stderr = os.Stderr
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			reached := make(chan bool, 1)
			readDone := make(chan struct{})
			go func() {
				defer close(readDone)
				scanner := bufio.NewScanner(output)
				sent := false
				for scanner.Scan() {
					if scanner.Text() == "cancellation checkpoint committed" {
						reached <- true
						sent = true
					}
				}
				if !sent {
					reached <- false
				}
			}()
			ready := <-reached // CommandContext bounds both the child and this pipe.
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
			<-readDone
			if !ready {
				t.Fatal("child failed before committed checkpoint")
			}
			data, err := os.ReadFile(marker)
			if err != nil {
				t.Fatal(err)
			}
			var saved checkpoint
			if err := json.Unmarshal(data, &saved); err != nil {
				t.Fatal(err)
			}
			wantAborts := 1
			if phase == "requested" {
				wantAborts = 0
			}
			if saved.Aborts != wantAborts {
				t.Fatalf("delivered %d, want %d", saved.Aborts, wantAborts)
			}
			db, err := sqlitedb.Open(saved.File)
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			logger := zap.NewNop()
			ph := payments.NewPaymentHandler(db, &config.DispatcherConfig{Sui: config.SuiConfig{Disabled: true}}, logger)
			d, err := New(logger, db, "cancel-restart", time.Minute, time.Minute, ph)
			if err != nil {
				t.Fatal(err)
			}
			defer d.Close()
			if err := d.RestoreScheduler(ctx); err != nil {
				t.Fatal(err)
			}
			doc, err := d.Cancellation(ctx, saved.Run)
			if err != nil || doc.RequestID != saved.Request || doc.State != models.RunStateUploaded.String() {
				t.Fatalf("restored request: %+v, %v", doc, err)
			}
			if (doc.AcknowledgedAt != nil) != (phase == "acknowledged") {
				t.Fatalf("invented/lost ACK: %+v", doc)
			}
			if phase != "acknowledged" && (doc.Disposition != "unresolved" || doc.Reason != "original_binding_unavailable") {
				t.Fatalf("uncertainty lost: %+v", doc)
			}
			if _, err := db.ExecContext(ctx, "DROP TRIGGER IF EXISTS cancel_boundary"); err != nil {
				t.Fatal(err)
			}
			if _, err := db.ExecContext(ctx, "DROP TRIGGER IF EXISTS "+tgTrigger); err != nil {
				t.Fatal(err)
			}
			if err := d.AbortDebuglet(ctx, tgExecutorID, saved.Run, "replacement reason"); err != nil {
				t.Fatal(err)
			}
			row, err := database.New(db).GetDebugletByUUID(ctx, saved.Run)
			if err != nil || row.State != models.RunStateExited || !strings.HasPrefix(row.Error.String, "original cancellation") {
				t.Fatalf("retry result: %+v, %v", row, err)
			}
			if strings.Contains(row.Error.String, unobservedCancellation) == (phase == "acknowledged") {
				t.Fatalf("remote disposition changed: %s", row.Error.String)
			}
			after, err := d.Cancellation(ctx, saved.Run)
			if err != nil || after.RequestID != saved.Request || (after.AcknowledgedAt != nil) != (phase == "acknowledged") {
				t.Fatalf("retry rewrote request: %+v, %v", after, err)
			}
		})
	}
}
