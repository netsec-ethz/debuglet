// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package executor

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/netsec-ethz/debuglet/internal/controlsession"
	"github.com/netsec-ethz/debuglet/internal/executor/outputstore"
	"github.com/netsec-ethz/debuglet/internal/executor/scheduler"
	"github.com/netsec-ethz/debuglet/internal/executor/scheduler/sqlite"
	pb "github.com/netsec-ethz/debuglet/protocol"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
)

// A real admission transaction fails before acceptance and leaves no run. Its
// normal diagnostic carries the stage, never the database's arbitrary text.
func TestUploadAdmissionDiagnostic(t *testing.T) {
	db := newFixtureDatabase(t)
	output, err := outputstore.New(db, outputstore.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	storage, err := sqlite.NewStorage(db, output, func(controlsession.Binding) bool { return true }, fixtureAdmission(), scheduler.DefaultQueueLimits())
	if err != nil {
		t.Fatal(err)
	}
	e, _ := newExecutorRPCFixture(t, newOperationPeer(), storage)
	e.outputVersion.Store(pb.OutputVersion)
	core, logs := observer.New(zap.InfoLevel)
	e.logger = zap.New(core)
	if _, err := db.Exec(`CREATE TRIGGER fail_admission BEFORE INSERT ON debuglets BEGIN SELECT RAISE(ABORT, 'private-sql-secret'); END`); err != nil {
		t.Fatal(err)
	}
	req := boundsUploadRequest()
	if _, err := e.OnUpload(t.Context(), operationBinding(), req); err == nil {
		t.Fatal("failed persistence was accepted")
	}
	entries := logs.FilterMessage("Run admission failed").All()
	if len(entries) != 1 {
		t.Fatalf("got %d admission failure events", len(entries))
	}
	fields := entries[0].ContextMap()
	if fields["upload_stage"] != "scheduler_admission" || fields["grpc_code"] != "Unknown" || fields["context_code"] != "OK" || fields["run_id"] != req.Id || fields["session_id"] != operationBinding().SessionID || fields["request_id"] != "unknown" {
		t.Fatalf("admission diagnostic = %v", fields)
	}
	if strings.Contains(fmt.Sprint(fields), "private-sql-secret") || logs.FilterMessage("Run accepted").Len() != 0 {
		t.Fatal("failed admission leaked SQL text or claimed acceptance")
	}
	var stored int
	if err := db.QueryRow("SELECT COUNT(*) FROM debuglets WHERE uuid = ?", req.Id).Scan(&stored); err != nil || stored != 0 {
		t.Fatalf("failed admission stored %d runs: %v", stored, err)
	}
	if err := db.QueryRow("SELECT COUNT(*) FROM output_runs WHERE run_id = ?", req.Id).Scan(&stored); err != nil || stored != 0 {
		t.Fatalf("failed admission stored %d outputs: %v", stored, err)
	}
}

func TestUploadAdmissionContextDiagnostic(t *testing.T) {
	db := newFixtureDatabase(t)
	storage := newFixtureStorage(t, db, func(controlsession.Binding) bool { return true })
	e, _ := newExecutorRPCFixture(t, newOperationPeer(), storage)
	core, logs := observer.New(zap.InfoLevel)
	e.logger = zap.New(core)
	// The one database connection is occupied: admission must wait for the
	// caller's budget, without fabricating a storage-transaction timeout.
	conn, err := db.Conn(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Millisecond)
	defer cancel()
	if _, err := e.OnUpload(ctx, operationBinding(), boundsUploadRequest()); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("blocked admission = %v, want caller deadline", err)
	}
	entries := logs.FilterMessage("Run admission failed").All()
	if len(entries) != 1 || entries[0].ContextMap()["grpc_code"] != "DeadlineExceeded" || entries[0].ContextMap()["context_code"] != "DeadlineExceeded" || entries[0].ContextMap()["upload_stage"] != "scheduler_admission" {
		t.Fatalf("caller deadline diagnostic = %v", entries)
	}
}
