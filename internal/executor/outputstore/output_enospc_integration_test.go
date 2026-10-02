// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

//go:build linux && output_integration

package outputstore

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"syscall"
	"testing"
	"time"

	"github.com/netsec-ethz/debuglet/internal/executor/database"
	"github.com/netsec-ethz/debuglet/internal/sqlitedb"
	"github.com/netsec-ethz/debuglet/internal/storageheadroom"
	pb "github.com/netsec-ethz/debuglet/protocol"
	"golang.org/x/sys/unix"
)

// TestSpoolPhysicalDiskFullPreservesCommittedPrefix requires an explicitly
// supplied, private small container tmpfs. It never fills an ordinary filesystem.
func TestSpoolPhysicalDiskFullPreservesCommittedPrefix(t *testing.T) {
	root := os.Getenv("DEBUGLET_OUTPUT_ENOSPC_ROOT")
	if !filepath.IsAbs(root) {
		t.Fatal("absolute private DEBUGLET_OUTPUT_ENOSPC_ROOT required")
	}
	var fs unix.Statfs_t
	if err := unix.Statfs(root, &fs); err != nil {
		t.Fatal(err)
	}
	if fs.Type != unix.TMPFS_MAGIC || fs.Blocks == 0 || fs.Blocks*uint64(fs.Bsize) > 16<<20 {
		t.Fatal("requires private tmpfs no larger than 16 MiB")
	}
	dir, err := os.MkdirTemp(root, "output-full-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	path := filepath.Join(dir, "spool.sqlite")
	db, err := sqlitedb.Open(path, sqlitedb.Create())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if _, err := sqlitedb.Migrate(t.Context(), db, database.MigrationFS(), sqlitedb.Latest); err != nil {
		t.Fatal(err)
	}
	limits := DefaultLimits()
	limits.ControlReserveBytes = 4096
	s, err := New(db, limits)
	if err != nil {
		t.Fatal(err)
	}
	id := admit(t, s)
	appendFrame(t, s, id, "prefix")
	before, err := s.Get(t.Context(), id)
	if err != nil {
		t.Fatal(err)
	}
	charged, err := database.New(db).GetOutputUsage(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	fillerPath := filepath.Join(dir, "filler")
	filler, err := os.OpenFile(fillerPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	block := make([]byte, 64<<10)
	for err == nil {
		_, err = filler.Write(block)
	}
	closeErr := filler.Close()
	if !errors.Is(err, syscall.ENOSPC) {
		t.Fatalf("no physical ENOSPC: %v", err)
	}
	if closeErr != nil {
		t.Fatal(closeErr)
	}
	// The headroom guard refuses this payload before attempting a database write.
	_, err = s.Append(t.Context(), id, time.Now().UTC(), bytes.Repeat([]byte("x"), pb.MaxOutputFrameBytes))
	if !errors.Is(err, ErrSpoolLimit) || !errors.Is(err, storageheadroom.ErrLowSpace) {
		t.Fatalf("expected storage headroom refusal on exhausted mount: %v", err)
	}

	after, err := s.Get(t.Context(), id)
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatalf("failed append altered prefix/end: before=%+v after=%+v err=%v", before, after, err)
	}
	usage, err := database.New(db).GetOutputUsage(t.Context())
	if err != nil || usage != charged {
		t.Fatalf("failed append changed charge: %d -> %d, %v", charged, usage, err)
	}
	if err := os.Remove(fillerPath); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	db, err = sqlitedb.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	s, err = New(db, limits)
	if err != nil {
		t.Fatal(err)
	}
	retained, err := s.Get(t.Context(), id)
	if err != nil || !reflect.DeepEqual(before, retained) {
		t.Fatalf("reopen changed prefix: %+v %v", retained, err)
	}
	if err := s.InterruptOpen(t.Context()); err != nil {
		t.Fatal(err)
	}
	retained, err = s.Get(t.Context(), id)
	if err != nil || retained.End == nil || retained.End.Status != pb.DebugletOutputStatus_DEBUGLET_OUTPUT_STATUS_TRUNCATED || retained.End.Reason != pb.OutputReasonExecutorInterrupted || retained.End.LastSequence != 1 {
		t.Fatalf("recovery invented complete output: %+v %v", retained, err)
	}
	frames, err := s.Frames(t.Context(), id, 0, 64)
	if err != nil || len(frames) != 1 || string(frames[0].Output) != "prefix" {
		t.Fatalf("durable prefix lost: %+v %v", frames, err)
	}
}
