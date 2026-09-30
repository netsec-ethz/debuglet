// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package outputstore

import (
	"bytes"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/netsec-ethz/debuglet/internal/executor/database"
	"github.com/netsec-ethz/debuglet/internal/storageheadroom"
	pb "github.com/netsec-ethz/debuglet/protocol"
)

func TestStorageHeadroomKeepsPrefixSiblingAndFinalRecords(t *testing.T) {
	limits := DefaultLimits()
	limits.ControlReserveBytes = 4096
	store, db, _ := fixture(t, limits)
	first, sibling := admit(t, store), admit(t, store)
	appendFrame(t, store, first, "prefix")
	var pages int64
	if err := db.QueryRow("PRAGMA page_count").Scan(&pages); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(fmt.Sprintf("PRAGMA max_page_count=%d", pages+22)); err != nil {
		t.Fatal(err)
	}
	before, err := database.New(db).GetOutputUsage(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	_, err = store.Append(t.Context(), first, time.Now(), bytes.Repeat([]byte("x"), pb.MaxOutputFrameBytes))
	if !errors.Is(err, ErrSpoolLimit) || !errors.Is(err, storageheadroom.ErrLowSpace) {
		t.Fatalf("headroom refusal=%v", err)
	}
	after, err := database.New(db).GetOutputUsage(t.Context())
	if err != nil || after != before {
		t.Fatalf("failed frame charge=%d -> %d, %v", before, after, err)
	}
	appendFrame(t, store, sibling, "ok")
	end, err := store.Finish(t.Context(), first, pb.DebugletOutputStatus_DEBUGLET_OUTPUT_STATUS_TRUNCATED, pb.OutputReasonStorageLimit)
	if err != nil || end.LastSequence != 1 {
		t.Fatalf("final receipt=%v,%v", end, err)
	}
	if _, err = store.Finish(t.Context(), sibling, pb.DebugletOutputStatus_DEBUGLET_OUTPUT_STATUS_COMPLETE, ""); err != nil {
		t.Fatal(err)
	}
	if err = store.Acknowledge(t.Context(), first, end.LastSequence, end); err != nil {
		t.Fatal(err)
	}
	retained, err := store.Get(t.Context(), first)
	if err != nil || retained.End == nil || !retained.EndAcknowledged || retained.End.Reason != pb.OutputReasonStorageLimit {
		t.Fatalf("lost finality=%+v,%v", retained, err)
	}
}
