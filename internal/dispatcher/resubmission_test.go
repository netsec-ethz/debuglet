// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package dispatcher

import (
	"errors"
	"strings"
	"testing"

	"github.com/netsec-ethz/debuglet/internal/dispatcher/database"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/models"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/resource"

	"github.com/google/uuid"
)

// batch pays for one TEST transaction with one order per floor, numbered from
// 1 the way LockPrice numbers them, and returns the matching submission specs.
func (f *tgFixture) batch(t *testing.T, floors ...resource.Bitrate) []models.DebugletSpec {
	t.Helper()
	txID, err := f.ph.NewTransactionID()
	if err != nil {
		t.Fatalf("transaction id: %v", err)
	}
	var total int64
	for _, floor := range floors {
		total += tgOrderPrice(floor)
	}
	if _, err := f.ph.CreatePaymentIntent(txID, total, "TEST", "tg-hash", f.ctx); err != nil {
		t.Fatalf("TEST intent: %v", err)
	}
	start := f.start
	specs := make([]models.DebugletSpec, len(floors))
	for i, floor := range floors {
		orderID := int64(i + 1)
		if _, err := f.q.CreateDebugletOrder(f.ctx, database.CreateDebugletOrderParams{
			TransactionID: txID, OrderID: orderID, ExecutorID: tgExecutorID, Price: tgOrderPrice(floor),
			Currency: tgCurrency, RefundAddress: "", State: int64(models.Outstanding),
		}); err != nil {
			t.Fatalf("TEST order %d: %v", orderID, err)
		}
		specs[i] = models.DebugletSpec{
			StartTime:     &start,
			Wasm:          tgWasm,
			Args:          []string{"tg"},
			ExecutorID:    tgExecutorID,
			TransactionID: txID,
			OrderID:       orderID,
			Policy:        models.DebugletPolicy{FloorBW: floor, CeilBW: 2 * floor, Timeout: tgTimeout},
		}
	}
	return specs
}

// submitBatch submits a copy of specs, so every submission of a batch carries
// the same values.
func (f *tgFixture) submitBatch(specs []models.DebugletSpec) (uuid.UUIDs, error) {
	return f.d.SubmitDebuglets(f.ctx, append([]models.DebugletSpec(nil), specs...), nil)
}

// resubmissionWindow is a run of the fixture's shared admission window, for
// reading the executor reservation over it.
func (f *tgFixture) resubmissionWindow(t *testing.T, id uuid.UUID) tgDebuglet {
	t.Helper()
	return tgDebuglet{id: id, row: f.row(t, id)}
}

func TestRepeatedSubmissionReturnsTheAdmittedRuns(t *testing.T) {
	peer := &tgPeer{}
	f := newTGFixture(t, peer)
	specs := f.batch(t, tgFloorA, tgFloorB)

	first, err := f.submitBatch(specs)
	if err != nil || len(first) != 2 || first[0] == first[1] {
		t.Fatalf("first submission = (%v, %v), want two runs", first, err)
	}
	window := f.resubmissionWindow(t, first[0])

	second, err := f.submitBatch(specs)
	if err != nil {
		t.Fatalf("repeated submission: %v", err)
	}
	if len(second) != 2 || second[0] != first[0] || second[1] != first[1] {
		t.Fatalf("repeated submission returned %v, want the admitted runs %v", second, first)
	}
	if got := len(peer.recordedUploads()); got != 2 {
		t.Fatalf("%d uploads after the repeated submission, want 2", got)
	}
	if got := batchRows(t, f); got != 2 {
		t.Fatalf("%d debuglets rows after the repeated submission, want 2", got)
	}
	tgAssertReserved(t, f, window, tgFloorA+tgFloorB)

	t.Run("another transaction is admitted", func(t *testing.T) {
		other, err := f.submitBatch(f.batch(t, tgFloorA, tgFloorB))
		if err != nil || len(other) != 2 {
			t.Fatalf("other transaction = (%v, %v), want two runs", other, err)
		}
		for _, id := range other {
			if id == first[0] || id == first[1] {
				t.Fatalf("other transaction returned the admitted run %s", id)
			}
		}
		if got := len(peer.recordedUploads()); got != 4 {
			t.Fatalf("%d uploads, want 4", got)
		}
		if got := batchRows(t, f); got != 4 {
			t.Fatalf("%d debuglets rows, want 4", got)
		}
		tgAssertReserved(t, f, window, 2*(tgFloorA+tgFloorB))
	})
}

func TestSubmissionOfAClaimedOrderIsRefused(t *testing.T) {
	peer := &tgPeer{}
	f := newTGFixture(t, peer)
	admitted, err := f.submitBatch(f.batch(t, tgFloorA))
	if err != nil || len(admitted) != 1 {
		t.Fatalf("admitted run = (%v, %v)", admitted, err)
	}
	window := f.resubmissionWindow(t, admitted[0])

	for _, tc := range []struct {
		name string
		// runID is the run the first order is claimed for before the
		// submission. The dispatcher has no run with the id -1, as for an
		// order another process admitted.
		runID func() int64
	}{
		{name: "an order carries a run the dispatcher does not have", runID: func() int64 { return -1 }},
		{name: "only some orders of the batch have runs", runID: func() int64 { return window.row.ID }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			specs := f.batch(t, tgFloorA, tgFloorB)
			if _, err := f.db.ExecContext(f.ctx,
				"UPDATE debuglet_order SET debuglet_id = ? WHERE transaction_id = ? AND order_id = 1",
				tc.runID(), specs[0].TransactionID); err != nil {
				t.Fatalf("claim order 1: %v", err)
			}
			rows, uploads := batchRows(t, f), len(peer.recordedUploads())

			ids, err := f.submitBatch(specs)
			if err == nil || ids != nil || !strings.Contains(err.Error(), "is not admissible") {
				t.Fatalf("submission = (%v, %v), want a refusal", ids, err)
			}
			if !errors.Is(err, ErrPaymentInUse) {
				t.Fatalf("refusal %v does not keep the payment", err)
			}
			if got := batchRows(t, f); got != rows {
				t.Fatalf("%d debuglets rows after the refusal, want %d", got, rows)
			}
			if got := len(peer.recordedUploads()); got != uploads {
				t.Fatalf("%d uploads after the refusal, want %d", got, uploads)
			}
			tgAssertReserved(t, f, window, tgFloorA)
		})
	}
}

// A retry of an admitted batch after the dispatcher closed is still answered
// with its runs: a refusal there would have the caller refund a payment whose
// runs execute.
func TestRepeatedSubmissionAfterCloseReturnsTheAdmittedRuns(t *testing.T) {
	peer := &tgPeer{}
	f := newTGFixture(t, peer)
	specs := f.batch(t, tgFloorA)
	first, err := f.submitBatch(specs)
	if err != nil || len(first) != 1 {
		t.Fatalf("first submission = (%v, %v), want one run", first, err)
	}

	f.d.mu.Lock()
	f.d.closed = true
	f.d.mu.Unlock()

	second, err := f.submitBatch(specs)
	if err != nil || len(second) != 1 || second[0] != first[0] {
		t.Fatalf("repeated submission after close = (%v, %v), want %v", second, err, first)
	}
	if _, err := f.submitBatch(f.batch(t, tgFloorA)); !errors.Is(err, ErrDispatcherClosed) {
		t.Fatalf("new submission after close = %v, want %v", err, ErrDispatcherClosed)
	}
}
