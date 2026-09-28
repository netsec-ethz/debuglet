// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package dispatcher

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/netsec-ethz/debuglet/internal/bitrate"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/database"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/models"
	pb "github.com/netsec-ethz/debuglet/protocol"

	"github.com/google/uuid"
)

// batch pays for one TEST transaction with one order per floor, numbered from
// 1 the way LockPrice numbers them, and returns the matching submission specs.
func (f *tgFixture) batch(t *testing.T, floors ...bitrate.Bitrate) []models.DebugletSpec {
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

// resubmission is the answer of one SubmitDebuglets call.
type resubmission struct {
	ids uuid.UUIDs
	err error
}

// awaitResubmission receives the answer of a submission running in the
// background, within the fixture's bound.
func (f *tgFixture) awaitResubmission(t *testing.T, answers <-chan resubmission, what string) resubmission {
	t.Helper()
	select {
	case answer := <-answers:
		return answer
	case <-f.ctx.Done():
		t.Fatalf("%s did not return: %v", what, f.ctx.Err())
		return resubmission{}
	}
}

// assertAdmittedOnce checks that a batch of the fixture's two floors was
// admitted once whatever number of identical submissions answered it: two
// runs, one per order and in order, each uploaded once, and the reservation
// counted once.
func assertAdmittedOnce(t *testing.T, f *tgFixture, peer *tgPeer, specs []models.DebugletSpec, ids uuid.UUIDs) {
	t.Helper()
	if len(ids) != len(specs) || ids[0] == ids[1] {
		t.Fatalf("admitted runs %v, want %d distinct runs", ids, len(specs))
	}
	for i, id := range ids {
		row := f.row(t, id)
		if row.TransactionID != specs[i].TransactionID || row.OrderID != specs[i].OrderID {
			t.Fatalf("run %d is %s of order %d, want order %d", i, id, row.OrderID, specs[i].OrderID)
		}
	}
	uploaded := map[string]int{}
	for _, upload := range peer.recordedUploads() {
		uploaded[upload.GetId()]++
	}
	if len(uploaded) != len(ids) {
		t.Fatalf("uploads %v, want exactly the runs %v", uploaded, ids)
	}
	for _, id := range ids {
		if uploaded[id.String()] != 1 {
			t.Fatalf("run %s uploaded %d times, want once (%v)", id, uploaded[id.String()], uploaded)
		}
	}
	if got := batchRows(t, f); got != len(ids) {
		t.Fatalf("%d debuglets rows, want %d", got, len(ids))
	}
	var claimed int
	if err := f.db.QueryRowContext(f.ctx,
		"SELECT COUNT(*) FROM debuglet_order WHERE transaction_id = ? AND debuglet_id IS NOT NULL",
		specs[0].TransactionID).Scan(&claimed); err != nil {
		t.Fatalf("count claimed orders: %v", err)
	}
	if claimed != len(ids) {
		t.Fatalf("%d orders record a run, want %d", claimed, len(ids))
	}
	tgAssertReserved(t, f, f.resubmissionWindow(t, ids[0]), tgFloorA+tgFloorB)
}

// Two identical submissions of one batch at the same time admit it once. The
// repeat is answered with the recorded runs as soon as the admission that won
// has committed them, which is before their uploads have finished: a caller
// can hold the run ids of a batch whose upload may still fail.
func TestConcurrentIdenticalSubmissionsAdmitOnce(t *testing.T) {
	t.Run("the repeat arrives while the first uploads", func(t *testing.T) {
		peer := &tgPeer{}
		f := newTGFixture(t, peer)
		specs := f.batch(t, tgFloorA, tgFloorB)
		uploading, release := make(chan struct{}), make(chan struct{})
		var once sync.Once
		peer.scriptUpload(func(ctx context.Context, _ *pb.UploadRequest) error {
			once.Do(func() { close(uploading) })
			select {
			case <-release:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		})

		answers := make(chan resubmission, 1)
		go func() {
			ids, err := f.submitBatch(specs)
			answers <- resubmission{ids, err}
		}()
		select {
		case <-uploading:
		case <-f.ctx.Done():
			t.Fatalf("the first submission never uploaded: %v", f.ctx.Err())
		}

		second, err := f.submitBatch(specs)
		if err != nil || len(second) != 2 {
			close(release)
			t.Fatalf("repeat during the upload = (%v, %v), want the recorded runs", second, err)
		}
		for _, id := range second {
			if state := f.row(t, id).State; state != models.RunStateUploading {
				t.Errorf("run %s is %s when the repeat is answered, want %s", id, state, models.RunStateUploading)
			}
		}
		close(release)
		first := f.awaitResubmission(t, answers, "the first submission")
		if first.err != nil || len(first.ids) != 2 || first.ids[0] != second[0] || first.ids[1] != second[1] {
			t.Fatalf("first submission = (%v, %v), repeat = %v, want the same runs in order", first.ids, first.err, second)
		}
		assertAdmittedOnce(t, f, peer, specs, first.ids)
	})

	// Which call takes the dispatcher lock first is up to the scheduler; the
	// other is answered with the runs it recorded, while the winner's upload
	// is held until that answer has been given.
	t.Run("both contend for admission", func(t *testing.T) {
		peer := &tgPeer{}
		f := newTGFixture(t, peer)
		specs := f.batch(t, tgFloorA, tgFloorB)
		answered := make(chan struct{})
		peer.scriptUpload(func(ctx context.Context, _ *pb.UploadRequest) error {
			select {
			case <-answered:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		})

		start := make(chan struct{})
		answers := make(chan resubmission, 2)
		for range 2 {
			go func() {
				<-start
				ids, err := f.submitBatch(specs)
				answers <- resubmission{ids, err}
			}()
		}
		close(start)
		repeat := f.awaitResubmission(t, answers, "the repeated submission")
		close(answered)
		admitted := f.awaitResubmission(t, answers, "the admitting submission")
		for _, answer := range []resubmission{repeat, admitted} {
			if answer.err != nil || len(answer.ids) != 2 {
				t.Fatalf("submission = (%v, %v), want two runs", answer.ids, answer.err)
			}
		}
		if repeat.ids[0] != admitted.ids[0] || repeat.ids[1] != admitted.ids[1] {
			t.Fatalf("repeat answered %v, admission returned %v, want the same runs in order", repeat.ids, admitted.ids)
		}
		assertAdmittedOnce(t, f, peer, specs, admitted.ids)
	})
}

// A retry after the dispatcher restarted is answered from the stored runs
// before anything is admitted. The restarted dispatcher has no transport to
// the executor, so an admission would fail at the upload; the answer instead
// uploads nothing, writes no row and reserves nothing.
func TestRepeatedSubmissionAfterReopenReturnsTheStoredRuns(t *testing.T) {
	peer := &tgPeer{}
	f := newTGFixture(t, peer)
	specs := f.batch(t, tgFloorA, tgFloorB)
	first, err := f.submitBatch(specs)
	if err != nil || len(first) != 2 {
		t.Fatalf("first submission = (%v, %v), want two runs", first, err)
	}

	g := restartTG(t, f)
	second, err := g.submitBatch(specs)
	if err != nil || len(second) != 2 || second[0] != first[0] || second[1] != first[1] {
		t.Fatalf("retry after reopening = (%v, %v), want %v", second, err, first)
	}
	if got := len(peer.recordedUploads()); got != 2 {
		t.Fatalf("%d uploads after the retry, want the first submission's 2", got)
	}
	if got := batchRows(t, g); got != 2 {
		t.Fatalf("%d debuglets rows after the retry, want 2", got)
	}
	tgAssertReserved(t, g, g.resubmissionWindow(t, first[0]), 0)
}
