package dispatcher

import (
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/netsec-ethz/debuglet/internal/dispatcher/models"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/resource"

	"github.com/google/uuid"
)

func batchSetCapacity(t *testing.T, f *tgFixture, capacity resource.Bitrate) {
	t.Helper()
	f.d.mu.Lock()
	f.d.executors[tgExecutorID].capacity = capacity
	f.d.mu.Unlock()
}

func batchRows(t *testing.T, f *tgFixture) int {
	t.Helper()
	var count int
	if err := f.db.QueryRow("SELECT COUNT(*) FROM debuglets").Scan(&count); err != nil {
		t.Fatalf("count debuglets: %v", err)
	}
	return count
}

func batchReserved(f *tgFixture, from, to time.Time) resource.Bitrate {
	return f.d.scheduler.QueryMaxExec(tgExecutorID, from, to)
}

func TestSubmitDebugletsStagesWholeBatchCapacity(t *testing.T) {
	t.Run("overlapping executor requests reject without rows or uploads", func(t *testing.T) {
		peer := &tgPeer{}
		f := newTGFixture(t, peer)
		batchSetCapacity(t, f, 100)
		a, b := f.spec(t, 60), f.spec(t, 60)
		ids, err := f.d.SubmitDebuglets(f.ctx, []models.DebugletSpec{a, b}, nil)
		if !errors.Is(err, resource.ErrCapacityFull) || ids != nil {
			t.Fatalf("overlapping batch = (%v, %v), want nil IDs and ErrCapacityFull", ids, err)
		}
		if got := batchRows(t, f); got != 0 {
			t.Fatalf("persisted debuglets = %d, want 0", got)
		}
		if got := len(peer.recordedUploads()); got != 0 {
			t.Fatalf("uploads = %d, want 0", got)
		}
		if got := batchReserved(f, f.start, f.start.Add(tgTimeout+10*time.Second)); got != 0 {
			t.Fatalf("reservation after rejection = %d, want 0", got)
		}
	})

	t.Run("fitting overlap and nonoverlap commit once", func(t *testing.T) {
		for _, tc := range []struct {
			name       string
			floors     []resource.Bitrate
			secondFrom time.Duration
		}{
			{name: "fitting overlap", floors: []resource.Bitrate{40, 60}},
			{name: "nonoverlap", floors: []resource.Bitrate{100, 100}, secondFrom: time.Hour},
		} {
			t.Run(tc.name, func(t *testing.T) {
				peer := &tgPeer{}
				f := newTGFixture(t, peer)
				batchSetCapacity(t, f, 100)
				a, b := f.spec(t, tc.floors[0]), f.spec(t, tc.floors[1])
				if tc.secondFrom != 0 {
					start := f.start.Add(tc.secondFrom)
					b.StartTime = &start
				}
				ids, err := f.d.SubmitDebuglets(f.ctx, []models.DebugletSpec{a, b}, nil)
				if err != nil || len(ids) != 2 {
					t.Fatalf("fitting batch = (%v, %v), want two IDs", ids, err)
				}
				if got := batchRows(t, f); got != 2 {
					t.Fatalf("persisted debuglets = %d, want 2", got)
				}
				if got := len(peer.recordedUploads()); got != 2 {
					t.Fatalf("uploads = %d, want 2", got)
				}
			})
		}
	})

	t.Run("destination and existing reservations bound the batch", func(t *testing.T) {
		peer := &tgPeer{}
		f := newTGFixture(t, peer)
		batchSetCapacity(t, f, 1_000)
		f.d.destinations.SetLimit("bounded.example", 100)
		a, b := f.spec(t, 60), f.spec(t, 60)
		a.Policy.Addresses, b.Policy.Addresses = []string{"bounded.example"}, []string{"bounded.example"}
		if ids, err := f.d.SubmitDebuglets(f.ctx, []models.DebugletSpec{a, b}, nil); !errors.Is(err, resource.ErrCapacityFull) || ids != nil {
			t.Fatalf("destination-bound batch = (%v, %v), want capacity rejection", ids, err)
		}

		batchSetCapacity(t, f, 100)
		existing := f.seedDirect(t, 60)
		candidate := f.spec(t, 50)
		if ids, err := f.d.SubmitDebuglets(f.ctx, []models.DebugletSpec{candidate}, nil); !errors.Is(err, resource.ErrCapacityFull) || ids != nil {
			t.Fatalf("batch against existing reservation = (%v, %v), want capacity rejection", ids, err)
		}
		if got := batchReserved(f, existing.row.StartTime.Time, existing.row.EndTime.Time); got != 60 {
			t.Fatalf("existing reservation after rejection = %d, want 60", got)
		}
	})
}

func TestSubmitDebugletsConcurrentBatchesDoNotOvercommit(t *testing.T) {
	peer := &tgPeer{}
	f := newTGFixture(t, peer)
	batchSetCapacity(t, f, 100)
	specs := []models.DebugletSpec{f.spec(t, 60), f.spec(t, 60)}
	type result struct {
		ids uuid.UUIDs
		err error
	}
	results := make(chan result, 2)
	var start sync.WaitGroup
	start.Add(1)
	for i := range specs {
		go func(spec models.DebugletSpec) {
			start.Wait()
			ids, err := f.d.SubmitDebuglets(f.ctx, []models.DebugletSpec{spec}, nil)
			results <- result{ids: ids, err: err}
		}(specs[i])
	}
	start.Done()
	var successes, rejected int
	for range specs {
		r := <-results
		switch {
		case r.err == nil && len(r.ids) == 1:
			successes++
		case errors.Is(r.err, resource.ErrCapacityFull) && r.ids == nil:
			rejected++
		default:
			t.Fatalf("unexpected concurrent result ids=%v err=%v", r.ids, r.err)
		}
	}
	if successes != 1 || rejected != 1 || batchRows(t, f) != 1 || len(peer.recordedUploads()) != 1 {
		t.Fatalf("concurrent outcome successes=%d rejected=%d rows=%d uploads=%d", successes, rejected, batchRows(t, f), len(peer.recordedUploads()))
	}
}

func TestSubmitDebugletsSQLFailureRollsBackReservation(t *testing.T) {
	peer := &tgPeer{}
	f := newTGFixture(t, peer)
	batchSetCapacity(t, f, 100)
	if _, err := f.db.Exec(`CREATE TRIGGER fail_batch_insert BEFORE INSERT ON debuglets BEGIN SELECT RAISE(FAIL, 'batch insert failed'); END`); err != nil {
		t.Fatalf("install failure trigger: %v", err)
	}
	spec := f.spec(t, 60)
	ids, err := f.d.SubmitDebuglets(f.ctx, []models.DebugletSpec{spec}, nil)
	if err == nil || ids != nil {
		t.Fatalf("SQL failure = (%v, %v), want nil IDs and error", ids, err)
	}
	if batchRows(t, f) != 0 || len(peer.recordedUploads()) != 0 {
		t.Fatalf("SQL failure left rows=%d uploads=%d", batchRows(t, f), len(peer.recordedUploads()))
	}
	if got := batchReserved(f, f.start, f.start.Add(tgTimeout+10*time.Second)); got != 0 {
		t.Fatalf("reservation after SQL failure = %d, want 0", got)
	}
}
