package dispatcher

import (
	"errors"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/netsec-ethz/debuglet/internal/dispatcher/models"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/resource"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/resource/schedule"
)

// Admission converts a submitted policy into a reserved window and into
// aggregate capacity. The tests below drive that arithmetic directly, without
// an HTTP handler in front of it, because a spec can reach admission from the
// control protocol as well and the ranges may not be assumed to hold.

// arithSpec is a submission that needs no payment row: it is rejected or
// accepted by validateDebugletSpec alone.
func arithSpec(floor, ceiling resource.Bitrate, timeout time.Duration, start *time.Time) models.DebugletSpec {
	return models.DebugletSpec{
		StartTime:  start,
		Wasm:       tgWasm,
		Args:       []string{"arith"},
		ExecutorID: tgExecutorID,
		Policy:     models.DebugletPolicy{FloorBW: floor, CeilBW: ceiling, Timeout: timeout},
	}
}

func arithStart(t *testing.T, unix int64) *time.Time {
	t.Helper()
	at := time.Unix(unix, 0).UTC()
	return &at
}

// TestValidateDebugletSpecRejectsOutOfRangeNumbers covers the numbers a policy
// carries. Each of them used to reach the schedule as it was: a negative floor
// as a negative reservation, a maximum-integer floor as an aggregate that
// wraps, a zero or maximum-integer budget as a window nobody asked for.
func TestValidateDebugletSpecRejectsOutOfRangeNumbers(t *testing.T) {
	f := newTGFixture(t, nil)
	future := f.start
	for _, tc := range []struct {
		name string
		spec models.DebugletSpec
	}{
		{"negative floor", arithSpec(-1, 1000, tgTimeout, &future)},
		{"negative ceiling", arithSpec(0, -1, tgTimeout, &future)},
		{"floor above the bound", arithSpec(resource.MaxBitrate+1, resource.MaxBitrate+1, tgTimeout, &future)},
		{"maximum floor", arithSpec(math.MaxInt64, math.MaxInt64, tgTimeout, &future)},
		{"ceiling above the bound", arithSpec(0, resource.MaxBitrate+1, tgTimeout, &future)},
		{"ceiling below floor", arithSpec(1000, 999, tgTimeout, &future)},
		{"zero timeout", arithSpec(0, 1000, 0, &future)},
		{"negative timeout", arithSpec(0, 1000, -time.Second, &future)},
		{"sub-millisecond timeout", arithSpec(0, 1000, time.Millisecond-1, &future)},
		{"maximum timeout", arithSpec(0, 1000, time.Duration(math.MaxInt64), &future)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			spec := tc.spec
			request, err := f.d.validateDebugletSpec(&spec)
			if err == nil {
				t.Fatalf("out of range policy was admitted as %+v", request)
			}
			// The rejection is of the request, so a caller can answer it as
			// one rather than as a failure of the dispatcher.
			if !errors.Is(err, ErrInvalidPolicy) {
				t.Fatalf("rejection is not an invalid policy: %v", err)
			}
			if reserved := f.d.scheduler.QueryMaxExec(tgExecutorID, future.Add(-time.Hour), future.Add(time.Hour)); reserved != 0 {
				t.Fatalf("rejected policy reserved %d bits per second, want 0", reserved)
			}
		})
	}
}

// TestValidateDebugletSpecRejectsUnreservableWindows covers the other half of
// the arithmetic: the end of the window. A start plus a budget that leaves the
// nanosecond timeline the scheduler reserves on used to wrap into an arbitrary
// earlier instant, which the scheduler then happily reserved capacity in.
func TestValidateDebugletSpecRejectsUnreservableWindows(t *testing.T) {
	f := newTGFixture(t, nil)
	for _, tc := range []struct {
		name    string
		start   *time.Time
		timeout time.Duration
		// named are the contract fields the rejection has to point at, so that
		// a caller is told which of the two values it may lower.
		named []string
	}{
		{"largest admitted budget from now", nil, models.MaxPolicyTimeout, []string{"timeout_ms"}},
		{"largest admitted budget from a start", arithStart(t, time.Now().Unix()+3600), models.MaxPolicyTimeout, []string{"timeout_ms"}},
		{"latest start time", arithStart(t, int64(math.MaxInt64)/int64(time.Second)), tgTimeout, []string{"start_time", "timeout_ms"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			spec := arithSpec(0, 1000, tc.timeout, tc.start)
			request, err := f.d.validateDebugletSpec(&spec)
			if err == nil {
				t.Fatalf("unreservable window was admitted as [%s, %s]", request.From, request.To)
			}
			// Each field is inside its own documented range here, so the
			// window is what the rejection has to be about, and it is still a
			// rejected request rather than a failure of the dispatcher.
			if !errors.Is(err, ErrInvalidPolicy) {
				t.Fatalf("rejection is not an invalid policy: %v", err)
			}
			for _, field := range tc.named {
				if !strings.Contains(err.Error(), field) {
					t.Fatalf("the rejection does not name %s: %v", field, err)
				}
			}
		})
	}
}

// TestValidateDebugletSpecChecksAggregateCapacity states what an aggregate
// that does not fit means. A sum that wraps is not spare capacity: the window
// below already holds nearly the largest representable reservation, and one
// more floor used to wrap it into a negative total that compared below the
// executor capacity and was admitted.
func TestValidateDebugletSpecChecksAggregateCapacity(t *testing.T) {
	for _, dimension := range []string{"executor", "destination"} {
		t.Run(dimension, func(t *testing.T) {
			f := newTGFixture(t, nil)
			const destination = "arith.example"
			batchSetCapacity(t, f, resource.MaxBitrate)
			f.d.destinations.SetLimit(destination, resource.MaxBitrate)

			occupied := schedule.Request{
				Executor: tgExecutorID,
				From:     f.start.Add(-time.Hour),
				To:       f.start.Add(time.Hour),
				Use:      resource.Bitrate(math.MaxInt64) - 1000,
			}
			if dimension == "destination" {
				// The executor tree stays empty, so only the destination sum
				// can reject the candidate.
				occupied.Executor = "arith-other-executor"
				occupied.Destination = []string{destination}
			}
			f.d.scheduler.Submit(occupied)

			start := f.start
			spec := arithSpec(2000, 2000, tgTimeout, &start)
			spec.Policy.Addresses = []string{destination}
			request, err := f.d.validateDebugletSpec(&spec)
			if !errors.Is(err, resource.ErrCapacityFull) {
				t.Fatalf("overflowing %s aggregate = (%+v, %v), want ErrCapacityFull", dimension, request, err)
			}
		})
	}
}

// TestValidateDebugletSpecAdmitsTheBoundaries states the ranges from the other
// side: the extreme values that are admitted keep their units and their window.
func TestValidateDebugletSpecAdmitsTheBoundaries(t *testing.T) {
	f := newTGFixture(t, nil)
	batchSetCapacity(t, f, resource.MaxBitrate)
	for _, tc := range []struct {
		name    string
		floor   resource.Bitrate
		ceiling resource.Bitrate
		timeout time.Duration
	}{
		{"zero bandwidth", 0, 0, time.Millisecond},
		{"equal floor and ceiling", 1000, 1000, tgTimeout},
		{"largest bandwidth", resource.MaxBitrate, resource.MaxBitrate, tgTimeout},
		{"smallest budget", 0, 1000, time.Millisecond},
	} {
		t.Run(tc.name, func(t *testing.T) {
			start := f.start
			spec := arithSpec(tc.floor, tc.ceiling, tc.timeout, &start)
			request, err := f.d.validateDebugletSpec(&spec)
			if err != nil {
				t.Fatalf("boundary spec rejected: %v", err)
			}
			if request.Use != tc.floor {
				t.Fatalf("reservation = %d, want the floor %d bits per second", int64(request.Use), int64(tc.floor))
			}
			if !request.From.Equal(start) {
				t.Fatalf("window start = %s, want %s", request.From, start)
			}
			if got := request.To.Sub(request.From); got != tc.timeout+schedulingGrace {
				t.Fatalf("window length = %s, want %s", got, tc.timeout+schedulingGrace)
			}
		})
	}
}

// TestSubmitDebugletsLeavesNoReservationForAnInvalidBatch covers the ordering
// requirement: validation precedes every side effect, and one rejected member
// releases what the batch had already reserved for the others.
func TestSubmitDebugletsLeavesNoReservationForAnInvalidBatch(t *testing.T) {
	peer := &tgPeer{}
	f := newTGFixture(t, peer)
	start := f.start
	valid := arithSpec(1000, 2000, tgTimeout, &start)
	invalid := arithSpec(1000, 2000, 0, &start)

	ids, err := f.d.SubmitDebuglets(f.ctx, []models.DebugletSpec{valid, invalid}, nil)
	if err == nil || ids != nil {
		t.Fatalf("invalid batch = (%v, %v), want a rejection", ids, err)
	}
	if got := batchRows(t, f); got != 0 {
		t.Fatalf("persisted debuglets = %d, want 0", got)
	}
	if got := len(peer.recordedUploads()); got != 0 {
		t.Fatalf("uploads = %d, want 0", got)
	}
	if got := batchReserved(f, start.Add(-time.Hour), start.Add(time.Hour)); got != 0 {
		t.Fatalf("reservation after rejection = %d, want 0", got)
	}
}

// TestAddBitrateReportsInexactSums is the arithmetic the aggregate checks rest
// on, stated on its own.
func TestAddBitrateReportsInexactSums(t *testing.T) {
	for _, tc := range []struct {
		a, b  resource.Bitrate
		sum   resource.Bitrate
		exact bool
	}{
		{0, 0, 0, true},
		{1000, 2000, 3000, true},
		{resource.MaxBitrate, resource.MaxBitrate, 2 * resource.MaxBitrate, true},
		{math.MaxInt64, 1, 0, false},
		{math.MaxInt64 - 1000, 1001, 0, false},
		{math.MinInt64, -1, 0, false},
		{math.MaxInt64, math.MinInt64, -1, true},
		{-1000, 1000, 0, true},
	} {
		sum, exact := resource.AddBitrate(tc.a, tc.b)
		if exact != tc.exact || (exact && sum != tc.sum) {
			t.Fatalf("AddBitrate(%d, %d) = (%d, %v), want (%d, %v)", int64(tc.a), int64(tc.b), int64(sum), exact, int64(tc.sum), tc.exact)
		}
	}
}
