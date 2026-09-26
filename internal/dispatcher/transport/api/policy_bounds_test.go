package api

import (
	"encoding/base64"
	"fmt"
	"math"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/netsec-ethz/debuglet/internal/dispatcher/models"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/resource"
)

// The numeric ranges of a policy are enforced by the server, on both routes a
// policy enters through, and they are the ranges api/openapi.yaml documents.
// The tests below drive the routes with values no SDK would send, because the
// server may not depend on a client having checked them: the conversions that
// follow admission turn a signed field straight into a rate or a duration.

// boundsDebuglets returns one valid debuglet with the policy edited in place.
func boundsDebuglets(edit func(*DebugletPolicyRequest)) []DebugletRequest {
	debuglets := modeDebuglets()
	edit(&debuglets[0].Policy)
	return debuglets
}

type boundsCase struct {
	name  string
	edit  func(*DebugletPolicyRequest)
	field string
}

// boundsRejectedPolicies are the policies the documented ranges exclude. Every
// one of them used to be converted into an internal value: a negative floor
// into a negative reservation, a maximum-integer bandwidth into an aggregate
// that wraps, a maximum-integer budget into a duration nobody asked for.
func boundsRejectedPolicies() []boundsCase {
	return []boundsCase{
		{"negative floor", func(p *DebugletPolicyRequest) { p.FloorBW = -1 }, "floor_bw"},
		{"maximum floor", func(p *DebugletPolicyRequest) { p.FloorBW, p.CeilBW = math.MaxInt64, math.MaxInt64 }, "floor_bw"},
		{"floor above the bound", func(p *DebugletPolicyRequest) {
			p.FloorBW, p.CeilBW = maxBandwidthBPS+1, maxBandwidthBPS+1
		}, "floor_bw"},
		{"negative ceiling", func(p *DebugletPolicyRequest) { p.FloorBW, p.CeilBW = 0, -1 }, "ceil_bw"},
		{"maximum ceiling", func(p *DebugletPolicyRequest) { p.CeilBW = math.MaxInt64 }, "ceil_bw"},
		{"ceiling above the bound", func(p *DebugletPolicyRequest) { p.CeilBW = maxBandwidthBPS + 1 }, "ceil_bw"},
		{"ceiling below floor", func(p *DebugletPolicyRequest) { p.FloorBW, p.CeilBW = 100, 99 }, "ceil_bw"},
		{"zero timeout", func(p *DebugletPolicyRequest) { p.TimeoutMS = 0 }, "timeout_ms"},
		{"negative timeout", func(p *DebugletPolicyRequest) { p.TimeoutMS = -1 }, "timeout_ms"},
		{"maximum timeout", func(p *DebugletPolicyRequest) { p.TimeoutMS = math.MaxInt64 }, "timeout_ms"},
		{"timeout above the bound", func(p *DebugletPolicyRequest) { p.TimeoutMS = maxTimeoutMS + 1 }, "timeout_ms"},
	}
}

// TestPolicyBoundsRejectOutOfRangeNumbersOnBothRoutes drives every rejected
// policy through pricing and through submission. Both answer the same typed
// envelope, name the field they rejected, and leave no admitted run behind.
func TestPolicyBoundsRejectOutOfRangeNumbersOnBothRoutes(t *testing.T) {
	for _, tc := range boundsRejectedPolicies() {
		t.Run(tc.name+" intent", func(t *testing.T) {
			f := modeNewFixture(t)
			f.registerExecutor()
			body := modeIntentBody("TEST")
			body.Debuglets = boundsDebuglets(tc.edit)
			rec := f.do(http.MethodPut, "/payment/intent", body)
			assertEnvelope(t, "priced policy", rec, http.StatusBadRequest, CodeInvalidPolicy, "")
			if !strings.Contains(rec.Body.String(), tc.field) {
				t.Fatalf("the message does not name %s: %s", tc.field, rec.Body.String())
			}
			f.expectationsMet("priced policy")
		})

		t.Run(tc.name+" submission", func(t *testing.T) {
			f := modeNewFixture(t)
			f.registerExecutor()
			debuglets := boundsDebuglets(tc.edit)
			f.mock.ExpectQuery(modeGetTransactionQuery).
				WithArgs(modeChainTxID).
				WillReturnRows(modeTransactionRows(modeChainTxID, "", "TEST", "", modeRequestHash(t, debuglets), models.Paid))

			rec := f.do(http.MethodPut, "/debuglet", modeSubmitBody(modeChainTxID, "", debuglets))
			assertEnvelope(t, "submitted policy", rec, http.StatusBadRequest, CodeInvalidPolicy, "")
			if !strings.Contains(rec.Body.String(), tc.field) {
				t.Fatalf("the message does not name %s: %s", tc.field, rec.Body.String())
			}
			f.expectationsMet("submitted policy")
			if n := f.recentDebugletIDs(); n != 0 {
				t.Fatalf("rejected policy left %d dispatched runs, want 0", n)
			}
		})
	}
}

// TestStartTimeBoundsRejectUnrepresentableTimestamps covers the second
// unchecked conversion of a submitted request. time.Unix wraps silently, so a
// far future start used to become an arbitrary instant the scheduler then
// reserved capacity from.
func TestStartTimeBoundsRejectUnrepresentableTimestamps(t *testing.T) {
	for _, tc := range []struct {
		name  string
		start int64
	}{
		{"negative", -1},
		{"maximum", math.MaxInt64},
		{"minimum", math.MinInt64},
		{"above the bound", maxStartTimestamp + 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := modeNewFixture(t)
			f.registerExecutor()
			debuglets := modeDebuglets()
			start := tc.start
			debuglets[0].StartTimestamp = &start
			f.mock.ExpectQuery(modeGetTransactionQuery).
				WithArgs(modeChainTxID).
				WillReturnRows(modeTransactionRows(modeChainTxID, "", "TEST", "", modeRequestHash(t, debuglets), models.Paid))

			rec := f.do(http.MethodPut, "/debuglet", modeSubmitBody(modeChainTxID, "", debuglets))
			assertEnvelope(t, "submitted start time", rec, http.StatusBadRequest, CodeInvalidRequest, "")
			if !strings.Contains(rec.Body.String(), "start_time") {
				t.Fatalf("the message does not name start_time: %s", rec.Body.String())
			}
			f.expectationsMet("submitted start time")
			if n := f.recentDebugletIDs(); n != 0 {
				t.Fatalf("rejected start time left %d dispatched runs, want 0", n)
			}
		})
	}
}

// TestValidatePolicyAcceptsTheDocumentedBoundaries states the ranges from the
// other side: the extreme values the contract does admit stay admitted.
func TestValidatePolicyAcceptsTheDocumentedBoundaries(t *testing.T) {
	for _, tc := range []struct {
		name   string
		policy DebugletPolicyRequest
	}{
		{"zero bandwidth", DebugletPolicyRequest{FloorBW: 0, CeilBW: 0, TimeoutMS: 1}},
		{"equal floor and ceiling", DebugletPolicyRequest{FloorBW: 1000, CeilBW: 1000, TimeoutMS: 1}},
		{"largest bandwidth", DebugletPolicyRequest{FloorBW: maxBandwidthBPS, CeilBW: maxBandwidthBPS, TimeoutMS: 1}},
		{"largest budget", DebugletPolicyRequest{FloorBW: 0, CeilBW: 0, TimeoutMS: maxTimeoutMS}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := validatePolicy(1, tc.policy); err != nil {
				t.Fatalf("boundary policy rejected: %v", err)
			}
		})
	}

	// The bounds the server enforces are the ones the contract documents.
	if got := fmt.Sprint(maxBandwidthBPS); got != "1000000000000000" {
		t.Fatalf("documented maximum bandwidth = %s, want 1000000000000000", got)
	}
	if got := fmt.Sprint(maxStartTimestamp); got != "9223372036" {
		t.Fatalf("documented maximum start_time = %s, want 9223372036", got)
	}
}

// TestAPIToSpecKeepsUnitsAtTheBoundaries pins the conversion itself: bits per
// second stay bits per second, milliseconds become exactly that many
// milliseconds, and a boundary value is not rounded on its way in.
func TestAPIToSpecKeepsUnitsAtTheBoundaries(t *testing.T) {
	for _, tc := range []struct {
		name    string
		floor   int64
		ceil    int64
		timeout int64
		start   *int64
	}{
		{name: "smallest", floor: 0, ceil: 0, timeout: 1},
		{name: "typical", floor: 64_000, ceil: 1_000_000, timeout: 30_000},
		{name: "largest bandwidth", floor: maxBandwidthBPS, ceil: maxBandwidthBPS, timeout: 1},
		{name: "largest budget", floor: 0, ceil: 1, timeout: maxTimeoutMS},
		{name: "largest start", floor: 0, ceil: 1, timeout: 1, start: boundsPtr(maxStartTimestamp)},
		{name: "epoch start", floor: 0, ceil: 1, timeout: 1, start: boundsPtr(minStartTimestamp)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			request := DebugletRequest{
				OrderID:        1,
				ExecutorID:     modeExecutorID,
				StartTimestamp: tc.start,
				Wasm:           base64.StdEncoding.EncodeToString([]byte("\x00asm bounds")),
				Policy: DebugletPolicyRequest{
					FloorBW: tc.floor, CeilBW: tc.ceil, TimeoutMS: tc.timeout,
				},
			}
			if err := validatePolicy(request.OrderID, request.Policy); err != nil {
				t.Fatalf("boundary policy rejected: %v", err)
			}
			spec, err := APIToSpec(request)
			if err != nil {
				t.Fatalf("boundary request rejected: %v", err)
			}
			if spec.Policy.FloorBW != resource.Bitrate(tc.floor) || spec.Policy.CeilBW != resource.Bitrate(tc.ceil) {
				t.Fatalf("bandwidth = (%d, %d), want (%d, %d) bits per second",
					int64(spec.Policy.FloorBW), int64(spec.Policy.CeilBW), tc.floor, tc.ceil)
			}
			if spec.Policy.Timeout != time.Duration(tc.timeout)*time.Millisecond {
				t.Fatalf("timeout = %s, want %d ms", spec.Policy.Timeout, tc.timeout)
			}
			if got := spec.Policy.Timeout.Milliseconds(); got != tc.timeout {
				t.Fatalf("timeout round trip = %d ms, want %d ms", got, tc.timeout)
			}
			if tc.start == nil {
				if spec.StartTime != nil {
					t.Fatalf("start time = %s, want none", spec.StartTime)
				}
				return
			}
			if spec.StartTime == nil || spec.StartTime.Unix() != *tc.start {
				t.Fatalf("start time = %v, want Unix %d", spec.StartTime, *tc.start)
			}
		})
	}
}

// TestAPIToSpecRejectsUnrepresentableStartTimes covers the direct caller of the
// conversion, without an HTTP request around it.
func TestAPIToSpecRejectsUnrepresentableStartTimes(t *testing.T) {
	for _, start := range []int64{-1, math.MinInt64, math.MaxInt64, maxStartTimestamp + 1} {
		request := DebugletRequest{
			OrderID:        1,
			ExecutorID:     modeExecutorID,
			StartTimestamp: boundsPtr(start),
			Wasm:           base64.StdEncoding.EncodeToString([]byte("\x00asm bounds")),
			Policy:         DebugletPolicyRequest{FloorBW: 0, CeilBW: 1, TimeoutMS: 1},
		}
		spec, err := APIToSpec(request)
		if err == nil {
			t.Fatalf("start_time %d was converted into %v", start, spec.StartTime)
		}
		if !strings.Contains(err.Error(), "start_time") {
			t.Fatalf("start_time %d: error does not name the field: %v", start, err)
		}
	}
}

// TestAdmissionRejectsAWindowThatDoesNotFit covers the values every documented
// maximum admits and admission still refuses. The maxima bound one field each;
// the window a run reserves is start_time plus timeout_ms plus ten seconds and
// has to fit as well. Such a request is a rejected request, and used to be
// answered as a failure of the server.
func TestAdmissionRejectsAWindowThatDoesNotFit(t *testing.T) {
	for _, tc := range []struct {
		name  string
		edit  func(*DebugletRequest)
		named []string
	}{
		{
			name:  "the largest documented budget",
			edit:  func(r *DebugletRequest) { r.Policy.TimeoutMS = maxTimeoutMS },
			named: []string{"timeout_ms"},
		},
		{
			name: "the latest documented start time",
			edit: func(r *DebugletRequest) {
				r.Policy.TimeoutMS = 1
				r.StartTimestamp = boundsPtr(maxStartTimestamp)
			},
			named: []string{"start_time", "timeout_ms"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := modeNewFixture(t)
			f.registerExecutor()
			debuglets := modeDebuglets()
			tc.edit(&debuglets[0])
			hash := modeRequestHash(t, debuglets)

			// The request passes the intent check and the documented per-field
			// bounds, so admission is what rejects it. The rejected submission
			// then refunds, which reads the transaction and its orders.
			f.mock.ExpectQuery(modeGetTransactionQuery).
				WithArgs(modeChainTxID).
				WillReturnRows(modeTransactionRows(modeChainTxID, "", "TEST", "", hash, models.Paid))
			modeExpectNoAdmittedRuns(f.mock)
			f.mock.ExpectBegin()
			f.mock.ExpectQuery(modeGetTransactionQuery).
				WithArgs(modeChainTxID).
				WillReturnRows(modeTransactionRows(modeChainTxID, "", "TEST", "", hash, models.Paid))
			f.mock.ExpectQuery(modeGetTransactionOrdersQuery).
				WithArgs(modeChainTxID).
				WillReturnRows(modeOrderRows(modeChainTxID, "TEST", models.Outstanding))
			f.mock.ExpectQuery(modeUpdateOrderStateQuery).
				WithArgs(int64(models.Refunded), modeChainTxID, modeOrderID).
				WillReturnRows(modeOrderRows(modeChainTxID, "TEST", models.Refunded))
			f.mock.ExpectRollback()

			rec := f.do(http.MethodPut, "/debuglet", modeSubmitBody(modeChainTxID, "", debuglets))
			assertEnvelope(t, "unfitting window", rec, http.StatusBadRequest, CodeInvalidPolicy, "")
			for _, field := range tc.named {
				if !strings.Contains(rec.Body.String(), field) {
					t.Fatalf("the message does not name %s: %s", field, rec.Body.String())
				}
			}
			f.expectationsMet("unfitting window")
			if n := f.recentDebugletIDs(); n != 0 {
				t.Fatalf("rejected submission left %d dispatched runs, want 0", n)
			}
		})
	}
}

// TestDestinationLimitBoundsMatchTheDocumentedRange covers the third number the
// API converts into a capacity. It becomes the capacity the runs of the
// destination are shared out of and summed against, and it used to be taken as
// it arrived.
func TestDestinationLimitBoundsMatchTheDocumentedRange(t *testing.T) {
	const destination = "bounded.example"
	for _, tc := range []struct {
		name  string
		limit int64
	}{
		{"negative", -1},
		{"maximum", math.MaxInt64},
		{"above the bound", maxBandwidthBPS + 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := modeNewFixture(t)
			rec := f.do(http.MethodPatch, "/destination", DestinationLimitRequest{Destination: destination, Limit: tc.limit})
			assertEnvelope(t, "destination limit", rec, http.StatusBadRequest, CodeInvalidPolicy, "")
			if !strings.Contains(rec.Body.String(), "limit") {
				t.Fatalf("the message does not name the rejected field: %s", rec.Body.String())
			}
			f.expectationsMet("destination limit")
		})
	}

	// The boundaries of the documented range are applied.
	for _, limit := range []int64{0, 1000, maxBandwidthBPS} {
		f := modeNewFixture(t)
		rec := f.do(http.MethodPatch, "/destination", DestinationLimitRequest{Destination: destination, Limit: limit})
		modeAssertStatus(t, rec, http.StatusNoContent)
		f.expectationsMet("destination limit")
	}
}

func boundsPtr(v int64) *int64 { return &v }
