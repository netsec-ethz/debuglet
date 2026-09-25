package api

import (
	"net/http"
	"strings"
	"testing"

	pb "github.com/netsec-ethz/debuglet/protocol"
)

func dlBandwidths(p *cpPeer) []*pb.BandwidthRequest {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]*pb.BandwidthRequest(nil), p.bandwidths...)
}

// dlAllocate submits one run with floor and ceiling ccFloorBW on destination
// and allocates it through the executor's own control session.
func dlAllocate(t *testing.T, f *ccFixture, destination string) {
	t.Helper()
	f.peer.setUploadHook(nil)
	sub := f.submit(f.client(f.root.URL, false), nil)
	ctx, cancel := f.requestCtx()
	defer cancel()
	if _, err := f.peer.direct.DebugletAllocate(ctx, &pb.DebugletAllocateRequest{
		DebugletId: sub.IDs[0], ExecutorId: ccExecutorID, TransactionId: sub.TransactionID,
		Policy: &pb.DebugletPolicy{Addresses: []string{destination}, FloorBw: ccFloorBW, CeilBw: ccFloorBW},
	}); err != nil {
		t.Fatalf("allocation: %v", err)
	}
}

// TestDestinationLimitAnswersWhetherItWasDelivered drives PATCH /destination
// through the real routes and the scripted executor holding an allocation on
// the destination. The change is acknowledged with 204 only once the executor
// received the recomputed share; when it cannot be delivered the answer is the
// typed internal failure, with no executor identity or transport text in it.
func TestDestinationLimitAnswersWhetherItWasDelivered(t *testing.T) {
	f := ccNewFixture(t)
	contract := oaContract(t)
	raw := &wfClient{t: t, base: f.root.URL, http: f.root.Client()}
	const destination = "127.0.0.1"
	patch := func(what string, limit int64, want int) []byte {
		t.Helper()
		status, body := raw.do(http.MethodPatch, "/destination", DestinationLimitRequest{Destination: destination, Limit: limit})
		wfExpect(t, what, status, want, body)
		oaCheckResponse(t, contract, http.MethodPatch, "/destination", status, body)
		return body
	}

	// Nobody holds the destination yet: the limit is recorded and nothing is sent.
	patch("unheld destination", 10*ccFloorBW, http.StatusNoContent)
	if n := len(dlBandwidths(f.peer)); n != 0 {
		t.Fatalf("an unheld destination sent %d bandwidth updates", n)
	}

	dlAllocate(t, f, destination)

	before := len(dlBandwidths(f.peer))
	patch("delivered limit", 2*ccFloorBW, http.StatusNoContent)
	pushed := dlBandwidths(f.peer)[before:]
	if len(pushed) != 1 {
		t.Fatalf("the executor received %d bandwidth updates, want 1", len(pushed))
	}
	if limits := pushed[0].GetLimits(); len(limits) != 1 || limits[0].GetAddress() != destination {
		t.Fatalf("pushed update %v, want one limit for %s", limits, destination)
	}

	// The executor's session ends while it still holds the allocation: the
	// limit is recorded, the share cannot reach it, and the caller is told so.
	f.peer.owner.Retire()
	body := patch("undelivered limit", ccFloorBW, http.StatusInternalServerError)
	if envelope := envelopeOf(t, "undelivered limit", body); envelope.Code != CodeInternal || envelope.Message != "destination limit recorded but not delivered to every executor" {
		t.Fatalf("undelivered limit answered %+v", envelope)
	}
	for _, private := range []string{ccExecutorID, "session", "rpc error", "unavailable"} {
		if strings.Contains(string(body), private) {
			t.Fatalf("delivery detail %q reached the caller: %s", private, body)
		}
	}

	body = patch("invalid limit", -1, http.StatusBadRequest)
	if envelope := envelopeOf(t, "invalid limit", body); envelope.Code != CodeInvalidPolicy {
		t.Fatalf("invalid limit answered %+v", envelope)
	}
}

// TestDestinationLimitBelowTheFloorsAnswersConflict states that PATCH
// /destination refuses a limit below the floors already admitted on the
// destination with 409 capacity_exhausted and sends nothing, and applies a
// limit equal to them.
func TestDestinationLimitBelowTheFloorsAnswersConflict(t *testing.T) {
	f := ccNewFixture(t)
	contract := oaContract(t)
	raw := &wfClient{t: t, base: f.root.URL, http: f.root.Client()}
	const destination = "127.0.0.1"
	patch := func(what string, limit int64, want int) []byte {
		t.Helper()
		status, body := raw.do(http.MethodPatch, "/destination", DestinationLimitRequest{Destination: destination, Limit: limit})
		wfExpect(t, what, status, want, body)
		oaCheckResponse(t, contract, http.MethodPatch, "/destination", status, body)
		return body
	}
	patch("unheld destination", 10*ccFloorBW, http.StatusNoContent)
	dlAllocate(t, f, destination)

	before := len(dlBandwidths(f.peer))
	body := patch("limit below the floors", ccFloorBW-1, http.StatusConflict)
	if envelope := envelopeOf(t, "limit below the floors", body); envelope.Code != CodeCapacityExhausted || envelope.Message != "limit is below the floors already admitted on the destination" {
		t.Fatalf("limit below the floors answered %+v", envelope)
	}
	if pushed := dlBandwidths(f.peer)[before:]; len(pushed) != 0 {
		t.Fatalf("a refused limit sent %v", pushed)
	}
	patch("limit equal to the floors", ccFloorBW, http.StatusNoContent)
	if pushed := dlBandwidths(f.peer)[before:]; len(pushed) != 1 {
		t.Fatalf("a limit equal to the floors sent %d updates, want 1", len(pushed))
	}
}
