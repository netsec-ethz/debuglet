package api

import (
	"encoding/json"
	"go.uber.org/zap"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/netsec-ethz/debuglet/pkg/client"
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
		status, body := raw.do(http.MethodPatch, "/destination", DestinationLimitRequest{Destination: destination, Limit: limit, Reason: "capacity planning"})
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
// /destination refuses a limit below the active allocation floors with 409
// capacity_exhausted and sends nothing, and applies a limit equal to them.
func TestDestinationLimitBelowTheFloorsAnswersConflict(t *testing.T) {
	f := ccNewFixture(t)
	contract := oaContract(t)
	raw := &wfClient{t: t, base: f.root.URL, http: f.root.Client()}
	const destination = "127.0.0.1"
	patch := func(what string, limit int64, want int) []byte {
		t.Helper()
		status, body := raw.do(http.MethodPatch, "/destination", DestinationLimitRequest{Destination: destination, Limit: limit, Reason: "capacity planning"})
		wfExpect(t, what, status, want, body)
		oaCheckResponse(t, contract, http.MethodPatch, "/destination", status, body)
		return body
	}
	patch("unheld destination", 10*ccFloorBW, http.StatusNoContent)
	dlAllocate(t, f, destination)

	before := len(dlBandwidths(f.peer))
	body := patch("limit below the floors", ccFloorBW-1, http.StatusConflict)
	if envelope := envelopeOf(t, "limit below the floors", body); envelope.Code != CodeCapacityExhausted || envelope.Message != "limit is below the floors admitted on the destination, active or reserved" {
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

// TestDestinationLimitBelowTheReservedFloorsAnswersConflict states that PATCH
// /destination refuses a limit below the floor reserved for a run admitted to
// start later, before it allocated anything, with the same 409 envelope, and
// applies a limit equal to that floor.
func TestDestinationLimitBelowTheReservedFloorsAnswersConflict(t *testing.T) {
	f := ccNewFixture(t)
	contract := oaContract(t)
	raw := &wfClient{t: t, base: f.root.URL, http: f.root.Client()}
	const destination = "127.0.0.1"
	patch := func(what string, limit int64, want int) []byte {
		t.Helper()
		status, body := raw.do(http.MethodPatch, "/destination", DestinationLimitRequest{Destination: destination, Limit: limit, Reason: "capacity planning"})
		wfExpect(t, what, status, want, body)
		oaCheckResponse(t, contract, http.MethodPatch, "/destination", status, body)
		return body
	}
	patch("unheld destination", 10*ccFloorBW, http.StatusNoContent)

	f.peer.setUploadHook(nil)
	request := ccRequest(nil)
	later := time.Now().Add(time.Hour).Unix()
	request.StartTimestamp = &later
	batch, err := client.Prepare([]client.Request{request})
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	ctx, cancel := f.requestCtx()
	defer cancel()
	if _, err := f.client(f.root.URL, false).SubmitTEST(ctx, batch); err != nil {
		t.Fatalf("SubmitTEST: %v", err)
	}

	body := patch("limit below the reserved floors", ccFloorBW-1, http.StatusConflict)
	if envelope := envelopeOf(t, "limit below the reserved floors", body); envelope.Code != CodeCapacityExhausted || envelope.Message != "limit is below the floors admitted on the destination, active or reserved" {
		t.Fatalf("limit below the reserved floors answered %+v", envelope)
	}
	if pushed := dlBandwidths(f.peer); len(pushed) != 0 {
		t.Fatalf("a refused limit sent %v", pushed)
	}
	patch("limit equal to the reserved floors", ccFloorBW, http.StatusNoContent)
}

func TestDestinationLimitLegacyPeerReturnsUpgradeInstruction(t *testing.T) {
	peer := &cpPeer{id: ccExecutorID, price: ccPricePerBwS, currency: "TEST", legacyBandwidth: true}
	f := ccNewFixturePeer(t, zap.NewNop(), peer, LocalDevelopment(true))
	dlAllocate(t, f, "127.0.0.1")
	raw := &wfClient{t: t, base: f.root.URL, http: f.root.Client()}
	status, body := raw.do(http.MethodPatch, "/destination", DestinationLimitRequest{Destination: "127.0.0.1", Limit: 2 * ccFloorBW, Reason: "capacity planning"})
	wfExpect(t, "legacy ordered update", status, http.StatusInternalServerError, body)
	envelope := envelopeOf(t, "legacy ordered update", body)
	if envelope.Code != CodeInternal || !strings.Contains(envelope.Message, "upgrade legacy executors") {
		t.Fatalf("no actionable legacy outcome: %+v", envelope)
	}
	oaCheckResponse(t, oaContract(t), http.MethodPatch, "/destination", status, body)
}

// dlExpectPolicyRecord scripts the recording of one destination policy event,
// the first of its destination, on a sqlmock database.
func dlExpectPolicyRecord(mock sqlmock.Sqlmock, destination string, limit int64) {
	mock.ExpectBegin()
	mock.ExpectQuery("SELECT CAST\\(COALESCE\\(MAX\\(revision\\), 0\\) AS INTEGER\\) FROM destination_policy_events").
		WithArgs(destination).WillReturnRows(sqlmock.NewRows([]string{"revision"}).AddRow(0))
	mock.ExpectQuery("INSERT INTO destination_policy_events").
		WillReturnRows(sqlmock.NewRows([]string{"id", "destination", "kind", "limit_bps", "reason", "actor", "requested_at_ns", "expires_at_ns", "revision"}).
			AddRow(1, destination, "limit", limit, "capacity planning", "local", time.Now().UnixNano(), nil, 1))
	mock.ExpectCommit()
}

func dlPolicies(t *testing.T, raw *wfClient, contract *contract) []DestinationPolicyResponse {
	t.Helper()
	status, body := raw.do(http.MethodGet, "/destinations", nil)
	wfExpect(t, "destination policies", status, http.StatusOK, body)
	oaCheckResponse(t, contract, http.MethodGet, "/destinations", status, body)
	var listed DestinationPoliciesResponse
	if err := json.Unmarshal(body, &listed); err != nil {
		t.Fatalf("decode destination policies: %v", err)
	}
	return listed.Destinations
}

// TestDestinationPolicyRequiresAnOperator states that neither listing nor
// changing destination policies is open to an account without the operator
// role.
func TestDestinationPolicyRequiresAnOperator(t *testing.T) {
	f := ccNewFixtureWith(t)
	account, token, _ := authAccount(t, f, "destination submitter")
	bearer := map[string]string{"Authorization": "Bearer " + token}
	deny := []byte(`{"destination":"192.0.2.10","limit":0,"denied":true,"reason":"owner request"}`)
	if status, code := authStatus(t, f, http.MethodPatch, "/destination", deny, bearer); status != http.StatusForbidden {
		t.Fatalf("submitter deny: %d (%s), want 403", status, code)
	}
	if status, code := authStatus(t, f, http.MethodGet, "/destinations", nil, bearer); status != http.StatusForbidden {
		t.Fatalf("submitter list: %d (%s), want 403", status, code)
	}
	authGrantOperator(t, f, account.ID)
	if status, code := authStatus(t, f, http.MethodPatch, "/destination", deny, bearer); status != http.StatusNoContent {
		t.Fatalf("operator deny: %d (%s), want 204", status, code)
	}
	status, _, body, _ := authRequest(t, f, http.MethodGet, "/destinations", nil, bearer)
	var listed DestinationPoliciesResponse
	if err := json.Unmarshal(body, &listed); status != http.StatusOK || err != nil || len(listed.Destinations) != 1 {
		t.Fatalf("operator list: %d %s (%v)", status, body, err)
	}
	if got := listed.Destinations[0]; got.Actor != account.ID || !got.Denied || got.Reason != "owner request" {
		t.Fatalf("recorded policy %+v, want a deny by %s", got, account.ID)
	}
}

// TestDestinationPolicyValidatesBeforeRecording states that a change without
// a required reason, with an oversized reason or with an unusable expiry is
// refused with 400 and records nothing.
func TestDestinationPolicyValidatesBeforeRecording(t *testing.T) {
	f := ccNewFixture(t)
	contract := oaContract(t)
	raw := &wfClient{t: t, base: f.root.URL, http: f.root.Client()}
	for _, tc := range []struct {
		what string
		req  DestinationLimitRequest
	}{
		{"deny without reason", DestinationLimitRequest{Destination: "192.0.2.11", Denied: true}},
		{"lowered limit without reason", DestinationLimitRequest{Destination: "192.0.2.11", Limit: 1000}},
		{"oversized reason", DestinationLimitRequest{Destination: "192.0.2.11", Denied: true, Reason: strings.Repeat("r", 501)}},
		{"expiry not RFC 3339", DestinationLimitRequest{Destination: "192.0.2.11", Denied: true, Reason: "x", ExpiresAt: "tomorrow"}},
		{"expiry in the past", DestinationLimitRequest{Destination: "192.0.2.11", Denied: true, Reason: "x", ExpiresAt: "2020-01-01T00:00:00Z"}},
		{"empty destination", DestinationLimitRequest{Denied: true, Reason: "x"}},
	} {
		status, body := raw.do(http.MethodPatch, "/destination", tc.req)
		wfExpect(t, tc.what, status, http.StatusBadRequest, body)
		oaCheckResponse(t, contract, http.MethodPatch, "/destination", status, body)
	}
	if listed := dlPolicies(t, raw, contract); len(listed) != 0 {
		t.Fatalf("refused changes recorded %+v", listed)
	}
	// Raising the limit above the current one needs no reason.
	status, body := raw.do(http.MethodPatch, "/destination", DestinationLimitRequest{Destination: "192.0.2.11", Limit: maxBandwidthBPS})
	wfExpect(t, "raised limit", status, http.StatusNoContent, body)
}

// TestDestinationDenyIsSentListedAndRefusesNewWork drives a deny through the
// real routes: the executor holding an allocation receives the destination
// with a zero limit and the denied flag, the listing reports the deny with its
// actor, reason, expiry and confirmed delivery, and a new allocation there is
// refused.
func TestDestinationDenyIsSentListedAndRefusesNewWork(t *testing.T) {
	f := ccNewFixture(t)
	contract := oaContract(t)
	raw := &wfClient{t: t, base: f.root.URL, http: f.root.Client()}
	const destination = "127.0.0.1"
	dlAllocate(t, f, destination)
	before := len(dlBandwidths(f.peer))
	expires := time.Now().Add(time.Hour).UTC().Truncate(time.Second)
	status, body := raw.do(http.MethodPatch, "/destination", DestinationLimitRequest{
		Destination: destination, Denied: true, Reason: "owner request", ExpiresAt: expires.Format(time.RFC3339)})
	wfExpect(t, "deny", status, http.StatusNoContent, body)
	pushed := dlBandwidths(f.peer)[before:]
	if len(pushed) != 1 {
		t.Fatalf("the executor received %d bandwidth updates, want 1", len(pushed))
	}
	if limits := pushed[0].GetLimits(); len(limits) != 1 || limits[0].GetAddress() != destination || limits[0].GetBitsLimit() != 0 || !limits[0].GetDenied() {
		t.Fatalf("pushed update %v, want %s denied with a zero limit", limits, destination)
	}
	listed := dlPolicies(t, raw, contract)
	if len(listed) != 1 {
		t.Fatalf("listed %+v, want one policy", listed)
	}
	got := listed[0]
	if got.Destination != destination || got.Kind != "deny" || !got.Denied || got.Limit != nil || got.Reason != "owner request" ||
		got.Actor != "local" || got.Revision != 1 || got.ExpiresAt == nil || !got.ExpiresAt.Equal(expires) ||
		got.Delivery != "confirmed" || got.Recipients != 1 || got.Unconfirmed != 0 {
		t.Fatalf("listed %+v", got)
	}

	f.peer.setUploadHook(nil)
	sub := f.submit(f.client(f.root.URL, false), nil)
	ctx, cancel := f.requestCtx()
	defer cancel()
	if _, err := f.peer.direct.DebugletAllocate(ctx, &pb.DebugletAllocateRequest{
		DebugletId: sub.IDs[0], ExecutorId: ccExecutorID, TransactionId: sub.TransactionID,
		Policy: &pb.DebugletPolicy{Addresses: []string{destination}, FloorBw: ccFloorBW, CeilBw: ccFloorBW},
	}); err == nil {
		t.Fatal("an allocation on a denied destination was admitted")
	}
}

// TestDestinationDenyReportsALegacyExecutorAsUnconfirmed states that an
// executor which cannot acknowledge ordered application is counted as not
// having confirmed the deny, while the deny itself stays recorded.
func TestDestinationDenyReportsALegacyExecutorAsUnconfirmed(t *testing.T) {
	peer := &cpPeer{id: ccExecutorID, price: ccPricePerBwS, currency: "TEST", legacyBandwidth: true}
	f := ccNewFixturePeer(t, zap.NewNop(), peer, LocalDevelopment(true))
	dlAllocate(t, f, "127.0.0.1")
	raw := &wfClient{t: t, base: f.root.URL, http: f.root.Client()}
	status, body := raw.do(http.MethodPatch, "/destination", DestinationLimitRequest{Destination: "127.0.0.1", Denied: true, Reason: "owner request"})
	wfExpect(t, "legacy deny", status, http.StatusInternalServerError, body)
	listed := dlPolicies(t, raw, oaContract(t))
	if len(listed) != 1 || !listed[0].Denied || listed[0].Delivery != "unconfirmed" || listed[0].Recipients != 1 || listed[0].Unconfirmed != 1 {
		t.Fatalf("listed %+v, want one unconfirmed deny", listed)
	}
	if limits := dlBandwidths(peer); len(limits) == 0 || limits[len(limits)-1].GetLimits()[0].GetBitsLimit() != 0 {
		t.Fatalf("legacy executor did not receive the zero limit: %v", limits)
	}
}
