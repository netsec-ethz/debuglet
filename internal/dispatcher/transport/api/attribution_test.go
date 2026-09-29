// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/netsec-ethz/debuglet/internal/dispatcher/database"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/tag"
	"github.com/netsec-ethz/debuglet/pkg/client"
	pb "github.com/netsec-ethz/debuglet/protocol"

	"github.com/labstack/echo/v4"
	"go.uber.org/zap"
	"golang.org/x/time/rate"
)

var (
	atAnchor = bytes.Repeat([]byte{0xA7}, 32)
	atT0     = time.Date(2026, 9, 29, 8, 0, 0, 0, time.UTC)
)

// atFixture is a dispatcher without the local development profile whose
// executor peer announces a TESLA chain.
func atFixture(t *testing.T) *ccFixture {
	t.Helper()
	peer := &cpPeer{id: ccExecutorID, price: ccPricePerBwS, currency: "TEST", tesla: &pb.HelloResponse{
		TeslaAnchorKey: atAnchor, TeslaAnchorTimestampNs: atT0.UnixNano(), TeslaDelaySec: 60,
		TeslaDisclosureDelayEpochs: 15, TeslaChainLength: 10080,
	}}
	return ccNewFixturePeer(t, zap.NewNop(), peer)
}

// TestAttributionCandidatesAnswerForAnAddressAndTime submits a run as one
// account and looks it up without any credential: the run is a candidate
// while it is active, with its chain's schedule, and the answer names neither
// the account nor anything but the documented fields.
func TestAttributionCandidatesAnswerForAnAddressAndTime(t *testing.T) {
	f := atFixture(t)
	account, _, owner := authAccount(t, f, "attribution owner")
	f.peer.setUploadHook(nil)
	submission := f.submit(owner, []string{"attribution"})
	anonymous := f.client(f.root.URL, false)
	ctx, cancel := f.requestCtx()
	defer cancel()

	doc, err := anonymous.AttributionCandidates(ctx, "127.0.0.1", time.Now())
	if err != nil {
		t.Fatalf("AttributionCandidates: %v", err)
	}
	if len(doc.Candidates) != 1 || doc.Truncated {
		t.Fatalf("candidates=%+v; want the submitted run", doc)
	}
	got := doc.Candidates[0]
	want := client.AttributionSchedule{Chain: tag.ChainID(atAnchor), K0: atAnchor, T0: atT0.UnixNano(), Interval: 60, DelayEpochs: 15, ChainLength: 10080, TagSpec: 1}
	if got.RunID != submission.IDs[0] || got.ExecutorID != ccExecutorID || got.IPSource != "observed" || !equalSchedule(got.Schedule, want) || got.DisclosedThrough != 0 {
		t.Fatalf("candidate=%+v; want run %s with schedule %+v", got, submission.IDs[0], want)
	}
	if !got.ActiveFrom.Before(time.Now()) || !got.ActiveTo.After(time.Now()) || doc.RetainedFrom.After(time.Now()) {
		t.Fatalf("interval %s..%s, retained_from %s", got.ActiveFrom, got.ActiveTo, doc.RetainedFrom)
	}

	// Before and after the run, and from another address, there is none.
	for _, probe := range []struct {
		ip string
		at time.Time
	}{{"127.0.0.1", got.ActiveFrom.Add(-time.Hour)}, {"127.0.0.1", got.ActiveTo.Add(time.Hour)}, {"192.0.2.9", time.Now()}} {
		doc, err := anonymous.AttributionCandidates(ctx, probe.ip, probe.at)
		if err != nil || len(doc.Candidates) != 0 {
			t.Errorf("candidates for %s at %s = %+v, %v; want none", probe.ip, probe.at, doc.Candidates, err)
		}
	}

	// The raw answer carries the documented fields only, and nothing of the
	// account that submitted the run.
	status, _, body, _ := authRequest(t, f, http.MethodGet, "/attribution/candidates?ip=127.0.0.1&at="+time.Now().UTC().Format(time.RFC3339Nano), nil, nil)
	if status != http.StatusOK {
		t.Fatalf("anonymous lookup answered %d: %s", status, body)
	}
	if bytes.Contains(body, []byte(account.ID)) {
		t.Fatalf("the lookup disclosed the submitting account: %s", body)
	}
	var raw struct {
		Candidates []map[string]json.RawMessage `json:"candidates"`
	}
	if err := json.Unmarshal(body, &raw); err != nil || len(raw.Candidates) != 1 {
		t.Fatalf("decode %s: %v", body, err)
	}
	var fields []string
	for name := range raw.Candidates[0] {
		fields = append(fields, name)
	}
	slices.Sort(fields)
	if strings.Join(fields, " ") != "active_from active_to disclosed_through executor_id ip_source run_id schedule" {
		t.Fatalf("candidate fields %v", fields)
	}

	// Once the run's exit is recorded, its interval ends there.
	f.peer.setUploadHook(f.exitHook(0, nil))
	exited := f.submit(owner, []string{"exited"})
	doc, err = anonymous.AttributionCandidates(ctx, "127.0.0.1", time.Now().Add(2*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	for _, candidate := range doc.Candidates {
		if candidate.RunID == exited.IDs[0] {
			t.Fatalf("an exited run is still a candidate two minutes later: %+v", candidate)
		}
	}

	// Beyond the retention the history is pruned and retained_from says so.
	future := time.Now().Add(100 * 24 * time.Hour)
	if err := f.d.PruneAttribution(ctx, future); err != nil {
		t.Fatal(err)
	}
	doc, err = anonymous.AttributionCandidates(ctx, "127.0.0.1", time.Now())
	if err != nil || len(doc.Candidates) != 0 || !doc.RetainedFrom.Equal(future.Add(-90*24*time.Hour).UTC()) {
		t.Fatalf("after pruning: %+v, %v; want no candidates before retained_from", doc, err)
	}
}

func equalSchedule(a, b client.AttributionSchedule) bool {
	return a.Chain == b.Chain && bytes.Equal(a.K0, b.K0) && a.T0 == b.T0 && a.Interval == b.Interval &&
		a.DelayEpochs == b.DelayEpochs && a.ChainLength == b.ChainLength && a.TagSpec == b.TagSpec
}

// TestAttributionKeysArePaged reads the disclosed keys of a chain in pages of
// at most 1024 epochs without a credential.
func TestAttributionKeysArePaged(t *testing.T) {
	f := atFixture(t)
	chain := tag.ChainID(atAnchor)
	for epoch := int64(1); epoch <= 1500; epoch++ {
		if epoch == 700 {
			continue // an epoch never disclosed is absent
		}
		if err := f.queries.InsertAttributionKey(f.ctx, database.InsertAttributionKeyParams{ExecutorID: ccExecutorID, ChainID: chain, Epoch: epoch, Key: []byte{byte(epoch)}, DisclosedAtNs: 1}); err != nil {
			t.Fatal(err)
		}
	}
	anonymous := f.client(f.root.URL, false)
	ctx, cancel := f.requestCtx()
	defer cancel()
	first, err := anonymous.AttributionKeys(ctx, ccExecutorID, chain, 1, 0)
	if err != nil || len(first.Keys) != 1023 || first.NextEpoch == nil || *first.NextEpoch != 1025 {
		t.Fatalf("first page: %d keys, next %v, %v", len(first.Keys), first.NextEpoch, err)
	}
	second, err := anonymous.AttributionKeys(ctx, ccExecutorID, chain, *first.NextEpoch, 0)
	if err != nil || len(second.Keys) != 476 || second.NextEpoch != nil || second.Keys[475].Epoch != 1500 {
		t.Fatalf("second page: %d keys, next %v, %v", len(second.Keys), second.NextEpoch, err)
	}
	bounded, err := anonymous.AttributionKeys(ctx, ccExecutorID, chain, 10, 20)
	if err != nil || len(bounded.Keys) != 11 || bounded.NextEpoch != nil || !bytes.Equal(bounded.Keys[0].Key, []byte{10}) {
		t.Fatalf("bounded page: %+v, %v", bounded, err)
	}
	var httpErr *client.HTTPError
	if _, err := anonymous.AttributionKeys(ctx, ccExecutorID, "no-such-chain", 1, 0); !errors.As(err, &httpErr) || httpErr.StatusCode != http.StatusNotFound || httpErr.Code != client.CodeNotFound {
		t.Fatalf("unknown chain: %v", err)
	}
	for _, target := range []string{
		"/attribution/keys?executor=" + ccExecutorID,
		"/attribution/keys?executor=" + ccExecutorID + "&chain=" + chain + "&from_epoch=9&to_epoch=3",
		"/attribution/keys?executor=" + ccExecutorID + "&chain=" + chain + "&from_epoch=-1",
		"/attribution/candidates?ip=127.0.0.1",
		"/attribution/candidates?ip=127.0.0.1&at=yesterday",
	} {
		if status, _, body, _ := authRequest(t, f, http.MethodGet, target, nil, nil); status != http.StatusBadRequest {
			t.Errorf("%s answered %d: %s", target, status, body)
		}
	}
}

// TestAttributionRoutesAreRateLimitedPerAddress spends one address's burst
// and checks that another address keeps its own.
func TestAttributionRoutesAreRateLimitedPerAddress(t *testing.T) {
	f := atFixture(t)
	e := echo.New()
	h := NewHandler(f.d, f.db, zap.NewNop())
	h.attributionLimiter = newAddressLimiter(rate.Every(time.Hour), 2)
	h.RegisterRoutes(e)
	lookup := func(remote string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/attribution/candidates?ip=127.0.0.1&at=2026-09-29T10:00:00Z", nil)
		req.RemoteAddr = remote
		rec := httptest.NewRecorder()
		e.ServeHTTP(rec, req)
		return rec
	}
	for i := range 2 {
		if rec := lookup("198.51.100.1:4000"); rec.Code != http.StatusOK {
			t.Fatalf("request %d answered %d", i, rec.Code)
		}
	}
	rec := lookup("198.51.100.1:4001")
	assertEnvelope(t, "over the limit", rec, http.StatusTooManyRequests, CodeRateLimited, "")
	if rec.Header().Get("Retry-After") == "" {
		t.Fatal("a rate-limited answer carries no Retry-After")
	}
	if rec := lookup("198.51.100.2:4000"); rec.Code != http.StatusOK {
		t.Fatalf("another address answered %d", rec.Code)
	}
	// Two addresses of one IPv6 /64 share a bucket.
	lookup("[2001:db8::1]:4000")
	lookup("[2001:db8::2]:4000")
	if rec := lookup("[2001:db8::3]:4000"); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("a third address of the same /64 answered %d", rec.Code)
	}
}
