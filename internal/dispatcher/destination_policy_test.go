// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package dispatcher

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/netsec-ethz/debuglet/internal/bitrate"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/resource"
	pb "github.com/netsec-ethz/debuglet/protocol"
	"go.uber.org/zap"
)

func dpPolicy(t *testing.T, d *Dispatcher, destination string) (DestinationPolicy, bool) {
	t.Helper()
	policies, err := d.ListDestinationPolicies(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	for _, policy := range policies {
		if policy.Destination == destination {
			return policy, true
		}
	}
	return DestinationPolicy{}, false
}

func dpDenied(d *Dispatcher, destination string) bool {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.destinations.Denied(destination)
}

// dpAwait waits for the current policy of destination to satisfy done.
func dpAwait(t *testing.T, d *Dispatcher, destination string, done func(DestinationPolicy) bool) DestinationPolicy {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		policy, _ := dpPolicy(t, d, destination)
		if done(policy) {
			return policy
		}
		if time.Now().After(deadline) {
			t.Fatalf("policy of %s is %+v", destination, policy)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// TestDestinationPolicyIsRecordedBeforeItApplies states that a policy whose
// event cannot be written applies nothing and sends nothing, and that the
// same change applies once it can be recorded.
func TestDestinationPolicyIsRecordedBeforeItApplies(t *testing.T) {
	peer := &tgPeer{}
	f := newTGFixture(t, peer)
	const destination = "192.0.2.120"
	dlHold(t, f, destination)
	before := len(dlBandwidth(peer))
	if _, err := f.db.ExecContext(t.Context(), `CREATE TRIGGER dp_refuse BEFORE INSERT ON destination_policy_events
BEGIN SELECT RAISE(ABORT, 'refused'); END`); err != nil {
		t.Fatal(err)
	}
	deny := DestinationPolicyChange{Denied: true, Reason: "owner request"}
	if err := f.d.SetDestinationPolicy(t.Context(), "operator", destination, deny); !errors.Is(err, ErrDestinationPolicyNotRecorded) {
		t.Fatalf("a policy that could not be recorded returned %v, want %v", err, ErrDestinationPolicyNotRecorded)
	}
	if dpDenied(f.d, destination) || dlCap(f.d, destination) != 10*tgFloorA {
		t.Fatal("a policy that could not be recorded was applied")
	}
	if n := len(dlBandwidth(peer)) - before; n != 0 {
		t.Fatalf("a policy that could not be recorded sent %d updates", n)
	}
	if _, err := f.db.ExecContext(t.Context(), `DROP TRIGGER dp_refuse`); err != nil {
		t.Fatal(err)
	}
	// A deny is not refused for the floors admitted there.
	if err := f.d.SetDestinationPolicy(t.Context(), "operator", destination, deny); err != nil {
		t.Fatalf("deny: %v", err)
	}
	if !dpDenied(f.d, destination) {
		t.Fatal("recorded deny not applied")
	}
	pushed := dlBandwidth(peer)[before:]
	if len(pushed) != 1 || pushed[0].GetRevision() == 0 {
		t.Fatalf("deny sent %v, want one revised update", pushed)
	}
	if limits := pushed[0].GetLimits(); len(limits) != 1 || limits[0].GetAddress() != destination || !limits[0].GetDenied() || limits[0].GetBitsLimit() != 0 {
		t.Fatalf("deny sent %v, want %s denied with a zero limit", limits, destination)
	}
	policy, _ := dpPolicy(t, f.d, destination)
	if policy.Kind != DestinationPolicyDeny || policy.Actor != "operator" || policy.Revision != 2 || policy.Limit != nil ||
		policy.Recipients != 1 || policy.Unconfirmed != 0 {
		t.Fatalf("listed %+v", policy)
	}
	// The reserved-floor refusal of a limit is unchanged.
	if err := f.d.SetDestinationLimit(destination, tgFloorA-1); !errors.Is(err, resource.ErrCapacityFull) {
		t.Fatalf("limit below the floors: %v", err)
	}
	if policy, _ := dpPolicy(t, f.d, destination); policy.Revision != 2 {
		t.Fatalf("a refused limit was recorded: %+v", policy)
	}
}

// TestDestinationPolicySurvivesRestartAndExpires states that a restarted
// dispatcher applies the recorded deny and limit before any executor
// registers, and that a policy whose expiry passed is returned to the default
// by the expiry sweep with a recorded event of the dispatcher.
func TestDestinationPolicySurvivesRestartAndExpires(t *testing.T) {
	f := newTGFixture(t, nil)
	const denied, limited, expiring = "192.0.2.121", "192.0.2.122", "192.0.2.123"
	ctx := t.Context()
	if err := f.d.SetDestinationPolicy(ctx, "operator", denied, DestinationPolicyChange{Denied: true, Reason: "owner request"}); err != nil {
		t.Fatal(err)
	}
	if err := f.d.SetDestinationPolicy(ctx, "operator", limited, DestinationPolicyChange{Limit: 7 * tgFloorA, Reason: "capacity planning"}); err != nil {
		t.Fatal(err)
	}
	expires := time.Now().Add(time.Hour)
	if err := f.d.SetDestinationPolicy(ctx, "operator", expiring, DestinationPolicyChange{Denied: true, Reason: "short", ExpiresAt: expires}); err != nil {
		t.Fatal(err)
	}

	restarted, err := New(zap.NewNop(), f.db, "tg-restart", time.Minute, time.Minute, f.ph)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(restarted.Close)
	later := expires.Add(time.Minute)
	restarted.now = func() time.Time { return later }
	if err := restarted.RestoreScheduler(ctx); err != nil {
		t.Fatal(err)
	}
	if !dpDenied(restarted, denied) {
		t.Fatal("restart lost the deny")
	}
	if got := dlCap(restarted, limited); got != 7*tgFloorA {
		t.Fatalf("restart restored limit %s, want %s", got, 7*tgFloorA)
	}
	if dpDenied(restarted, expiring) {
		t.Fatal("restart applied an expired deny")
	}
	policy := dpAwait(t, restarted, expiring, func(p DestinationPolicy) bool { return p.Revision == 2 })
	if policy.Kind != DestinationPolicyAllow || policy.Actor != SystemActor || policy.Reason != "expired" || policy.Limit != nil || policy.ExpiresAt != nil {
		t.Fatalf("expiry recorded %+v", policy)
	}
	if got := dlCap(restarted, expiring); got != bitrate.Gigabit {
		t.Fatalf("expiry left the limit at %s, want the default", got)
	}
}

// TestDestinationPolicyExpiryReachesTheHoldingExecutor states that the
// running expiry sweep lifts an expired deny and sends the destination to the
// executor holding an allocation there without the denied flag.
func TestDestinationPolicyExpiryReachesTheHoldingExecutor(t *testing.T) {
	peer := &tgPeer{}
	f := newTGFixture(t, peer)
	const destination = "192.0.2.124"
	dlHold(t, f, destination)
	expires := time.Now().Add(300 * time.Millisecond)
	if err := f.d.SetDestinationPolicy(t.Context(), "operator", destination, DestinationPolicyChange{Denied: true, Reason: "short", ExpiresAt: expires}); err != nil {
		t.Fatal(err)
	}
	before := len(dlBandwidth(peer))
	policy := dpAwait(t, f.d, destination, func(p DestinationPolicy) bool { return p.Kind == DestinationPolicyAllow && p.Unconfirmed == 0 })
	if policy.Actor != SystemActor || policy.Reason != "expired" || policy.Recipients != 1 || policy.Unconfirmed != 0 {
		t.Fatalf("expiry recorded %+v", policy)
	}
	if dpDenied(f.d, destination) {
		t.Fatal("expired deny still applied")
	}
	pushed := dlBandwidth(peer)[before:]
	if len(pushed) == 0 {
		t.Fatal("expiry sent nothing to the holding executor")
	}
	limits := pushed[len(pushed)-1].GetLimits()
	if len(limits) != 1 || limits[0].GetDenied() || limits[0].GetBitsLimit() == 0 {
		t.Fatalf("expiry sent %v, want a nonzero share without the denied flag", limits)
	}
}

// TestDestinationPolicyReportsExecutorsThatDidNotAcknowledge states that an
// executor which refuses the update, or has no session to receive it, is
// counted as unconfirmed while the deny stays recorded and applied.
func TestDestinationPolicyReportsExecutorsThatDidNotAcknowledge(t *testing.T) {
	d, _, _ := newRegistryFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	fairshareStartPeer(t, ctx, d, &fairsharePeer{bandwidth: func() error { return errors.New("refused") }})
	const destination = "192.0.2.125"
	dlInsert(t, d, destination, fairshareExecutorID)
	dlInsert(t, d, destination, "dp-gone-executor")
	if err := d.SetDestinationPolicy(ctx, "operator", destination, DestinationPolicyChange{Denied: true, Reason: "owner request"}); err == nil {
		t.Fatal("undelivered deny reported success")
	}
	if !dpDenied(d, destination) {
		t.Fatal("undelivered deny not applied")
	}
	if _, ok := d.GetExecutor(fairshareExecutorID); ok {
		t.Fatal("unconfirmed denial left the stale session available")
	}
	policy, _ := dpPolicy(t, d, destination)
	if policy.Recipients != 2 || policy.Unconfirmed != 2 {
		t.Fatalf("listed %+v, want two unconfirmed recipients", policy)
	}
}

// dpLimitOf returns the last limit an executor received for destination.
func dpLimitOf(t *testing.T, requests []*pb.BandwidthRequest, destination string) *pb.DestinationLimit {
	t.Helper()
	for i := len(requests) - 1; i >= 0; i-- {
		for _, limit := range requests[i].GetLimits() {
			if limit.GetAddress() == destination {
				return limit
			}
		}
	}
	t.Fatalf("no update carried %s", destination)
	return nil
}

// TestEverySnapshotCarriesTheDeny states that a snapshot built after a deny
// for any other reason, here an allocation on another destination and the
// snapshot a session's pending reconciliation resends, still marks the denied
// destination: an executor takes every revised snapshot as its complete set,
// so a snapshot without the flag would lift the deny there.
func TestEverySnapshotCarriesTheDeny(t *testing.T) {
	peer := &tgPeer{}
	f := newTGFixture(t, peer)
	const denied, other = "192.0.2.126", "192.0.2.127"
	dlHold(t, f, denied)
	if err := f.d.SetDestinationPolicy(t.Context(), "operator", denied, DestinationPolicyChange{Denied: true, Reason: "owner request"}); err != nil {
		t.Fatal(err)
	}
	before := len(dlBandwidth(peer))
	dlHold(t, f, other)
	pushed := dlBandwidth(peer)[before:]
	if len(pushed) == 0 {
		t.Fatal("the allocation on another destination sent nothing")
	}
	if limit := dpLimitOf(t, pushed, denied); !limit.GetDenied() || limit.GetBitsLimit() != 0 {
		t.Fatalf("unrelated update carried %v for the denied destination", limit)
	}
	if limit := dpLimitOf(t, pushed, other); limit.GetDenied() || limit.GetBitsLimit() == 0 {
		t.Fatalf("unrelated update carried %v for the allowed destination", limit)
	}
	f.d.mu.Lock()
	snapshot := f.d.allocationSnapshot(tgExecutorID)
	f.d.mu.Unlock()
	if limit := dpLimitOf(t, []*pb.BandwidthRequest{{Limits: snapshot}}, denied); !limit.GetDenied() || limit.GetBitsLimit() != 0 {
		t.Fatalf("reconciliation snapshot carried %v for the denied destination", limit)
	}
}

// TestSubmissionNamingADeniedDestinationIsRefused states that admission
// refuses a run naming a denied destination, whatever its floor, as it
// refuses exhausted capacity, and reserves nothing for it.
func TestSubmissionNamingADeniedDestinationIsRefused(t *testing.T) {
	f := newTGFixture(t, nil)
	const denied = "192.0.2.128"
	if err := f.d.SetDestinationPolicy(t.Context(), "operator", denied, DestinationPolicyChange{Denied: true, Reason: "owner request"}); err != nil {
		t.Fatal(err)
	}
	future := f.start
	spec := arithSpec(0, 1000, tgTimeout, &future)
	spec.Policy.Addresses = []string{"192.0.2.129", denied}
	f.d.mu.Lock()
	request, err := f.d.validateDebugletSpec(&spec)
	f.d.mu.Unlock()
	if !errors.Is(err, resource.ErrDenied) || !errors.Is(err, resource.ErrCapacityFull) {
		t.Fatalf("submission to a denied destination: request %+v, error %v", request, err)
	}
	if reserved := f.d.scheduler.QueryMaxDest(denied, future.Add(-time.Hour), future.Add(time.Hour)); reserved != 0 {
		t.Fatalf("refused submission reserved %d", reserved)
	}
	spec.Policy.Addresses = []string{"192.0.2.129"}
	f.d.mu.Lock()
	_, err = f.d.validateDebugletSpec(&spec)
	f.d.mu.Unlock()
	if err != nil {
		t.Fatalf("submission to an allowed destination: %v", err)
	}
}

// TestDenialIsConfirmedOnlyByExecutorsThatRevoke states that an executor
// predating denials, which acknowledges the revision and applies the zero
// limit but ignores the flag, does not confirm a deny while it holds a
// positive-floor allocation, and that an executor that revokes does.
func TestDenialIsConfirmedOnlyByExecutorsThatRevoke(t *testing.T) {
	for _, tc := range []struct {
		name           string
		predatesDenial bool
	}{{"version 1", true}, {"version 2", false}} {
		t.Run(tc.name, func(t *testing.T) {
			peer := &tgPeer{predatesDenial: tc.predatesDenial}
			f := newTGFixture(t, peer)
			const destination = "192.0.2.130"
			dlHold(t, f, destination)
			before := len(dlBandwidth(peer))
			err := f.d.SetDestinationPolicy(t.Context(), "operator", destination, DestinationPolicyChange{Denied: true, Reason: "owner request"})
			pushed := dlBandwidth(peer)[before:]
			if len(pushed) != 1 || pushed[0].GetRevision() == 0 || !dpLimitOf(t, pushed, destination).GetDenied() {
				t.Fatalf("deny sent %v, want one revised update carrying the flag", pushed)
			}
			policy, _ := dpPolicy(t, f.d, destination)
			if tc.predatesDenial {
				if !errors.Is(err, ErrDenialUnsupported) || policy.Recipients != 1 || policy.Unconfirmed != 1 {
					t.Fatalf("deny acknowledged by an executor that predates denials: %v, listed %+v", err, policy)
				}
				return
			}
			if err != nil || policy.Recipients != 1 || policy.Unconfirmed != 0 {
				t.Fatalf("deny acknowledged by a revoking executor: %v, listed %+v", err, policy)
			}
		})
	}
}

// A spelling change cannot hide an existing allocation from an opt-out or
// admit new work. The original run policy still identifies the same target.
func TestDestinationPolicyUsesTheExecutorDestinationKey(t *testing.T) {
	for _, names := range [][2]string{{"TARGET.Example.:443", "target.example"}, {"[::ffff:192.0.2.131]:443", "192.0.2.131"}} {
		t.Run(names[0], func(t *testing.T) {
			peer := &tgPeer{}
			f := newTGFixture(t, peer)
			dlHold(t, f, names[0])
			before := len(dlBandwidth(peer))
			if err := f.d.SetDestinationPolicy(t.Context(), "operator", names[1], DestinationPolicyChange{Denied: true, Reason: "opt out"}); err != nil {
				t.Fatal(err)
			}
			policy, ok := dpPolicy(t, f.d, names[1])
			if !ok || policy.Recipients != 1 || policy.Unconfirmed != 0 || !dpDenied(f.d, names[0]) {
				t.Fatalf("normalized denial: %+v found=%v", policy, ok)
			}
			if !dpLimitOf(t, dlBandwidth(peer)[before:], names[1]).GetDenied() {
				t.Fatal("the existing allocation did not receive its denial")
			}
			future := f.start
			spec := arithSpec(0, 1000, tgTimeout, &future)
			spec.Policy.Addresses = []string{names[0]}
			f.d.mu.Lock()
			_, err := f.d.validateDebugletSpec(&spec)
			f.d.mu.Unlock()
			if !errors.Is(err, resource.ErrDenied) {
				t.Fatalf("equivalent destination admitted: %v", err)
			}
			if dpDenied(f.d, "unrelated.example") {
				t.Fatal("denial affected an unrelated destination")
			}
		})
	}
}

func TestDestinationPolicyRejectsMalformedKeysWithoutRecording(t *testing.T) {
	f := newTGFixture(t, nil)
	for _, destination := range []string{".", "192.0.2.0/24", "bad/path", "bad name", "name\n.example", "[invalid]:port"} {
		if err := f.d.SetDestinationPolicy(t.Context(), "operator", destination, DestinationPolicyChange{Denied: true, Reason: "opt out"}); !errors.Is(err, ErrInvalidDestinationPolicy) {
			t.Fatalf("destination %q: %v", destination, err)
		}
	}
	policies, err := f.d.ListDestinationPolicies(t.Context())
	if err != nil || len(policies) != 0 {
		t.Fatalf("malformed policy changed history: %+v, %v", policies, err)
	}
}
