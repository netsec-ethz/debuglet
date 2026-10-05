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
	if err := f.d.SetDestinationPolicy(t.Context(), "operator", destination, deny); err == nil {
		t.Fatal("a policy that could not be recorded was accepted")
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
	policy := dpAwait(t, f.d, destination, func(p DestinationPolicy) bool { return p.Kind == DestinationPolicyAllow })
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
	policy, _ := dpPolicy(t, d, destination)
	if policy.Recipients != 2 || policy.Unconfirmed != 2 {
		t.Fatalf("listed %+v, want two unconfirmed recipients", policy)
	}
}
