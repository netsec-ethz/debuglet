package rpc

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"go.uber.org/zap"
)

func TestSessionLeaseDeadlineAndRenewal(t *testing.T) {
	base := time.Now()
	var offset atomic.Int64
	now := func() time.Time { return base.Add(time.Duration(offset.Load())) }
	owner, err := NewSessionOwnerWithClock("executor", testOwnerBinding(), time.Second, now)
	if err != nil {
		t.Fatal(err)
	}
	if owner.Available() || owner.ExpireLease() || owner.CommitLease(1) {
		t.Fatal("unregistered setup obtained lease authority")
	}
	if !owner.MarkRegistered() {
		t.Fatal("initial registration failed")
	}
	initial := owner.deadline
	offset.Store(int64(200 * time.Millisecond))
	if !owner.MarkRegistered() || owner.deadline != initial {
		t.Fatal("repeated Bind rearmed initial lease")
	}
	if !owner.CommitLease(1) {
		t.Fatal("valid renewal refused")
	}
	renewed := owner.deadline
	if renewed != now().Add(time.Second) || owner.CommitLease(1) || owner.CommitLease(0) || owner.deadline != renewed {
		t.Fatal("duplicate/stale sequence changed authority")
	}
	// Admission checks the clock even though no expiry worker has run.
	offset.Store(int64(1200 * time.Millisecond))
	if owner.Available() || owner.MarkRegistered() || owner.CommitLease(2) {
		t.Fatal("late response revived expired authority")
	}
	if ticket, err := owner.AdmitMutation(context.Background()); err == nil {
		ticket.Finish()
		t.Fatal("expired owner admitted ordinary work")
	}
	if !owner.ExpireLease() || owner.ExpireLease() || owner.Active() {
		t.Fatal("expiry did not retire exactly once")
	}
	if owner.deadline != renewed {
		t.Fatal("rejected renewal changed deadline")
	}
	awaitOwnerSignal(t, owner.Done())
	awaitOwnerSignal(t, owner.MutationsDrained())
}

func TestLeaseExpiryRetainsAdmittedContinuation(t *testing.T) {
	base := time.Now()
	var offset atomic.Int64
	owner, err := NewSessionOwnerWithClock("executor", testOwnerBinding(), time.Second, func() time.Time { return base.Add(time.Duration(offset.Load())) })
	if err != nil {
		t.Fatal(err)
	}
	owner.MarkRegistered()
	ticket, err := owner.AdmitMutation(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer ticket.Finish()
	offset.Store(int64(time.Second))
	if !owner.ExpireLease() {
		t.Fatal("did not expire")
	}
	awaitOwnerSignal(t, ticket.Context().Done())
	child, err := ticket.Fork(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer child.Finish()
	ticket.Finish()
	select {
	case <-owner.MutationsDrained():
		t.Fatal("expiry discarded retained continuation")
	default:
	}
	child.Finish()
	awaitOwnerSignal(t, owner.MutationsDrained())
}

func TestLeaseConstructorsRejectBeforeOwnership(t *testing.T) {
	for _, duration := range []time.Duration{0, time.Second - 1, 5*time.Minute + 1} {
		if b, err := NewBidiServer(zap.NewNop(), nil, testOwnerBinding().Incarnation, duration); err == nil || b != nil {
			t.Fatal("invalid transport lease accepted")
		}
		if owner, err := NewSessionOwner("executor", testOwnerBinding(), duration); err == nil || owner != nil {
			t.Fatal("invalid owner lease accepted")
		}
	}
	if b, err := NewBidiServer(zap.NewNop(), nil, "not-an-incarnation", time.Minute); err == nil || b != nil {
		t.Fatal("invalid transport incarnation accepted")
	}
	if b, err := NewBidiServerWithClock(zap.NewNop(), nil, testOwnerBinding().Incarnation, time.Minute, nil); err == nil || b != nil {
		t.Fatal("nil transport clock accepted")
	}
	if owner, err := NewSessionOwnerWithClock("executor", testOwnerBinding(), time.Minute, nil); err == nil || owner != nil {
		t.Fatal("nil owner clock accepted")
	}
}
