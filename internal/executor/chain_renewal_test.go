// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package executor

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/netsec-ethz/debuglet/internal/controlsession"
	"github.com/netsec-ethz/debuglet/internal/executor/scheduler"
	"github.com/netsec-ethz/debuglet/internal/hostprobe"
	pb "github.com/netsec-ethz/debuglet/protocol"
	"go.uber.org/zap"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func renewalSession(t *testing.T, seed string) (*Node, *Session) {
	t.Helper()
	cfg := nodeTestConfig()
	cfg.Tesla.Seed = seed
	cfg.Tesla.ChainLength = 30
	cfg.Tesla.DisclosureDelayEpochs = 11
	cfg.Clock.MaxErrorMS = 60000
	db := newFixtureDatabase(t)
	n, err := NewNode(cfg, zap.NewNop(), db)
	if err != nil {
		t.Fatal(err)
	}
	s, err := NewSession(n, db)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		n.mu.Lock()
		active := n.active
		n.mu.Unlock()
		if active != nil {
			stopRenewalSession(t, active)
		}
		if err := n.Close(); err != nil {
			t.Error(err)
		}
	})
	return n, s
}

func stopRenewalSession(t *testing.T, s *Session) {
	t.Helper()
	s.Stop(sessionEnd(controlsession.ParentStopped, context.Canceled))
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := s.Wait(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestRenewalWaitsForSignersReceiptsAndRetainedResults(t *testing.T) {
	_, s := renewalSession(t, "renewal coverage")
	e := s.executor
	clock := &deliveryClock{mono: time.Second, wall: time.Second}
	e.teslaSchedule = deliverySchedule(t, clock)
	if len(e.teslaSchedule.CurrentKey(time.Now())) == 0 {
		t.Fatal("no signing key")
	}
	e.renewing.Store(true)
	e.scheduler.BeginDrain()
	binding := operationBinding()
	settled := func(want bool) {
		t.Helper()
		got, err := e.renewalSettled(t.Context(), binding)
		if err != nil || got != want {
			t.Fatalf("settled=%v err=%v; want %v", got, err, want)
		}
	}
	settled(false)
	// A successful heartbeat without a matching durable receipt cannot retire keys.
	e.disclosureDelivery.acknowledge(e.teslaSchedule, nil, time.Now())
	settled(false)
	// Losing the metric's timing bound must not erase later durable key coverage.
	clock.mono, clock.wall = 4*time.Second, 40*time.Second
	e.disclosureDelivery.acknowledge(e.teslaSchedule, []*pb.TeslaDisclosureReceipt{{Anchor: e.teslaSchedule.Anchor(), StoredThroughEpoch: 1}}, time.Now())
	if !e.disclosureDelivery.invalid {
		t.Fatal("clock drift did not invalidate timing metric")
	}
	settled(true)
	e.retired.schedule = e.teslaSchedule
	settled(false)
	e.retired.delivered([]*pb.TeslaDisclosureReceipt{{Anchor: e.teslaSchedule.Anchor(), StoredThroughEpoch: e.teslaSchedule.ChainLength() - 1}})
	settled(true)
	retention := e.scheduler.(scheduler.TerminalRetention)
	event := scheduler.TerminalEvent{DebugletID: uuid.New(), Binding: binding, RecordedAt: time.Now()}
	if err := retention.RecordTerminal(t.Context(), event); err != nil {
		t.Fatal(err)
	}
	settled(false)
	if err := retention.ReleaseTerminal(t.Context(), event.DebugletID, binding); err != nil {
		t.Fatal(err)
	}
	settled(true)
	id := uuid.New()
	if err := e.output.Admit(t.Context(), id, binding, pb.OutputVersion); err != nil {
		t.Fatal(err)
	}
	settled(false)
	end, err := e.output.Finish(t.Context(), id, pb.DebugletOutputStatus_DEBUGLET_OUTPUT_STATUS_COMPLETE, "")
	if err != nil {
		t.Fatal(err)
	}
	settled(false)
	if err := e.output.Acknowledge(t.Context(), id, 0, end); err != nil {
		t.Fatal(err)
	}
	settled(true)
	historical := controlsession.Binding{Incarnation: uuid.NewString(), SessionID: uuid.NewString()}
	if err := e.output.Admit(t.Context(), uuid.New(), historical, pb.OutputVersion); err != nil {
		t.Fatal(err)
	}
	settled(true)
}

func TestRenewalStartsNearExpiryWithoutClosingAcceptedWork(t *testing.T) {
	_, s := renewalSession(t, "")
	e := s.executor
	clock := &deliveryClock{mono: 80 * time.Second, wall: 80 * time.Second}
	e.teslaSchedule = deliverySchedule(t, clock)
	e.beginChainRenewal(time.Now())
	if e.renewing.Load() {
		t.Fatal("renewal started before the final tenth of the chain")
	}
	clock.mono, clock.wall = 90*time.Second, 90*time.Second
	e.beginChainRenewal(time.Now())
	if !e.renewing.Load() || !e.scheduler.IsDrained() {
		t.Fatal("empty scheduler did not drain")
	}
	caps, _ := e.capabilityReport(t.Context(), true)
	if caps.GetAttribution().GetReason() != "chain_renewing" {
		t.Fatalf("renewal not advertised: %v", caps.Attribution)
	}
	if e.teslaSchedule.HighestSigningEpoch() != 0 {
		t.Fatal("test unexpectedly signed")
	}
	if settled, err := e.renewalSettled(t.Context(), operationBinding()); err != nil || !settled {
		t.Fatalf("unused future keys delayed renewal: %v %v", settled, err)
	}
}

func TestRenewalRecordsFreshChainsOnlyForNextJoinedSession(t *testing.T) {
	for _, seed := range []string{"", "renewal seed"} {
		t.Run(seed, func(t *testing.T) {
			n, s := renewalSession(t, seed)
			if clock := hostprobe.ReadClock(n.cfg.Clock.MaxErrorBound()); clock.Readiness != hostprobe.ReadinessReady {
				if err := n.prepareChainRenewal(t.Context(), s); err == nil || n.nextSchedule != nil {
					t.Fatal("unready clock allowed renewal")
				}
				return
			}
			// A failed durable chain record leaves the old schedule untouched and retries.
			if _, err := n.db.Exec(`CREATE TRIGGER refuse_renewal BEFORE INSERT ON tesla_chains BEGIN SELECT RAISE(ABORT,'unavailable storage'); END`); err != nil {
				t.Fatal(err)
			}
			initial := n.schedule
			if err := n.prepareChainRenewal(t.Context(), s); err == nil || n.nextSchedule != nil || n.schedule != initial {
				t.Fatal("failed persistence replaced schedule")
			}
			if _, err := n.db.Exec(`DROP TRIGGER refuse_renewal`); err != nil {
				t.Fatal(err)
			}
			for rotation := 0; rotation < 2; rotation++ {
				old := n.schedule
				if err := n.prepareChainRenewal(t.Context(), s); err != nil {
					t.Fatal(err)
				}
				next := n.nextSchedule
				if next == nil || bytes.Equal(next.Anchor(), old.Anchor()) || n.schedule != old || s.executor.teslaSchedule != old {
					t.Fatal("renewal changed a live session or reused keys")
				}
				chains := recordedChains(t, n.db)
				if len(chains) != rotation+2 || !bytes.Equal(chains[len(chains)-1].Anchor, next.Anchor()) {
					t.Fatal("next chain not durably recorded")
				}
				if err := n.prepareChainRenewal(t.Context(), s); err != nil || len(recordedChains(t, n.db)) != rotation+2 {
					t.Fatal("retry created another chain")
				}
				n.disclosureDelivery.storedThrough = 9
				n.chainReport.exhausted = true
				stopRenewalSession(t, s)
				var err error
				s, err = NewSession(n, n.db)
				if err != nil {
					t.Fatal(err)
				}
				if n.schedule != next || s.executor.teslaSchedule != next || n.disclosureDelivery.storedThrough != 0 || n.chainReport.exhausted {
					t.Fatal("new session did not install/reset chain state")
				}
				hello, err := s.executor.OnHello(t.Context(), &pb.HelloRequest{})
				if err != nil || !bytes.Equal(hello.TeslaAnchorKey, next.Anchor()) {
					t.Fatalf("Hello omitted replacement anchor: %v", err)
				}
				// A failed Hello/reconnect keeps this same registered candidate; it does
				// not mint another generation or run an old queued row.
				stopRenewalSession(t, s)
				s, err = NewSession(n, n.db)
				if err != nil || n.schedule != next || n.nextSchedule != nil {
					t.Fatalf("reconnect changed candidate: %v", err)
				}
			}
		})
	}
}

func TestUploadCannotReservePastChainExpiry(t *testing.T) {
	storage := &uploadBindingScheduler{abortTestScheduler: &abortTestScheduler{}}
	e, _ := newExecutorRPCFixture(t, newOperationPeer(), storage)
	req := boundsUploadRequest()
	req.Policy.TimeoutMs = e.teslaSchedule.Expiry().Sub(time.Now()).Milliseconds() + 1000
	if _, err := e.OnUpload(t.Context(), operationBinding(), req); err == nil || len(storage.inserted) != 0 {
		t.Fatalf("accepted reservation across renewal: %v", err)
	}
	e.renewing.Store(true)
	req = boundsUploadRequest()
	if _, err := e.OnUpload(t.Context(), operationBinding(), req); err == nil || len(storage.inserted) != 0 {
		t.Fatalf("admitted while renewing: %v", err)
	}
	if errors.Is(scheduler.ErrDraining, scheduler.ErrClosed) {
		t.Fatal("graceful admission drain confused with shutdown")
	}
}

func TestRenewalLeadWindowKeepsAdmissionOpenWhileWorkIsQueued(t *testing.T) {
	_, owner := renewalSession(t, "")
	e, _ := newExecutorRPCFixture(t, newOperationPeer(), nil)
	e.session = owner
	clock := &deliveryClock{mono: 90 * time.Second, wall: 90 * time.Second}
	e.teslaSchedule = deliverySchedule(t, clock)
	first := boundsUploadRequest()
	first.Policy.TimeoutMs = 1000
	first.StartTime = timestamppb.New(time.Now().Add(5 * time.Second))
	if _, err := e.OnUpload(t.Context(), operationBinding(), first); err != nil {
		t.Fatal(err)
	}
	e.beginChainRenewal(time.Now())
	if e.renewing.Load() {
		t.Fatal("early renewal closed admission around accepted future work")
	}
	second := boundsUploadRequest()
	second.Policy.TimeoutMs = 1000
	if _, err := e.OnUpload(t.Context(), operationBinding(), second); err != nil {
		t.Fatalf("short run refused during lead window: %v", err)
	}
	clock.mono, clock.wall = 100*time.Second, 100*time.Second
	e.beginChainRenewal(time.Now())
	if !e.renewing.Load() || e.scheduler.IsDrained() {
		t.Fatal("expiry did not drain accepted work")
	}
	if _, err := e.OnUpload(t.Context(), operationBinding(), boundsUploadRequest()); err == nil {
		t.Fatal("expiry drain allowed new work")
	}
	for _, request := range []*pb.UploadRequest{first, second} {
		present, err := e.scheduler.CancelBound(t.Context(), uuid.MustParse(request.Id), operationBinding(), context.Canceled)
		if err != nil || !present {
			t.Fatalf("drain lost accepted work: %v %v", present, err)
		}
	}
	if !e.scheduler.IsDrained() {
		t.Fatal("accepted work did not join")
	}
}
