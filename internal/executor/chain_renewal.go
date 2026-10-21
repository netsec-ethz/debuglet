// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package executor

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/netsec-ethz/debuglet/internal/controlsession"
	"github.com/netsec-ethz/debuglet/internal/executor/scheduler"
	"github.com/netsec-ethz/debuglet/internal/executor/tagger"
	"github.com/netsec-ethz/debuglet/internal/hostprobe"
	pb "github.com/netsec-ethz/debuglet/protocol"
	"go.uber.org/zap"
)

func (e *Executor) beginChainRenewal(now time.Time) {
	if e.session == nil || e.session.node.db == nil || e.renewing.Load() {
		return
	}
	cfg := e.teslaSchedule.Config()
	lead := min(time.Hour, e.teslaSchedule.Expiry().Sub(cfg.Epoch)/10)
	elapsed, _ := cfg.Clock.Elapsed(cfg.Epoch, now)
	if elapsed < e.teslaSchedule.Expiry().Sub(cfg.Epoch)-lead {
		return
	}
	// Insert reservations made before this atomic drain remain accepted. The
	// scheduler keeps their callbacks/finalizers until IsDrained confirms joins.
	if elapsed < e.teslaSchedule.Expiry().Sub(cfg.Epoch) {
		if !e.scheduler.TryDrain() {
			return
		}
	} else {
		e.scheduler.BeginDrain()
	}
	e.renewing.Store(true)
	e.logger.Info("Renewing TESLA attribution keys: waiting for accepted work and disclosure acknowledgements")
}

func (e *Executor) attribution(now time.Time, mode tagger.Mode) *pb.AttributionState {
	if e.renewing.Load() {
		return &pb.AttributionState{State: "unavailable", Reason: "chain_renewing", Epoch: max(0, e.teslaSchedule.EpochOf(now))}
	}
	return attributionForTagging(e.teslaSchedule, now, mode)
}

// renewalSettled runs only after new admission is closed and every accepted
// operation, including tagger teardown, has joined. A successful response by
// itself is not disclosure: coverage must come from a matched durable receipt.
func (e *Executor) renewalSettled(ctx context.Context, binding controlsession.Binding) (bool, error) {
	if !e.renewing.Load() || !e.scheduler.IsDrained() {
		return false, nil
	}
	e.disclosureDelivery.mu.Lock()
	covered := e.disclosureDelivery.storedThrough >= e.teslaSchedule.HighestSigningEpoch()
	e.disclosureDelivery.mu.Unlock()
	if !covered {
		return false, nil
	}
	e.retired.mu.Lock()
	retired := e.retired.schedule != nil
	e.retired.mu.Unlock()
	if retired {
		return false, nil
	}
	if retention, ok := e.scheduler.(scheduler.TerminalRetention); ok {
		pending, err := retention.ListRetainedTerminals(ctx, binding, 1)
		if err != nil || len(pending) > 0 {
			return false, err
		}
	}
	if e.output != nil {
		pending, err := e.output.PendingForBinding(ctx, binding)
		if err != nil || pending {
			return false, err
		}
	}
	return true, nil
}

func (e *Executor) tryChainRenewal(ctx context.Context, binding controlsession.Binding) bool {
	if e.session == nil || !e.renewing.Load() {
		return false
	}
	callCtx, cancel := context.WithTimeout(ctx, scheduler.CleanupTimeout)
	defer cancel()
	settled, err := e.renewalSettled(callCtx, binding)
	if err == nil && settled {
		err = e.session.node.prepareChainRenewal(callCtx, e.session)
	}
	if err != nil {
		e.logger.Warn("TESLA chain renewal is waiting", zap.Error(err))
		return false
	}
	if !settled {
		return false
	}
	// The normal join/reconnect path consumes the pending schedule only after
	// this session has stopped. Hello announces it before any new admission.
	e.Bidi.Stop(sessionEnd(controlsession.TransportUnavailable, errors.New("TESLA chain renewed; reconnecting to announce the new schedule")))
	return true
}

func (n *Node) prepareChainRenewal(ctx context.Context, owner *Session) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.closed || n.active != owner {
		return errors.New("executor session no longer owns chain renewal")
	}
	if n.nextSchedule != nil {
		return nil
	}
	if clock := hostprobe.ReadClock(n.cfg.Clock.MaxErrorBound()); clock.Readiness != hostprobe.ReadinessReady {
		return fmt.Errorf("host clock is not ready: %s", clock.Reason)
	}
	next, _, clock, err := startChain(ctx, n.db, n.cfg.Tesla, n.cfg.Clock.MaxErrorBound())
	if err != nil {
		return err
	}
	if next.Config().ClockUnready {
		return fmt.Errorf("host clock lost readiness during renewal: %s", clock.Reason)
	}
	var proof []byte
	if n.opts.TLSConfig != nil {
		proof, err = signSchedule(n.cfg.Identity.ExecutorID, next, n.opts.TLSConfig.Certificates[0])
		if err != nil {
			return fmt.Errorf("sign renewed TESLA schedule: %w", err)
		}
	}
	n.nextSchedule, n.nextProof = next, proof
	n.logger.Info("Created replacement TESLA chain", zap.Time("expires_at", next.Expiry()))
	return nil
}
