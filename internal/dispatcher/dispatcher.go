// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

// Package dispatcher holds the dispatcher's application state: the registry of
// the executors that currently hold a control session, admission of submitted
// runs against reserved capacity, and the results those runs report.
//
// An executor is in the registry as an entry keyed by its ID, holding the
// metadata of its session and the transport owner that session belongs to. The
// owner is the authority: an entry is exposed, and work is admitted for it, only
// while its owner is active, registered and inside its lease, never because an
// executor reported a heartbeat. The transport publishes an owner and calls
// registration under the setup operation it admitted for it; publication into
// the registry is committed under the owner's own guard, so a retirement racing
// it wins. Package transport/rpc defines owners, mutations and their lifetime.
//
// Callbacks from the control transport arrive with the mutation they were
// admitted under, and that mutation's owner is compared against the executor's
// current owner before any effect of it is applied. Work this package starts
// itself, uploading or aborting a run on an executor, admits its own mutation on
// that executor's owner, and a continuation that has to outlive the request
// which started it is forked from the live mutation rather than detached from it.
//
// Close closes admission first and then cancels and joins what this package
// owns: the registrations in flight, the lease expiry goroutine and the control
// transport. Cancelling is not completing — a canceled call is still waited for.
package dispatcher

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"github.com/netsec-ethz/debuglet/internal/controlsession"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/database"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/models"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/payments"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/resource"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/resource/schedule"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/tag"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/transport/rpc"
	"sync"
	"time"

	"go.uber.org/zap"
)

type Dispatcher struct {
	version     string
	incarnation string

	executors   map[string]*executorEntry
	leaseTiming controlsession.LeaseTiming
	keystore    *tag.KeyStore
	logger      *zap.Logger
	Bidi        *rpc.BidiServer
	mu          sync.RWMutex
	db          *sql.DB

	closed             bool
	restored           bool // set under mu once a RestoreScheduler call has succeeded
	closeOnce          sync.Once
	registrations      map[*registrationOperation]struct{}
	registrationWG     sync.WaitGroup
	expiryStop         chan struct{}
	expiryDone         chan struct{} // reserved under mu before the sole worker starts
	now                func() time.Time
	newExpiryTicker    func(time.Duration) expiryTicker
	initializeEarnings func(context.Context, *RegisteredExecutor)

	destinations *resource.DestinationsUsage
	Payment      *payments.PaymentHandler
	scheduler    *schedule.JobScheduler
}

func New(l *zap.Logger, db *sql.DB, version string, execTimeout, granularity time.Duration, paymentHandler *payments.PaymentHandler) (*Dispatcher, error) {
	leaseTiming, err := controlsession.NewLeaseTiming(execTimeout)
	if err != nil {
		return nil, fmt.Errorf("executor control lease: %w", err)
	}
	incarnation, err := controlsession.NewIncarnation()
	if err != nil {
		return nil, fmt.Errorf("create dispatcher incarnation: %w", err)
	}
	if granularity <= 0 {
		granularity = 30 * time.Second
	}
	d := &Dispatcher{
		version:         version,
		incarnation:     incarnation,
		executors:       make(map[string]*executorEntry),
		registrations:   make(map[*registrationOperation]struct{}),
		expiryStop:      make(chan struct{}),
		now:             time.Now,
		newExpiryTicker: func(period time.Duration) expiryTicker { return realExpiryTicker{time.NewTicker(period)} },
		leaseTiming:     leaseTiming,
		keystore:        tag.NewKeyStore(),
		logger:          l,
		db:              db,
		destinations:    resource.NewDestinations(resource.Gigabit),
		Payment:         paymentHandler,
		scheduler:       schedule.New(granularity),
	}

	d.initializeEarnings = func(ctx context.Context, exec *RegisteredExecutor) {
		d.Payment.CreateEarningsIfNotExists(exec.ID, exec.Currency, exec.SuiWallet, database.New(d.db), ctx)
	}
	d.Bidi, err = rpc.NewBidiServer(l, d, incarnation, leaseTiming.Duration)
	if err != nil {
		return nil, fmt.Errorf("create control transport: %w", err)
	}
	return d, nil
}

// ControlIncarnation is the nonsecret identity of this dispatcher lifetime. A
// transport installed in place of the one New built carries it unchanged.
func (d *Dispatcher) ControlIncarnation() string { return d.incarnation }

// ControlLeaseDuration is the lease policy of this dispatcher lifetime, retained
// with the incarnation by any such replacement.
func (d *Dispatcher) ControlLeaseDuration() time.Duration { return d.leaseTiming.Duration }

// RestoreScheduler reserves again, when the dispatcher starts, the floors of
// the stored runs whose window has not ended, or ended less than a minute ago,
// so that admission counts them as the previous dispatcher did. A run whose
// stored state is exited released its floor when it finished and reserves
// nothing; every other run, pending or of uncertain outcome, keeps its
// reservation until its window ends.
//
// Reservations are restored once per dispatcher lifetime: after a restore has
// succeeded, a further call reserves nothing and returns an error, so no run is
// counted twice. A call that fails has reserved nothing and may be repeated.
func (d *Dispatcher) RestoreScheduler(ctx context.Context) error {
	// mu is held from the check to the mark, so two calls cannot both restore.
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.restored {
		return errors.New("debuglet schedule was already restored in this dispatcher lifetime")
	}
	queries := database.New(d.db)
	debuglets, err := queries.ListDebugletsEndAfter(ctx, models.NewUTCTime(time.Now().Add(-1*time.Minute)))
	if err != nil {
		return fmt.Errorf("failed to list debuglets from database: %w", err)
	}
	d.logger.Info("Restoring debuglet schedule from database", zap.Int("count", len(debuglets)))
	for _, deb := range debuglets {
		if deb.State == models.RunStateExited {
			d.logger.Debug("Skipping finished debuglet", zap.String("debugletID", deb.Uuid.String()), zap.String("executor", deb.ExecutorID))
			continue
		}
		d.logger.Info("Restoring debuglet schedule", zap.String("executor", deb.ExecutorID), zap.Strings("addresses", deb.Addresses), zap.Time("from", deb.StartTime.Time), zap.Time("to", deb.EndTime.Time), zap.Int64("usage", deb.Usage))
		d.scheduler.Submit(schedule.Request{
			Executor:    deb.ExecutorID,
			From:        deb.StartTime.Time,
			To:          deb.EndTime.Time,
			Destination: deb.Addresses,
			Use:         resource.Bitrate(deb.Usage),
		})
	}
	d.restored = true
	return nil
}

// Close closes admission before it cancels and joins owned work. Resource Close
// and cancellation hooks never run under either shared map lock.
func (d *Dispatcher) Close() {
	d.closeOnce.Do(func() {
		d.mu.Lock()
		d.closed = true
		var cancel []context.CancelFunc
		for op := range d.registrations {
			cancel = append(cancel, op.cancel)
		}
		for _, entry := range d.executors {
			entry.owner.Retire()
		}
		clear(d.executors)
		close(d.expiryStop)
		expiryDone := d.expiryDone
		d.mu.Unlock()
		for _, stop := range cancel {
			stop()
		}
		d.Bidi.Close()
		d.registrationWG.Wait()
		if expiryDone != nil {
			<-expiryDone
		}
	})
}
func (d *Dispatcher) GetVersion() string         { return d.version }
func (d *Dispatcher) GetKeyStore() *tag.KeyStore { return d.keystore }

func (d *Dispatcher) SetDestinationLimit(destination string, limit resource.Bitrate) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.destinations.SetLimit(destination, limit)
	// TODO: Notify executors of the new limit if needed
}
