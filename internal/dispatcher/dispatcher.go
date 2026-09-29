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
	"github.com/netsec-ethz/debuglet/internal/bitrate"
	"github.com/netsec-ethz/debuglet/internal/controlsession"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/config"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/database"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/models"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/payments"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/resource"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/resource/schedule"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/tag"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/transport/rpc"
	"sync"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

type Dispatcher struct {
	version     string
	incarnation string

	executors    map[string]*executorEntry
	leaseTiming  controlsession.LeaseTiming
	keystore     *tag.KeyStore
	logger       *zap.Logger
	Bidi         *rpc.BidiServer
	mu           sync.RWMutex
	db           *sql.DB
	outputLimits config.OutputConfig
	attribution  config.AttributionConfig
	display      map[string]config.ExecutorDisplay

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
	reservations map[uuid.UUID]schedule.Request
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
		attribution:     config.DefaultAttributionConfig(),
		logger:          l,
		db:              db,
		outputLimits:    config.DefaultOutputConfig(),
		destinations:    resource.NewDestinations(bitrate.Gigabit),
		Payment:         paymentHandler,
		scheduler:       schedule.New(granularity),
		reservations:    make(map[uuid.UUID]schedule.Request),
	}

	if db != nil {
		d.keystore = tag.NewPersistentKeyStore(attributionBackend{db: db})
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
// the stored runs whose window has not ended, so that admission counts them as
// the previous dispatcher did. A run whose stored state is exited reserves
// nothing: every resource a terminal release frees is held in memory only, so
// a restart leaves nothing of it to release. Every other run, pending or of
// uncertain outcome, keeps its reservation until its window ends. A run whose
// window ended less than expiredWindowGrace ago is logged and not reserved. Release uses run identity, so a skipped reservation
// cannot subtract another run's floor in overlapping rounded buckets.
//
// A restored run bound to a previous dispatcher lifetime is logged as a
// warning with its ID: its control session ended with that lifetime, so it
// will not execute, and its reservation lasts until the run is cancelled or it
// is classified with outcome unknown after its window ends. A run without a
// complete stored binding cannot be cancelled or classified; its reservation
// lasts until its window ends.
//
// Reservations are restored once per dispatcher lifetime: after a restore has
// succeeded, a further call reserves nothing and returns an error, so no run is
// counted twice. A call that fails has reserved nothing and may be repeated. A
// successful restore also starts the expiry loop if no executor registration
// has started it yet, so a restarted dispatcher classifies ended windows
// before any executor connects.
func (d *Dispatcher) RestoreScheduler(ctx context.Context) error {
	// mu is held from the check to the mark, so two calls cannot both restore.
	var startExpiry chan struct{}
	d.mu.Lock()
	defer func() {
		d.mu.Unlock()
		if startExpiry != nil {
			go d.runExpiry(startExpiry)
		}
	}()
	if d.restored {
		return errors.New("debuglet schedule was already restored in this dispatcher lifetime")
	}
	now := d.now()
	queries := database.New(d.db)
	debuglets, err := queries.ListDebugletsEndAfter(ctx, models.NewUTCTime(now.Add(-expiredWindowGrace)))
	if err != nil {
		return fmt.Errorf("failed to list debuglets from database: %w", err)
	}
	d.logger.Info("Restoring debuglet schedule from database", zap.Int("count", len(debuglets)))
	for _, deb := range debuglets {
		if deb.State == models.RunStateExited {
			d.logger.Debug("Skipping finished debuglet", zap.String("debugletID", deb.Uuid.String()), zap.String("executor", deb.ExecutorID))
			continue
		}
		if !deb.EndTime.Time.After(now) {
			msg := "Not reserving debuglet whose window has ended; it will be classified with outcome unknown"
			if deb.DispatcherIncarnation == "" || deb.SessionID == "" {
				msg = "Not reserving debuglet whose window has ended; it has no complete control binding and keeps its stored state"
			}
			d.logger.Info(msg, zap.String("debugletID", deb.Uuid.String()), zap.String("executor", deb.ExecutorID), zap.Time("to", deb.EndTime.Time))
			continue
		}
		d.logger.Info("Restoring debuglet schedule", zap.String("executor", deb.ExecutorID), zap.Strings("addresses", deb.Addresses), zap.Time("from", deb.StartTime.Time), zap.Time("to", deb.EndTime.Time), zap.Int64("usage", deb.Usage))
		if deb.DispatcherIncarnation == "" || deb.SessionID == "" {
			d.logger.Warn("Restored debuglet has no complete control binding; cancellation is unavailable and its reservation lasts until its window ends",
				zap.String("debugletID", deb.Uuid.String()), zap.String("executor", deb.ExecutorID), zap.Time("from", deb.StartTime.Time), zap.Time("to", deb.EndTime.Time))
		} else if deb.DispatcherIncarnation != d.incarnation {
			d.logger.Warn("Restored debuglet belongs to a previous dispatcher lifetime; its control session has ended and it will not execute; cancelling it releases its reservation",
				zap.String("debugletID", deb.Uuid.String()), zap.String("executor", deb.ExecutorID), zap.Time("from", deb.StartTime.Time), zap.Time("to", deb.EndTime.Time))
		}
		d.reserveFloor(deb.Uuid, schedule.Request{
			Executor:    deb.ExecutorID,
			From:        deb.StartTime.Time,
			To:          deb.EndTime.Time,
			Destination: deb.Addresses,
			Use:         bitrate.Bitrate(deb.Usage),
		})
	}
	d.restored = true
	if !d.closed && d.expiryDone == nil {
		d.expiryDone = make(chan struct{})
		startExpiry = d.expiryDone
	}
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

// SetDestinationLimit records the limit of destination and sends the share it
// recomputes to every executor holding an allocation there, waiting up to
// five seconds, on a context of its own, for those deliveries. A limit below
// the floors already charged or reserved there is refused with resource.ErrCapacityFull
// before anything is recorded or sent. Otherwise the limit governs admission
// at once and stays recorded whether or not every executor acknowledged; the
// error joins the failed deliveries.
func (d *Dispatcher) SetDestinationLimit(destination string, limit bitrate.Bitrate) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	work, err := d.captureFairshareAfter(ctx, nil, []string{destination}, func() error {
		// Runs admitted for a window still ahead hold their floors only in
		// the scheduler; a lower limit would fail them at their allocation.
		if reserved := d.scheduler.QueryMaxDest(destination, d.now(), maxReservableTime); limit < reserved {
			return fmt.Errorf("%s destination limit below its reserved floors (want %s, reserved %s): %w", destination, limit, reserved, resource.ErrCapacityFull)
		}
		return d.destinations.SetLimit(destination, limit)
	})
	if err != nil {
		return err
	}
	return work.send(ctx)
}
