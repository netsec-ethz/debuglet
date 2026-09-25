// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

// Package sqlite keeps one executor's persisted work and terminal results
// across restarts without silently running stored work again. A failed write
// cannot provide that persistence guarantee.
//
// The in-memory core owns admission, owners and phases; this package owns the
// canonical rows behind them. Restoring reads the stored runs and applies the
// startup eligibility policy: a row whose control binding the new session cannot
// own is quarantined, which means it stays persisted, is never started under the
// new binding and is counted so an operator can see it. Terminal results are
// retained under the binding that chose them, and released, updated or kept as
// evidence as scheduler.TerminalRetention describes.
//
// Inspecting a stopped executor's database reports that disposition without
// running, starting or deleting anything.
package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"github.com/netsec-ethz/debuglet/internal/controlsession"
	"github.com/netsec-ethz/debuglet/internal/executor/database"
	"github.com/netsec-ethz/debuglet/internal/executor/scheduler"
	"github.com/netsec-ethz/debuglet/internal/executor/scheduler/memory"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
)

// SqliteStorage naively uses the memory storage under the hood, but saves all debuglet specs
// to a SQLite database to persist states across executor restarts.
type SqliteStorage struct {
	db          *sql.DB
	decorate    func(database.DBTX) database.DBTX
	local       *memory.MemoryStorage
	callbackMu  sync.RWMutex
	onStartCb   scheduler.StartFunc
	onFailedCb  scheduler.FailedFunc
	eligibility scheduler.RestoreEligibility
	quarantined atomic.Int64
	// retainedExits counts the terminal results this executor still holds
	// because it does not know whether the dispatcher accepted them.
	retainedExits atomic.Int64
}

var _ scheduler.Scheduler = (*SqliteStorage)(nil)

// NewStorage persists the in-memory core's accepted work. Its admission guards
// are the ones that core commits new reservations and queue promotion under.
func NewStorage(db *sql.DB, eligibility scheduler.RestoreEligibility, admission scheduler.Admission) (*SqliteStorage, error) {
	s := &SqliteStorage{db: db, eligibility: eligibility}
	local, err := memory.NewPersistentStorage(s.persist, s.finalize, s.inspectAbsent, admission)
	if err != nil {
		return nil, err
	}
	s.local = local
	s.local.RegisterOnStart(s.onStart)
	return s, nil
}

// withDatabase separates owned pool admission from statement execution. A
// waiting operation retains its existing core owner; cancellation of a caller's
// join cannot abandon a detached deletion/finalizer waiting for this connection.
// Generated queries consume/close their rows before returning, and the acquired
// connection is released before callbacks, reporting, or restore emission.
func (s *SqliteStorage) withDatabase(ctx context.Context, query func(context.Context, *database.Queries) error) error {
	conn, err := s.db.Conn(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	executionCtx, cancel := context.WithTimeout(ctx, scheduler.CleanupTimeout)
	defer cancel()
	var db database.DBTX = conn
	if s.decorate != nil {
		db = s.decorate(db)
	}
	return query(executionCtx, database.New(db))
}

func (s *SqliteStorage) RestoreFromDatabase(ctx context.Context) error {
	return s.local.Restore(ctx, s.restore)
}

// QuarantinedCount reports the count observed by the latest serialized restore.
// Callers serialize RestoreFromDatabase with startup and subsequent restores.
func (s *SqliteStorage) QuarantinedCount() int64 { return s.quarantined.Load() }

func (s *SqliteStorage) restore(ctx context.Context, emit func(scheduler.Spec) error) error {
	s.quarantined.Store(0)
	// Terminal results outlive the execution rows they describe. Counting them
	// first makes unreconciled work visible even when no queue row survives.
	var retained int64
	if err := s.withDatabase(ctx, func(ctx context.Context, queries *database.Queries) error {
		var err error
		retained, err = queries.CountDebugletExits(ctx)
		return err
	}); err != nil {
		return fmt.Errorf("failed to count retained terminal events: %w", err)
	}
	s.retainedExits.Store(retained)
	var offset int64 = 0

	for {
		var debs []database.Debuglet
		err := s.withDatabase(ctx, func(ctx context.Context, queries *database.Queries) error {
			var err error
			debs, err = queries.ListDebuglets(ctx, database.ListDebugletsParams{Limit: 100, Offset: offset})
			return err
		})
		if err != nil {
			return fmt.Errorf("failed to list debuglets from database: %w", err)
		}
		if len(debs) == 0 {
			break
		}
		offset += int64(len(debs))
		for _, deb := range debs {
			binding := controlsession.Binding{Incarnation: deb.DispatcherIncarnation, SessionID: deb.SessionID}
			if !binding.Valid() || s.eligibility == nil || !s.eligibility(binding) {
				s.quarantined.Add(1)
				continue
			}
			spec := scheduler.Spec{
				Binding:       binding,
				DebugletID:    deb.Uuid,
				StartTime:     &deb.StartTime.Time,
				Args:          deb.Args,
				Wasm:          nil,
				TransactionID: deb.TransactionID,
				Policy: scheduler.Policy{
					FloorBW:     deb.FloorBw,
					CeilBW:      deb.CeilBw,
					Timeout:     time.Duration(time.Duration(deb.TimeoutMs) * time.Millisecond),
					Addresses:   deb.Addresses,
					RequireICMP: deb.RequireIcmp,
					ListenUDP:   deb.ListenUdp,
					ListenTCP:   deb.ListenTcp,
					ListenSCION: deb.ListenScion,
				},
			}

			if err := emit(spec); err != nil {
				return fmt.Errorf("failed to insert debuglet %s into local storage: %w", deb.Uuid, err)
			}
		}
	}
	return nil
}

func (s *SqliteStorage) Insert(ctx context.Context, spec scheduler.Spec) error {
	return s.local.Insert(ctx, spec)
}

func (s *SqliteStorage) persist(ctx context.Context, spec scheduler.Spec) (scheduler.Spec, error) {
	if err := ctx.Err(); err != nil {
		return scheduler.Spec{}, err
	}
	startTime := time.Time{}
	if spec.StartTime != nil {
		startTime = *spec.StartTime
	}

	if err := s.withDatabase(ctx, func(ctx context.Context, queries *database.Queries) error {
		return queries.CreateDebuglet(ctx, database.CreateDebugletParams{
			Uuid:                  spec.DebugletID,
			DispatcherIncarnation: spec.Binding.Incarnation,
			SessionID:             spec.Binding.SessionID,
			StartTime:             database.NewUTCTime(startTime),
			Args:                  spec.Args,
			Wasm:                  spec.Wasm,
			TransactionID:         spec.TransactionID,
			// policy
			FloorBw:     spec.Policy.FloorBW,
			CeilBw:      spec.Policy.CeilBW,
			TimeoutMs:   spec.Policy.Timeout.Milliseconds(),
			Addresses:   spec.Policy.Addresses,
			RequireIcmp: spec.Policy.RequireICMP,
			ListenUdp:   spec.Policy.ListenUDP,
			ListenTcp:   spec.Policy.ListenTCP,
			ListenScion: spec.Policy.ListenSCION,
		})
	}); err != nil {
		return scheduler.Spec{}, err
	}

	spec.Wasm = nil // prevent storing WASM to avoid using up memory
	// The core completes this reservation without another caller-cancellation
	// or shutdown check: a successful write is what commits acceptance.
	return spec, nil
}

func (s *SqliteStorage) Remove(ctx context.Context, debugletID uuid.UUID) (bool, error) {
	return s.local.Remove(ctx, debugletID)
}

func (s *SqliteStorage) Cancel(ctx context.Context, id uuid.UUID, cause error) (bool, error) {
	return s.local.Cancel(ctx, id, cause)
}

func (s *SqliteStorage) CancelBound(ctx context.Context, id uuid.UUID, binding controlsession.Binding, cause error) (bool, error) {
	return s.local.CancelBound(ctx, id, binding, cause)
}

// inspectAbsent runs only after the core reserved an absent-owner inspection. It
// never deletes or emits quarantined work, even when the binding matches.
func (s *SqliteStorage) inspectAbsent(ctx context.Context, id uuid.UUID, binding controlsession.Binding) error {
	return s.withDatabase(ctx, func(ctx context.Context, q *database.Queries) error {
		row, err := q.GetDebugletByUUID(ctx, id)
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		stored := controlsession.Binding{Incarnation: row.DispatcherIncarnation, SessionID: row.SessionID}
		if !stored.Valid() || stored != binding {
			return scheduler.ErrBindingMismatch
		}
		return nil
	})
}

func (s *SqliteStorage) Shutdown(ctx context.Context) error { return s.local.Shutdown(ctx) }

func (s *SqliteStorage) finalize(ctx context.Context, debugletID uuid.UUID) error {
	if err := s.withDatabase(ctx, func(ctx context.Context, queries *database.Queries) error {
		return queries.DeleteDebuglet(ctx, debugletID)
	}); err != nil {
		return fmt.Errorf("failed to delete debuglet %s from database: %w", debugletID, err)
	}
	return nil
}

func (s *SqliteStorage) RegisterOnStart(cb scheduler.StartFunc) {
	s.callbackMu.Lock()
	defer s.callbackMu.Unlock()
	s.onStartCb = cb
}

func (s *SqliteStorage) RegisterFailed(cb scheduler.FailedFunc) {
	s.callbackMu.Lock()
	defer s.callbackMu.Unlock()
	s.onFailedCb = cb
}

func (s *SqliteStorage) onStart(ctx context.Context, spec scheduler.Spec) scheduler.Completion {
	s.callbackMu.RLock()
	start, failed := s.onStartCb, s.onFailedCb
	s.callbackMu.RUnlock()
	fail := func(err error) scheduler.Completion {
		if cause := context.Cause(ctx); cause != nil {
			err = cause
		}
		if failed == nil {
			return scheduler.Completion{CleanupErr: errors.New("onFailed is not registered")}
		}
		return failed(ctx, spec, err)
	}
	var oldStarted database.UTCTime
	err := s.withDatabase(ctx, func(ctx context.Context, queries *database.Queries) error {
		var err error
		oldStarted, err = queries.GetDebugletStarted(ctx, spec.DebugletID)
		return err
	})
	if err != nil {
		return fail(fmt.Errorf("read debuglet start marker: %w", err))
	}
	if !oldStarted.IsZero() {
		return fail(scheduler.ErrDebugletAlreadyStarted)
	}
	var deb database.Debuglet
	err = s.withDatabase(ctx, func(ctx context.Context, queries *database.Queries) error {
		var err error
		deb, err = queries.UpdateDebugletStarted(ctx, database.UpdateDebugletStartedParams{
			Uuid: spec.DebugletID, StartedAt: database.NewUTCTime(time.Now()),
		})
		return err
	})
	if err != nil {
		return fail(fmt.Errorf("write debuglet start marker: %w", err))
	}
	if cause := context.Cause(ctx); cause != nil {
		return fail(cause)
	}
	spec.Wasm = deb.Wasm
	return start(ctx, spec)
}

func (s *SqliteStorage) StartLoop(ctx context.Context) error {
	s.callbackMu.RLock()
	registered := s.onStartCb != nil
	s.callbackMu.RUnlock()
	if !registered {
		return errors.New("onStart is not registered")
	}
	return s.local.StartLoop(ctx)
}
