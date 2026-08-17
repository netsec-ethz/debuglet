package sqlite

import (
	"context"
	"database/sql"
	"debuglet/internal/executor/database"
	"debuglet/internal/executor/scheduler"
	"debuglet/internal/executor/scheduler/memory"
	"fmt"
	"log"
	"time"
)

// SqliteStorage naively uses the memory storage under the hood, but saves all debuglet specs
// to a SQLite database to persist states across executor restarts.
type SqliteStorage struct {
	db        *sql.DB
	local     *memory.MemoryStorage
	onStartCb func(context.Context, scheduler.Spec)
}

var _ scheduler.Scheduler = (*SqliteStorage)(nil)

func NewStorage(db *sql.DB) *SqliteStorage {
	s := SqliteStorage{
		db:    db,
		local: memory.NewStorage(),
	}
	s.local.RegisterOnStart(s.onStart)
	return &s
}

func (s *SqliteStorage) RestoreFromDatabase(ctx context.Context) error {
	queries := database.New(s.db)
	var offset int64 = 0

	for {
		debs, err := queries.ListDebuglets(ctx, database.ListDebugletsParams{Limit: 100, Offset: offset})
		if err != nil {
			return fmt.Errorf("failed to list debuglets from database: %w", err)
		}
		if len(debs) == 0 {
			break
		}
		offset += int64(len(debs))
		for _, deb := range debs {
			spec := scheduler.Spec{
				DebugletID:    deb.ID,
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
					ListenICMP:  deb.ListenIcmp,
					ListenSCION: deb.ListenScion,
				},
			}

			if err := s.local.Insert(ctx, spec); err != nil {
				return fmt.Errorf("failed to insert debuglet %s into local storage: %w", deb.ID, err)
			}
		}
	}
	return nil
}

func (s *SqliteStorage) Insert(ctx context.Context, spec scheduler.Spec) error {
	startTime := time.Time{}
	if spec.StartTime != nil {
		startTime = *spec.StartTime
	}

	queries := database.New(s.db)
	if err := queries.CreateDebuglet(ctx, database.CreateDebugletParams{
		ID:            spec.DebugletID,
		StartTime:     database.NewUTCTime(startTime),
		Args:          spec.Args,
		Wasm:          spec.Wasm,
		TransactionID: spec.TransactionID,
		// policy
		FloorBw:     spec.Policy.FloorBW,
		CeilBw:      spec.Policy.CeilBW,
		TimeoutMs:   spec.Policy.Timeout.Milliseconds(),
		Addresses:   spec.Policy.Addresses,
		RequireIcmp: spec.Policy.RequireICMP,
		ListenUdp:   spec.Policy.ListenUDP,
		ListenTcp:   spec.Policy.ListenTCP,
		ListenIcmp:  spec.Policy.ListenICMP,
		ListenScion: spec.Policy.ListenSCION,
	}); err != nil {
		return err
	}

	spec.Wasm = nil // prevent storing WASM to avoid using up memory
	if err := s.local.Insert(ctx, spec); err != nil {
		return err
	}

	return nil
}

func (s *SqliteStorage) Remove(ctx context.Context, debugletID string) (bool, error) {
	exists, localErr := s.local.Remove(ctx, debugletID)
	queries := database.New(s.db)
	if err := queries.DeleteDebuglet(ctx, debugletID); err != nil {
		return false, fmt.Errorf("failed to delete debuglet %s from database: %w", debugletID, err)
	}
	return exists, localErr
}

func (s *SqliteStorage) RegisterOnStart(cb func(context.Context, scheduler.Spec)) {
	s.onStartCb = cb
}

func (s *SqliteStorage) onStart(ctx context.Context, spec scheduler.Spec) {
	queries := database.New(s.db)
	deb, err := queries.UpdateDebugletStarted(ctx, database.UpdateDebugletStartedParams{
		ID:        spec.DebugletID,
		StartedAt: database.NewUTCTime(time.Now()),
	})
	if err != nil {
		log.Printf("Failed to set debuglet %s as started in database: %v", spec.DebugletID, err)
		return
	}
	spec.Wasm = deb.Wasm

	s.onStartCb(ctx, spec)
	if err := queries.DeleteDebuglet(ctx, spec.DebugletID); err != nil {
		log.Printf("Failed to delete debuglet %s from database: %v", spec.DebugletID, err)
	}
}

func (s *SqliteStorage) StartLoop(ctx context.Context) error {
	return s.local.StartLoop(ctx)
}
