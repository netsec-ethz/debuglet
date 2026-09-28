// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package dispatcher

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/database"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/resource/schedule"
)

// completeTerminal selects the result and records its remaining local resource
// cleanup in one transaction. Resource release takes mu after SQL completes;
// terminal SQL itself must not block unrelated executor registry operations.
func (d *Dispatcher) completeTerminal(ctx context.Context, result database.CompleteDebugletParams) (database.Debuglet, error) {
	tx, err := d.db.BeginTx(ctx, nil)
	if err != nil {
		return database.Debuglet{}, err
	}
	defer tx.Rollback()
	q := database.New(tx)
	deb, err := q.CompleteDebuglet(ctx, result)
	if err != nil {
		return database.Debuglet{}, err
	}
	if err := q.CreateTerminalCleanup(ctx, deb.ID); err != nil {
		return database.Debuglet{}, err
	}
	if err := tx.Commit(); err != nil {
		return database.Debuglet{}, err
	}
	return deb, nil
}

// reserveFloor and releaseFloor use the original run identity. Called with mu
// held; an absent reservation cannot subtract another run's capacity.
func (d *Dispatcher) reserveFloor(id uuid.UUID, request schedule.Request) {
	if _, exists := d.reservations[id]; exists {
		return
	}
	request.Destination = append([]string(nil), request.Destination...)
	d.scheduler.Submit(request)
	d.reservations[id] = request
}

func (d *Dispatcher) releaseFloor(id uuid.UUID) {
	request, exists := d.reservations[id]
	if !exists {
		return
	}
	d.scheduler.Remove(request)
	delete(d.reservations, id)
}

// releaseTerminalResources is idempotent even if the durable completion write
// fails. Payment handling is deliberately separate and is never retried here.
// Called with mu held.
func (d *Dispatcher) releaseTerminalResources(deb database.Debuglet) {
	for _, destination := range deb.Addresses {
		d.destinations.Remove(deb.Uuid, destination)
	}
	d.releaseFloor(deb.Uuid)
}

func (d *Dispatcher) finishTerminalCleanup(ctx context.Context, id uuid.UUID) error {
	q := database.New(d.db)
	deb, err := q.GetTerminalCleanup(ctx, id)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read terminal resource cleanup: %w", err)
	}
	d.mu.Lock()
	d.releaseTerminalResources(deb)
	d.mu.Unlock()
	if err := q.DeleteTerminalCleanup(ctx, deb.ID); err != nil {
		return fmt.Errorf("record terminal resource cleanup: %w", err)
	}
	return nil
}

// restoreTerminalCleanup drains persisted work before startup restores floors.
// A terminal run was not restored in this lifetime, so its release is a no-op.
// Called with mu held; failed completion leaves the row available for retry.
func (d *Dispatcher) restoreTerminalCleanup(ctx context.Context) error {
	q := database.New(d.db)
	for {
		pending, err := q.ListTerminalCleanup(ctx, 128)
		if err != nil {
			return fmt.Errorf("list terminal resource cleanup: %w", err)
		}
		if len(pending) == 0 {
			return nil
		}
		for _, deb := range pending {
			d.releaseTerminalResources(deb)
			if err := q.DeleteTerminalCleanup(ctx, deb.ID); err != nil {
				return fmt.Errorf("restore terminal resource cleanup: %w", err)
			}
		}
	}
}
