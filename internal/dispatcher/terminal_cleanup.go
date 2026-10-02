// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package dispatcher

import (
	"github.com/google/uuid"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/database"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/resource/schedule"
)

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

// releaseTerminalResources frees the in-memory destination allocations and
// floor reservation of a terminal or reclaimed run. Every release is keyed by run identity,
// so it is idempotent: a winner, a duplicate delivery after an earlier failure
// and a window sweep may all call it, and a run that was never reserved in this
// lifetime releases nothing. Payment handling is deliberately separate and is
// never retried here. Called with mu held.
func (d *Dispatcher) releaseTerminalResources(deb database.Debuglet) {
	for _, destination := range deb.Addresses {
		d.destinations.Remove(deb.Uuid, destination)
	}
	d.releaseFloor(deb.Uuid)
}

// releaseTerminal takes mu and releases a terminal run's resources.
func (d *Dispatcher) releaseTerminal(deb database.Debuglet) {
	d.mu.Lock()
	d.releaseTerminalResources(deb)
	d.mu.Unlock()
}
