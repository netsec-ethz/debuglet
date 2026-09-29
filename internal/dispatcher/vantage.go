// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package dispatcher

import (
	"errors"
	"maps"
	"slices"
	"time"

	"github.com/netsec-ethz/debuglet/internal/dispatcher/config"
	"github.com/netsec-ethz/debuglet/pkg/wire"
	pb "github.com/netsec-ethz/debuglet/protocol"
)

// vantageReport is a validated executor VantagePointReport. It is replaced,
// never mutated, so snapshots may share it.
type vantageReport struct {
	isdAS     string // Canonical; empty unknown.
	listeners []string
}

// Unknown versions and malformed content discard the whole report, as for
// capabilities, so a bad field cannot be published as a claim.
func vantageFromReport(report *pb.VantagePointReport) *vantageReport {
	if report.GetSchemaVersion() != 1 || len(report.GetListeners()) > 3 {
		return nil
	}
	out := &vantageReport{listeners: []string{}}
	if text := report.GetScionIsdAs(); text != "" {
		canonical, ok := wire.CanonicalISDAS(text)
		if !ok {
			return nil
		}
		out.isdAS = canonical
	}
	for _, listener := range report.GetListeners() {
		switch listener {
		case "tcp", "udp", "scion":
		default:
			return nil
		}
		if slices.Contains(out.listeners, listener) {
			return nil
		}
		out.listeners = append(out.listeners, listener)
	}
	return out
}

// ConfigureExecutorDisplay fixes operator display metadata before registration
// starts; each registration copies its executor's entry.
func (d *Dispatcher) ConfigureExecutorDisplay(executors map[string]config.ExecutorDisplay) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed || d.restored || len(d.executors) != 0 || len(d.registrations) != 0 {
		return errors.New("executor display metadata must be configured before dispatcher startup")
	}
	d.display = maps.Clone(executors)
	return nil
}

// Display is the operator's metadata, labelled operator where configured.
func (e *RegisteredExecutor) Display() wire.ExecutorDisplay {
	c := e.display
	return wire.ExecutorDisplay{
		DisplayName: labelled(c.DisplayName, wire.SourceOperator), City: labelled(c.City, wire.SourceOperator),
		Country: labelled(c.Country, wire.SourceOperator), Network: labelled(c.Network, wire.SourceOperator),
	}
}

// Vantage returns the live SCION ISD-AS and listener observations. Called on a
// snapshot, whose expired report is already cleared, both are then unknown.
func (e *RegisteredExecutor) Vantage() (wire.ObservedString, wire.ObservedList) {
	if e.vantage == nil {
		return wire.ObservedString{}, wire.ObservedList{}
	}
	observed := e.vantageObserved.Unix()
	source := wire.SourceExecutorReported
	listeners := wire.ObservedList{Value: slices.Clone(e.vantage.listeners), Source: &source, ObservedAt: &observed}
	if e.vantage.isdAS == "" {
		return wire.ObservedString{}, listeners
	}
	isdAS := e.vantage.isdAS
	return wire.ObservedString{Value: &isdAS, Source: &source, ObservedAt: &observed}, listeners
}

// Admission summarises a listed executor for selection: offline until its
// current session has sent a heartbeat, then maintenance while the operator's
// switch stops admission. Normal admission still decides each submission.
func (e *RegisteredExecutor) Admission(paused bool) string {
	switch {
	case !e.Ready:
		return wire.AdmissionOffline
	case paused:
		return wire.AdmissionMaintenance
	default:
		return wire.AdmissionReady
	}
}

func vantageExpired(observed, now time.Time) bool {
	return now.Before(observed) || now.Sub(observed) >= capabilityLifetime
}

// Caller holds the registry lock. Like capabilities, an expired ISD-AS is kept
// and marked stale, because a result records what was known at admission.
func admissionISDAS(entry *executorEntry, now time.Time) wire.LabelledObservation {
	if entry.vantage == nil || entry.vantage.isdAS == "" {
		return wire.LabelledObservation{}
	}
	value, source, observed := entry.vantage.isdAS, wire.SourceExecutorReported, entry.vantageObserved.UTC()
	stale := vantageExpired(entry.vantageObserved, now)
	return wire.LabelledObservation{Value: &value, Source: &source, ObservedAt: &observed, Stale: &stale}
}
