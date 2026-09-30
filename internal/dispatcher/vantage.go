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
	clock     *wire.ClockReport  // Nil unknown.
	platform  *wire.HostPlatform // Nil unknown; operator-only.
}

// Unknown versions and malformed ISD-AS or listeners discard the whole report,
// as for capabilities, so a bad field cannot be published as a claim. The
// probe fields added later within schema 1 are validated alone: a malformed
// clock or platform leaves that field unknown and keeps the rest.
func vantageFromReport(report *pb.VantagePointReport) *vantageReport {
	out := networkFromReport(report)
	if out == nil {
		return nil
	}
	if report.Clock != nil {
		out.clock = clockFromReport(report.Clock)
	}
	if report.Platform != nil {
		out.platform = platformFromReport(report.Platform)
	}
	return out
}

// maxClockError bounds a reported error estimate; the kernel caps maxerror at
// 16 s, and anything beyond an hour is not a disciplined clock.
const maxClockError = time.Hour

func clockFromReport(report *pb.ClockState) *wire.ClockReport {
	bound := report.GetErrorBoundNs()
	if bound <= 0 || bound > int64(time.Minute) {
		return nil
	}
	valid := func(ns *int64) bool { return ns == nil || (*ns >= 0 && *ns <= int64(maxClockError)) }
	if !valid(report.EstimatedErrorNs) || !valid(report.MaxErrorNs) {
		return nil
	}
	estimated, maximum := report.EstimatedErrorNs, report.MaxErrorNs
	state, readiness, reason := report.GetState(), report.GetReadiness(), report.GetReason()
	// Readiness must follow from the state and the bound, so the dispatcher
	// never publishes a grade the reported numbers contradict.
	var want, wantReason string
	switch state {
	case "synced":
		switch {
		case estimated == nil:
			want = "unknown"
		case *estimated > bound:
			want, wantReason = "degraded", "error_exceeds_bound"
		default:
			want = "ready"
		}
	case "unsynced", "unknown":
		if estimated != nil || maximum != nil {
			return nil
		}
		want = "unknown"
		if state == "unsynced" {
			want, wantReason = "degraded", "unsynced"
		}
	default:
		return nil
	}
	if readiness != want || reason != wantReason {
		return nil
	}
	out := &wire.ClockReport{State: state, ErrorBoundNS: bound, Readiness: readiness, Reason: reason}
	if estimated != nil {
		value := *estimated
		out.EstimatedErrorNS = &value
	}
	if maximum != nil {
		value := *maximum
		out.MaxErrorNS = &value
	}
	return out
}

// Platform text is short printable ASCII; GOOS and GOARCH are lower-case
// identifiers.
func platformFromReport(report *pb.HostPlatform) *wire.HostPlatform {
	out := &wire.HostPlatform{}
	for _, field := range []struct {
		value string
		limit int
		ident bool
		dst   **string
	}{
		{report.GetOs(), 32, true, &out.OS}, {report.GetArch(), 32, true, &out.Arch},
		{report.GetKernelRelease(), 128, false, &out.KernelRelease}, {report.GetBuildVersion(), 64, false, &out.BuildVersion},
	} {
		if field.value == "" {
			continue
		}
		if len(field.value) > field.limit || !platformText(field.value, field.ident) {
			return nil
		}
		value := field.value
		*field.dst = &value
	}
	if cpus := report.GetCpus(); cpus > 0 {
		if cpus > 1<<16 {
			return nil
		}
		value := int64(cpus)
		out.CPUs = &value
	}
	if report.MemoryBytes != nil {
		if *report.MemoryBytes == 0 || *report.MemoryBytes > 1<<50 {
			return nil
		}
		value := *report.MemoryBytes
		out.MemoryBytes = &value
	}
	return out
}

func platformText(value string, ident bool) bool {
	for _, r := range value {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '_':
		case ident:
			return false
		case r > ' ' && r < 0x7f:
		default:
			return false
		}
	}
	return true
}

func networkFromReport(report *pb.VantagePointReport) *vantageReport {
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

// Display prefers operator metadata, with approximate database location when
// the operator supplied neither city nor country. Each value keeps its source.
func (e *RegisteredExecutor) Display() wire.ExecutorDisplay {
	c := e.display
	out := wire.ExecutorDisplay{
		DisplayName: labelled(c.DisplayName, wire.SourceOperator), City: labelled(c.City, wire.SourceOperator),
		Country: labelled(c.Country, wire.SourceOperator), Network: labelled(c.Network, wire.SourceOperator),
	}
	// An operator location overrides the whole automatic location, so an
	// operator country is never combined with an unrelated automatic city.
	if c.City == "" && c.Country == "" {
		if auto := e.automaticLocation(); auto.Value != nil && auto.Source != nil {
			out.City = labelled(auto.Value.City, *auto.Source)
			out.Country = labelled(auto.Value.Country, *auto.Source)
		}
	}
	return out
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

// Clock returns the live clock observation; unknown on an expired snapshot.
func (e *RegisteredExecutor) Clock() wire.ObservedClock {
	if e.vantage == nil || e.vantage.clock == nil {
		return wire.ObservedClock{}
	}
	observed, source, clock := e.vantageObserved.Unix(), wire.SourceExecutorReported, *e.vantage.clock
	return wire.ObservedClock{Value: &clock, Source: &source, ObservedAt: &observed}
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

// Caller holds the registry lock. The report is replaced, never mutated, so
// a shallow copy of the value is enough.
func admissionReport[T any](entry *executorEntry, value *T, now time.Time) wire.LabelledReport[T] {
	if value == nil {
		return wire.LabelledReport[T]{}
	}
	copied, source, observed := *value, wire.SourceExecutorReported, entry.vantageObserved.UTC()
	stale := vantageExpired(entry.vantageObserved, now)
	return wire.LabelledReport[T]{Value: &copied, Source: &source, ObservedAt: &observed, Stale: &stale}
}

// Caller holds the registry lock.
func admissionClock(entry *executorEntry, now time.Time) wire.LabelledReport[wire.ClockReport] {
	if entry.vantage == nil {
		return wire.LabelledReport[wire.ClockReport]{}
	}
	return admissionReport(entry, entry.vantage.clock, now)
}

// Caller holds the registry lock.
func admissionPlatform(entry *executorEntry, now time.Time) wire.LabelledReport[wire.HostPlatform] {
	if entry.vantage == nil {
		return wire.LabelledReport[wire.HostPlatform]{}
	}
	return admissionReport(entry, entry.vantage.platform, now)
}
