// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package dispatcher

import (
	"errors"
	"slices"
	"strings"

	"github.com/netsec-ethz/debuglet/internal/ipmetadata"
	"github.com/netsec-ethz/debuglet/pkg/wire"
)

// ConfigureIPMetadata fixes the offline database readers before registration.
// The caller owns readers and closes them only after dispatcher shutdown.
func (d *Dispatcher) ConfigureIPMetadata(databases *ipmetadata.Databases) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed || d.restored || len(d.executors) != 0 || len(d.registrations) != 0 {
		return errors.New("IP metadata must be configured before dispatcher startup")
	}
	d.ipMetadata = databases
	return nil
}

func (e *RegisteredExecutor) collectIPMetadata(databases *ipmetadata.Databases, optOut bool) {
	source := wire.SourceExecutorReported
	if e.sourceIPObserved {
		source = wire.SourceDispatcherObserved
	}
	at := e.LastSeen.Unix()
	m := &wire.IPMetadata{
		Observed:       databases.Lookup(e.sourceIp, source, at, optOut),
		Advertised:     databases.Lookup(e.PublicHost(), wire.SourceExecutorReported, at, optOut),
		LocationOptOut: optOut, Disagreements: []string{},
	}
	if a, b := m.Observed.ASN.Value, m.Advertised.ASN.Value; a != nil && b != nil && a.Number != b.Number {
		m.Disagreements = append(m.Disagreements, "observed_advertised_asn")
	}
	if a, b := m.Observed.Location.Value, m.Advertised.Location.Value; locationsDiffer(a, b) {
		m.Disagreements = append(m.Disagreements, "observed_advertised_location")
	}
	operator := &wire.GeoLocation{City: e.display.City, Country: e.display.Country}
	if locationsDiffer(operator, m.Observed.Location.Value) || locationsDiffer(operator, m.Advertised.Location.Value) {
		m.Disagreements = append(m.Disagreements, "operator_location")
	}
	e.ipMetadata = m
}

func locationsDiffer(a, b *wire.GeoLocation) bool {
	if a == nil || b == nil {
		return false
	}
	return a.Country != "" && b.Country != "" && a.Country != b.Country || a.City != "" && b.City != "" && !strings.EqualFold(a.City, b.City)
}

// IPMetadata is independent of the registry's immutable observation. Raw
// addresses remain private; the result's existing source_ip/public_host carry
// those lookup keys for its owner.
func (e *RegisteredExecutor) IPMetadata() *wire.IPMetadata {
	if e.ipMetadata == nil {
		return nil
	}
	out := *e.ipMetadata
	out.Disagreements = slices.Clone(out.Disagreements)
	out.Observed.ASN = cloneLookup(out.Observed.ASN)
	out.Observed.Location = cloneLookup(out.Observed.Location)
	out.Advertised.ASN = cloneLookup(out.Advertised.ASN)
	out.Advertised.Location = cloneLookup(out.Advertised.Location)
	return &out
}

func cloneLookup[T any](r wire.IPLookup[T]) wire.IPLookup[T] {
	if r.Value != nil {
		v := *r.Value
		r.Value = &v
	}
	if r.Source != nil {
		s := *r.Source
		r.Source = &s
	}
	return r
}
