// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package netpolicy

import (
	"errors"
	"net/netip"
	"sync"
	"testing"
)

func TestDenialObservationsCountFinalDecisions(t *testing.T) {
	r := NewRevocations()
	spec := Defaults()
	spec.DeniedDestinations = "93.184.216.7"
	p := New(mustParse(t, spec).WithRevocations(r), Run{Addresses: []string{"mixed.example", "93.184.216.8"}},
		WithResolver(newResolver(map[string][]string{"mixed.example": {"93.184.216.7", "93.184.216.8"}})))
	// One denied DNS candidate does not turn an admitted operation into a
	// refusal. A failed target lookup is not a policy decision.
	if _, err := p.AdmitDestination(t.Context(), TCP, "mixed.example:443"); err != nil {
		t.Fatal(err)
	}
	_, _ = p.AdmitDestination(t.Context(), TCP, "unknown.example:443")
	if refused, closed := r.DenialObservations(); refused != 0 || closed != 0 {
		t.Fatalf("success/errors counted: %d/%d", refused, closed)
	}
	var wg sync.WaitGroup
	for range 20 {
		wg.Go(func() {
			_, err := p.AdmitDestination(t.Context(), TCP, "93.184.216.7:443")
			if !errors.Is(err, ErrDenied) {
				t.Errorf("denied operation: %v", err)
			}
		})
	}
	wg.Wait()
	if _, err := p.AdmitAddr(t.Context(), TCP, netip.MustParseAddrPort("93.184.216.9:443")); !errors.Is(err, ErrNotInPolicy) {
		t.Fatal(err)
	}
	if refused, closed := r.DenialObservations(); refused != 21 || closed != 0 {
		t.Fatalf("final refusals: %d/%d", refused, closed)
	}
	// No watcher means no socket-close claim, regardless of policy entries.
	r.Update([]string{"93.184.216.8"}, true)
	if _, closed := r.DenialObservations(); closed != 0 {
		t.Fatal("policy mutation counted as socket closure")
	}
}
