// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package netpolicy

import (
	"context"
	"errors"
	"net/netip"
	"testing"
)

// A destination the dispatcher denies is refused on every admission path, by
// name and by the addresses the name resolves to, with its own error, while
// other destinations and the operator's static denials behave as before.
func TestRevokedDestinationsAreRefused(t *testing.T) {
	ctx := context.Background()
	resolver := newResolver(map[string][]string{
		"denied.example": {"93.184.216.7"},
		"alias.example":  {"93.184.216.7"},
		"kept.example":   {"93.184.216.8"},
	})
	revoked := NewRevocations()
	spec := Defaults()
	spec.DeniedDestinations = "93.184.216.99"
	operator := mustParse(t, spec).WithRevocations(revoked)
	policy := New(operator, Run{
		Addresses: []string{"denied.example", "alias.example", "kept.example", "93.184.216.9", "93.184.216.99"},
		ListenTCP: true, ListenUDP: true,
	}, WithResolver(resolver))

	admitted, err := policy.AdmitDestination(ctx, TCP, "denied.example:443")
	if err != nil {
		t.Fatal("before the denial:", err)
	}
	revoked.Update([]string{"Denied.Example.", "93.184.216.9"}, true)

	denied := func(what string, err error) {
		t.Helper()
		if !errors.Is(err, ErrDestinationDenied) || !errors.Is(err, ErrDenied) {
			t.Errorf("%s = %v, want the destination denial", what, err)
		}
	}
	for _, transport := range []Transport{TCP, TLS, UDP} {
		_, err := policy.AdmitDestination(ctx, transport, "denied.example:443")
		denied(transport.String()+" connect by name", err)
		_, err = policy.AdmitDestination(ctx, transport, "alias.example:443")
		denied(transport.String()+" connect through another name", err)
		_, err = policy.AdmitDestination(ctx, transport, "93.184.216.7:443")
		denied(transport.String()+" connect by resolved address", err)
		_, err = policy.AdmitDestination(ctx, transport, "93.184.216.9:443")
		denied(transport.String()+" connect by denied address", err)
	}
	for _, transport := range []Transport{Inbound, UDP} {
		_, err := policy.AdmitAddr(ctx, transport, netip.MustParseAddrPort("93.184.216.7:5000"))
		denied(transport.String()+" peer of a denied name", err)
		_, err = policy.AdmitAddr(ctx, transport, netip.MustParseAddrPort("[::ffff:93.184.216.9]:5000"))
		denied(transport.String()+" peer at a denied address", err)
	}
	denied("socket of an earlier admission", admitted.CheckSocket("tcp", "93.184.216.7:443"))

	if _, err := policy.AdmitDestination(ctx, TCP, "kept.example:443"); err != nil {
		t.Errorf("a destination that is not denied was refused: %v", err)
	}
	if _, err := policy.AdmitAddr(ctx, Inbound, netip.MustParseAddrPort("93.184.216.8:5000")); err != nil {
		t.Errorf("a peer that is not denied was refused: %v", err)
	}
	_, err = policy.AdmitDestination(ctx, TCP, "93.184.216.99:443")
	if !errors.Is(err, ErrDenied) || errors.Is(err, ErrDestinationDenied) {
		t.Errorf("the operator's static denial changed: %v", err)
	}

	// The next full snapshot no longer denies the name: it is admitted again.
	revoked.Update([]string{"93.184.216.9"}, true)
	if _, err := policy.AdmitDestination(ctx, TCP, "denied.example:443"); err != nil {
		t.Errorf("a destination the snapshot allowed again is refused: %v", err)
	}
	// A request without a revision adds to the set instead of replacing it.
	revoked.Update([]string{"kept.example"}, false)
	_, err = policy.AdmitDestination(ctx, TCP, "93.184.216.9:443")
	denied("address after an additive update", err)
	_, err = policy.AdmitDestination(ctx, TCP, "kept.example:443")
	denied("name after an additive update", err)
}

// Revoked finds a run's connections to a denied name by the addresses the run
// resolved it to, including an answer it has since replaced, and an update
// closes them through every run that registered.
func TestRevocationClosesWatchedRuns(t *testing.T) {
	ctx := context.Background()
	resolver := newResolver(map[string][]string{"denied.example": {"93.184.216.7"}})
	revoked := NewRevocations()
	policy := New(mustParse(t, Defaults()).WithRevocations(revoked),
		Run{Addresses: []string{"denied.example", "93.184.216.8"}}, WithResolver(resolver))
	policy.ttl = 0
	if _, err := policy.AdmitDestination(ctx, TCP, "denied.example:443"); err != nil {
		t.Fatal(err)
	}
	resolver.set("denied.example", "93.184.216.17")
	if _, err := policy.AdmitDestination(ctx, TCP, "denied.example:443"); err != nil {
		t.Fatal(err)
	}

	var remotes []string
	stop := policy.WatchRevocations("run", func() int {
		closed := 0
		for _, remote := range []string{"93.184.216.7:443", "93.184.216.17:443", "93.184.216.8:443"} {
			if policy.Revoked(remote) {
				remotes = append(remotes, remote)
				closed++
			}
		}
		return closed
	})
	if got := revoked.Update(nil, true); len(got) != 0 || len(remotes) != 0 {
		t.Fatalf("an empty snapshot closed sockets: %v %v", got, remotes)
	}
	got := revoked.Update([]string{"denied.example"}, true)
	if len(got) != 1 || got[0] != (Revoked{Run: "run", Sockets: 2}) {
		t.Fatalf("revoked runs = %v", got)
	}
	if len(remotes) != 2 || remotes[0] != "93.184.216.7:443" || remotes[1] != "93.184.216.17:443" {
		t.Fatalf("closed %v, want both addresses of the denied name only", remotes)
	}
	if !policy.Revoked("[::ffff:93.184.216.7]:443") || policy.Revoked("93.184.216.8:443") || policy.Revoked("not an address") {
		t.Fatal("Revoked does not match by normalized address only")
	}
	stop()
	remotes = nil
	if got := revoked.Update([]string{"denied.example"}, true); len(got) != 0 || len(remotes) != 0 {
		t.Fatalf("a stopped run was asked to close: %v", got)
	}
}
