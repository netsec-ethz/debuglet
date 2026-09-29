// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package netpolicy

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"
)

// TestRefuseIPv6RefusesUntaggedDestinations covers a run whose kernel tagger
// tags IPv4 only: an IPv6 destination is refused with ErrUntagged before any
// socket exists, while the same destination is admitted to a run that does
// not expect attribution.
func TestRefuseIPv6RefusesUntaggedDestinations(t *testing.T) {
	run := Run{Addresses: []string{"::1", "127.0.0.1"}, RequireICMP: true}
	tagged := New(mustParse(t, localProfile()), Run{Addresses: run.Addresses, RefuseIPv6: true}, WithResolver(newResolver(nil)))
	untagged := New(mustParse(t, localProfile()), run, WithResolver(newResolver(nil)))
	if !tagged.RefusesIPv6() || untagged.RefusesIPv6() {
		t.Fatal("RefusesIPv6 does not follow the run")
	}
	for _, transport := range []Transport{TCP, TLS, UDP} {
		_, err := tagged.AdmitDestination(context.Background(), transport, "[::1]:8080")
		if !errors.Is(err, ErrUntagged) || errors.Is(err, ErrDenied) || errors.Is(err, ErrNotInPolicy) {
			t.Errorf("%s to [::1]: %v, want only ErrUntagged", transport, err)
		}
		if err == nil || !strings.Contains(err.Error(), "::1") || !strings.Contains(err.Error(), transport.String()) {
			t.Errorf("%s refusal %v does not name the transport and address", transport, err)
		}
		if _, err := untagged.AdmitDestination(context.Background(), transport, "[::1]:8080"); err != nil {
			t.Errorf("%s to [::1] refused without attribution: %v", transport, err)
		}
		if _, err := tagged.AdmitDestination(context.Background(), transport, "127.0.0.1:8080"); err != nil {
			t.Errorf("%s to an IPv4 destination refused: %v", transport, err)
		}
		// An IPv4-mapped address is the IPv4 address it carries, which the
		// kernel sends as IPv4 and the tagger tags.
		if _, err := tagged.AdmitDestination(context.Background(), transport, "[::ffff:127.0.0.1]:8080"); err != nil {
			t.Errorf("%s to an IPv4-mapped destination refused: %v", transport, err)
		}
	}
}

// TestRefuseIPv6KeepsTheIPv4AddressesOfAName covers a dual-stack name: only
// its IPv4 addresses are dialled, so the name stays reachable and no IPv6
// packet is sent; a name with IPv6 addresses only is refused.
func TestRefuseIPv6KeepsTheIPv4AddressesOfAName(t *testing.T) {
	resolver := newResolver(map[string][]string{
		"dual.example": {"::1", "127.0.0.1"},
		"six.example":  {"::1"},
	})
	policy := New(mustParse(t, localProfile()), Run{Addresses: []string{"dual.example", "six.example"}, RefuseIPv6: true},
		WithResolver(resolver))
	destination, err := policy.AdmitDestination(context.Background(), TCP, "dual.example:80")
	if err != nil {
		t.Fatalf("dual-stack name refused: %v", err)
	}
	if got := destination.DialAddresses(); len(got) != 1 || got[0] != "127.0.0.1:80" {
		t.Fatalf("dual-stack name dials %q, want its IPv4 address only", got)
	}
	if err := destination.CheckSocket("tcp6", "[::1]:80"); !errors.Is(err, ErrDenied) {
		t.Errorf("the dropped IPv6 address passed the socket gate: %v", err)
	}
	if _, err := policy.AdmitDestination(context.Background(), TCP, "six.example:80"); !errors.Is(err, ErrUntagged) {
		t.Errorf("IPv6-only name: %v, want ErrUntagged", err)
	}
}

// TestRefuseIPv6RefusesIPv6Peers covers peers the host already holds, and
// SCION, whose traffic is labelled untagged rather than refused.
func TestRefuseIPv6RefusesIPv6Peers(t *testing.T) {
	spec := localProfile()
	spec.SCION = true
	policy := New(mustParse(t, spec), Run{Addresses: []string{"::1", "127.0.0.1"}, ListenTCP: true, RefuseIPv6: true},
		WithResolver(newResolver(nil)))
	if _, err := policy.AdmitAddr(context.Background(), Inbound, netip.MustParseAddrPort("[::1]:54321")); !errors.Is(err, ErrUntagged) {
		t.Errorf("IPv6 inbound peer: %v, want ErrUntagged", err)
	}
	if _, err := policy.AdmitAddr(context.Background(), UDP, netip.MustParseAddrPort("[::1]:53")); !errors.Is(err, ErrUntagged) {
		t.Errorf("IPv6 datagram peer: %v, want ErrUntagged", err)
	}
	if _, err := policy.AdmitAddr(context.Background(), Inbound, netip.MustParseAddrPort("127.0.0.1:54321")); err != nil {
		t.Errorf("IPv4 inbound peer refused: %v", err)
	}
	if _, err := policy.AdmitAddr(context.Background(), SCION, netip.MustParseAddrPort("[::1]:30041")); err != nil {
		t.Errorf("SCION host address over IPv6 refused: %v", err)
	}
}
