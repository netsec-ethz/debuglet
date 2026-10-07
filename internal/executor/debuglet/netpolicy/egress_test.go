// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package netpolicy

import (
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	pb "github.com/netsec-ethz/debuglet/protocol"
)

func testEgressGrant() *pb.EgressGrant {
	now := time.Now().Unix()
	return &pb.EgressGrant{Version: 1, BitsPerSecond: 8, BurstBytes: 64, Bytes: 64,
		AttemptsPerSecond: 1, AttemptBurst: 4, Attempts: 4, Addresses: []string{"127.0.0.1"}, NotBeforeUnix: now - 60, ExpiresUnix: now + 3600}
}

func TestEgressSharedConcurrentSockets(t *testing.T) {
	grant := testEgressGrant()
	e := NewEgress(grant)
	// Caller mutation cannot increase authority already accepted by a run.
	grant.Bytes, grant.BurstBytes = 1<<20, 1<<20
	var accepted atomic.Int64
	var wg sync.WaitGroup
	for range 16 {
		writer, reader := net.Pipe()
		conn := e.Wrap(writer)
		wg.Add(2)
		go func() { defer wg.Done(); defer reader.Close(); _, _ = io.Copy(io.Discard, reader) }()
		go func() {
			defer wg.Done()
			defer conn.Close()
			n, err := conn.Write(make([]byte, 16))
			if err != nil && !errors.Is(err, ErrDenied) {
				t.Errorf("write: %v", err)
			}
			accepted.Add(int64(n))
		}()
	}
	wg.Wait()
	if got := accepted.Load(); got != 64 {
		t.Fatalf("shared bytes = %d, want 64", got)
	}
	if err := e.Charge(1); !errors.Is(err, ErrDenied) {
		t.Fatalf("exhaustion: %v", err)
	}
}

func TestEgressAttemptsAndBursts(t *testing.T) {
	for _, limited := range []string{"total attempts", "attempt burst", "payload burst"} {
		t.Run(limited, func(t *testing.T) {
			g := testEgressGrant()
			if limited == "attempt burst" {
				g.Attempts = 100
			}
			if limited == "payload burst" {
				g.Bytes = 1000
			}
			e := NewEgress(g)
			if limited == "payload burst" {
				if err := e.Charge(65); !errors.Is(err, ErrDenied) {
					t.Fatalf("oversized write: %v", err)
				}
				if err := e.Charge(64); err != nil {
					t.Fatal(err)
				}
				if err := e.Charge(1); !errors.Is(err, ErrDenied) {
					t.Fatalf("burst: %v", err)
				}
				return
			}
			for range 4 {
				if err := e.Connect(netip.MustParseAddr("127.0.0.1")); err != nil {
					t.Fatal(err)
				}
			}
			if err := e.Connect(netip.MustParseAddr("127.0.0.1")); !errors.Is(err, ErrDenied) {
				t.Fatalf("attempt: %v", err)
			}
		})
	}
}

func TestEgressPinsAliasesAcrossDNSChanges(t *testing.T) {
	resolver := newResolver(map[string][]string{"target.example": {"127.0.0.1"}, "alias.example": {"127.0.0.1"}})
	policy := New(mustParse(t, localProfile()), Run{Addresses: []string{"target.example"}, Egress: NewEgress(testEgressGrant())}, WithResolver(resolver))
	policy.ttl = 0
	destination, err := policy.AdmitDestination(t.Context(), TCP, "alias.example:80")
	if err != nil {
		t.Fatal(err)
	}
	if err := destination.CheckSocket("tcp", "127.0.0.1:80"); err != nil {
		t.Fatal(err)
	}
	resolver.set("target.example", "127.0.0.2")
	resolver.set("alias.example", "127.0.0.2")
	if _, err := policy.AdmitDestination(t.Context(), TCP, "alias.example:80"); !errors.Is(err, ErrDenied) {
		t.Fatalf("DNS escaped grant: %v", err)
	}
}

func TestEgressExpiryCannotReactivate(t *testing.T) {
	e := NewEgress(testEgressGrant())
	before := time.Now()
	if err := e.activeAt(before); err != nil {
		t.Fatal(err)
	}
	if err := e.activeAt(e.deadline.Add(time.Nanosecond)); !errors.Is(err, ErrDenied) {
		t.Fatalf("expired: %v", err)
	}
	if err := e.activeAt(before); !errors.Is(err, ErrDenied) {
		t.Fatalf("backward clock reactivated: %v", err)
	}
	expired := testEgressGrant()
	expired.NotBeforeUnix, expired.ExpiresUnix = 1, 2
	if err := NewEgress(expired).Charge(1); !errors.Is(err, ErrDenied) {
		t.Fatalf("expired restore: %v", err)
	}
	invalid := testEgressGrant()
	invalid.BitsPerSecond = 0
	if err := NewEgress(invalid).Charge(1); !errors.Is(err, ErrDenied) {
		t.Fatalf("invalid: %v", err)
	}
}

func TestEgressPrefixAliases(t *testing.T) {
	for _, prefix := range []string{"127.0.0.0/8", "::ffff:127.0.0.0/104"} {
		if !MatchesPrefix(netip.MustParsePrefix(prefix), netip.MustParseAddr("::ffff:127.0.0.1")) {
			t.Fatalf("prefix %s missed mapped address", prefix)
		}
	}
}
