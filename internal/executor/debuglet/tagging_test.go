// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package debuglet

import (
	"bytes"
	"context"
	"net"
	"runtime"
	"testing"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/netsec-ethz/debuglet/internal/executor/debuglet/netpolicy"
	"github.com/netsec-ethz/debuglet/internal/executor/scheduler"
	"github.com/netsec-ethz/debuglet/internal/executor/tagger"
	"github.com/netsec-ethz/debuglet/internal/executor/tagger/ebpf"
	"github.com/netsec-ethz/debuglet/internal/executor/tagger/tesla"
)

// ExpectedTagging predicts the kernel tagger only where the eBPF counter
// loaded on an interface; IPv6 and SCION are never tagged.
func TestExpectedTagging(t *testing.T) {
	iface := &net.Interface{Index: 1, Name: "lo"}
	kernel := UserspaceTagging()
	if runtime.GOOS == "linux" {
		kernel = tagger.ModeEBPF
	}
	for _, tc := range []struct {
		name    string
		iface   *net.Interface
		counter string
		ipv4    string
	}{
		{"ebpf counter", iface, "ebpf", kernel},
		{"fallback counter", iface, "fallback", UserspaceTagging()},
		{"no interface", nil, "ebpf", UserspaceTagging()},
		{"no counter", nil, "", UserspaceTagging()},
	} {
		want := tagger.Mode{IPv4: tc.ipv4, IPv6: tagger.ModeNone, SCION: tagger.ModeNone}
		if got := ExpectedTagging(tc.iface, tc.counter); got != want {
			t.Errorf("%s: %+v, want %+v", tc.name, got, want)
		}
	}
}

// A run with the pure-Go tagger expects no attribution of its streams, so it
// keeps IPv6: nothing it sends is labelled attributable, and its mode says
// which IPv4 packets are tagged.
func TestUserspaceRunKeepsIPv6(t *testing.T) {
	schedule, err := tesla.NewKeySchedule(tesla.Config{Seed: bytes.Repeat([]byte{0x72}, 32), EpochLength: time.Second, ChainLength: 64})
	if err != nil {
		t.Fatal(err)
	}
	spec := netpolicy.Defaults()
	spec.LocalTargets = true
	operator, err := netpolicy.Parse(spec)
	if err != nil {
		t.Fatal(err)
	}
	d := newWithBPFTagger(zap.NewNop(), uuid.New(), "transaction", scheduler.Policy{Addresses: []string{"::1"}}, operator, schedule, nil, nil, nil, nil,
		func(*zap.Logger, *net.Interface, *tesla.KeySchedule, []byte) (*ebpf.BPFTagger, error) {
			t.Fatal("kernel tagger constructed without an interface")
			return nil, nil
		})
	t.Cleanup(func() { _ = d.Close(context.Background()) })
	if want := (tagger.Mode{IPv4: UserspaceTagging(), IPv6: tagger.ModeNone, SCION: tagger.ModeNone}); d.Tagging() != want {
		t.Fatalf("tagging %+v, want %+v", d.Tagging(), want)
	}
	if d.env.Net.RefusesIPv6() || d.Tagging().RefusesIPv6() {
		t.Fatal("pure-Go run refuses IPv6")
	}
	if _, err := d.env.Net.AdmitDestination(context.Background(), netpolicy.TCP, "[::1]:80"); err != nil {
		t.Fatalf("IPv6 destination of a pure-Go run: %v", err)
	}
}
