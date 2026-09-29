// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package ratelimit

import (
	"errors"
	"fmt"
	"net"
	"syscall"
	"testing"

	"go.uber.org/zap"
)

// A fallback counter carries a short reason for the eBPF refusal; the full
// error stays in the log.
func TestFallbackCounterRecordsReason(t *testing.T) {
	for _, tc := range []struct {
		name  string
		iface *net.Interface
		cause error
		want  string
	}{
		{"no interface", nil, nil, FallbackNoInterface},
		{"eperm", &net.Interface{Index: 3}, syscall.EPERM, FallbackNotPermitted},
		{"eacces", &net.Interface{Index: 3}, syscall.EACCES, FallbackNotPermitted},
		{"unsupported platform", &net.Interface{Index: 3}, errors.ErrUnsupported, FallbackUnsupported},
		{"eopnotsupp", &net.Interface{Index: 3}, syscall.EOPNOTSUPP, FallbackUnsupported},
		{"einval", &net.Interface{Index: 3}, syscall.EINVAL, FallbackAttachFailed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			count, err := newPacketCount(tc.iface, zap.NewNop(), func(*net.Interface) (PacketCount, error) {
				return nil, fmt.Errorf("attach tc program: %w", tc.cause)
			})
			if err != nil {
				t.Fatal(err)
			}
			defer count.Close()
			if got := FallbackReason(count); got != tc.want {
				t.Fatalf("reason %q, want %q", got, tc.want)
			}
		})
	}
}

type fakeEBPF struct{ PacketCount }

func (fakeEBPF) Type() string   { return "ebpf" }
func (fakeEBPF) Reason() string { return "leaked" }

func TestFallbackReasonIgnoresOtherCounters(t *testing.T) {
	if got := FallbackReason(fakeEBPF{}); got != "" {
		t.Fatalf("ebpf counter reason %q", got)
	}
}
