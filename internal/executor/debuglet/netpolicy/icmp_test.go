// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package netpolicy

import (
	"errors"
	"fmt"
	"syscall"
	"testing"
)

func TestICMPReason(t *testing.T) {
	denied := fmt.Errorf("raw ICMPv4 sockets are not permitted: %w", syscall.EPERM)
	opens := func() error { return nil }
	refused := func() error { return syscall.EACCES }
	calledPing := false
	for _, tc := range []struct {
		name string
		err  error
		ping func() error
		want string
	}{
		{"permitted", nil, func() error { calledPing = true; return nil }, ""},
		{"permission denied", denied, refused, ICMPNotPermitted},
		{"ping socket only", denied, opens, ICMPPingSocketOnly},
		{"other failure", fmt.Errorf("wrapped: %w", syscall.EAFNOSUPPORT), func() error { calledPing = true; return nil }, ICMPUnsupported},
		{"opaque failure", errors.New("boom"), func() error { calledPing = true; return nil }, ICMPUnsupported},
	} {
		if got := icmpReason(tc.err, tc.ping); got != tc.want {
			t.Errorf("%s: got %q, want %q", tc.name, got, tc.want)
		}
	}
	if calledPing {
		t.Fatal("ping socket probed without a permission refusal")
	}
}

// The refreshed answer is what ICMPPermitted, and so guest admission, sees.
func TestRefreshICMPUpdatesPermitted(t *testing.T) {
	reason, err := RefreshICMP()
	if (err == nil) != (reason == "") {
		t.Fatalf("reason %q with error %v", reason, err)
	}
	if got := ICMPPermitted(); (got == nil) != (err == nil) {
		t.Fatalf("ICMPPermitted %v after refresh %v", got, err)
	}
}
