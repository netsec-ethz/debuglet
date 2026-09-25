package ratelimit

import (
	"errors"
	"fmt"
	"net"
	"testing"

	"github.com/netsec-ethz/debuglet/internal/executor/ratelimit/cleanup"
	"github.com/netsec-ethz/debuglet/internal/executor/ratelimit/fallback"
	"go.uber.org/zap"
)

func TestPacketCounterFallbackDecision(t *testing.T) {
	original := errors.New("constructor cause")
	for _, tc := range []struct {
		name   string
		marker error
		fatal  bool
	}{
		{"clean_attach_rollback", nil, false},
		{"release_failed", cleanup.ErrCleanupFailed, true},
		{"loader_rollback_unconfirmed", cleanup.ErrCleanupUnconfirmed, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var called bool
			count, err := newPacketCount(&net.Interface{Index: 8}, zap.NewNop(), func(iface *net.Interface) (PacketCount, error) {
				called = true
				if iface.Index != 8 {
					t.Error("factory interface changed")
				}
				return nil, fmt.Errorf("nested constructor: %w", errors.Join(original, tc.marker))
			})
			if !called {
				t.Fatal("BPF factory not called")
			}
			if tc.fatal {
				if count != nil || !errors.Is(err, original) || !errors.Is(err, tc.marker) {
					t.Fatalf("unsafe fallback or lost cause: %v/%v", count, err)
				}
			} else {
				if err != nil || count == nil || count.Type() != "fallback" {
					t.Fatalf("clean fallback=%v/%v", count, err)
				}
				if err := count.Close(); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}

func TestPacketCounterExplicitFallbackSkipsBPF(t *testing.T) {
	count, err := newPacketCount(nil, zap.NewNop(), func(*net.Interface) (PacketCount, error) {
		t.Error("explicit fallback invoked BPF constructor")
		return nil, cleanup.ErrCleanupUnconfirmed
	})
	if err != nil || count == nil || count.Type() != "fallback" {
		t.Fatalf("fallback=%v/%v", count, err)
	}
	if err := count.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestPacketCounterSuccessfulFactoryTransfersIdentity(t *testing.T) {
	// This known implementation provides a harmless identity witness; the
	// capable kernel test independently exercises the real BPF constructor.
	expected, err := fallback.NewFallbackCount()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = expected.Close() })
	actual, err := newPacketCount(&net.Interface{Index: 9}, zap.NewNop(), func(*net.Interface) (PacketCount, error) { return expected, nil })
	if err != nil || actual != expected {
		t.Fatalf("factory ownership changed: %v/%v", actual, err)
	}
}
