package ratelimit

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"syscall"
	"testing"

	"github.com/netsec-ethz/debuglet/internal/executor/ratelimit/cleanup"
	"github.com/netsec-ethz/debuglet/internal/executor/ratelimit/fallback"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
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

func TestPacketCounterLoadRefusalFallsBack(t *testing.T) {
	// The factory errors have the shape the eBPF constructor returns for a
	// failed load: a refused load is a plain error, any other load failure
	// carries ErrCleanupUnconfirmed.
	for _, tc := range []struct {
		name  string
		cause error
		fatal bool
	}{
		{"eperm", syscall.EPERM, false},
		{"eacces", syscall.EACCES, false},
		{"einval", syscall.EINVAL, false},
		{"other_load_error", syscall.ENOMEM, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			core, logs := observer.New(zapcore.DebugLevel)
			count, err := newPacketCount(&net.Interface{Index: 8}, zap.New(core), func(*net.Interface) (PacketCount, error) {
				loadErr := fmt.Errorf("failed to load eBPF objects: map create: %w", tc.cause)
				if tc.fatal {
					return nil, errors.Join(cleanup.ErrCleanupUnconfirmed, loadErr)
				}
				return nil, loadErr
			})
			if tc.fatal {
				if count != nil || !errors.Is(err, tc.cause) || logs.Len() != 0 {
					t.Fatalf("unrefused load fell back or lost cause: %v/%v, logs=%d", count, err, logs.Len())
				}
				return
			}
			if err != nil || count == nil || count.Type() != "fallback" {
				t.Fatalf("refused load fallback=%v/%v", count, err)
			}
			t.Cleanup(func() { _ = count.Close() })
			warnings := logs.FilterLevelExact(zapcore.WarnLevel).All()
			if logs.Len() != 1 || len(warnings) != 1 || !strings.Contains(fmt.Sprint(warnings[0].ContextMap()["error"]), tc.cause.Error()) {
				t.Fatalf("fallback logs=%v", logs.All())
			}
		})
	}
}

func TestPacketCounterNewWithoutPrivilegeFallsBack(t *testing.T) {
	iface, err := net.InterfaceByName("lo")
	if err != nil {
		t.Skipf("no loopback interface named lo: %v", err)
	}
	core, logs := observer.New(zapcore.WarnLevel)
	count, err := New(iface, zap.New(core))
	if err != nil {
		t.Fatalf("auto packet counter: %v", err)
	}
	defer func() {
		if err := count.Close(); err != nil {
			t.Errorf("packet counter cleanup: %v", err)
		}
	}()
	// With the eBPF capabilities the counter loads; without them the load is
	// refused and the fallback counter is used with one warning.
	if count.Type() == "fallback" && logs.Len() != 1 {
		t.Fatalf("fallback warnings=%d want=1", logs.Len())
	}
	if count.Type() == "ebpf" && logs.Len() != 0 {
		t.Fatalf("loaded counter logged warnings: %v", logs.All())
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
