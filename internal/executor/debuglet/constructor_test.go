//go:build linux

package debuglet

import (
	"bytes"
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
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

// The constructor fixture supplies a failed release with the same projection
// protocol as the BPF constructor. Actual attach/update rollback is separately
// exercised in ebpf; this fixture exercises the parent's real fallback path.
type constructorRollbackError struct{ err error }

func (e *constructorRollbackError) Error() string       { return e.err.Error() }
func (e *constructorRollbackError) Unwrap() error       { return e.err }
func (e *constructorRollbackError) CleanupError() error { return e.err }

type constructorResource struct {
	calls atomic.Int32
	err   error
}

func (r *constructorResource) Close() error { r.calls.Add(1); return r.err }

func TestDebugletConstructorFallbackCleanup(t *testing.T) {
	for _, failedRollback := range []bool{false, true} {
		name := "ordinary_unavailable"
		if failedRollback {
			name = "failed_rollback"
		}
		t.Run(name, func(t *testing.T) {
			schedule, err := tesla.NewKeySchedule(tesla.Config{Seed: bytes.Repeat([]byte{0x71}, 32), Delay: time.Second, ChainLength: 64})
			if err != nil {
				t.Fatal(err)
			}
			id := uuid.New()
			iface := &net.Interface{Index: 17, Name: "fixture"}
			initErr := errors.New("BPF unavailable")
			programErr, mapErr := errors.New("program release failed"), errors.New("map release failed")
			program, mapping := &constructorResource{}, &constructorResource{}
			if failedRollback {
				program.err, mapping.err = programErr, mapErr
			}
			var constructors atomic.Int32
			operator, err := netpolicy.Parse(localProfile())
			if err != nil {
				t.Fatal(err)
			}
			d := newWithBPFTagger(zap.NewNop(), id, "transaction", scheduler.Policy{}, operator, schedule, nil, nil, iface, nil,
				func(gotIface *net.Interface, gotSchedule *tesla.KeySchedule, measurement []byte) (*ebpf.BPFTagger, error) {
					constructors.Add(1)
					if gotIface != iface || gotSchedule != schedule || string(measurement) != id.String() {
						t.Error("BPF constructor inputs changed")
					}
					cleanup := errors.Join(program.Close(), mapping.Close())
					if cleanup != nil {
						return nil, errors.Join(initErr, &constructorRollbackError{cleanup})
					}
					return nil, initErr
				})
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			t.Cleanup(func() { _ = d.Close(context.Background()) })
			fallback, ok := d.env.Tagger.(*tagger.Tagger)
			if !ok || fallback.Schedule() != schedule {
				t.Fatalf("fallback tagger=%T", d.env.Tagger)
			}
			packet := []byte("not an IPv4 packet")
			if got, err := fallback.TagPacket(packet); err != nil || !bytes.Equal(got, packet) {
				t.Fatalf("fallback operation=%q,%v", got, err)
			}

			results := make(chan error, 8)
			var callers sync.WaitGroup
			for i := 0; i < cap(results); i++ {
				callers.Add(1)
				go func() { defer callers.Done(); results <- d.Close(ctx) }()
			}
			joined := make(chan struct{})
			go func() { callers.Wait(); close(results); close(joined) }()
			select {
			case <-joined:
			case <-ctx.Done():
				t.Fatal("constructor Close callers did not join")
			}
			for got := range results {
				if errors.Is(got, initErr) {
					t.Errorf("initialization failure became cleanup failure: %v", got)
				}
				if failedRollback {
					if !errors.Is(got, programErr) || !errors.Is(got, mapErr) {
						t.Errorf("constructor rollback errors lost: %v", got)
					}
				} else if got != nil {
					t.Errorf("ordinary fallback Close=%v", got)
				}
			}
			if constructors.Load() != 1 || program.calls.Load() != 1 || mapping.calls.Load() != 1 {
				t.Fatalf("constructor/release repeated: %d/%d/%d", constructors.Load(), program.calls.Load(), mapping.calls.Load())
			}
		})
	}
}

// localProfile is the operator policy of an executor that measures against
// services on its own host. The shipped default denies loopback, so the
// fixtures that reach a loopback peer say so.
func localProfile() netpolicy.Spec {
	spec := netpolicy.Defaults()
	spec.LocalTargets = true
	return spec
}
