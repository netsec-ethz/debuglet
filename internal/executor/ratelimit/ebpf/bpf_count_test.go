//go:build linux

package ebpf

import (
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/netsec-ethz/debuglet/internal/executor/ratelimit/cleanup"
)

func TestCounterObjectOwnershipList(t *testing.T) {
	objects := countObjects{
		countPrograms: countPrograms{HandleEgress: new(ebpf.Program), HandleIngress: new(ebpf.Program)},
		countMaps: countMaps{
			DebugletSkMap: new(ebpf.Map), ExecPacketSizeMap: new(ebpf.Map), ExecRatesMap: new(ebpf.Map),
			PacketSizeMap: new(ebpf.Map), RatesMap: new(ebpf.Map),
		},
	}
	// These uninitialized handles are only identity witnesses. Do not Close
	// them; the capable kernel test below verifies actual acquired handles.
	want := map[string]io.Closer{
		"handle_egress": objects.HandleEgress, "handle_ingress": objects.HandleIngress,
		"debuglet_sk_map": objects.DebugletSkMap, "exec_packet_size_map": objects.ExecPacketSizeMap,
		"exec_rates_map": objects.ExecRatesMap, "packet_size_map": objects.PacketSizeMap, "rates_map": objects.RatesMap,
	}
	for _, resource := range counterObjectResources(&objects) {
		if want[resource.name] != resource.closer {
			t.Fatalf("unexpected or duplicate owned handle %q", resource.name)
		}
		delete(want, resource.name)
	}
	if len(want) != 0 {
		t.Fatalf("transferred handles omitted from cleanup: %v", want)
	}
	if got := counterObjectResources(&countObjects{}); len(got) != 0 {
		t.Fatal("nil generated handles granted cleanup ownership")
	}
}

type counterProbe struct {
	calls   atomic.Int32
	err     error
	onClose func()
}

func (p *counterProbe) Close() error {
	p.calls.Add(1)
	if p.onClose != nil {
		p.onClose()
	}
	return p.err
}

func counterTestObjects() ([]counterResource, []*counterProbe) {
	names := []string{"handle_egress", "handle_ingress", "debuglet_sk_map", "exec_packet_size_map", "exec_rates_map", "packet_size_map", "rates_map"}
	var resources []counterResource
	var probes []*counterProbe
	for _, name := range names {
		probe := new(counterProbe)
		resources = append(resources, counterResource{name, probe})
		probes = append(probes, probe)
	}
	return resources, probes
}

func counterWait(t *testing.T, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("counter fixture failed to join")
	}
}

func TestCounterCloseJoinsAndPreservesEveryRelease(t *testing.T) {
	resources, probes := counterTestObjects()
	programErr, mapErr, linkErr := errors.New("program release"), errors.New("map release"), errors.New("link release")
	probes[0].err, probes[4].err = programErr, mapErr
	egress, ingress := new(counterProbe), &counterProbe{err: linkErr}
	entered, release := make(chan struct{}), make(chan struct{})
	var enteredOnce, releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	ingress.onClose = func() { enteredOnce.Do(func() { close(entered) }); <-release }
	var orderMu sync.Mutex
	var order []string
	for _, resource := range resources {
		resource := resource
		resource.closer.(*counterProbe).onClose = func() {
			orderMu.Lock()
			order = append(order, resource.name)
			orderMu.Unlock()
		}
	}
	egress.onClose = func() { orderMu.Lock(); order = append(order, "egress TCX"); orderMu.Unlock() }
	count, err := newBPFCount(&net.Interface{Index: 7}, counterDependencies{
		load: func() (countObjects, []counterResource, error) { return countObjects{}, resources, nil },
		attach: func(opts link.TCXOptions) (io.Closer, error) {
			if opts.Interface != 7 {
				t.Error("attachment lost interface identity")
			}
			if opts.Attach == ebpf.AttachTCXEgress {
				return egress, nil
			}
			return ingress, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	results := make(chan error, 8)
	var callers sync.WaitGroup
	done := make(chan struct{})
	t.Cleanup(func() { unblock(); counterWait(t, done); _ = count.Close() })
	for i := 0; i < 8; i++ {
		callers.Add(1)
		go func() { defer callers.Done(); results <- count.Close() }()
	}
	go func() { callers.Wait(); close(done) }()
	counterWait(t, entered)
	select {
	case <-results:
		t.Fatal("Close returned before the owned release completed")
	case <-time.After(20 * time.Millisecond):
	}
	if egress.calls.Load() != 0 {
		t.Fatal("release order bypassed the held last-acquired link")
	}
	unblock()
	counterWait(t, done)
	close(results)
	var first error
	for result := range results {
		for _, cause := range []error{cleanup.ErrCleanupFailed, programErr, mapErr, linkErr} {
			if !errors.Is(result, cause) {
				t.Errorf("Close lost release cause %v: %v", cause, result)
			}
		}
		if first == nil {
			first = result
		} else if result != first {
			t.Error("concurrent callers did not observe the same final result")
		}
	}
	if count.Close() != first {
		t.Error("repeated Close lost cached aggregate")
	}
	for _, probe := range append(probes, egress, ingress) {
		if got := probe.calls.Load(); got != 1 {
			t.Errorf("release called %d times, want exactly once", got)
		}
	}
	wantOrder := []string{"egress TCX", "rates_map", "packet_size_map", "exec_rates_map", "exec_packet_size_map", "debuglet_sk_map", "handle_ingress", "handle_egress"}
	if len(order) != len(wantOrder) {
		t.Fatalf("release list=%v", order)
	}
	for i := range order {
		if order[i] != wantOrder[i] {
			t.Fatalf("release order=%v", order)
		}
	}
}

func TestCounterConstructorRollback(t *testing.T) {
	for _, phase := range []string{"egress", "egress_partial", "ingress", "ingress_partial"} {
		for _, failClose := range []bool{false, true} {
			name := phase + "/clean"
			if failClose {
				name = phase + "/release_error"
			}
			t.Run(name, func(t *testing.T) {
				resources, probes := counterTestObjects()
				attachErr, programErr, mapErr, linkErr := errors.New("attach"), errors.New("program"), errors.New("map"), errors.New("link")
				egress, ingress := new(counterProbe), new(counterProbe)
				if failClose {
					probes[0].err, probes[6].err, egress.err, ingress.err = programErr, mapErr, linkErr, linkErr
				}
				var acquired []*counterProbe
				var calls int
				counter, err := newBPFCount(&net.Interface{Index: 1}, counterDependencies{
					load: func() (countObjects, []counterResource, error) { return countObjects{}, resources, nil },
					attach: func(opts link.TCXOptions) (io.Closer, error) {
						calls++
						if opts.Attach == ebpf.AttachTCXEgress {
							if phase == "egress" {
								return nil, attachErr
							}
							acquired = append(acquired, egress)
							if phase == "egress_partial" {
								return egress, attachErr
							}
							return egress, nil
						}
						if phase == "ingress" {
							return nil, attachErr
						}
						acquired = append(acquired, ingress)
						return ingress, attachErr
					},
				})
				if counter != nil || !errors.Is(err, attachErr) {
					t.Fatalf("constructor=%v/%v", counter, err)
				}
				if errors.Is(err, cleanup.ErrCleanupUnconfirmed) {
					t.Fatal("observed rollback classified unconfirmed")
				}
				if errors.Is(err, cleanup.ErrCleanupFailed) != failClose {
					t.Fatalf("cleanup classification=%v", err)
				}
				if failClose {
					for _, cause := range []error{programErr, mapErr} {
						if !errors.Is(err, cause) {
							t.Errorf("lost rollback cause %v", cause)
						}
					}
					if len(acquired) > 0 && !errors.Is(err, linkErr) {
						t.Error("lost link rollback cause")
					}
				}
				for _, probe := range append(probes, acquired...) {
					if probe.calls.Load() != 1 {
						t.Errorf("acquired release count=%d", probe.calls.Load())
					}
				}
				if len(acquired) == 0 && egress.calls.Load() != 0 || ingress.calls.Load() != 0 && phase != "ingress_partial" {
					t.Error("unacquired link closed")
				}
				wantCalls := 2
				if phase == "egress" || phase == "egress_partial" {
					wantCalls = 1
				}
				if calls != wantCalls {
					t.Errorf("attach attempts=%d want=%d", calls, wantCalls)
				}
			})
		}
	}
}

func TestCounterLoadFailureDoesNotRepeatLibraryCleanup(t *testing.T) {
	loadErr := errors.New("loader failed")
	partial := new(counterProbe)
	var attached bool
	count, err := newBPFCount(&net.Interface{Index: 1}, counterDependencies{
		load: func() (countObjects, []counterResource, error) {
			_ = partial.Close() // The library retains partial-load ownership.
			return countObjects{}, []counterResource{{"partial", partial}}, loadErr
		},
		attach: func(link.TCXOptions) (io.Closer, error) { attached = true; return nil, nil },
	})
	if count != nil || !errors.Is(err, loadErr) || !errors.Is(err, cleanup.ErrCleanupUnconfirmed) {
		t.Fatalf("load failure=%v/%v", count, err)
	}
	if errors.Is(err, cleanup.ErrCleanupFailed) || partial.calls.Load() != 1 || attached {
		t.Fatal("library rollback was repeated or its unobserved result invented")
	}
}

func TestCounterNilInterfaceDoesNotAcquireResources(t *testing.T) {
	var loaded bool
	count, err := newBPFCount(nil, counterDependencies{
		load: func() (countObjects, []counterResource, error) {
			loaded = true
			return countObjects{}, nil, nil
		},
	})
	if count != nil || err == nil || loaded {
		t.Fatalf("invalid interface acquired resources: %v/%v, loaded=%t", count, err, loaded)
	}
	if errors.Is(err, cleanup.ErrCleanupFailed) || errors.Is(err, cleanup.ErrCleanupUnconfirmed) {
		t.Fatal("pre-acquisition validation invented a cleanup failure")
	}
}

func TestBPFCounterLinuxLoad(t *testing.T) {
	iface, err := net.InterfaceByName("lo")
	if err != nil {
		t.Fatal(err)
	}
	count, err := NewBPFCount(iface)
	if err != nil {
		if errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES) {
			t.Skipf("counter load requires kernel capabilities: %v", err)
		}
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := count.Close(); err != nil {
			t.Errorf("counter cleanup: %v", err)
		}
	})
	if len(count.cleanup.resources) != 9 {
		t.Fatalf("owned kernel handles=%d want=9", len(count.cleanup.resources))
	}
	// Both programs/maps and pinned cilium/ebpf's tcxLink (via RawLink)
	// expose FD. Observe the actual transferred descriptors before and after
	// Close; an arbitrary Info error would not establish that they closed.
	var handles []interface{ FD() int }
	for _, resource := range count.cleanup.resources {
		handle, ok := resource.closer.(interface{ FD() int })
		if !ok || handle.FD() < 0 {
			t.Fatalf("kernel handle was not open before Close: %s", resource.name)
		}
		handles = append(handles, handle)
	}
	if err := count.Close(); err != nil {
		t.Fatal(err)
	}
	for i, handle := range handles {
		if handle.FD() >= 0 {
			t.Errorf("kernel handle remains open: %s", count.cleanup.resources[i].name)
		}
	}
}
