package memory

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/netsec-ethz/debuglet/internal/controlsession"
	"github.com/netsec-ethz/debuglet/internal/executor/scheduler"
)

const testBound = 2 * time.Second

// admissionPass commits every transition, which is how a core behaves while its
// session binding stays eligible. Cases about admission script their own guards.
func admissionPass(_ controlsession.Binding, commit func()) error { commit(); return nil }

func passingAdmission() scheduler.Admission {
	return scheduler.Admission{Insert: admissionPass, Start: admissionPass}
}

func newTestStorage(t *testing.T) *MemoryStorage {
	t.Helper()
	m, err := NewStorage(passingAdmission())
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func newTestPersistentStorage(t *testing.T, persist func(context.Context, scheduler.Spec) (scheduler.Spec, error),
	finalize func(context.Context, uuid.UUID) error, inspect func(context.Context, uuid.UUID, controlsession.Binding) error) *MemoryStorage {
	t.Helper()
	m, err := NewPersistentStorage(persist, finalize, inspect, passingAdmission())
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func distinctSpecs(n int) []scheduler.Spec {
	specs := make([]scheduler.Spec, n)
	for i := range specs {
		specs[i] = scheduler.Spec{DebugletID: uuid.New(), Args: []string{fmt.Sprintf("job-%d", i)}, Wasm: []byte{byte(i)}}
	}
	return specs
}
func await(t *testing.T, done <-chan struct{}, what string) bool {
	t.Helper()
	timer := time.NewTimer(testBound)
	defer timer.Stop()
	select {
	case <-done:
		return true
	case <-timer.C:
		t.Errorf("timed out waiting for %s", what)
		return false
	}
}
func waitFor(t *testing.T, what string, predicate func() bool) bool {
	t.Helper()
	deadline := time.NewTimer(testBound)
	defer deadline.Stop()
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
	for {
		if predicate() {
			return true
		}
		select {
		case <-deadline.C:
			t.Errorf("timed out waiting for %s", what)
			return false
		case <-tick.C:
		}
	}
}
func queueState(m *MemoryStorage) (queued, inflight int) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, o := range m.owners {
		if o.phase == active || o.phase == finalizing {
			inflight++
		}
	}
	return m.tq.Len(), inflight
}
func closed(ch <-chan struct{}) bool {
	select {
	case <-ch:
		return true
	default:
		return false
	}
}

// Each harness starts at most one dispatcher. StartLoop cancellation does not
// own user callbacks, so cleanup releases them explicitly and waits for their
// inflight entries to disappear after the callback returns.
type loopHarness struct {
	t            *testing.T
	m            *MemoryStorage
	ctx          context.Context
	cancel       context.CancelFunc
	started      bool
	loopDone     chan struct{}
	loopErr      error
	release      chan struct{}
	releaseOnce  sync.Once
	producerDone <-chan struct{}
}

func newLoopHarness(t *testing.T, m *MemoryStorage) *loopHarness {
	ctx, cancel := context.WithCancel(context.Background())
	h := &loopHarness{t: t, m: m, ctx: ctx, cancel: cancel, loopDone: make(chan struct{}), release: make(chan struct{})}
	t.Cleanup(h.cleanup)
	return h
}
func (h *loopHarness) start() {
	if h.started {
		return
	}
	h.started = true
	go func() { h.loopErr = h.m.StartLoop(h.ctx); close(h.loopDone) }()
}
func (h *loopHarness) unblockCallbacks() { h.releaseOnce.Do(func() { close(h.release) }) }
func (h *loopHarness) cleanup() {
	h.unblockCallbacks()
	// A mutation restoring the old blocking send can strand a producer before
	// start. Only after its failed assertion, run a consumer and supply hints to
	// release it. Never count this recovery as successful insertion/dispatch.
	if h.producerDone != nil {
		h.start()
		waitFor(h.t, "producer and due callbacks during recovery", func() bool {
			select {
			case h.m.wakeup <- struct{}{}:
			default:
			}
			q, inflight := queueState(h.m)
			return closed(h.producerDone) && q == 0 && inflight == 0
		})
	}
	h.cancel()
	if h.started {
		if await(h.t, h.loopDone, "scheduler loop cleanup") && !errors.Is(h.loopErr, context.Canceled) {
			h.t.Errorf("loop error=%v", h.loopErr)
		}
	}
	waitFor(h.t, "each dispatched callback to return", func() bool { _, n := queueState(h.m); return n == 0 })
	ctx, cancel := context.WithTimeout(context.Background(), testBound)
	defer cancel()
	if err := h.m.Shutdown(ctx); err != nil {
		h.t.Errorf("owned scheduler shutdown: %v", err)
	}
}

func TestInsertBeforeStartLoop(t *testing.T) {
	for _, n := range []int{0, 1, 32, 33, 1000} {
		t.Run(fmt.Sprint(n), func(t *testing.T) {
			m := newTestStorage(t)
			h := newLoopHarness(t, m)
			specs := distinctSpecs(n)
			callbacks := make(chan scheduler.Spec, n+1)
			m.RegisterOnStart(func(_ context.Context, spec scheduler.Spec) scheduler.Completion {
				callbacks <- spec
				return scheduler.Completion{}
			})
			producerDone := make(chan struct{})
			h.producerDone = producerDone
			var insertErr error
			go func() {
				defer close(producerDone)
				for _, spec := range specs {
					if err := m.Insert(context.Background(), spec); err != nil {
						insertErr = err
						return
					}
				}
			}()
			if !await(t, producerDone, "all inserts before StartLoop") {
				return
			}
			if insertErr != nil {
				t.Fatal(insertErr)
			}
			if h.started {
				t.Fatal("consumer ran before insertion assertion")
			}
			if q, _ := queueState(m); q != n {
				t.Fatalf("queued=%d want%d", q, n)
			}
			// Deliberately retain exactly one hint. Callback count must be controlled by
			// the queue, even if a partial fix left a larger notification buffer.
		drain:
			for {
				select {
				case <-m.wakeup:
				default:
					break drain
				}
			}
			if n > 0 {
				m.wakeup <- struct{}{}
			}
			h.start()
			if !waitFor(t, "all due work without additional hints", func() bool { q, inflight := queueState(m); return q == 0 && inflight == 0 }) {
				return
			}
			if len(callbacks) != n {
				t.Fatalf("callbacks=%d want%d", len(callbacks), n)
			}
			expected := map[uuid.UUID]scheduler.Spec{}
			for _, spec := range specs {
				expected[spec.DebugletID] = spec
			}
			for i := 0; i < n; i++ {
				spec := <-callbacks
				want, ok := expected[spec.DebugletID]
				if !ok {
					t.Fatalf("unexpected or repeated callback %s", spec.DebugletID)
				}
				if len(spec.Args) != 1 || spec.Args[0] != want.Args[0] || len(spec.Wasm) != 1 || spec.Wasm[0] != want.Wasm[0] {
					t.Fatal("callback changed accepted job")
				}
				delete(expected, spec.DebugletID)
			}
		})
	}
}

type timerEvent struct {
	kind     string
	deadline time.Time
}
type manualClock struct {
	mu       sync.Mutex
	now      time.Time
	timer    *manualTimer
	creates  int
	nowCalls int
	events   chan timerEvent
	armHook  func()
}
type manualTimer struct {
	clock    *manualClock
	channel  chan time.Time
	active   bool
	deadline time.Time
}

func newManualClock() *manualClock {
	return &manualClock{now: time.Date(2026, 9, 10, 0, 0, 0, 0, time.UTC), events: make(chan timerEvent, 128)}
}
func (c *manualClock) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); c.nowCalls++; return c.now }
func (c *manualClock) NewTimer(d time.Duration) schedulerTimer {
	c.mu.Lock()
	c.creates++
	timer := &manualTimer{clock: c, channel: make(chan time.Time, 1)}
	c.timer = timer
	hook := c.armHook
	c.mu.Unlock()
	timer.Reset(d)
	if hook != nil {
		hook()
	}
	return timer
}
func (t *manualTimer) Chan() <-chan time.Time { return t.channel }
func (t *manualTimer) Stop() bool {
	c := t.clock
	c.mu.Lock()
	defer c.mu.Unlock()
	was := t.active
	t.active = false
	select {
	case c.events <- timerEvent{kind: "stop", deadline: t.deadline}:
	default:
	}
	return was
}
func (t *manualTimer) Reset(d time.Duration) bool {
	c := t.clock
	c.mu.Lock()
	defer c.mu.Unlock()
	was := t.active
	t.active = true
	t.deadline = c.now.Add(d)
	if d <= 0 {
		t.active = false
		select {
		case t.channel <- c.now:
		default:
		}
	}
	select {
	case c.events <- timerEvent{kind: "arm", deadline: t.deadline}:
	default:
	}
	return was
}
func (c *manualClock) advance(to time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = to
	if c.timer != nil && c.timer.active && !c.timer.deadline.After(to) {
		c.timer.active = false
		select {
		case c.timer.channel <- to:
		default:
		}
	}
}
func (c *manualClock) snapshot() (int, bool, int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.creates, c.timer != nil && c.timer.active, c.nowCalls
}
func (c *manualClock) armed(t *testing.T, deadline time.Time) bool {
	t.Helper()
	timer := time.NewTimer(testBound)
	defer timer.Stop()
	for {
		select {
		case event := <-c.events:
			if event.kind == "arm" && event.deadline.Equal(deadline) {
				return true
			}
		case <-timer.C:
			t.Error("timer never armed for expected head")
			return false
		}
	}
}
func callbackID(t *testing.T, callbacks <-chan scheduler.Spec, id uuid.UUID) bool {
	t.Helper()
	timer := time.NewTimer(testBound)
	defer timer.Stop()
	select {
	case spec := <-callbacks:
		if spec.DebugletID != id {
			t.Errorf("callback=%s want%s", spec.DebugletID, id)
			return false
		}
		return true
	case <-timer.C:
		t.Error("expected callback did not start")
		return false
	}
}
func assertNoCallback(t *testing.T, callbacks <-chan scheduler.Spec) {
	t.Helper()
	select {
	case spec := <-callbacks:
		t.Errorf("unexpected early callback %s", spec.DebugletID)
	default:
	}
}

func TestSchedulerRechecksQueueHead(t *testing.T) {
	t.Run("future_earlier_and_equality", func(t *testing.T) {
		m := newTestStorage(t)
		clock := newManualClock()
		m.clock = clock
		h := newLoopHarness(t, m)
		callbacks := make(chan scheduler.Spec, 3)
		m.RegisterOnStart(func(_ context.Context, s scheduler.Spec) scheduler.Completion {
			callbacks <- s
			return scheduler.Completion{}
		})
		specs := distinctSpecs(3)
		future := clock.Now().Add(time.Hour)
		earlier := clock.Now().Add(time.Minute)
		specs[0].StartTime = &future
		specs[1].StartTime = &earlier
		if err := m.Insert(context.Background(), specs[0]); err != nil {
			t.Fatal(err)
		}
		h.start()
		if !clock.armed(t, future) {
			return
		}
		assertNoCallback(t, callbacks)
		if err := m.Insert(context.Background(), specs[1]); err != nil {
			t.Fatal(err)
		}
		if !clock.armed(t, earlier) {
			return
		}
		assertNoCallback(t, callbacks)
		if err := m.Insert(context.Background(), specs[2]); err != nil {
			t.Fatal(err)
		}
		if !callbackID(t, callbacks, specs[2].DebugletID) {
			return
		}
		if !clock.armed(t, earlier) {
			return
		}
		clock.advance(earlier)
		if !callbackID(t, callbacks, specs[1].DebugletID) {
			return
		}
		if !clock.armed(t, future) {
			return
		}
		clock.advance(future)
		if !callbackID(t, callbacks, specs[0].DebugletID) {
			return
		}
		if !waitFor(t, "queue empty with inactive timer", func() bool {
			q, inflight := queueState(m)
			_, active, _ := clock.snapshot()
			return q == 0 && inflight == 0 && !active
		}) {
			return
		}
		creates, _, _ := clock.snapshot()
		if creates != 1 {
			t.Errorf("created%d timers instead of reusing one", creates)
		}
	})
	t.Run("remove_future_head_and_last_timer", func(t *testing.T) {
		m := newTestStorage(t)
		clock := newManualClock()
		m.clock = clock
		h := newLoopHarness(t, m)
		callbacks := make(chan scheduler.Spec, 2)
		m.RegisterOnStart(func(_ context.Context, s scheduler.Spec) scheduler.Completion {
			callbacks <- s
			return scheduler.Completion{}
		})
		specs := distinctSpecs(2)
		first := clock.Now().Add(time.Minute)
		second := clock.Now().Add(time.Hour)
		specs[0].StartTime = &first
		specs[1].StartTime = &second
		for _, spec := range specs {
			if err := m.Insert(context.Background(), spec); err != nil {
				t.Fatal(err)
			}
		}
		h.start()
		if !clock.armed(t, first) {
			return
		}
		if removed, err := m.Remove(context.Background(), specs[0].DebugletID); err != nil || !removed {
			t.Fatal("remove head", removed, err)
		}
		if !clock.armed(t, second) {
			return
		}
		if removed, err := m.Remove(context.Background(), specs[1].DebugletID); err != nil || !removed {
			t.Fatal("remove last", removed, err)
		}
		if !waitFor(t, "removed head timer to stop", func() bool { _, active, _ := clock.snapshot(); return !active }) {
			return
		}
		clock.advance(second)
		assertNoCallback(t, callbacks)
		creates, active, _ := clock.snapshot()
		if creates != 1 || active {
			t.Errorf("timer state creates=%d active=%t", creates, active)
		}
	})
	t.Run("check_wait_boundary", func(t *testing.T) {
		m := newTestStorage(t)
		clock := newManualClock()
		m.clock = clock
		h := newLoopHarness(t, m)
		callbacks := make(chan scheduler.Spec, 2)
		m.RegisterOnStart(func(_ context.Context, s scheduler.Spec) scheduler.Completion {
			callbacks <- s
			return scheduler.Completion{}
		})
		inspected, continueWait := make(chan struct{}), make(chan struct{})
		var release sync.Once
		clock.armHook = func() { close(inspected); <-continueWait }
		t.Cleanup(func() { release.Do(func() { close(continueWait) }) })
		specs := distinctSpecs(2)
		future := clock.Now().Add(time.Hour)
		specs[0].StartTime = &future
		if err := m.Insert(context.Background(), specs[0]); err != nil {
			t.Fatal(err)
		}
		h.start()
		if !await(t, inspected, "future head inspection before wait") {
			return
		}
		// The loop has unlocked and inspected a future head, but has not selected
		// its wait yet. The only hint must survive this exact boundary.
		if err := m.Insert(context.Background(), specs[1]); err != nil {
			t.Fatal(err)
		}
		release.Do(func() { close(continueWait) })
		if !callbackID(t, callbacks, specs[1].DebugletID) {
			return
		}
		assertNoCallback(t, callbacks)
	})
	t.Run("empty_queue_no_timer_or_spin", func(t *testing.T) {
		m := newTestStorage(t)
		clock := newManualClock()
		m.clock = clock
		h := newLoopHarness(t, m)
		m.RegisterOnStart(func(context.Context, scheduler.Spec) scheduler.Completion {
			t.Error("empty queue dispatched")
			return scheduler.Completion{}
		})
		waiting := make(chan struct{})
		wrapped := &doneHookContext{Context: h.ctx, hook: func() { close(waiting) }, rechecked: make(chan struct{}, 1)}
		h.ctx = wrapped
		h.start()
		if !await(t, waiting, "idle wait") {
			return
		}
		creates, active, calls := clock.snapshot()
		if creates != 0 || active || calls != 0 {
			t.Errorf("idle clock used: creates=%d active=%t calls=%d", creates, active, calls)
		}
		quiet := time.NewTimer(20 * time.Millisecond)
		select {
		case <-wrapped.rechecked:
			t.Error("empty queue spun without an insertion, timer or cancellation")
		case <-quiet.C:
		}
		quiet.Stop()
		if got := wrapped.calls.Load(); got != 1 {
			t.Errorf("idle loop checked wait%d times", got)
		}
	})
}

type doneHookContext struct {
	context.Context
	hook      func()
	once      sync.Once
	calls     atomic.Int64
	rechecked chan struct{}
}

func (c *doneHookContext) Done() <-chan struct{} {
	if c.calls.Add(1) > 1 && c.rechecked != nil {
		select {
		case c.rechecked <- struct{}{}:
		default:
		}
	}
	c.once.Do(c.hook)
	return c.Context.Done()
}

func TestSchedulerCancellation(t *testing.T) {
	t.Run("pre_canceled_and_canceled_under_mutex", func(t *testing.T) {
		m := newTestStorage(t)
		spec := distinctSpecs(1)[0]
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if err := m.Insert(ctx, spec); !errors.Is(err, context.Canceled) {
			t.Fatalf("pre-canceled insert=%v", err)
		}
		if q, _ := queueState(m); q != 0 {
			t.Fatal("pre-canceled work appended")
		}
		ctx, cancel = context.WithCancel(context.Background())
		defer cancel()
		m.mu.Lock()
		entered, done := make(chan struct{}), make(chan struct{})
		var insertErr error
		go func() { close(entered); insertErr = m.Insert(ctx, spec); close(done) }()
		if !await(t, entered, "producer entering Insert") {
			m.mu.Unlock()
			cancel()
			await(t, done, "late producer cleanup")
			return
		}
		cancel()
		m.mu.Unlock()
		if !await(t, done, "insertion rejected after mutex acquisition") {
			return
		}
		if !errors.Is(insertErr, context.Canceled) {
			t.Errorf("canceled under mutex=%v", insertErr)
		}
		if q, _ := queueState(m); q != 0 {
			t.Error("canceled under mutex appended work")
		}
	})
	t.Run("accepted_append_survives_racing_cancellation", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		// The test guard injects cancellation after the actual accepted append,
		// independent of how many context checks precede the commit. Production
		// lease guards do not invoke cancellation callbacks under their lock.
		m, err := NewStorage(scheduler.Admission{
			Insert: func(_ controlsession.Binding, commit func()) error { commit(); cancel(); return nil },
			Start:  func(_ controlsession.Binding, commit func()) error { commit(); return nil },
		})
		if err != nil {
			t.Fatal(err)
		}
		if err := m.Insert(ctx, distinctSpecs(1)[0]); err != nil {
			t.Fatalf("accepted append returned error: %v", err)
		}
		if ctx.Err() == nil {
			t.Fatal("cancellation not injected")
		}
		if q, _ := queueState(m); q != 1 {
			t.Fatalf("accepted queue length=%d", q)
		}
	})
	t.Run("idle", func(t *testing.T) {
		m := newTestStorage(t)
		h := newLoopHarness(t, m)
		m.RegisterOnStart(func(context.Context, scheduler.Spec) scheduler.Completion {
			t.Error("idle callback")
			return scheduler.Completion{}
		})
		waiting := make(chan struct{})
		h.ctx = &doneHookContext{Context: h.ctx, hook: func() { close(waiting) }}
		h.start()
		if !await(t, waiting, "idle scheduler") {
			return
		}
		h.cancel()
		await(t, h.loopDone, "idle cancellation")
	})
	t.Run("draining_callbacks_remain_owned", func(t *testing.T) {
		var cancelAfterThird context.CancelFunc
		commits := 0
		m, err := NewStorage(scheduler.Admission{
			Insert: func(_ controlsession.Binding, commit func()) error { commit(); return nil },
			Start: func(_ controlsession.Binding, commit func()) error {
				commit()
				commits++
				// Inject only after three real ownership transitions. As above,
				// this cancellation is a test boundary, not production guard work.
				if commits == 3 {
					cancelAfterThird()
				}
				return nil
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		h := newLoopHarness(t, m)
		cancelAfterThird = h.cancel
		callbacks := make(chan scheduler.Spec, 1000)
		m.RegisterOnStart(func(_ context.Context, s scheduler.Spec) scheduler.Completion {
			callbacks <- s
			<-h.release
			return scheduler.Completion{}
		})
		for _, spec := range distinctSpecs(1000) {
			if err := m.Insert(context.Background(), spec); err != nil {
				t.Fatal(err)
			}
		}
		h.start()
		if !await(t, h.loopDone, "cancellation between due dispatches") {
			return
		}
		q, inflight := queueState(m)
		if q != 997 || inflight != 3 {
			t.Errorf("cancelled drain queued=%d inflight=%d want997/3", q, inflight)
		}
		// Cancellation stops dispatch, not arbitrary active callbacks. Their owner
		// releases them and the cleanup harness joins their real returns.
		h.unblockCallbacks()
		if !waitFor(t, "three callbacks to finish", func() bool { _, n := queueState(m); return n == 0 }) {
			return
		}
		if len(callbacks) != 3 {
			t.Errorf("callbacks=%d want3", len(callbacks))
		}
	})
}

func TestCallbacksOutsideMutexAndConcurrent(t *testing.T) {
	m := newTestStorage(t)
	h := newLoopHarness(t, m)
	specs := distinctSpecs(2)
	second := make(chan struct{})
	firstDone := make(chan struct{})
	m.RegisterOnStart(func(_ context.Context, s scheduler.Spec) scheduler.Completion {
		if s.DebugletID == specs[0].DebugletID {
			// Probe mutex availability before reentrant Insert. If a regression
			// invokes the callback while holding mu, fail and return rather than
			// deadlocking the fixture forever on a noncancelable lock acquisition.
			deadline := time.NewTimer(testBound)
			tick := time.NewTicker(time.Millisecond)
			for !m.mu.TryLock() {
				select {
				case <-deadline.C:
					tick.Stop()
					t.Error("callback could not acquire queue mutex")
					close(firstDone)
					return scheduler.Completion{}
				case <-tick.C:
				}
			}
			m.mu.Unlock()
			deadline.Stop()
			tick.Stop()
			if err := m.Insert(context.Background(), specs[1]); err != nil {
				t.Error(err)
			}
			<-h.release
			close(firstDone)
		} else {
			close(second)
		}
		return scheduler.Completion{}
	})
	if err := m.Insert(context.Background(), specs[0]); err != nil {
		t.Fatal(err)
	}
	h.start()
	if !await(t, second, "second callback while first holds its own gate") {
		return
	}
	if closed(firstDone) {
		t.Error("first callback did not stay active")
	}
	h.unblockCallbacks()
	await(t, firstDone, "first callback release")
}
