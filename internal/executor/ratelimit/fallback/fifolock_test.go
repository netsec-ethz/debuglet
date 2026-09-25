package fallback

import (
	"errors"
	"net"
	"os"
	"testing"
	"time"

	"github.com/netsec-ethz/debuglet/internal/executor/ratelimit/app"
)

func waitForFIFOQueue(t *testing.T, lock *FIFOLock, size int) {
	t.Helper()
	waitUntil(t, func() bool {
		lock.mu.Lock()
		defer lock.mu.Unlock()
		return len(lock.waiters) == size
	}, "FIFO queue size")
}

func TestFIFOLockCancellationPreservesSurvivorOrder(t *testing.T) {
	for _, canceled := range []int{0, 2, 4} {
		t.Run([]string{"head", "middle", "tail"}[canceled/2], func(t *testing.T) {
			lock := NewFIFOLock()
			lock.Lock()
			cancel := make([]chan struct{}, 5)
			result := make(chan struct {
				index int
				err   error
			}, len(cancel))
			for i := range cancel {
				cancel[i] = make(chan struct{})
				go func(index int) {
					err := lock.LockUntil(cancel[index], func() (time.Time, <-chan struct{}) { return time.Time{}, nil })
					result <- struct {
						index int
						err   error
					}{index, err}
					if err == nil {
						lock.Unlock()
					}
				}(i)
				waitForFIFOQueue(t, lock, i+1)
			}

			close(cancel[canceled])
			got := <-result
			if got.index != canceled || !errors.Is(got.err, net.ErrClosed) {
				t.Fatalf("canceled result = (%d, %v), want (%d, %v)", got.index, got.err, canceled, net.ErrClosed)
			}
			lock.Unlock()
			for want := 0; want < len(cancel); want++ {
				if want == canceled {
					continue
				}
				got := <-result
				if got.index != want || got.err != nil {
					t.Fatalf("survivor result = (%d, %v), want (%d, nil)", got.index, got.err, want)
				}
			}
			waitForFIFOQueue(t, lock, 0)
		})
	}
}

func TestQueuedWriteExpiresWithoutSocketIO(t *testing.T) {
	raw := newScriptedConn(nil)
	fc := newTestConn(t, raw, app.FromBytes(1024), app.FromBytes(1024))
	fc.writeMu.Lock()
	if err := fc.SetWriteDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
		t.Fatalf("SetWriteDeadline: %v", err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := fc.Write([]byte("queued"))
		done <- err
	}()
	waitForFIFOQueue(t, fc.writeMu, 1)
	select {
	case err := <-done:
		if !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("Write error = %v, want %v", err, os.ErrDeadlineExceeded)
		}
	case <-time.After(boundedWait):
		t.Fatal("queued Write did not observe its deadline")
	}
	fc.writeMu.Unlock()
	if writes := raw.written(); len(writes) != 0 {
		t.Fatalf("underlying writes = %d, want 0", len(writes))
	}
}
