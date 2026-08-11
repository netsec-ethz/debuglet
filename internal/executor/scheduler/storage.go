package scheduler

import (
	"context"
	"sync"
	"time"
)

type Scheduler interface {
	Insert(Spec) error
	// Remove removes a debuglet from storage preventing it from being started. It returns false if
	// the given ID does not exist in the storage anymore (i.e. the debuglet has already started).
	Remove(debugletID string) bool
	// RegisterOnStart sets the callback function for when a debuglet should be started.
	// [RunLock.Release] is to be called when the receiver has taken over ownership of the debuglet.
	// Without it, if a schedular calls OnStart in a new goroutine while removing the debuglet from
	// its storage, there is a brief race condition where a debuglet is neither in the scheduler storage
	// nor marked as being actively run by the executor.
	// It can be called multiple times.
	RegisterOnStart(func(context.Context, Spec, *RunLock))
	// StartLoop starts the loop that checks if any jobs are to be started and correspondingly calls the registered onStart function
	StartLoop(ctx context.Context) error
}

type Policy struct {
	FloorBW     int64
	CeilBW      int64
	Timeout     time.Duration
	Addresses   []string
	RequireICMP bool
	ListenUDP   bool
	ListenTCP   bool
	ListenICMP  bool
	ListenSCION bool
}

type Spec struct {
	DebugletID    string
	StartTime     *time.Time
	Args          []string
	Wasm          []byte
	Policy        Policy
	TransactionID string
}

// RunLock is a synchronization primitive that allows a scheduler to signal to the executor that it has taken over ownership of a debuglet.
// It is safe to initialize a barebones RunLock struct and call [RunLock.Done] and [RunLock.Release] multiple times.
type RunLock struct {
	o    sync.Once
	done *chan struct{}
	mu   sync.Mutex
}

// Done returns a channel that is closed when the scheduler has signaled that it has taken over ownership of the debuglet.
func (r *RunLock) Done() <-chan struct{} {
	r.mu.Lock()
	if r.done == nil {
		ch := make(chan struct{})
		r.done = &ch
	}
	r.mu.Unlock()
	return *r.done
}

func (r *RunLock) Release() {
	r.mu.Lock()
	if r.done == nil {
		ch := make(chan struct{})
		r.done = &ch
	}
	r.mu.Unlock()
	r.o.Do(func() {
		close(*r.done)
	})
}
