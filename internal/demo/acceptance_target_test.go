//go:build linux && demoacceptance

package demo

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

// Only the tagged harness replaces the target. Both faults still traverse the
// actual installed daemons and bundled WASM. Withheld EOF first checks its ACK.
type acceptanceTarget struct {
	lis        net.Listener
	mu         sync.Mutex
	conn       net.Conn
	done       chan struct{}
	err        error
	triggered  bool
	injectedAt time.Time
	closed     bool
	once       sync.Once
}

func startAcceptanceTarget(ctx context.Context, nonce, mode string) (*acceptanceTarget, error) {
	lis, err := (&net.ListenConfig{}).Listen(ctx, "tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	target := &acceptanceTarget{lis: lis, done: make(chan struct{})}
	go func() {
		watchDone := make(chan struct{})
		stopWatch := context.AfterFunc(ctx, func() { target.close(); close(watchDone) })
		target.err = target.exchange(ctx, nonce, mode)
		if !stopWatch() {
			<-watchDone
		}
		close(target.done)
	}()
	return target, nil
}
func (t *acceptanceTarget) exchange(ctx context.Context, nonce, mode string) error {
	defer t.lis.Close()
	conn, err := t.lis.Accept()
	if err != nil {
		return err
	}
	defer conn.Close()
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return errors.New("target closed before accepting the connection")
	}
	t.conn = conn
	t.mu.Unlock()
	deadline, _ := ctx.Deadline()
	if deadline.IsZero() {
		deadline = time.Now().Add(2 * time.Second)
	}
	_ = conn.SetDeadline(deadline)
	response := "DEBUGLET/1 " + nonce + "\n"
	if mode == "wrong_reply" {
		response = "DEBUGLET/1 incorrect-nonce\n"
		t.mu.Lock()
		t.injectedAt = time.Now()
		t.mu.Unlock()
	}
	if _, err := io.WriteString(conn, response); err != nil {
		return err
	}
	if mode == "wrong_reply" {
		t.mu.Lock()
		t.triggered = true
		t.mu.Unlock()
		return errors.New("acceptance injected wrong target reply")
	}
	line, err := readProtocolLine(conn)
	if err != nil {
		return err
	}
	if line != "ACK "+nonce+"\n" {
		return fmt.Errorf("withheld-EOF target received %q", line)
	}
	t.mu.Lock()
	t.injectedAt = time.Now()
	t.mu.Unlock()
	// The two-second fault window starts after the real ACK. Startup remains
	// inside the enclosing normal execution deadline and is never retried.
	timer := time.NewTimer(2 * time.Second)
	defer timer.Stop()
	select {
	case <-timer.C:
		t.mu.Lock()
		t.triggered = true
		t.mu.Unlock()
		return errors.New("acceptance withheld normal EOF after the real guest ACK")
	case <-ctx.Done():
		return ctx.Err()
	}
}
func (t *acceptanceTarget) Addr() string          { return t.lis.Addr().String() }
func (t *acceptanceTarget) Done() <-chan struct{} { return t.done }
func (t *acceptanceTarget) faultState() (bool, time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.triggered, t.injectedAt
}
func (t *acceptanceTarget) Wait(ctx context.Context) error {
	select {
	case <-t.done:
		return t.err
	case <-ctx.Done():
		return ctx.Err()
	}
}
func (t *acceptanceTarget) close() {
	t.once.Do(func() {
		t.mu.Lock()
		defer t.mu.Unlock()
		t.closed = true
		_ = t.lis.Close()
		if t.conn != nil {
			_ = t.conn.Close()
		}
	})
}
func (t *acceptanceTarget) Stop(ctx context.Context) error {
	t.close()
	select {
	case <-t.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
