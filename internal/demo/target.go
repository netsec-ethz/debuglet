package demo

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

const maxProtocolLine = 128

type targetProcess interface {
	Addr() string
	Done() <-chan struct{}
	Wait(context.Context) error
	Stop(context.Context) error
}

// exchangeTarget accepts one connection. Success means its exact ACK was
// received and the connection was closed normally, allowing the guest's EOF.
type exchangeTarget struct {
	lis      net.Listener
	mu       sync.Mutex
	conn     net.Conn
	stopped  bool
	done     chan struct{}
	err      error
	stopOnce sync.Once
}

func startTarget(ctx context.Context, nonce string) (targetProcess, error) {
	var lc net.ListenConfig
	lis, err := lc.Listen(ctx, "tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("start demo target: %w", err)
	}
	t := &exchangeTarget{lis: lis, done: make(chan struct{})}
	go func() {
		watchDone := make(chan struct{})
		stopWatch := context.AfterFunc(ctx, func() { t.close(); close(watchDone) })
		t.err = t.exchange(ctx, nonce)
		if !stopWatch() {
			<-watchDone
		}
		close(t.done)
	}()
	return t, nil
}

func (t *exchangeTarget) Addr() string          { return t.lis.Addr().String() }
func (t *exchangeTarget) Done() <-chan struct{} { return t.done }

func (t *exchangeTarget) exchange(ctx context.Context, nonce string) error {
	defer t.lis.Close()
	conn, err := t.lis.Accept()
	if err != nil {
		return fmt.Errorf("accept demo connection: %w", err)
	}
	defer conn.Close()
	t.mu.Lock()
	if t.stopped {
		t.mu.Unlock()
		return errors.New("demo target stopped before the exchange")
	}
	t.conn = conn
	t.mu.Unlock()
	deadline := time.Now().Add(10 * time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	if err := conn.SetDeadline(deadline); err != nil {
		return err
	}
	if _, err := io.WriteString(conn, "DEBUGLET/1 "+nonce+"\n"); err != nil {
		return fmt.Errorf("send demo response: %w", err)
	}
	line, err := readProtocolLine(conn)
	if err != nil {
		return fmt.Errorf("read demo acknowledgement: %w", err)
	}
	if line != "ACK "+nonce+"\n" {
		return errors.New("demo target received an incorrect acknowledgement")
	}
	// Closing here, before publishing success, is the normal peer EOF used by
	// the guest. Cleanup cancellation must never stand in for this predicate.
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.stopped || ctx.Err() != nil {
		return errors.New("demo target interrupted before normal completion")
	}
	if err := conn.Close(); err != nil {
		return fmt.Errorf("close completed demo connection: %w", err)
	}
	t.conn = nil
	return nil
}

func readProtocolLine(r io.Reader) (string, error) {
	reader := bufio.NewReaderSize(io.LimitReader(r, maxProtocolLine+1), 4096)
	line, err := reader.ReadString('\n')
	if len(line) > maxProtocolLine {
		return "", errors.New("demo protocol line exceeds 128 bytes")
	}
	if err != nil {
		return "", err
	}
	return line, nil
}

func (t *exchangeTarget) close() {
	t.stopOnce.Do(func() {
		t.mu.Lock()
		defer t.mu.Unlock()
		t.stopped = true
		t.lis.Close()
		if t.conn != nil {
			t.conn.Close()
		}
	})
}

func (t *exchangeTarget) Wait(ctx context.Context) error {
	select {
	case <-t.done:
		return t.err
	default:
	}
	select {
	case <-t.done:
		return t.err
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (t *exchangeTarget) Stop(ctx context.Context) error {
	t.close()
	select {
	case <-t.done:
		return nil // Wait owns protocol success/failure; Stop only joins ownership.
	case <-ctx.Done():
		return ctx.Err()
	}
}
