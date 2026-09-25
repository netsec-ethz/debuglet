// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package hostconn

import (
	"context"
	"errors"
	"net"
	"syscall"
	"testing"
	"time"
)

// peerRecorder is a Marker that records whether each socket it marks already
// had a peer, or refuses to mark.
type peerRecorder struct {
	fail     error
	peerErrs []error
}

func (m *peerRecorder) SetSocketMark(fd int) error {
	_, err := syscall.Getpeername(fd)
	m.peerErrs = append(m.peerErrs, err)
	return m.fail
}

func dialMarked(t *testing.T, guard Guard, marker *peerRecorder) (net.Listener, net.Conn, error) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	dialer, err := NewDialer(guard, marker)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := dialer.DialContext(ctx, "tcp", listener.Addr().String())
	return listener, conn, err
}

func TestDialerMarksBeforeConnect(t *testing.T) {
	marker := &peerRecorder{}
	_, conn, err := dialMarked(t, &admittingGuard{}, marker)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	if len(marker.peerErrs) != 1 {
		t.Fatalf("socket marked %d times, want once", len(marker.peerErrs))
	}
	if !errors.Is(marker.peerErrs[0], syscall.ENOTCONN) {
		t.Fatalf("socket marked with peer state %v, want ENOTCONN (marked before connect)", marker.peerErrs[0])
	}
}

func TestDialerDoesNotMarkRefusedDestination(t *testing.T) {
	marker := &peerRecorder{}
	_, conn, err := dialMarked(t, &refusingGuard{}, marker)
	if err == nil {
		conn.Close()
		t.Fatal("the refused destination was dialled")
	}
	if len(marker.peerErrs) != 0 {
		t.Errorf("a refused socket was marked %d times", len(marker.peerErrs))
	}
}

func TestDialerFailedMarkIsNeverConnected(t *testing.T) {
	errMark := errors.New("mark refused")
	listener, conn, err := dialMarked(t, &admittingGuard{}, &peerRecorder{fail: errMark})
	if err == nil {
		conn.Close()
		t.Fatal("an unmarked socket was connected")
	}
	if !errors.Is(err, errMark) {
		t.Errorf("dial error = %v, want the mark failure", err)
	}
	if err := listener.(*net.TCPListener).SetDeadline(time.Now().Add(300 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if accepted, err := listener.Accept(); err == nil {
		accepted.Close()
		t.Fatal("the target accepted a connection from an unmarked socket")
	}
}
