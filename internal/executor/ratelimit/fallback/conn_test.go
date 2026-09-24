package fallback

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/netsec-ethz/debuglet/internal/executor/ratelimit/app"
)

const (
	testAddr = "127.0.0.1"
	// boundedWait is the maximum time a canceled or empty Read may take.
	boundedWait = 10 * time.Second
)

// errExtraRead is returned by a scriptedConn whose read budget is exhausted.
// It keeps a fill loop in the layer under test bounded and visible instead of
// spinning or panicking.
var errExtraRead = errors.New("unexpected additional underlying read")

// scriptedConn is a net.Conn whose Read and Write are driven by the test.
// It records every underlying call so tests can assert exact call counts
// and the size of the slice handed to the socket.
type scriptedConn struct {
	// read is invoked for every Read; nil blocks until Close is called.
	read func(b []byte) (int, error)
	// maxReads > 0 limits how many times read is invoked.
	maxReads int
	// write is invoked for every Write; nil accepts the complete slice.
	write func(b []byte) (int, error)
	// network is the network of the local address, tcp when empty. Attach
	// decides from it whether the connection carries datagrams.
	network string
	// blocked is closed the first time a nil-read Read starts blocking.
	blocked     chan struct{}
	blockedOnce sync.Once

	mu        sync.Mutex
	readCalls int
	readSizes []int
	writes    [][]byte

	closed    chan struct{}
	closeOnce sync.Once
}

type readStartedConn struct {
	net.Conn
	started chan struct{}
	once    sync.Once
}

type gatedDeadlineConn struct {
	*scriptedConn
	setDeadlineEntered chan struct{}
	releaseSetDeadline chan struct{}
	enteredOnce        sync.Once

	deadlineMu    sync.Mutex
	writeDeadline time.Time
}

func newGatedDeadlineConn() *gatedDeadlineConn {
	return &gatedDeadlineConn{
		scriptedConn:       newScriptedConn(nil),
		setDeadlineEntered: make(chan struct{}),
		releaseSetDeadline: make(chan struct{}),
	}
}

func (c *gatedDeadlineConn) SetDeadline(t time.Time) error {
	c.deadlineMu.Lock()
	c.writeDeadline = t
	c.deadlineMu.Unlock()
	c.enteredOnce.Do(func() { close(c.setDeadlineEntered) })
	<-c.releaseSetDeadline
	return nil
}

func (c *gatedDeadlineConn) SetWriteDeadline(t time.Time) error {
	c.deadlineMu.Lock()
	c.writeDeadline = t
	c.deadlineMu.Unlock()
	return nil
}

func (c *gatedDeadlineConn) currentWriteDeadline() time.Time {
	c.deadlineMu.Lock()
	defer c.deadlineMu.Unlock()
	return c.writeDeadline
}

func (c *readStartedConn) Read(b []byte) (int, error) {
	c.once.Do(func() { close(c.started) })
	return c.Conn.Read(b)
}

func newScriptedConn(read func(b []byte) (int, error)) *scriptedConn {
	return &scriptedConn{
		read:    read,
		blocked: make(chan struct{}),
		closed:  make(chan struct{}),
	}
}

// oneRead returns a scriptedConn that answers exactly one read with the
// given result and reports any further read as errExtraRead.
func oneRead(n int, err error) *scriptedConn {
	s := newScriptedConn(func(b []byte) (int, error) {
		for i := 0; i < n && i < len(b); i++ {
			b[i] = 'x'
		}
		return n, err
	})
	s.maxReads = 1
	return s
}

func (s *scriptedConn) Read(b []byte) (int, error) {
	s.mu.Lock()
	s.readCalls++
	s.readSizes = append(s.readSizes, len(b))
	read := s.read
	extra := s.maxReads > 0 && s.readCalls > s.maxReads
	s.mu.Unlock()

	if extra {
		return 0, errExtraRead
	}
	if read != nil {
		return read(b)
	}
	s.blockedOnce.Do(func() { close(s.blocked) })
	<-s.closed
	return 0, net.ErrClosed
}

func (s *scriptedConn) Write(b []byte) (int, error) {
	s.mu.Lock()
	s.writes = append(s.writes, bytes.Clone(b))
	write := s.write
	s.mu.Unlock()
	if write != nil {
		return write(b)
	}
	return len(b), nil
}

func (s *scriptedConn) Close() error {
	s.closeOnce.Do(func() { close(s.closed) })
	return nil
}

func (s *scriptedConn) LocalAddr() net.Addr {
	if s.network == "udp" {
		return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1}
	}
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1}
}

func (s *scriptedConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 2}
}

func (s *scriptedConn) SetDeadline(time.Time) error      { return nil }
func (s *scriptedConn) SetReadDeadline(time.Time) error  { return nil }
func (s *scriptedConn) SetWriteDeadline(time.Time) error { return nil }

func (s *scriptedConn) reads() (int, []int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.readCalls, append([]int(nil), s.readSizes...)
}

func (s *scriptedConn) written() [][]byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([][]byte, len(s.writes))
	copy(out, s.writes)
	return out
}

// newTestConn attaches raw to a fresh FallbackCount. A zero rate leaves the
// corresponding limit unconfigured.
func newTestConn(t *testing.T, raw net.Conn, destRate, execRate app.Bitrate) *FallbackConn {
	t.Helper()
	count, err := NewFallbackCount()
	if err != nil {
		t.Fatalf("NewFallbackCount: %v", err)
	}
	id := uuid.New()
	conn, err := count.Attach(raw, id, testAddr)
	if err != nil {
		t.Fatalf("Attach: %v", err)
	}
	if destRate > 0 {
		if err := count.SetLimit(testAddr, id, destRate); err != nil {
			t.Fatalf("SetLimit: %v", err)
		}
	}
	if execRate > 0 {
		if err := count.SetExecLimit(id, execRate); err != nil {
			t.Fatalf("SetExecLimit: %v", err)
		}
	}
	fc := conn.(*FallbackConn)
	t.Cleanup(func() { _ = fc.Close() })
	return fc
}

// bucketTokens reads the current credit of both accounting levels.
func bucketTokens(fc *FallbackConn) (dest app.Bitrate, destOK bool, exec app.Bitrate, execOK bool) {
	fc.count.mu.Lock()
	defer fc.count.mu.Unlock()
	if b, ok := fc.count.packetSize[debugletKey{id: fc.id, dest: fc.ipv6}]; ok {
		dest, destOK = b.tokens, true
	}
	if eb, ok := fc.count.execPacketSize[fc.id]; ok {
		exec, execOK = eb.tokens, true
	}
	return dest, destOK, exec, execOK
}

func assertTokens(t *testing.T, fc *FallbackConn, wantDest, wantExec app.Bitrate) {
	t.Helper()
	dest, destOK, exec, execOK := bucketTokens(fc)
	if !destOK || dest != wantDest {
		t.Errorf("destination bucket = %d bits (present=%v), want %d bits", dest, destOK, wantDest)
	}
	if !execOK || exec != wantExec {
		t.Errorf("executor bucket = %d bits (present=%v), want %d bits", exec, execOK, wantExec)
	}
}

// forceReservationWait drives the buckets of a one-byte-per-second
// connection into debt so that the next reservation on fc must sleep for
// well over boundedWait. It uses the production reserve path only.
func forceReservationWait(t *testing.T, fc *FallbackConn) {
	t.Helper()
	const debt = 3 * int(boundedWait/time.Second)
	for i := 0; i < debt; i++ {
		if _, err := fc.reserve(1); err != nil {
			t.Fatalf("reserve: %v", err)
		}
	}
	probe, err := fc.reserve(1)
	if err != nil {
		t.Fatalf("reserve: %v", err)
	}
	probe.free()
	if probe.waitFor <= boundedWait {
		t.Fatalf("forced wait is %v, want more than %v", probe.waitFor, boundedWait)
	}
}

// loopbackPair returns a client connection to a loopback TCP server. The
// server runs serve on the accepted connection until serve returns or stop
// is closed; join waits for it to exit.
func loopbackPair(t *testing.T, serve func(c net.Conn, stop <-chan struct{})) (client net.Conn, join func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	stop := make(chan struct{})
	var stopOnce sync.Once
	done := make(chan struct{})
	go func() {
		defer close(done)
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		serve(c, stop)
	}()
	join = func() {
		stopOnce.Do(func() { close(stop) })
		_ = ln.Close()
		<-done
	}
	client, err = net.Dial("tcp", ln.Addr().String())
	if err != nil {
		join()
		t.Fatalf("Dial: %v", err)
	}
	t.Cleanup(func() {
		_ = client.Close()
		join()
	})
	return client, join
}

// waitBounded fails the test when done is not closed within boundedWait. It
// then runs release (which must unblock the helper) and joins on done so no
// helper goroutine outlives the test.
func waitBounded(t *testing.T, done <-chan struct{}, what string, release func()) {
	t.Helper()
	select {
	case <-done:
		return
	case <-time.After(boundedWait):
		t.Errorf("%s did not terminate within %v", what, boundedWait)
	}
	if release != nil {
		release()
	}
	<-done
}

// waitUntil polls cond until it holds, failing after boundedWait.
func waitUntil(t *testing.T, cond func() bool, what string) {
	t.Helper()
	deadline := time.Now().Add(boundedWait)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("%s did not happen within %v", what, boundedWait)
		}
		time.Sleep(time.Millisecond)
	}
}

// Regression 1: a short reply from an open peer is delivered as a positive
// prefix instead of waiting to fill the whole buffer.
func TestReadReturnsShortReplyWhilePeerOpen(t *testing.T) {
	reply := []byte("pong\n")
	var replyConsumed atomic.Bool
	ackBeforeClose := make(chan bool, 1)

	raw, join := loopbackPair(t, func(c net.Conn, stop <-chan struct{}) {
		if _, err := c.Write(reply); err != nil {
			ackBeforeClose <- false
			return
		}
		<-stop
		ackBeforeClose <- replyConsumed.Load()
	})
	fc := newTestConn(t, raw, app.FromBytes(1<<20), app.FromBytes(1<<20))
	if err := fc.SetReadDeadline(time.Now().Add(boundedWait)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}

	buf := make([]byte, 4096)
	var got []byte
	for len(got) < len(reply) {
		n, err := fc.Read(buf)
		if err != nil {
			t.Fatalf("Read while the peer is open: n=%d err=%v (got %q so far)", n, err, got)
		}
		if n <= 0 || n > len(buf) {
			t.Fatalf("Read returned n=%d while the peer is open, want a positive prefix", n)
		}
		got = append(got, buf[:n]...)
	}
	if !bytes.Equal(got, reply) {
		t.Fatalf("accumulated %q, want %q", got, reply)
	}

	// The peer is still open: only now let it close.
	replyConsumed.Store(true)
	join()
	if !<-ackBeforeClose {
		t.Fatal("server closed before the short reply was fully read")
	}

	n, err := fc.Read(buf)
	if n != 0 || !errors.Is(err, io.EOF) {
		t.Fatalf("Read after peer close = (%d, %v), want (0, io.EOF)", n, err)
	}
}

func TestBlockedReadAllowsWriteToReachPeer(t *testing.T) {
	request := []byte("request\n")
	reply := []byte("reply\n")
	serverDone := make(chan error, 1)
	raw, join := loopbackPair(t, func(c net.Conn, _ <-chan struct{}) {
		got := make([]byte, len(request))
		if _, err := io.ReadFull(c, got); err != nil {
			serverDone <- fmt.Errorf("read request: %w", err)
			return
		}
		if !bytes.Equal(got, request) {
			serverDone <- fmt.Errorf("request = %q, want %q", got, request)
			return
		}
		_, err := c.Write(reply)
		serverDone <- err
	})
	readStarted := make(chan struct{})
	fc := newTestConn(t, &readStartedConn{Conn: raw, started: readStarted}, app.FromBytes(1024), app.FromBytes(1024))
	if err := fc.SetDeadline(time.Now().Add(boundedWait)); err != nil {
		t.Fatalf("SetDeadline: %v", err)
	}

	readDone := make(chan struct{})
	gotReply := make([]byte, len(reply))
	var readErr error
	go func() {
		defer close(readDone)
		_, readErr = io.ReadFull(fc, gotReply)
	}()
	waitBounded(t, readStarted, "underlying read start", func() { _ = fc.Close() })

	if n, err := fc.Write(request); n != len(request) || err != nil {
		t.Fatalf("Write = (%d, %v), want (%d, nil)", n, err, len(request))
	}
	waitBounded(t, readDone, "read after full-duplex handshake", func() { _ = fc.Close() })
	join()
	if readErr != nil {
		t.Fatalf("ReadFull: %v", readErr)
	}
	if !bytes.Equal(gotReply, reply) {
		t.Fatalf("reply = %q, want %q", gotReply, reply)
	}
	if err := <-serverDone; err != nil {
		t.Fatalf("server: %v", err)
	}
}

// Regression 2: exactly one underlying read, its result returned unchanged.
func TestReadReturnsSingleUnderlyingResult(t *testing.T) {
	sentinel := errors.New("sentinel read error")
	const (
		bufSize   = 64
		destBytes = 16 // caps the slice handed to the socket at 16 bytes
		execBytes = 1024
	)
	cases := []struct {
		name string
		n    int
		err  error
	}{
		{"positive nil", 5, nil},
		{"positive EOF", 5, io.EOF},
		{"positive sentinel", 5, sentinel},
		{"zero EOF", 0, io.EOF},
		{"zero nil", 0, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			raw := oneRead(tc.n, tc.err)
			fc := newTestConn(t, raw, app.FromBytes(destBytes), app.FromBytes(execBytes))

			buf := make([]byte, bufSize)
			n, err := fc.Read(buf)
			if n != tc.n || err != tc.err {
				t.Fatalf("Read = (%d, %v), want (%d, %v)", n, err, tc.n, tc.err)
			}
			if want := bytes.Repeat([]byte{'x'}, tc.n); !bytes.Equal(buf[:n], want) {
				t.Fatalf("Read data = %q, want %q", buf[:n], want)
			}
			calls, sizes := raw.reads()
			if calls != 1 {
				t.Fatalf("underlying Read calls = %d, want 1", calls)
			}
			if sizes[0] != destBytes {
				t.Fatalf("underlying Read slice length = %d, want %d", sizes[0], destBytes)
			}
		})
	}
}

// Regression 3: unused reserved bytes are credited back to both accounting
// levels, independently and capped at the current rate.
func TestReadRefundsUnusedReservation(t *testing.T) {
	const (
		destBytes = 100
		execBytes = 400
		bufSize   = 100 // one reservation of the full destination rate
	)

	t.Run("partial refund", func(t *testing.T) {
		raw := oneRead(30, nil)
		fc := newTestConn(t, raw, app.FromBytes(destBytes), app.FromBytes(execBytes))
		if n, err := fc.Read(make([]byte, bufSize)); n != 30 || err != nil {
			t.Fatalf("Read = (%d, %v), want (30, nil)", n, err)
		}
		// Fresh buckets start full: dest 100-100+70, exec 400-100+70.
		assertTokens(t, fc, app.FromBytes(70), app.FromBytes(370))
	})

	t.Run("full refund on zero read", func(t *testing.T) {
		raw := oneRead(0, io.EOF)
		fc := newTestConn(t, raw, app.FromBytes(destBytes), app.FromBytes(execBytes))
		if n, err := fc.Read(make([]byte, bufSize)); n != 0 || !errors.Is(err, io.EOF) {
			t.Fatalf("Read = (%d, %v), want (0, io.EOF)", n, err)
		}
		assertTokens(t, fc, app.FromBytes(destBytes), app.FromBytes(execBytes))
	})

	t.Run("no refund when everything was used", func(t *testing.T) {
		raw := oneRead(bufSize, nil)
		fc := newTestConn(t, raw, app.FromBytes(destBytes), app.FromBytes(execBytes))
		if n, err := fc.Read(make([]byte, bufSize)); n != bufSize || err != nil {
			t.Fatalf("Read = (%d, %v), want (%d, nil)", n, err, bufSize)
		}
		assertTokens(t, fc, 0, app.FromBytes(execBytes-destBytes))
	})

	t.Run("executor refunded after destination detach", func(t *testing.T) {
		raw := newScriptedConn(nil)
		fc := newTestConn(t, raw, app.FromBytes(destBytes), app.FromBytes(execBytes))
		r, err := fc.reserve(bufSize)
		if err != nil {
			t.Fatalf("reserve: %v", err)
		}
		assertTokens(t, fc, 0, app.FromBytes(execBytes-destBytes))

		// Close detaches the destination entry first; the executor entry stays.
		if err := fc.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}
		r.free()

		_, destOK, exec, execOK := bucketTokens(fc)
		if destOK {
			t.Error("destination bucket was recreated after detach")
		}
		if !execOK || exec != app.FromBytes(execBytes) {
			t.Errorf("executor bucket = %d bits (present=%v), want %d bits", exec, execOK, app.FromBytes(execBytes))
		}
	})

	t.Run("destination refunded after executor delete", func(t *testing.T) {
		raw := newScriptedConn(nil)
		fc := newTestConn(t, raw, app.FromBytes(destBytes), app.FromBytes(execBytes))
		r, err := fc.reserve(bufSize)
		if err != nil {
			t.Fatalf("reserve: %v", err)
		}
		if err := fc.count.DeleteExecLimit(fc.id); err != nil {
			t.Fatalf("DeleteExecLimit: %v", err)
		}
		r.free()

		dest, destOK, _, execOK := bucketTokens(fc)
		if execOK {
			t.Error("executor bucket was recreated after delete")
		}
		if !destOK || dest != app.FromBytes(destBytes) {
			t.Errorf("destination bucket = %d bits (present=%v), want %d bits", dest, destOK, app.FromBytes(destBytes))
		}
	})

	t.Run("refund is capped at the current rate", func(t *testing.T) {
		raw := newScriptedConn(nil)
		fc := newTestConn(t, raw, app.FromBytes(destBytes), app.FromBytes(execBytes))
		r, err := fc.reserve(bufSize)
		if err != nil {
			t.Fatalf("reserve: %v", err)
		}
		if err := fc.count.SetLimit(testAddr, fc.id, app.FromBytes(50)); err != nil {
			t.Fatalf("SetLimit: %v", err)
		}
		if err := fc.count.SetExecLimit(fc.id, app.FromBytes(200)); err != nil {
			t.Fatalf("SetExecLimit: %v", err)
		}
		r.free()
		assertTokens(t, fc, app.FromBytes(50), app.FromBytes(200))
	})
}

// Regression 4: an empty read never reaches the socket, the limiter or the
// FIFO lock.
func TestEmptyReadNeedsNoLimits(t *testing.T) {
	t.Run("no limits configured", func(t *testing.T) {
		raw := oneRead(0, nil)
		fc := newTestConn(t, raw, 0, 0) // no destination or executor limit at all

		for _, b := range [][]byte{nil, {}} {
			if n, err := fc.Read(b); n != 0 || err != nil {
				t.Fatalf("Read(len %d) = (%d, %v), want (0, nil)", len(b), n, err)
			}
		}
		if calls, _ := raw.reads(); calls != 0 {
			t.Fatalf("underlying Read calls = %d, want 0", calls)
		}
		if _, destOK, _, execOK := bucketTokens(fc); destOK || execOK {
			t.Fatal("empty Read created accounting state")
		}

		// A nonempty read on the same connection still fails admission without I/O.
		if n, err := fc.Read(make([]byte, 1)); n != 0 || err == nil {
			t.Fatalf("Read without limits = (%d, %v), want an admission error", n, err)
		}
		if calls, _ := raw.reads(); calls != 0 {
			t.Fatalf("underlying Read calls after admission failure = %d, want 0", calls)
		}
	})

	t.Run("does not wait for the FIFO lock", func(t *testing.T) {
		raw := newScriptedConn(nil) // blocks until closed
		fc := newTestConn(t, raw, app.FromBytes(1024), app.FromBytes(1024))

		blockedRead := make(chan struct{})
		go func() {
			defer close(blockedRead)
			_, _ = fc.Read(make([]byte, 16))
		}()
		waitBounded(t, raw.blocked, "underlying read start", func() { _ = fc.Close() })

		emptyRead := make(chan struct{})
		var n int
		var err error
		go func() {
			defer close(emptyRead)
			n, err = fc.Read(nil)
		}()
		waitBounded(t, emptyRead, "empty Read while another Read holds the lock", func() { _ = fc.Close() })
		if n != 0 || err != nil {
			t.Errorf("empty Read = (%d, %v), want (0, nil)", n, err)
		}

		_ = fc.Close()
		<-blockedRead
		if calls, _ := raw.reads(); calls != 1 {
			t.Fatalf("underlying Read calls = %d, want 1 (only the blocked read)", calls)
		}
	})
}

// Regression 5a: an already expired deadline cancels a forced reservation wait
// with the deadline error, without I/O and without losing the reservation.
func TestReadExpiredDeadlineDuringReservationWait(t *testing.T) {
	set := map[string]func(*FallbackConn, time.Time) error{
		"read deadline": (*FallbackConn).SetReadDeadline,
		"deadline":      (*FallbackConn).SetDeadline,
	}
	for name, setDeadline := range set {
		t.Run(name, func(t *testing.T) {
			raw := oneRead(1, nil)
			fc := newTestConn(t, raw, app.FromBytes(1), app.FromBytes(1))
			forceReservationWait(t, fc)
			destBefore, _, execBefore, _ := bucketTokens(fc)

			if err := setDeadline(fc, time.Now().Add(-time.Second)); err != nil {
				t.Fatalf("set deadline: %v", err)
			}
			start := time.Now()
			n, err := fc.Read(make([]byte, 1))
			if n != 0 || !errors.Is(err, os.ErrDeadlineExceeded) {
				t.Fatalf("Read = (%d, %v), want (0, %v)", n, err, os.ErrDeadlineExceeded)
			}
			if elapsed := time.Since(start); elapsed > boundedWait {
				t.Fatalf("Read took %v", elapsed)
			}
			if calls, _ := raw.reads(); calls != 0 {
				t.Fatalf("underlying Read calls = %d, want 0", calls)
			}
			// The canceled reservation was refunded: at one byte per second a
			// missing 8-bit refund cannot be masked by refill within this test.
			dest, _, exec, _ := bucketTokens(fc)
			if dest < destBefore || exec < execBefore {
				t.Fatalf("buckets after canceled wait = (%d, %d) bits, want at least (%d, %d)", dest, exec, destBefore, execBefore)
			}
		})
	}
}

func TestLimiterWaitTracksDeadlineChanges(t *testing.T) {
	t.Run("earlier", func(t *testing.T) {
		raw := newScriptedConn(nil)
		fc := newTestConn(t, raw, app.FromBytes(1), app.FromBytes(1024))
		forceReservationWait(t, fc)
		if err := fc.SetWriteDeadline(time.Now().Add(time.Hour)); err != nil {
			t.Fatalf("SetWriteDeadline: %v", err)
		}
		destBefore, _, _, _ := bucketTokens(fc)
		done := make(chan error, 1)
		go func() {
			_, err := fc.Write([]byte("x"))
			done <- err
		}()
		waitUntil(t, func() bool {
			dest, _, _, _ := bucketTokens(fc)
			return dest < destBefore
		}, "reservation by waiting Write")
		if err := fc.SetWriteDeadline(time.Now().Add(50 * time.Millisecond)); err != nil {
			t.Fatalf("move deadline earlier: %v", err)
		}
		select {
		case err := <-done:
			if !errors.Is(err, os.ErrDeadlineExceeded) {
				t.Fatalf("Write error = %v, want %v", err, os.ErrDeadlineExceeded)
			}
		case <-time.After(boundedWait):
			t.Fatal("limiter wait did not observe earlier deadline")
		}
		if writes := raw.written(); len(writes) != 0 {
			t.Fatalf("underlying writes = %d, want 0", len(writes))
		}
	})

	for _, tc := range []struct {
		name   string
		update func(*FallbackConn) error
	}{
		{"later", func(fc *FallbackConn) error { return fc.SetWriteDeadline(time.Now().Add(time.Hour)) }},
		{"cleared", func(fc *FallbackConn) error { return fc.SetWriteDeadline(time.Time{}) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := newScriptedConn(nil)
			fc := newTestConn(t, raw, app.FromBytes(1), app.FromBytes(1024))
			forceReservationWait(t, fc)
			if err := fc.SetWriteDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
				t.Fatalf("SetWriteDeadline: %v", err)
			}
			destBefore, _, _, _ := bucketTokens(fc)
			done := make(chan error, 1)
			go func() {
				_, err := fc.Write([]byte("x"))
				done <- err
			}()
			waitUntil(t, func() bool {
				dest, _, _, _ := bucketTokens(fc)
				return dest < destBefore
			}, "reservation by waiting Write")
			if err := tc.update(fc); err != nil {
				t.Fatalf("update deadline: %v", err)
			}
			select {
			case err := <-done:
				t.Fatalf("Write returned at old deadline: %v", err)
			case <-time.After(250 * time.Millisecond):
			}
			if err := fc.Close(); err != nil {
				t.Fatalf("Close: %v", err)
			}
			if err := <-done; !errors.Is(err, net.ErrClosed) {
				t.Fatalf("Write error after Close = %v, want %v", err, net.ErrClosed)
			}
		})
	}
}

func TestDirectionalDeadlineOverride(t *testing.T) {
	fc := newTestConn(t, newScriptedConn(nil), app.FromBytes(1), app.FromBytes(1))
	common := time.Now().Add(time.Minute)
	if err := fc.SetDeadline(common); err != nil {
		t.Fatalf("SetDeadline: %v", err)
	}
	if err := fc.SetWriteDeadline(time.Time{}); err != nil {
		t.Fatalf("clear write deadline: %v", err)
	}
	read, _ := fc.deadlineState(false)
	write, _ := fc.deadlineState(true)
	if !read.Equal(common) {
		t.Fatalf("read deadline = %v, want %v", read, common)
	}
	if !write.IsZero() {
		t.Fatalf("write deadline = %v, want cleared", write)
	}
}

func TestDeadlineSettersKeepSocketAndWrapperOrdered(t *testing.T) {
	raw := newGatedDeadlineConn()
	fc := newTestConn(t, raw, app.FromBytes(1), app.FromBytes(1))
	first := time.Now().Add(time.Minute)
	second := first.Add(time.Minute)
	firstDone := make(chan error, 1)
	go func() { firstDone <- fc.SetDeadline(first) }()
	<-raw.setDeadlineEntered
	released := false
	defer func() {
		if !released {
			close(raw.releaseSetDeadline)
		}
	}()
	if fc.deadlineMu.TryLock() {
		fc.deadlineMu.Unlock()
		t.Fatal("wrapper deadline lock was not held across the underlying setter")
	}

	secondDone := make(chan error, 1)
	go func() { secondDone <- fc.SetWriteDeadline(second) }()
	close(raw.releaseSetDeadline)
	released = true
	if err := <-firstDone; err != nil {
		t.Fatalf("SetDeadline: %v", err)
	}
	if err := <-secondDone; err != nil {
		t.Fatalf("SetWriteDeadline: %v", err)
	}
	wrapper, _ := fc.deadlineState(true)
	if socket := raw.currentWriteDeadline(); !socket.Equal(wrapper) || !wrapper.Equal(second) {
		t.Fatalf("write deadlines: socket=%v wrapper=%v, want %v", socket, wrapper, second)
	}
}

func TestLimiterTimerWakeRechecksCurrentDeadlineBeforeWrite(t *testing.T) {
	raw := newScriptedConn(nil)
	fc := newTestConn(t, raw, app.FromBytes(1), app.FromBytes(1024))
	forceReservationWait(t, fc)
	if err := fc.SetWriteDeadline(time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("initial SetWriteDeadline: %v", err)
	}
	waitEntered := make(chan struct{})
	releaseTimer := make(chan struct{})
	fc.waitForLimiter = func(time.Duration, <-chan struct{}, <-chan struct{}, <-chan struct{}) limiterWaitResult {
		close(waitEntered)
		<-releaseTimer
		return limiterReady
	}
	done := make(chan error, 1)
	go func() {
		_, err := fc.Write([]byte("x"))
		done <- err
	}()
	<-waitEntered
	if err := fc.SetWriteDeadline(time.Now().Add(-time.Second)); err != nil {
		t.Fatalf("SetWriteDeadline: %v", err)
	}
	close(releaseTimer)
	select {
	case err := <-done:
		if !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("Write error = %v, want %v", err, os.ErrDeadlineExceeded)
		}
	case <-time.After(boundedWait):
		t.Fatal("Write did not finish after controlled limiter timer wake")
	}
	if writes := raw.written(); len(writes) != 0 {
		t.Fatalf("underlying writes = %d, want 0", len(writes))
	}
}

func TestQueuedWriteTracksEarlierDeadline(t *testing.T) {
	raw := newScriptedConn(nil)
	fc := newTestConn(t, raw, app.FromBytes(1024), app.FromBytes(1024))
	fc.writeMu.Lock()
	defer fc.writeMu.Unlock()
	if err := fc.SetWriteDeadline(time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("SetWriteDeadline: %v", err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := fc.Write([]byte("queued"))
		done <- err
	}()
	waitForFIFOQueue(t, fc.writeMu, 1)
	if err := fc.SetWriteDeadline(time.Now().Add(50 * time.Millisecond)); err != nil {
		t.Fatalf("move deadline earlier: %v", err)
	}
	select {
	case err := <-done:
		if !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("Write error = %v, want %v", err, os.ErrDeadlineExceeded)
		}
	case <-time.After(boundedWait):
		t.Fatal("queued Write did not observe earlier deadline")
	}
	if writes := raw.written(); len(writes) != 0 {
		t.Fatalf("underlying writes = %d, want 0", len(writes))
	}
}

// Regression 5b: Close cancels a reservation wait within a bounded time.
func TestCloseDuringReservationWait(t *testing.T) {
	raw := oneRead(1, nil)
	fc := newTestConn(t, raw, app.FromBytes(1), app.FromBytes(1024))
	forceReservationWait(t, fc)
	destBefore, _, _, _ := bucketTokens(fc)

	var (
		n    int
		err  error
		done = make(chan struct{})
	)
	go func() {
		defer close(done)
		n, err = fc.Read(make([]byte, 1))
	}()
	// Only close once the Read has taken its reservation and is sleeping.
	waitUntil(t, func() bool {
		dest, _, _, _ := bucketTokens(fc)
		return dest < destBefore
	}, "reservation by the sleeping Read")
	if cerr := fc.Close(); cerr != nil {
		t.Errorf("Close: %v", cerr)
	}
	waitBounded(t, done, "Read canceled by Close during reservation wait", nil)

	if n != 0 || !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Read = (%d, %v), want (0, %v)", n, err, net.ErrClosed)
	}
	if calls, _ := raw.reads(); calls != 0 {
		t.Fatalf("underlying Read calls = %d, want 0", calls)
	}
}

func TestOperationQueuedBeforeCloseReturnsNetErrClosedWithoutIO(t *testing.T) {
	for _, tc := range []struct {
		name string
		run  func(*FallbackConn) (int, error)
	}{
		{"read", func(fc *FallbackConn) (int, error) { return fc.Read(make([]byte, 1)) }},
		{"write", func(fc *FallbackConn) (int, error) { return fc.Write([]byte("x")) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := oneRead(1, nil)
			fc := newTestConn(t, raw, app.FromBytes(1), app.FromBytes(1))
			gate := fc.writeMu
			if tc.name == "read" {
				gate = fc.readMu
			}
			gate.Lock()
			defer gate.Unlock()

			done := make(chan struct{})
			var n int
			var err error
			go func() {
				defer close(done)
				n, err = tc.run(fc)
			}()
			waitForFIFOQueue(t, gate, 1)
			if cerr := fc.Close(); cerr != nil {
				t.Fatalf("Close: %v", cerr)
			}
			waitBounded(t, done, tc.name+" queued before Close", nil)

			if n != 0 || !errors.Is(err, net.ErrClosed) {
				t.Fatalf("operation = (%d, %v), want (0, %v)", n, err, net.ErrClosed)
			}
			if reads, _ := raw.reads(); reads != 0 {
				t.Fatalf("underlying reads = %d, want 0", reads)
			}
			if writes := raw.written(); len(writes) != 0 {
				t.Fatalf("underlying writes = %d, want 0", len(writes))
			}
		})
	}
}

// Regression 5c: Close terminates a Read blocked inside the underlying socket
// read, and the executor bucket is still refunded although Close already
// detached the destination entry.
func TestCloseDuringBlockedRead(t *testing.T) {
	const (
		destBytes = 8192
		execBytes = 8192
		bufSize   = 4096
	)

	t.Run("scripted blocking conn", func(t *testing.T) {
		raw := newScriptedConn(nil) // blocks until closed
		fc := newTestConn(t, raw, app.FromBytes(destBytes), app.FromBytes(execBytes))

		var (
			n    int
			err  error
			done = make(chan struct{})
		)
		go func() {
			defer close(done)
			n, err = fc.Read(make([]byte, bufSize))
		}()
		waitBounded(t, raw.blocked, "underlying read start", func() { _ = fc.Close() })
		if cerr := fc.Close(); cerr != nil {
			t.Errorf("Close: %v", cerr)
		}
		waitBounded(t, done, "Read blocked in the socket", nil)

		if n != 0 || err == nil {
			t.Fatalf("Read = (%d, %v), want (0, error)", n, err)
		}
		if calls, sizes := raw.reads(); calls != 1 || sizes[0] != bufSize {
			t.Fatalf("underlying Read calls = %d sizes = %v, want one call of %d", calls, sizes, bufSize)
		}
		_, destOK, exec, execOK := bucketTokens(fc)
		if destOK {
			t.Error("destination bucket was recreated after Close")
		}
		if !execOK || exec != app.FromBytes(execBytes) {
			t.Errorf("executor bucket = %d bits (present=%v), want full refund to %d bits", exec, execOK, app.FromBytes(execBytes))
		}
	})

	t.Run("loopback tcp", func(t *testing.T) {
		raw, join := loopbackPair(t, func(c net.Conn, stop <-chan struct{}) { <-stop })
		fc := newTestConn(t, raw, app.FromBytes(destBytes), app.FromBytes(execBytes))
		// Final bound in case Close does not wake the socket read.
		if err := fc.SetReadDeadline(time.Now().Add(2 * boundedWait)); err != nil {
			t.Fatalf("SetReadDeadline: %v", err)
		}

		var (
			n    int
			err  error
			done = make(chan struct{})
		)
		go func() {
			defer close(done)
			n, err = fc.Read(make([]byte, bufSize))
		}()
		if cerr := fc.Close(); cerr != nil {
			t.Errorf("Close: %v", cerr)
		}
		waitBounded(t, done, "Read on a closed loopback socket", nil)
		join()

		if n != 0 || err == nil || errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("Read = (%d, %v), want (0, close error)", n, err)
		}
		if _, destOK, _, _ := bucketTokens(fc); destOK {
			t.Error("destination bucket was recreated after Close")
		}
	})
}

// Regression 6: Write still splits output at the reservation cap and
// delivers every chunk in order.
func TestWriteCompletesMultiChunkInOrder(t *testing.T) {
	const (
		destBytes = 1000 // caps one reservation at 1000 bytes
		execBytes = 1 << 20
		payload   = 1020 // second chunk of 20 bytes waits about 20ms
	)
	data := make([]byte, payload)
	for i := range data {
		data[i] = byte(i % 251)
	}

	raw := newScriptedConn(nil)
	fc := newTestConn(t, raw, app.FromBytes(destBytes), app.FromBytes(execBytes))

	n, err := fc.Write(data)
	if n != payload || err != nil {
		t.Fatalf("Write = (%d, %v), want (%d, nil)", n, err, payload)
	}

	writes := raw.written()
	wantSizes := []int{destBytes, payload - destBytes}
	if len(writes) != len(wantSizes) {
		t.Fatalf("underlying Write calls = %d, want %d", len(writes), len(wantSizes))
	}
	var joined []byte
	for i, w := range writes {
		if len(w) != wantSizes[i] {
			t.Errorf("chunk %d has %d bytes, want %d", i, len(w), wantSizes[i])
		}
		joined = append(joined, w...)
	}
	if !bytes.Equal(joined, data) {
		t.Fatal("chunks were not delivered in order")
	}
	if calls, _ := raw.reads(); calls != 0 {
		t.Fatalf("Write performed %d underlying reads", calls)
	}
}

func TestWriteRefundsUnusedReservation(t *testing.T) {
	const (
		destBytes = 200
		execBytes = 400
		payload   = 100
	)
	sentinel := errors.New("sentinel write error")

	t.Run("full write", func(t *testing.T) {
		raw := newScriptedConn(nil)
		fc := newTestConn(t, raw, app.FromBytes(destBytes), app.FromBytes(execBytes))
		if n, err := fc.Write(make([]byte, payload)); n != payload || err != nil {
			t.Fatalf("Write = (%d, %v), want (%d, nil)", n, err, payload)
		}
		assertTokens(t, fc, app.FromBytes(destBytes-payload), app.FromBytes(execBytes-payload))
	})

	t.Run("short successful writes", func(t *testing.T) {
		raw := newScriptedConn(nil)
		calls := 0
		raw.write = func(b []byte) (int, error) {
			calls++
			if calls == 1 {
				return 30, nil
			}
			return len(b), nil
		}
		fc := newTestConn(t, raw, app.FromBytes(destBytes), app.FromBytes(execBytes))
		if n, err := fc.Write(make([]byte, payload)); n != payload || err != nil {
			t.Fatalf("Write = (%d, %v), want (%d, nil)", n, err, payload)
		}
		if calls != 2 {
			t.Fatalf("underlying Write calls = %d, want 2", calls)
		}
		assertTokens(t, fc, app.FromBytes(destBytes-payload), app.FromBytes(execBytes-payload))
	})

	t.Run("accumulates short write before error", func(t *testing.T) {
		raw := newScriptedConn(nil)
		calls := 0
		raw.write = func([]byte) (int, error) {
			calls++
			if calls == 1 {
				return 30, nil
			}
			return 20, sentinel
		}
		fc := newTestConn(t, raw, app.FromBytes(destBytes), app.FromBytes(execBytes))
		if n, err := fc.Write(make([]byte, payload)); n != 50 || !errors.Is(err, sentinel) {
			t.Fatalf("Write = (%d, %v), want (50, %v)", n, err, sentinel)
		}
		assertTokens(t, fc, app.FromBytes(destBytes-50), app.FromBytes(execBytes-50))
	})

	for _, tc := range []struct {
		name     string
		n        int
		err      error
		wantErr  error
		wantDest int
		wantExec int
	}{
		{"partial with error", 30, sentinel, sentinel, destBytes - 30, execBytes - 30},
		{"zero with error", 0, sentinel, sentinel, destBytes, execBytes},
		{"zero progress", 0, nil, io.ErrNoProgress, destBytes, execBytes},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := newScriptedConn(nil)
			raw.write = func([]byte) (int, error) { return tc.n, tc.err }
			fc := newTestConn(t, raw, app.FromBytes(destBytes), app.FromBytes(execBytes))
			n, err := fc.Write(make([]byte, payload))
			if n != tc.n || !errors.Is(err, tc.wantErr) {
				t.Fatalf("Write = (%d, %v), want (%d, %v)", n, err, tc.n, tc.wantErr)
			}
			if calls := len(raw.written()); calls != 1 {
				t.Fatalf("underlying Write calls = %d, want 1", calls)
			}
			assertTokens(t, fc, app.FromBytes(tc.wantDest), app.FromBytes(tc.wantExec))
		})
	}

	t.Run("executor refunded after destination detach", func(t *testing.T) {
		raw := newScriptedConn(nil)
		fc := newTestConn(t, raw, app.FromBytes(destBytes), app.FromBytes(execBytes))
		raw.write = func([]byte) (int, error) {
			fc.count.Detach(fc.addr, fc.id, fc.ipv6)
			return 30, sentinel
		}
		if n, err := fc.Write(make([]byte, payload)); n != 30 || !errors.Is(err, sentinel) {
			t.Fatalf("Write = (%d, %v), want (30, %v)", n, err, sentinel)
		}
		_, destOK, exec, execOK := bucketTokens(fc)
		if destOK {
			t.Error("destination bucket was recreated after detach")
		}
		if !execOK || exec != app.FromBytes(execBytes-30) {
			t.Errorf("executor bucket = %d bits (present=%v), want %d bits", exec, execOK, app.FromBytes(execBytes-30))
		}
	})

	t.Run("destination refunded after executor delete", func(t *testing.T) {
		raw := newScriptedConn(nil)
		fc := newTestConn(t, raw, app.FromBytes(destBytes), app.FromBytes(execBytes))
		raw.write = func([]byte) (int, error) {
			if err := fc.count.DeleteExecLimit(fc.id); err != nil {
				t.Fatalf("DeleteExecLimit: %v", err)
			}
			return 30, sentinel
		}
		if n, err := fc.Write(make([]byte, payload)); n != 30 || !errors.Is(err, sentinel) {
			t.Fatalf("Write = (%d, %v), want (30, %v)", n, err, sentinel)
		}
		dest, destOK, _, execOK := bucketTokens(fc)
		if execOK {
			t.Error("executor bucket was recreated after delete")
		}
		if !destOK || dest != app.FromBytes(destBytes-30) {
			t.Errorf("destination bucket = %d bits (present=%v), want %d bits", dest, destOK, app.FromBytes(destBytes-30))
		}
	})

	for _, invalid := range []int{-1, payload + 1} {
		t.Run(fmt.Sprintf("invalid count %d", invalid), func(t *testing.T) {
			raw := newScriptedConn(nil)
			raw.write = func([]byte) (int, error) { return invalid, nil }
			fc := newTestConn(t, raw, app.FromBytes(destBytes), app.FromBytes(execBytes))
			n, err := fc.Write(make([]byte, payload))
			if n != 0 || err == nil {
				t.Fatalf("Write = (%d, %v), want (0, invalid-count error)", n, err)
			}
			// The writer's actual byte count is unknowable after it violates the
			// contract, so retain the reservation rather than creating credit.
			assertTokens(t, fc, app.FromBytes(destBytes-payload), app.FromBytes(execBytes-payload))
		})
	}
}

func TestSharedIPRateLivesUntilLastAliasDetaches(t *testing.T) {
	count, err := NewFallbackCount()
	if err != nil {
		t.Fatalf("NewFallbackCount: %v", err)
	}
	id := uuid.New()
	otherID := uuid.New()
	attach := func(id uuid.UUID, alias string) *FallbackConn {
		t.Helper()
		conn, err := count.Attach(newScriptedConn(nil), id, alias)
		if err != nil {
			t.Fatalf("Attach(%q): %v", alias, err)
		}
		return conn.(*FallbackConn)
	}
	first := attach(id, "first.example")
	second := attach(id, "second.example")
	otherRun := attach(otherID, "first.example")
	t.Cleanup(func() {
		_ = first.Close()
		_ = second.Close()
		_ = otherRun.Close()
	})

	const limitBytes = 1024
	for _, item := range []struct {
		alias string
		id    uuid.UUID
	}{
		{"first.example", id},
		{"second.example", id},
		{"first.example", otherID},
	} {
		if err := count.SetLimit(item.alias, item.id, app.FromBytes(limitBytes)); err != nil {
			t.Fatalf("SetLimit(%q): %v", item.alias, err)
		}
		if err := count.SetExecLimit(item.id, app.FromBytes(limitBytes)); err != nil {
			t.Fatalf("SetExecLimit: %v", err)
		}
	}

	if err := first.Close(); err != nil {
		t.Fatalf("close first alias: %v", err)
	}
	if n, err := second.Write([]byte("still attached")); n != len("still attached") || err != nil {
		t.Fatalf("second alias Write = (%d, %v), want (%d, nil)", n, err, len("still attached"))
	}

	key := debugletKey{id: id, dest: second.ipv6}
	otherKey := debugletKey{id: otherID, dest: otherRun.ipv6}
	reservation, err := second.reserve(10)
	if err != nil {
		t.Fatalf("reserve before final detach: %v", err)
	}
	start := make(chan struct{})
	closeDone := make(chan error, 1)
	refundDone := make(chan struct{})
	go func() {
		<-start
		closeDone <- second.Close()
	}()
	go func() {
		defer close(refundDone)
		<-start
		reservation.free()
	}()
	close(start)
	if err := <-closeDone; err != nil {
		t.Fatalf("close final alias: %v", err)
	}
	<-refundDone

	count.mu.Lock()
	_, rateExists := count.rates[key]
	_, bucketExists := count.packetSize[key]
	_, attachmentExists := count.attached[key]
	_, otherRateExists := count.rates[otherKey]
	count.mu.Unlock()
	if rateExists || bucketExists || attachmentExists {
		t.Fatalf("final detach retained state: rate=%v bucket=%v attachment=%v", rateExists, bucketExists, attachmentExists)
	}
	if !otherRateExists {
		t.Fatal("final detach removed another run's rate")
	}
}

func TestClosedConnWithExpiredDeadlineReportsClosed(t *testing.T) {
	fc := newTestConn(t, newScriptedConn(nil), app.FromBytes(1024), app.FromBytes(1024))
	if err := fc.SetDeadline(time.Now().Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := fc.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := fc.Write([]byte("x")); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Write after Close = %v, want %v", err, net.ErrClosed)
	}
	if _, err := fc.Read(make([]byte, 1)); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Read after Close = %v, want %v", err, net.ErrClosed)
	}
}

// paidWrite describes the destination accounting at the moment a write
// reached the socket.
type paidWrite struct {
	at   time.Time
	rate app.Bitrate
	// credit is the destination balance at that moment, in bits: the stored
	// tokens refilled at rate since the bucket was last updated. A write that
	// is released only once its reservation is paid for never finds it below
	// zero.
	credit float64
}

// observePaidWrites makes every underlying write on raw report the
// destination accounting it found.
func observePaidWrites(fc *FallbackConn, raw *scriptedConn) <-chan paidWrite {
	seen := make(chan paidWrite, 16)
	raw.write = func(b []byte) (int, error) {
		w := paidWrite{at: time.Now()}
		key := debugletKey{id: fc.id, dest: fc.ipv6}
		fc.count.mu.Lock()
		if bucket, ok := fc.count.packetSize[key]; ok {
			w.rate = fc.count.rates[key]
			w.credit = float64(bucket.tokens) + w.at.Sub(bucket.last).Seconds()*float64(w.rate)
		}
		fc.count.mu.Unlock()
		seen <- w
		return len(b), nil
	}
	return seen
}

// onlyPaidWrite returns the single write reported by observePaidWrites.
func onlyPaidWrite(t *testing.T, raw *scriptedConn, seen <-chan paidWrite) paidWrite {
	t.Helper()
	if writes := raw.written(); len(writes) != 1 {
		t.Fatalf("underlying writes = %d, want 1", len(writes))
	}
	return <-seen
}

// Regression: a rate lowered while a write waited for its reservation left
// the wait computed under the old rate in force, and the write reached the
// socket before the lowered rate had paid for it.
func TestLoweredRateDelaysWaitingWrite(t *testing.T) {
	const (
		oldBytes  = 40 // per second: the empty bucket pays the payload in 0.5s
		newBytes  = 20 // per second: in 1s
		payload   = 20
		execBytes = 1 << 20
	)
	raw := newScriptedConn(nil)
	fc := newTestConn(t, raw, app.FromBytes(oldBytes), app.FromBytes(execBytes))
	seen := observePaidWrites(fc, raw)
	seeded := time.Now()
	seedBuckets(t, fc, 0, app.FromBytes(execBytes))

	var (
		n    int
		err  error
		done = make(chan struct{})
	)
	go func() {
		defer close(done)
		n, err = fc.Write(make([]byte, payload))
	}()
	waitUntil(t, func() bool {
		dest, _, _, _ := bucketTokens(fc)
		return dest < 0
	}, "reservation by the waiting Write")
	if err := fc.count.SetLimit(testAddr, fc.id, app.FromBytes(newBytes)); err != nil {
		t.Fatalf("SetLimit: %v", err)
	}
	lowered := time.Now()
	waitBounded(t, done, "Write after the rate was lowered", func() { _ = fc.Close() })

	if n != payload || err != nil {
		t.Fatalf("Write = (%d, %v), want (%d, nil)", n, err, payload)
	}
	w := onlyPaidWrite(t, raw, seen)
	if w.rate != app.FromBytes(newBytes) {
		t.Fatalf("write released at %d bits/s: the rate was not lowered while it waited", int64(w.rate))
	}
	if w.credit < 0 {
		t.Errorf("write released with %.1f bits of destination credit at the lowered rate, want none owed", w.credit)
	}
	// Until the change the empty bucket gained at most the old rate; the rest
	// of the payload can only have accrued at the new rate after it.
	gained := lowered.Sub(seeded).Seconds() * float64(app.FromBytes(oldBytes))
	owed := (float64(app.FromBytes(payload)) - gained) / float64(app.FromBytes(newBytes))
	if earliest := time.Duration(owed * float64(time.Second)); w.at.Sub(lowered) < earliest {
		t.Errorf("write released %v after the rate was lowered, want at least %v", w.at.Sub(lowered), earliest)
	}
}

// Regression: a rate raised while a write waited had no effect until the wait
// computed under the old rate ran out. The write now observes the new
// permission without any other event: its wait is recomputed, and it waits
// for what the bucket still owes at the new rate.
func TestRaisedRateShortensWaitingWrite(t *testing.T) {
	const (
		oldBytes  = 1   // per second: the write below waits 30s
		newBytes  = 100 // per second: 0.3s
		debtBytes = 29  // owed before the one-byte write
		execBytes = 1 << 20
	)
	raw := newScriptedConn(nil)
	fc := newTestConn(t, raw, app.FromBytes(oldBytes), app.FromBytes(execBytes))
	seen := observePaidWrites(fc, raw)
	seeded := time.Now()
	seedBuckets(t, fc, -app.FromBytes(debtBytes), app.FromBytes(execBytes))
	owed := app.FromBytes(debtBytes + 1)

	var (
		n    int
		err  error
		done = make(chan struct{})
	)
	start := time.Now()
	go func() {
		defer close(done)
		n, err = fc.Write([]byte("x"))
	}()
	waitUntil(t, func() bool {
		dest, _, _, _ := bucketTokens(fc)
		return dest < -app.FromBytes(debtBytes)
	}, "reservation by the waiting Write")
	if err := fc.count.SetLimit(testAddr, fc.id, app.FromBytes(newBytes)); err != nil {
		t.Fatalf("SetLimit: %v", err)
	}
	raised := time.Now()
	waitBounded(t, done, "Write after the rate was raised", func() { _ = fc.Close() })

	if n != 1 || err != nil {
		t.Fatalf("Write = (%d, %v), want (1, nil)", n, err)
	}
	w := onlyPaidWrite(t, raw, seen)
	if w.rate != app.FromBytes(newBytes) {
		t.Fatalf("write released at %d bits/s, want the raised rate", int64(w.rate))
	}
	if w.credit < 0 {
		t.Errorf("write released with %.1f bits of destination credit at the raised rate, want none owed", w.credit)
	}
	elapsed := w.at.Sub(start)
	if old := tokenWait(owed, app.FromBytes(oldBytes)); elapsed >= old {
		t.Errorf("write released after %v, not earlier than the %v the old rate needed", elapsed, old)
	}
	// The debt still counts: before the change the old rate paid a negligible
	// part of it, and the rest takes its time at the new rate.
	gained := raised.Sub(seeded).Seconds() * float64(app.FromBytes(oldBytes))
	if least := time.Duration((float64(owed) - gained) / float64(app.FromBytes(newBytes)) * float64(time.Second)); elapsed < least {
		t.Errorf("write released after %v, want at least the %v the debt takes at the raised rate", elapsed, least)
	}
}

// Regression: deleting a rate, or setting it to zero, while a write waited
// left the old permission in force, so the write reached the socket once the
// old wait ran out. The waiting reservation is now given back and the write
// fails with the error a new reservation gets, before any I/O.
func TestRevokedRateFailsWaitingWrite(t *testing.T) {
	const debtBytes = 29 // at one byte per second the write below waits 30s
	balance := -app.FromBytes(debtBytes)
	for _, tc := range []struct {
		name               string
		revoke             func(*FallbackConn) error
		wantErr            func(error) bool
		destLeft, execLeft bool
	}{
		{
			name:     "destination deleted",
			revoke:   func(fc *FallbackConn) error { return fc.count.DeleteLimit(fc.ipv6, fc.id) },
			wantErr:  func(err error) bool { return err != nil && strings.Contains(err.Error(), "no dest rate") },
			execLeft: true,
		},
		{
			name:     "executor deleted",
			revoke:   func(fc *FallbackConn) error { return fc.count.DeleteExecLimit(fc.id) },
			wantErr:  func(err error) bool { return err != nil && strings.Contains(err.Error(), "no exec rate") },
			destLeft: true,
		},
		{
			name:     "destination zero",
			revoke:   func(fc *FallbackConn) error { return fc.count.SetLimit(testAddr, fc.id, 0) },
			wantErr:  func(err error) bool { return err != nil && strings.Contains(err.Error(), "no dest rate") },
			destLeft: true,
			execLeft: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := newScriptedConn(nil)
			fc := newTestConn(t, raw, app.FromBytes(1), app.FromBytes(1))
			seedBuckets(t, fc, balance, balance)

			var (
				n    int
				err  error
				done = make(chan struct{})
			)
			go func() {
				defer close(done)
				n, err = fc.Write([]byte("x"))
			}()
			waitUntil(t, func() bool {
				dest, _, _, _ := bucketTokens(fc)
				return dest < balance
			}, "reservation by the waiting Write")
			if err := tc.revoke(fc); err != nil {
				t.Fatalf("revoke: %v", err)
			}
			waitBounded(t, done, "waiting Write after the rate was revoked", func() { _ = fc.Close() })

			if n != 0 || !tc.wantErr(err) {
				t.Fatalf("Write = (%d, %v), want (0, the error a new reservation gets)", n, err)
			}
			if writes := raw.written(); len(writes) != 0 {
				t.Fatalf("underlying writes = %d, want 0", len(writes))
			}
			// Every bucket that is left got the reservation back: at one byte
			// per second a missing 8-bit refund cannot hide behind refill.
			dest, destOK, exec, execOK := bucketTokens(fc)
			if destOK != tc.destLeft || execOK != tc.execLeft {
				t.Fatalf("buckets left: destination=%v executor=%v, want %v and %v", destOK, execOK, tc.destLeft, tc.execLeft)
			}
			if destOK && dest < balance {
				t.Errorf("destination bucket = %d bits, want at least %d after the refund", int64(dest), int64(balance))
			}
			if execOK && exec < balance {
				t.Errorf("executor bucket = %d bits, want at least %d after the refund", int64(exec), int64(balance))
			}
		})
	}
}

// Rate updates racing the cancellation of a waiting write: the write still
// ends with the cancellation error and nothing written, and every reservation
// taken along the way was given back, so each bucket that is left holds what
// it held before plus refill, never less and never more.
func TestRateUpdatesDuringCanceledWaitConserveAccounting(t *testing.T) {
	const (
		debtBytes = 29 // the write below waits 15s or more at either rate
		updates   = 200
	)
	balance := -app.FromBytes(debtBytes)
	for _, tc := range []struct {
		name    string
		cancel  func(*FallbackConn) error
		wantErr error
	}{
		{"close", (*FallbackConn).Close, net.ErrClosed},
		{"deadline", func(fc *FallbackConn) error { return fc.SetWriteDeadline(time.Now()) }, os.ErrDeadlineExceeded},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := newScriptedConn(nil)
			fc := newTestConn(t, raw, app.FromBytes(1), app.FromBytes(1))
			seeded := time.Now()
			seedBuckets(t, fc, balance, balance)

			var (
				n    int
				err  error
				done = make(chan struct{})
			)
			go func() {
				defer close(done)
				n, err = fc.Write([]byte("x"))
			}()
			waitUntil(t, func() bool {
				dest, _, _, _ := bucketTokens(fc)
				return dest < balance
			}, "reservation by the waiting Write")
			updated := make(chan struct{})
			go func() {
				defer close(updated)
				for i := range updates {
					rate := app.FromBytes(1 + i%2)
					_ = fc.count.SetLimit(testAddr, fc.id, rate)
					_ = fc.count.SetExecLimit(fc.id, rate)
				}
			}()
			if err := tc.cancel(fc); err != nil {
				t.Fatalf("cancel: %v", err)
			}
			<-updated
			waitBounded(t, done, "canceled Write during rate updates", func() { _ = fc.Close() })

			if n != 0 || !errors.Is(err, tc.wantErr) {
				t.Fatalf("Write = (%d, %v), want (0, %v)", n, err, tc.wantErr)
			}
			if writes := raw.written(); len(writes) != 0 {
				t.Fatalf("underlying writes = %d, want 0", len(writes))
			}
			most := balance + app.Bitrate(math.Ceil(time.Since(seeded).Seconds()*float64(app.FromBytes(2))))
			dest, destOK, exec, execOK := bucketTokens(fc)
			if !execOK || exec < balance || exec > most {
				t.Errorf("executor bucket = %d bits (present=%v), want between %d and %d", int64(exec), execOK, int64(balance), int64(most))
			}
			if destOK && (dest < balance || dest > most) {
				t.Errorf("destination bucket = %d bits, want between %d and %d", int64(dest), int64(balance), int64(most))
			}
		})
	}
}

// A datagram waiting for its reservation keeps it whole when the rate moves:
// once the rate is raised it leaves as one write, well before the old rate
// would have allowed it.
func TestRaisedRateReleasesWaitingDatagramWhole(t *testing.T) {
	const (
		oldBytes = 10 // per second: the full bucket holds a third of the datagram
		newBytes = 1000
		size     = 30
	)
	raw := newScriptedConn(nil)
	raw.network = "udp"
	fc := newTestConn(t, raw, app.FromBytes(oldBytes), app.FromBytes(1<<20))

	var (
		n    int
		err  error
		done = make(chan struct{})
	)
	start := time.Now()
	go func() {
		defer close(done)
		n, err = fc.Write(bytes.Repeat([]byte{'d'}, size))
	}()
	waitUntil(t, func() bool {
		dest, ok, _, _ := bucketTokens(fc)
		return ok && dest < 0
	}, "reservation by the waiting datagram")
	if err := fc.count.SetLimit(testAddr, fc.id, app.FromBytes(newBytes)); err != nil {
		t.Fatalf("SetLimit: %v", err)
	}
	waitBounded(t, done, "datagram after the rate was raised", func() { _ = fc.Close() })

	if n != size || err != nil {
		t.Fatalf("Write = (%d, %v), want (%d, nil)", n, err, size)
	}
	if writes := raw.written(); len(writes) != 1 || len(writes[0]) != size {
		t.Fatalf("underlying writes = %d, want one write of the whole %d-byte datagram", len(writes), size)
	}
	if elapsed, old := time.Since(start), tokenWait(app.FromBytes(size-oldBytes), app.FromBytes(oldBytes)); elapsed >= old {
		t.Errorf("datagram released after %v, not earlier than the %v the old rate needed", elapsed, old)
	}
}

// A datagram connection hands each datagram to the socket whole, even when it
// is larger than one second of the rate: one write of the whole payload and
// one read into the whole buffer, after waiting for the part the bucket does
// not hold. On a stream the same sizes are split at the rate, see
// TestWriteCompletesMultiChunkInOrder and TestReadReturnsSingleUnderlyingResult.
func TestDatagramIsAdmittedWhole(t *testing.T) {
	const (
		destBytes = 1000
		execBytes = 1 << 20
		size      = 1020 // 20 bytes beyond the full bucket
	)
	wait := tokenWait(app.FromBytes(size-destBytes), app.FromBytes(destBytes))

	t.Run("write", func(t *testing.T) {
		raw := newScriptedConn(nil)
		raw.network = "udp"
		fc := newTestConn(t, raw, app.FromBytes(destBytes), app.FromBytes(execBytes))
		data := bytes.Repeat([]byte{'d'}, size)
		start := time.Now()
		if n, err := fc.Write(data); n != size || err != nil {
			t.Fatalf("Write = (%d, %v), want (%d, nil)", n, err, size)
		}
		if elapsed := time.Since(start); elapsed < wait {
			t.Errorf("Write returned after %v, want at least the %v the deficit takes", elapsed, wait)
		}
		if writes := raw.written(); len(writes) != 1 || !bytes.Equal(writes[0], data) {
			t.Fatalf("underlying writes = %d, want one write of the whole %d-byte datagram", len(writes), size)
		}
		// The part beyond the bucket is charged too, as debt.
		assertTokens(t, fc, app.FromBytes(destBytes-size), app.FromBytes(execBytes-size))
	})

	t.Run("read", func(t *testing.T) {
		raw := oneRead(5, nil)
		raw.network = "udp"
		fc := newTestConn(t, raw, app.FromBytes(destBytes), app.FromBytes(execBytes))
		start := time.Now()
		if n, err := fc.Read(make([]byte, size)); n != 5 || err != nil {
			t.Fatalf("Read = (%d, %v), want (5, nil)", n, err)
		}
		if elapsed := time.Since(start); elapsed < wait {
			t.Errorf("Read returned after %v, want at least the %v the deficit takes", elapsed, wait)
		}
		if calls, sizes := raw.reads(); calls != 1 || sizes[0] != size {
			t.Fatalf("underlying reads = %d of sizes %v, want one read into the whole %d-byte buffer", calls, sizes, size)
		}
		// Only the datagram that arrived is charged.
		assertTokens(t, fc, app.FromBytes(destBytes-5), app.FromBytes(execBytes-5))
	})

	t.Run("empty write", func(t *testing.T) {
		raw := newScriptedConn(nil)
		raw.network = "udp"
		fc := newTestConn(t, raw, 0, 0) // an empty datagram needs no limits
		if n, err := fc.Write(nil); n != 0 || err != nil {
			t.Fatalf("Write(nil) = (%d, %v), want (0, nil)", n, err)
		}
		if writes := raw.written(); len(writes) != 1 || len(writes[0]) != 0 {
			t.Fatalf("underlying writes = %q, want one empty datagram", writes)
		}
		if _, destOK, _, execOK := bucketTokens(fc); destOK || execOK {
			t.Fatal("empty datagram created accounting state")
		}
	})

	t.Run("empty write on a stream", func(t *testing.T) {
		raw := newScriptedConn(nil)
		fc := newTestConn(t, raw, 0, 0)
		if n, err := fc.Write(nil); n != 0 || err != nil {
			t.Fatalf("Write(nil) = (%d, %v), want (0, nil)", n, err)
		}
		if writes := raw.written(); len(writes) != 0 {
			t.Fatalf("underlying writes = %d, want none", len(writes))
		}
	})
}

// A rate of zero admits nothing. A datagram, although reserved whole beyond
// one second of the rate, is refused with the error a stream gets at a zero
// rate, before any I/O and without charging a bucket.
func TestZeroRateRefusesDatagram(t *testing.T) {
	for _, tc := range []struct {
		name string
		run  func(*FallbackConn) (int, error)
	}{
		{"write", func(fc *FallbackConn) (int, error) { return fc.Write([]byte("datagram")) }},
		{"read", func(fc *FallbackConn) (int, error) { return fc.Read(make([]byte, 64)) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := oneRead(8, nil)
			raw.network = "udp"
			fc := newTestConn(t, raw, 0, app.FromBytes(1024))
			if err := fc.count.SetLimit(testAddr, fc.id, 0); err != nil {
				t.Fatalf("SetLimit: %v", err)
			}
			if n, err := tc.run(fc); n != 0 || err == nil || !strings.Contains(err.Error(), "no dest rate") {
				t.Fatalf("%s = (%d, %v), want (0, the no dest rate error)", tc.name, n, err)
			}
			if reads, _ := raw.reads(); reads != 0 {
				t.Fatalf("underlying reads = %d, want 0", reads)
			}
			if writes := raw.written(); len(writes) != 0 {
				t.Fatalf("underlying writes = %d, want 0", len(writes))
			}
			if _, destOK, _, execOK := bucketTokens(fc); destOK || execOK {
				t.Fatal("refused datagram created accounting state")
			}
		})
	}
}

// The socket's answer to a datagram is final. Its error is passed through
// unchanged, and a datagram it took only part of is reported as a short write
// instead of being completed by a second datagram. Only what was sent is
// charged, and a count outside the datagram keeps the reservation, as on a
// stream.
func TestDatagramWriteResult(t *testing.T) {
	const (
		destBytes = 200
		execBytes = 400
		payload   = 100
	)
	sentinel := errors.New("sentinel write error")
	for _, tc := range []struct {
		name    string
		n       int
		err     error
		wantErr error
		charged int
	}{
		{"socket error", 0, sentinel, sentinel, 0},
		{"partial with error", 30, sentinel, sentinel, 30},
		{"short", 30, nil, io.ErrShortWrite, 30},
		{"nothing sent", 0, nil, io.ErrShortWrite, 0},
		{"invalid count -1", -1, nil, nil, payload},
		{"invalid count beyond the datagram", payload + 1, nil, nil, payload},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := newScriptedConn(nil)
			raw.network = "udp"
			raw.write = func([]byte) (int, error) { return tc.n, tc.err }
			fc := newTestConn(t, raw, app.FromBytes(destBytes), app.FromBytes(execBytes))
			n, err := fc.Write(make([]byte, payload))
			switch {
			case tc.wantErr == nil && (n != 0 || err == nil):
				t.Fatalf("Write = (%d, %v), want (0, invalid-count error)", n, err)
			case tc.wantErr != nil && (n != tc.n || !errors.Is(err, tc.wantErr)):
				t.Fatalf("Write = (%d, %v), want (%d, %v)", n, err, tc.n, tc.wantErr)
			}
			if writes := raw.written(); len(writes) != 1 || len(writes[0]) != payload {
				t.Fatalf("underlying writes = %d, want one write of the whole datagram", len(writes))
			}
			assertTokens(t, fc, app.FromBytes(destBytes-tc.charged), app.FromBytes(execBytes-tc.charged))
		})
	}
}

// Regression: a rate change woke a datagram waiting for a reservation beyond
// one second of the rate, and the reservation was given back and taken again.
// The refund is capped at one second of the rate, so the wait already served
// was lost and the datagram waited for the whole deficit once more. A change
// that does not shorten what it owes now leaves its release where it was.
func TestRateChangeKeepsServedWaitOfDatagram(t *testing.T) {
	const (
		destBytes = 10 // per second: the full bucket holds a third of the datagram
		size      = 30
		execBytes = 1 << 20
		wakeAfter = time.Second
		margin    = time.Second
	)
	raw := newScriptedConn(nil)
	raw.network = "udp"
	fc := newTestConn(t, raw, app.FromBytes(destBytes), app.FromBytes(execBytes))
	owed := tokenWait(app.FromBytes(size-destBytes), app.FromBytes(destBytes))

	var (
		n    int
		err  error
		done = make(chan struct{})
	)
	start := time.Now()
	go func() {
		defer close(done)
		n, err = fc.Write(bytes.Repeat([]byte{'d'}, size))
	}()
	waitUntil(t, func() bool {
		dest, ok, _, _ := bucketTokens(fc)
		return ok && dest < 0
	}, "reservation by the waiting datagram")
	time.Sleep(time.Until(start.Add(wakeAfter)))
	if err := fc.count.SetExecLimit(fc.id, app.FromBytes(execBytes/2)); err != nil {
		t.Fatalf("SetExecLimit: %v", err)
	}
	if moved := time.Since(start); moved >= owed {
		t.Fatalf("executor rate moved %v after the start, not within the %v wait", moved, owed)
	}
	waitBounded(t, done, "datagram after the executor rate moved", func() { _ = fc.Close() })
	elapsed := time.Since(start)

	if n != size || err != nil {
		t.Fatalf("Write = (%d, %v), want (%d, nil)", n, err, size)
	}
	if writes := raw.written(); len(writes) != 1 || len(writes[0]) != size {
		t.Fatalf("underlying writes = %d, want one write of the whole %d-byte datagram", len(writes), size)
	}
	if elapsed < owed {
		t.Errorf("datagram released after %v, want at least the %v the deficit takes", elapsed, owed)
	}
	if elapsed > owed+margin {
		t.Errorf("datagram released after %v, want at most %v: the wait served before the rate change was lost", elapsed, owed+margin)
	}
}

// Regression: a rate change made a waiting reservation wait for the whole
// balance of the shared buckets, including what reservations charged after it
// owe, instead of what it still owes itself. Two connections of one run to one
// destination share both buckets: the first keeps its place ahead of the
// second, and once the rates are raised it waits only for its own deficit at
// the new rate.
func TestRateChangeKeepsOwnDeficitOfWaitingReservation(t *testing.T) {
	const (
		oldBytes = 10 // per second, both levels: from empty buckets A waits 1s, B 5s
		newBytes = 20
		sizeA    = 10
		sizeB    = 40
		raiseAt  = 500 * time.Millisecond
		margin   = time.Second
		labelA   = "A"
		labelB   = "B"
	)
	type release struct {
		label string
		at    time.Time
	}
	released := make(chan release, 2)
	record := func(label string) func([]byte) (int, error) {
		return func(b []byte) (int, error) {
			released <- release{label: label, at: time.Now()}
			return len(b), nil
		}
	}
	rawA := newScriptedConn(nil)
	rawA.network = "udp"
	rawA.write = record(labelA)
	fcA := newTestConn(t, rawA, app.FromBytes(oldBytes), app.FromBytes(oldBytes))
	rawB := newScriptedConn(nil)
	rawB.network = "udp"
	rawB.write = record(labelB)
	connB, err := fcA.count.Attach(rawB, fcA.id, testAddr)
	if err != nil {
		t.Fatalf("Attach: %v", err)
	}
	fcB := connB.(*FallbackConn)
	t.Cleanup(func() { _ = fcB.Close() })
	seeded := time.Now()
	seedBuckets(t, fcA, 0, 0)

	var (
		errA, errB   error
		nA, nB       int
		doneA, doneB = make(chan struct{}), make(chan struct{})
	)
	go func() {
		defer close(doneA)
		nA, errA = fcA.Write(bytes.Repeat([]byte{'a'}, sizeA))
	}()
	waitUntil(t, func() bool {
		dest, _, _, _ := bucketTokens(fcA)
		return dest < 0
	}, "reservation by A")
	go func() {
		defer close(doneB)
		nB, errB = fcB.Write(bytes.Repeat([]byte{'b'}, sizeB))
	}()
	waitUntil(t, func() bool {
		dest, _, _, _ := bucketTokens(fcA)
		return dest < -app.FromBytes(sizeA)
	}, "reservation by B behind A")
	time.Sleep(time.Until(seeded.Add(raiseAt)))
	if err := fcA.count.SetLimit(testAddr, fcA.id, app.FromBytes(newBytes)); err != nil {
		t.Fatalf("SetLimit: %v", err)
	}
	if err := fcA.count.SetExecLimit(fcA.id, app.FromBytes(newBytes)); err != nil {
		t.Fatalf("SetExecLimit: %v", err)
	}
	raised := time.Now()
	if ownWait := tokenWait(app.FromBytes(sizeA), app.FromBytes(oldBytes)); raised.Sub(seeded) >= ownWait {
		t.Fatalf("rates raised %v after the seed, not within A's %v wait", raised.Sub(seeded), ownWait)
	}
	waitBounded(t, doneA, "A after the rates were raised", func() { _ = fcA.Close() })
	waitBounded(t, doneB, "B after the rates were raised", func() { _ = fcB.Close() })

	if nA != sizeA || errA != nil || nB != sizeB || errB != nil {
		t.Fatalf("Writes = A (%d, %v), B (%d, %v), want (%d, nil) and (%d, nil)", nA, errA, nB, errB, sizeA, sizeB)
	}
	if writesA, writesB := rawA.written(), rawB.written(); len(writesA) != 1 || len(writesB) != 1 {
		t.Fatalf("underlying writes = A %d, B %d, want one each", len(writesA), len(writesB))
	}
	first, second := <-released, <-released
	if first.label != labelA || second.label != labelB || !first.at.Before(second.at) {
		t.Fatalf("released %s then %s, want A before B", first.label, second.label)
	}
	// Until the raise the empty buckets gained at most the old rate; the rest
	// of A's own charge accrues at the new rate after it.
	gained := raised.Sub(seeded).Seconds() * float64(app.FromBytes(oldBytes))
	owed := (float64(app.FromBytes(sizeA)) - gained) / float64(app.FromBytes(newBytes))
	if least := time.Duration(owed * float64(time.Second)); first.at.Sub(raised) < least {
		t.Errorf("A released %v after the raise, want at least %v", first.at.Sub(raised), least)
	}
	if most := raised.Sub(seeded) + tokenWait(app.FromBytes(sizeA), app.FromBytes(newBytes)) + margin; first.at.Sub(seeded) > most {
		t.Errorf("A released %v after the seed, want at most %v: it waited for the deficit of B charged after it", first.at.Sub(seeded), most)
	}
}

// Regression: a rate revoked just as the limiter timer fired could let the
// timer win the select, and the write was admitted under the revoked rate. The
// timer wake now checks for a rate change before admitting anything.
func TestRateRevokedAsTimerFiresFailsWrite(t *testing.T) {
	raw := newScriptedConn(nil)
	fc := newTestConn(t, raw, app.FromBytes(1), app.FromBytes(1024))
	forceReservationWait(t, fc)
	fc.waitForLimiter = func(time.Duration, <-chan struct{}, <-chan struct{}, <-chan struct{}) limiterWaitResult {
		// Both the timer and the rate change are ready; the timer is chosen.
		if err := fc.count.DeleteLimit(fc.ipv6, fc.id); err != nil {
			t.Errorf("DeleteLimit: %v", err)
		}
		return limiterReady
	}
	if n, err := fc.Write([]byte("x")); n != 0 || err == nil || !strings.Contains(err.Error(), "no dest rate") {
		t.Fatalf("Write = (%d, %v), want (0, the no dest rate error)", n, err)
	}
	if writes := raw.written(); len(writes) != 0 {
		t.Fatalf("underlying writes = %d, want 0", len(writes))
	}
}
