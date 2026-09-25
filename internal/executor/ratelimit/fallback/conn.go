// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package fallback

import (
	"fmt"
	"github.com/netsec-ethz/debuglet/internal/executor/debuglet/socket/netutil"
	"github.com/netsec-ethz/debuglet/internal/executor/ratelimit/app"
	"io"
	"math"
	"net"
	"os"
	"sync"
	"time"

	"github.com/google/uuid"
)

type FallbackConn struct {
	conn    net.Conn
	count   *FallbackCount
	id      uuid.UUID
	readMu  *FIFOLock
	writeMu *FIFOLock // Ensures FIFO for the write operation
	ipv6    netutil.IPv6
	addr    string
	close   chan struct{}
	// closed is protected by count.mu so admission and detach observe one
	// connection lifecycle order.
	closed bool
	// datagram is set for a connection whose socket carries datagrams: every
	// Read and Write is then admitted whole and is exactly one socket call,
	// so one datagram stays one datagram.
	datagram bool

	deadlineMu           sync.Mutex
	readDeadline         time.Time
	writeDeadline        time.Time
	readDeadlineChanged  chan struct{}
	writeDeadlineChanged chan struct{}
	waitForLimiter       func(time.Duration, <-chan struct{}, <-chan struct{}, <-chan struct{}) limiterWaitResult
	once                 sync.Once
}

type limiterWaitResult uint8

const (
	limiterReady limiterWaitResult = iota
	limiterChanged
	limiterRatesChanged
	limiterClosed
)

func waitForLimiter(duration time.Duration, changed, ratesChanged, closed <-chan struct{}) limiterWaitResult {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-timer.C:
		return limiterReady
	case <-changed:
		return limiterChanged
	case <-ratesChanged:
		return limiterRatesChanged
	case <-closed:
		return limiterClosed
	}
}

func (f *FallbackConn) LocalAddr() net.Addr  { return f.conn.LocalAddr() }
func (f *FallbackConn) RemoteAddr() net.Addr { return f.conn.RemoteAddr() }
func (f *FallbackConn) SetDeadline(t time.Time) error {
	f.deadlineMu.Lock()
	defer f.deadlineMu.Unlock()
	if err := f.conn.SetDeadline(t); err != nil {
		return err
	}
	f.readDeadline = t
	f.writeDeadline = t
	close(f.readDeadlineChanged)
	close(f.writeDeadlineChanged)
	f.readDeadlineChanged = make(chan struct{})
	f.writeDeadlineChanged = make(chan struct{})
	return nil
}
func (f *FallbackConn) SetReadDeadline(t time.Time) error {
	f.deadlineMu.Lock()
	defer f.deadlineMu.Unlock()
	if err := f.conn.SetReadDeadline(t); err != nil {
		return err
	}
	f.readDeadline = t
	close(f.readDeadlineChanged)
	f.readDeadlineChanged = make(chan struct{})
	return nil
}
func (f *FallbackConn) SetWriteDeadline(t time.Time) error {
	f.deadlineMu.Lock()
	defer f.deadlineMu.Unlock()
	if err := f.conn.SetWriteDeadline(t); err != nil {
		return err
	}
	f.writeDeadline = t
	close(f.writeDeadlineChanged)
	f.writeDeadlineChanged = make(chan struct{})
	return nil
}

func (f *FallbackConn) Read(b []byte) (n int, err error) {
	// An empty read needs no bandwidth: return before taking the FIFO lock,
	// reserving tokens or touching the socket.
	if len(b) == 0 {
		return 0, nil
	}

	if err := f.readMu.LockUntil(f.close, func() (time.Time, <-chan struct{}) { return f.deadlineState(false) }); err != nil {
		return 0, err
	}
	defer f.readMu.Unlock()

	r, err := f.admit(len(b), false)
	if err != nil {
		return 0, err
	}

	// Exactly one underlying read, returned unchanged: a short read, data
	// returned together with an error, (n>0, io.EOF) and (0, nil) are all
	// passed through. Stream interpretation belongs to the host layer. A
	// datagram connection reserved the whole buffer, so the datagram is read
	// into all of it: the limiter never truncates a datagram, and one longer
	// than the caller's buffer is truncated by the socket as usual.
	n, err = f.conn.Read(b[:r.allocated])
	r.refund(r.allocated - n)
	return n, err
}

func (f *FallbackConn) Write(b []byte) (int, error) {
	// Connection lock is held even while being ratelimited and sleeping
	// to ensure concurrent writes are handled in the correct order.
	if err := f.writeMu.LockUntil(f.close, func() (time.Time, <-chan struct{}) { return f.deadlineState(true) }); err != nil {
		return 0, err
	}
	defer f.writeMu.Unlock()

	if f.datagram {
		return f.writeDatagram(b)
	}

	var n int
	for len(b) > 0 {
		r, err := f.admit(len(b), true)
		if err != nil {
			return n, err
		}

		nn, err := f.conn.Write(b[:r.allocated])
		if nn < 0 || nn > r.allocated {
			if err != nil {
				return n, fmt.Errorf("invalid write count %d: %w", nn, err)
			}
			return n, fmt.Errorf("invalid write count %d", nn)
		}

		r.refund(r.allocated - nn)
		n += nn
		if err != nil {
			return n, err
		}
		if nn == 0 {
			return n, io.ErrNoProgress
		}
		b = b[nn:]
	}

	return n, nil
}

// writeDatagram sends b as exactly one datagram with one underlying write.
// The whole payload is reserved at once, even when it is larger than one
// second of the rate, in which case the write waits for the deficit. An empty
// datagram costs no bytes but still needs permission. The limiter never splits or
// truncates a datagram: one the socket cannot send, such as one larger than
// the largest datagram, fails with the socket's own error.
func (f *FallbackConn) writeDatagram(b []byte) (int, error) {
	r, err := f.admit(len(b), true)
	if err != nil {
		return 0, err
	}

	n, err := f.conn.Write(b)
	if n < 0 || n > len(b) {
		if err != nil {
			return 0, fmt.Errorf("invalid write count %d: %w", n, err)
		}
		return 0, fmt.Errorf("invalid write count %d", n)
	}
	r.refund(len(b) - n)
	if err == nil && n < len(b) {
		// The rest cannot follow without becoming a second datagram.
		err = io.ErrShortWrite
	}
	return n, err
}

func (f *FallbackConn) deadlineState(write bool) (time.Time, <-chan struct{}) {
	f.deadlineMu.Lock()
	defer f.deadlineMu.Unlock()
	if write {
		return f.writeDeadline, f.writeDeadlineChanged
	}
	return f.readDeadline, f.readDeadlineChanged
}

func (f *FallbackConn) Close() error {
	f.once.Do(func() {
		f.count.mu.Lock()
		f.closed = true
		f.count.detachLocked(f.addr, f.id, f.ipv6)
		close(f.close)
		f.count.mu.Unlock()
	})
	return f.conn.Close()
}

// admit reserves bandwidth for up to size bytes and sleeps until the
// reservation may be used. The caller must hold the corresponding I/O lock. A reservation that is
// canceled by a deadline or by Close is refunded in full before the error is
// returned. A reservation whose rates change while it sleeps keeps its charge
// and its place ahead of later charges, and then waits for what it still owes
// itself at the current rates: a lowered or revoked rate never admits I/O
// under the old one, a raised rate shortens the sleep, and the wait already
// served is never lost. The I/O lock stays held throughout, so the caller
// keeps its place.
func (f *FallbackConn) admit(size int, write bool) (*reservation, error) {
	r, err := f.reserve(size)
	if err != nil {
		return nil, fmt.Errorf("failed to reserve: %w", err)
	}
	if r.waitFor <= 0 {
		return r, nil
	}

	readyAt := time.Now().Add(r.waitFor)
	for {
		select {
		case <-f.close:
			r.free()
			return nil, net.ErrClosed
		default:
		}
		deadline, changed := f.deadlineState(write)
		now := time.Now()
		if !deadline.IsZero() && !now.Before(deadline) {
			r.free()
			return nil, os.ErrDeadlineExceeded
		}
		wakeAt := readyAt
		deadlineWake := false
		if !deadline.IsZero() && deadline.Before(wakeAt) {
			wakeAt = deadline
			deadlineWake = true
		}
		switch f.waitForLimiter(time.Until(wakeAt), changed, r.ratesChanged, f.close) {
		case limiterReady:
			if err := f.waitCompletionError(write); err != nil {
				r.free()
				return nil, err
			}
			if deadlineWake {
				continue
			}
			select {
			case <-r.ratesChanged:
			default:
				return r, nil
			}
			// A rate moved as the timer fired: the wait is recomputed
			// before anything is admitted under the old rates.
			fallthrough
		case limiterRatesChanged:
			// The wait was computed under rates that no longer hold. A
			// recomputed wait of zero still goes round once more, so Close
			// and the deadline are checked before the I/O as after any other
			// wait.
			if err := r.reevaluate(); err != nil {
				return nil, fmt.Errorf("failed to reserve: %w", err)
			}
			readyAt = time.Now().Add(r.waitFor)
		case limiterChanged:
		case limiterClosed:
			r.free()
			return nil, net.ErrClosed
		}
	}
}

// waitCompletionError is checked on every timer wake because a deadline
// update and the timer can become ready together. Socket I/O is admitted only
// against current lifecycle state, regardless of which ready case select chose.
func (f *FallbackConn) waitCompletionError(write bool) error {
	select {
	case <-f.close:
		return net.ErrClosed
	default:
	}
	deadline, _ := f.deadlineState(write)
	if !deadline.IsZero() && !time.Now().Before(deadline) {
		return os.ErrDeadlineExceeded
	}
	return nil
}

type reservation struct {
	// The amount of bytes that were reserved. May be smaller than the inputted reserve size.
	allocated int
	// Amount of time to sleep before writing.
	waitFor time.Duration
	// ratesChanged is closed when a rate changes after waitFor was computed,
	// which makes waitFor stale until it is recomputed.
	ratesChanged <-chan struct{}
	// dest and exec are the charges held on the two buckets.
	dest, exec charge

	conn *FallbackConn
}

// tokenWait is how long a bucket filling at rate needs to cover a deficit.
// Both are bits: a balance rounded to whole bytes first either loses the part
// of a debt that is smaller than a byte, which grants the next reservation
// before it is paid for, or charges for a wait that is not owed. A rate of
// zero admits nothing, so reserve refuses the write before reaching this.
//
// The result is rounded up, and a deficit that is owed never waits nothing: on
// a fast enough link the exact wait is a fraction of a nanosecond, which the
// clock cannot express and truncation would turn back into the early grant
// this accounting exists to prevent.
func tokenWait(deficit, rate app.Bitrate) time.Duration {
	if deficit <= 0 || rate <= 0 {
		return 0
	}
	wait := time.Duration(math.Ceil(float64(deficit) / float64(rate) * float64(time.Second)))
	if wait <= 0 {
		return 1
	}
	return wait
}

func (f *FallbackConn) reserve(size int) (*reservation, error) {
	// TODO: replace the locking with some atomic flag indicating when the last change took place, so we
	// don't have to constantly lock and access the maps again
	f.count.mu.Lock()
	defer f.count.mu.Unlock()
	if f.closed {
		return nil, net.ErrClosed
	}
	rate, execRate, err := f.ratesLocked()
	if err != nil {
		return nil, err
	}

	// Both rates are positive, so at least one byte is admitted.
	toWrite := min(size, min(rate, execRate).Bytes())
	if f.datagram {
		// A datagram is reserved whole, because no part of it can be sent or
		// received on its own. Beyond one second of the rate it waits for the
		// deficit like any other reservation.
		toWrite = size
	}
	r := &reservation{allocated: toWrite, conn: f}
	r.chargeLocked(rate, execRate)
	return r, nil
}

// ratesLocked returns the destination and executor rates of f. A missing rate
// and a rate of zero both admit nothing. count.mu must be held.
func (f *FallbackConn) ratesLocked() (app.Bitrate, app.Bitrate, error) {
	rate, ok := f.count.rates[debugletKey{id: f.id, dest: f.ipv6}]
	if !ok || rate <= 0 {
		return 0, 0, fmt.Errorf("no dest rate allowed for addr '%s'", f.ipv6.String())
	}
	execRate, ok := f.count.execRates[f.id]
	if !ok || execRate <= 0 {
		return 0, 0, fmt.Errorf("no exec rate allowed for addr '%s'", f.ipv6.String())
	}
	return rate, execRate, nil
}

// chargeLocked refills both buckets up to now at the current rates, charges
// the reservation to every bucket that does not hold it yet, and sets waitFor
// to what the reservation still owes itself at these rates. A new reservation
// charges both buckets; a recomputed one only a bucket that was deleted and
// created again since, which lost the charge with the old bucket. count.mu
// must be held.
func (r *reservation) chargeLocked(rate, execRate app.Bitrate) {
	count, now := r.conn.count, time.Now()
	reserved := app.FromBytes(r.allocated)
	b := bucketLocked(count.packetSize, debugletKey{id: r.conn.id, dest: r.conn.ipv6}, rate, now)
	eb := bucketLocked(count.execPacketSize, r.conn.id, execRate, now)
	r.waitFor = max(r.dest.owed(b, reserved, rate), r.exec.owed(eb, reserved, execRate))
	r.ratesChanged = count.ratesChanged
}

// charge is a reservation's charge on one bucket.
type charge struct {
	bucket *bucketState
	// need is the refill level of bucket at which the charge is paid.
	need         app.Bitrate
	needFraction int64
}

// owed charges b with reserved unless c already holds a charge on it, and
// returns how long the charge still waits at rate. The wait covers this
// charge's own deficit only, never what later charges on b owe.
func (c *charge) owed(b *bucketState, reserved, rate app.Bitrate) time.Duration {
	if c.bucket != b {
		c.bucket, c.need, c.needFraction = b, b.refilled, b.refillFraction
		if reserved > b.tokens {
			c.need += reserved - b.tokens
			c.needFraction -= b.tokenFraction
			if c.needFraction < 0 {
				c.need--
				c.needFraction += int64(time.Second)
			}
		}
		b.tokens -= reserved
	}
	bits, fraction := c.need-b.refilled, c.needFraction-b.refillFraction
	if fraction < 0 {
		bits--
		fraction += int64(time.Second)
	}
	if bits < 0 {
		return 0
	}
	wait := tokenWait(bits, rate)
	if fraction > 0 {
		wait += time.Duration((fraction-1)/int64(rate) + 1)
	}
	return wait
}

// reevaluate recomputes the remaining wait of r after a rate change. The
// charge stays in the buckets, so r keeps the wait already served and its
// place ahead of later charges, and then waits for what it still owes itself
// at the current rates. A closed connection
// or a rate that no longer admits anything gives the reservation back and
// returns the error a new reservation gets.
func (r *reservation) reevaluate() error {
	f := r.conn
	f.count.mu.Lock()
	defer f.count.mu.Unlock()
	if f.closed {
		r.refundLocked(r.allocated)
		return net.ErrClosed
	}
	rate, execRate, err := f.ratesLocked()
	if err != nil {
		r.refundLocked(r.allocated)
		return err
	}
	r.chargeLocked(rate, execRate)
	return nil
}

// free reverts the whole reservation, for example when the wait is canceled.
func (r *reservation) free() {
	r.refund(r.allocated)
}

// refund returns unused reserved bytes to the accounting state that still
// exists. Each bucket is refunded independently and capped at its current
// rate. Detached or deleted entries are never recreated: Close can delete
// the destination entry before the executor entry, so a refund must not
// require both to exist.
func (r *reservation) refund(unused int) {
	if unused <= 0 {
		return
	}
	r.conn.count.mu.Lock()
	defer r.conn.count.mu.Unlock()
	r.refundLocked(unused)
}

// refundLocked is refund with count.mu held.
func (r *reservation) refundLocked(unused int) {
	count := r.conn.count
	key := debugletKey{id: r.conn.id, dest: r.conn.ipv6}
	if b, ok := count.packetSize[key]; ok {
		if rate, ok := count.rates[key]; ok {
			b.tokens += app.FromBytes(unused)
			b.cap(rate)
		}
	}
	if eb, ok := count.execPacketSize[r.conn.id]; ok {
		if execRate, ok := count.execRates[r.conn.id]; ok {
			eb.tokens += app.FromBytes(unused)
			eb.cap(execRate)
		}
	}
}
