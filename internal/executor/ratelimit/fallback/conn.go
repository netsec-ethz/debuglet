package fallback

import (
	"debuglet/internal/executor/ratelimit/app"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sync"
	"time"

	"github.com/google/uuid"
)

var (
	ErrEmptyWrite = errors.New("write size is empty (=0)")
)

type FallbackConn struct {
	conn  net.Conn
	count *FallbackCount
	id    uuid.UUID
	mu    *FIFOLock // Ensures FIFO for the write operation
	addr  netip.Addr
	close chan struct{}

	deadline      time.Time
	readDeadline  time.Time
	writeDeadline time.Time
	once          sync.Once
}

func (f *FallbackConn) LocalAddr() net.Addr  { return f.conn.LocalAddr() }
func (f *FallbackConn) RemoteAddr() net.Addr { return f.conn.RemoteAddr() }
func (f *FallbackConn) SetDeadline(t time.Time) error {
	f.deadline = t
	return f.conn.SetDeadline(t)
}
func (f *FallbackConn) SetReadDeadline(t time.Time) error {
	f.readDeadline = t
	return f.conn.SetReadDeadline(t)
}
func (f *FallbackConn) SetWriteDeadline(t time.Time) error {
	f.writeDeadline = t
	return f.conn.SetWriteDeadline(t)
}

// TODO: Read is equivalent to ingress in this case. Only add ratelimit once the EBPF part also
// supports ingress to match the implementation.
func (f *FallbackConn) Read(b []byte) (n int, err error) { return f.conn.Read(b) }

func (f *FallbackConn) Write(b []byte) (int, error) {
	// Connection lock is held even while being ratelimited and sleeping
	// to ensure concurrent writes are handled in the correct order.
	f.mu.Lock()
	defer f.mu.Unlock()

	var n int

	for len(b) > 0 {
		r, err := f.reserve(len(b))
		if err != nil {
			return n, fmt.Errorf("failed to reserve: %w", err)
		}

		if r.waitFor > 0 {
			var dCh, wdCh <-chan time.Time
			if !f.deadline.IsZero() {
				dCh = time.After(time.Until(f.deadline))
			}
			if !f.writeDeadline.IsZero() {
				wdCh = time.After(time.Until(f.writeDeadline))
			}

			sleep := time.NewTimer(r.waitFor)
			select {
			case <-sleep.C:
			case <-wdCh:
				sleep.Stop()
				r.free()
				return n, os.ErrDeadlineExceeded
			case <-dCh:
				sleep.Stop()
				r.free()
				return n, os.ErrDeadlineExceeded
			case <-f.close:
				sleep.Stop()
				r.free()
				return n, net.ErrClosed
			}
			sleep.Stop()
		}

		nn, err := f.conn.Write(b[:r.allocated])
		n += nn
		if err != nil {
			return n, err
		}
		b = b[nn:]
	}
	return n, nil
}

func (f *FallbackConn) Close() error {
	f.once.Do(func() {
		close(f.close)
	})
	return f.conn.Close()
}

type reservation struct {
	// The amount of bytes that were reserved. May be smaller than the inputted reserve size.
	allocated int
	// Amount of time to sleep before writing.
	waitFor time.Duration

	conn *FallbackConn
}

func (f *FallbackConn) reserve(size int) (*reservation, error) {
	// TODO: replace the locking with some atomic flag indicating when the last change took place, so we
	// don't have to constantly lock and access the maps again
	f.count.mu.Lock()
	defer f.count.mu.Unlock()
	key := debugletKey{id: f.id, dest: f.addr}

	rate, ok := f.count.rates[key]
	if !ok {
		return nil, fmt.Errorf("no dest rate allowed for addr '%s'", f.addr.String())
	}
	execRate, ok := f.count.execRates[f.id]
	if !ok {
		return nil, fmt.Errorf("no exec rate allowed for addr '%s'", f.addr.String())
	}

	maxWrite := min(rate, execRate).Bytes()
	toWrite := min(size, maxWrite)
	if toWrite == 0 {
		return nil, ErrEmptyWrite
	}
	now := time.Now()

	// token buckets
	// dest
	b, ok := f.count.packetSize[key]
	if !ok {
		b = &bucketState{last: now, tokens: rate}
		f.count.packetSize[key] = b
	} else { // fill up token bucket
		delta := now.Sub(b.last)
		b.tokens = min(rate, b.tokens+app.Bitrate(delta.Seconds()*float64(rate)))
		b.last = now
	}
	// exec
	eb, ok := f.count.execPacketSize[f.id]
	if !ok {
		eb = &bucketState{last: now, tokens: execRate}
		f.count.execPacketSize[f.id] = eb
	} else { // fill up token bucket
		delta := now.Sub(eb.last)
		eb.tokens = min(execRate, eb.tokens+app.Bitrate(delta.Seconds()*float64(execRate)))
		eb.last = now
	}

	// compute how long we have to sleep for and allocate the tokens
	// NOTE: this does not handle the case where rates are updated while sleeping
	var waitFor, execWaitFor time.Duration
	if bt := b.tokens.Bytes(); toWrite > bt {
		waitFor = time.Duration(float64(toWrite-bt) / float64(rate.Bytes()) * float64(time.Second))
	}
	b.tokens -= app.FromBytes(toWrite)

	if bt := eb.tokens.Bytes(); toWrite > bt {
		execWaitFor = time.Duration(float64(toWrite-bt) / float64(execRate.Bytes()) * float64(time.Second))
	}
	eb.tokens -= app.FromBytes(toWrite)

	resv := &reservation{
		allocated: toWrite,
		waitFor:   max(waitFor, execWaitFor),
		conn:      f,
	}
	return resv, nil
}

// free reverts the reservation and frees up the tokens in the token bucket
// as much as is possible.
func (r *reservation) free() {
	r.conn.count.mu.Lock()
	defer r.conn.count.mu.Unlock()

	key := debugletKey{id: r.conn.id, dest: r.conn.addr}
	rate, ok := r.conn.count.rates[key]
	if !ok {
		return
	}
	execRate, ok := r.conn.count.execRates[r.conn.id]
	if !ok {
		return
	}
	b, ok := r.conn.count.packetSize[key]
	if !ok {
		return
	}
	eb, ok := r.conn.count.execPacketSize[r.conn.id]
	if !ok {
		return
	}
	b.tokens = min(rate, b.tokens+app.FromBytes(r.allocated))
	eb.tokens = min(execRate, eb.tokens+app.FromBytes(r.allocated))
}
