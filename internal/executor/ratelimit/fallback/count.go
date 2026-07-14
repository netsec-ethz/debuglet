package fallback

import (
	"debuglet/internal/executor/debuglet/socket"
	"debuglet/internal/executor/ratelimit/app"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/google/uuid"
)

type debugletKey struct {
	id   uuid.UUID
	dest netip.Addr
}

type bucketState struct {
	tokens app.Bitrate
	last   time.Time
}

type FallbackCount struct {
	// The current amount of bandwidth being used
	packetSize     map[debugletKey]*bucketState
	execPacketSize map[uuid.UUID]*bucketState
	// The maximum allowed bandwidth rates
	rates     map[debugletKey]app.Bitrate
	execRates map[uuid.UUID]app.Bitrate

	mu sync.RWMutex
}

func NewFallbackCount() (*FallbackCount, error) {
	return &FallbackCount{
		packetSize:     make(map[debugletKey]*bucketState),
		execPacketSize: make(map[uuid.UUID]*bucketState),
		rates:          make(map[debugletKey]app.Bitrate),
		execRates:      make(map[uuid.UUID]app.Bitrate),
	}, nil
}

func (f *FallbackCount) Attach(conn net.Conn, id uuid.UUID) (net.Conn, error) {
	host, err := socket.HostFromAddr(conn.RemoteAddr().String())
	if err != nil {
		return nil, err
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return nil, fmt.Errorf("invalid address: %w", err)
	}
	fc := &FallbackConn{conn: conn,
		count: f,
		id:    id,
		mu:    NewFIFOLock(),
		addr:  addr,
		close: make(chan struct{}),
	}
	return fc, nil
}

func (f *FallbackCount) SetLimit(addr netip.Addr, id uuid.UUID, limit app.Bitrate) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.rates[debugletKey{id: id, dest: addr}] = limit
	return nil
}

func (f *FallbackCount) SetExecLimit(id uuid.UUID, limit app.Bitrate) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.execRates[id] = limit
	return nil
}

func (f *FallbackCount) DeleteLimit(addr netip.Addr, id uuid.UUID) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	k := debugletKey{id: id, dest: addr}
	delete(f.rates, k)
	delete(f.packetSize, k)
	return nil
}

func (f *FallbackCount) DeleteExecLimit(id uuid.UUID) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.execRates, id)
	delete(f.execPacketSize, id)
	return nil
}

func (f *FallbackCount) Close() error { return nil }
func (f *FallbackCount) Type() string { return "fallback" }
