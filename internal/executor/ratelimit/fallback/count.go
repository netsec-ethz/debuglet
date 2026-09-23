// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package fallback

import (
	"fmt"
	"github.com/netsec-ethz/debuglet/internal/executor/debuglet/socket/netutil"
	"github.com/netsec-ethz/debuglet/internal/executor/ratelimit/app"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/google/uuid"
)

type debugletKey struct {
	id   uuid.UUID
	dest netutil.IPv6
}

type domainKey struct {
	domain string
	id     uuid.UUID
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

	domainIPs map[domainKey]map[netutil.IPv6]int
	attached  map[debugletKey]int

	mu sync.RWMutex
}

func NewFallbackCount() (*FallbackCount, error) {
	return &FallbackCount{
		packetSize:     make(map[debugletKey]*bucketState),
		execPacketSize: make(map[uuid.UUID]*bucketState),
		rates:          make(map[debugletKey]app.Bitrate),
		execRates:      make(map[uuid.UUID]app.Bitrate),
		attached:       make(map[debugletKey]int),
	}, nil
}

func (f *FallbackCount) Attach(conn net.Conn, id uuid.UUID, addr string) (net.Conn, error) {
	host, err := netutil.HostFromAddr(conn.RemoteAddr().String())
	if err != nil {
		return nil, err
	}
	remoteIP, err := netip.ParseAddr(host)
	if err != nil {
		return nil, fmt.Errorf("invalid address: %w", err)
	}
	ipv6 := netutil.ToIPv6(remoteIP)

	f.mu.Lock()
	defer f.mu.Unlock()
	if f.domainIPs == nil {
		f.domainIPs = make(map[domainKey]map[netutil.IPv6]int)
	}
	dk := domainKey{domain: addr, id: id}
	if _, ok := f.domainIPs[dk]; !ok {
		f.domainIPs[dk] = make(map[netutil.IPv6]int)
	}
	f.domainIPs[dk][ipv6]++
	f.attached[debugletKey{id: id, dest: ipv6}]++

	fc := &FallbackConn{conn: conn,
		count:                f,
		id:                   id,
		readMu:               NewFIFOLock(),
		writeMu:              NewFIFOLock(),
		ipv6:                 ipv6,
		addr:                 addr,
		close:                make(chan struct{}),
		readDeadlineChanged:  make(chan struct{}),
		writeDeadlineChanged: make(chan struct{}),
		waitForLimiter:       waitForLimiter,
	}
	return fc, nil
}

func (f *FallbackCount) SetLimit(addr string, id uuid.UUID, limit app.Bitrate) error {
	parsedIP, err := netip.ParseAddr(addr)
	if err == nil {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.rates[debugletKey{id: id, dest: netutil.ToIPv6(parsedIP)}] = limit
		return nil
	}

	f.mu.Lock()
	defer f.mu.Unlock()
	for ipv6 := range f.domainIPs[domainKey{domain: addr, id: id}] {
		f.rates[debugletKey{id: id, dest: ipv6}] = limit
	}
	return nil
}

func (f *FallbackCount) SetExecLimit(id uuid.UUID, limit app.Bitrate) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.execRates[id] = limit
	return nil
}

func (f *FallbackCount) DeleteLimit(addr netutil.IPv6, id uuid.UUID) error {
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

func (f *FallbackCount) Detach(addr string, id uuid.UUID, ipv6 netutil.IPv6) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.detachLocked(addr, id, ipv6)
	return nil
}

func (f *FallbackCount) detachLocked(addr string, id uuid.UUID, ipv6 netutil.IPv6) {
	dk := domainKey{domain: addr, id: id}
	ips, ok := f.domainIPs[dk]
	if !ok {
		return
	}
	attachments, ok := ips[ipv6]
	if !ok || attachments <= 0 {
		return
	}
	if attachments == 1 {
		delete(ips, ipv6)
	} else {
		ips[ipv6] = attachments - 1
	}
	key := debugletKey{id: id, dest: ipv6}
	f.attached[key]--
	if f.attached[key] <= 0 {
		delete(f.attached, key)
		delete(f.rates, key)
		delete(f.packetSize, key)
	}
	if len(ips) == 0 {
		delete(f.domainIPs, dk)
	}
}

func (f *FallbackCount) Close() error { return nil }
func (f *FallbackCount) Type() string { return "fallback" }
