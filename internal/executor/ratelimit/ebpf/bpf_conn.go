// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

//go:build linux

package ebpf

import (
	"net"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/netsec-ethz/debuglet/internal/executor/debuglet/socket/netutil"
)

type BpfConn struct {
	count        *BpfCount
	conn         net.Conn
	domain       string
	id           uuid.UUID
	resolvedIPv6 netutil.IPv6

	closeOnce sync.Once
	closeErr  error
}

func (bc *BpfConn) Read(b []byte) (n int, err error)   { return bc.conn.Read(b) }
func (bc *BpfConn) Write(b []byte) (n int, err error)  { return bc.conn.Write(b) }
func (bc *BpfConn) LocalAddr() net.Addr                { return bc.conn.LocalAddr() }
func (bc *BpfConn) RemoteAddr() net.Addr               { return bc.conn.RemoteAddr() }
func (bc *BpfConn) SetDeadline(t time.Time) error      { return bc.conn.SetDeadline(t) }
func (bc *BpfConn) SetReadDeadline(t time.Time) error  { return bc.conn.SetReadDeadline(t) }
func (bc *BpfConn) SetWriteDeadline(t time.Time) error { return bc.conn.SetWriteDeadline(t) }

// Close closes the socket and then detaches its rate limit, once. Later calls
// return the first call's result.
//
// Close does not delete the socket's debuglet_sk_map entry. That map is an
// SK_STORAGE map: the entry belongs to the socket and the kernel frees it when
// the socket is destroyed. Until then, data the kernel still sends after
// close(2) (the unsent send buffer, the FIN, retransmissions) keeps this run's
// UUID and is dropped once Detach has removed the rate entry. Deleting the
// entry earlier would let that tail leave unattributed and unthrottled, and
// deleting it after close(2) addresses a descriptor that no longer names the
// socket (#412).
func (bc *BpfConn) Close() error {
	bc.closeOnce.Do(func() { bc.closeErr = bc.close() })
	return bc.closeErr
}

func (bc *BpfConn) close() error {
	// Close connection before detaching/removing ratelimit, otherwise ratelimited writes will
	// be passed through before the connection is actually closed
	closeErr := bc.conn.Close()
	detachErr := bc.count.Detach(bc.domain, bc.id, bc.resolvedIPv6)
	if closeErr != nil {
		return closeErr
	}
	return detachErr
}
