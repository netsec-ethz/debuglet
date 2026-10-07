// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

//go:build linux

package ebpf

import (
	"errors"
	"fmt"
	"net"
	"sync"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/google/uuid"
	"github.com/netsec-ethz/debuglet/internal/executor/debuglet/socket/netutil"
)

type BpfConn struct {
	count *BpfCount
	conn  net.Conn
	// raw reaches the socket's descriptor while it is still open. Its Control
	// holds a reference on the descriptor, so the number cannot be closed and
	// reused by another socket during the delete, and it refuses to run once
	// the connection is closed.
	raw syscall.RawConn
	// deleteStorage removes the socket's entry from debuglet_sk_map. The map
	// is an SK_STORAGE map, whose key is a descriptor the kernel resolves to a
	// socket at the time of the call.
	deleteStorage func(fd uint32) error
	domain        string
	id            uuid.UUID
	resolvedIPv6  netutil.IPv6

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

// Close releases the socket's map entry, the socket and its rate limit, in
// that order, once. Later calls return the first call's result.
func (bc *BpfConn) Close() error {
	bc.closeOnce.Do(func() { bc.closeErr = bc.close() })
	return bc.closeErr
}

func (bc *BpfConn) close() error {
	// The socket storage is addressed by descriptor, so it must be deleted
	// while the descriptor still names this socket: after Close it names
	// nothing (EBADF) or, once reused, another socket.
	deleteErr := bc.deleteSocketStorage()
	// The socket is closed even when the delete failed; the kernel frees
	// its storage with the socket. Close the connection before detaching
	// the rate limit, otherwise rate-limited writes would be passed through
	// before the connection is actually closed.
	closeErr := bc.conn.Close()
	detachErr := bc.count.Detach(bc.domain, bc.id, bc.resolvedIPv6)
	if closeErr != nil {
		return closeErr
	}
	if deleteErr != nil {
		return deleteErr
	}
	return detachErr
}

func (bc *BpfConn) deleteSocketStorage() error {
	var deleteErr error
	if err := bc.raw.Control(func(fd uintptr) {
		deleteErr = bc.deleteStorage(uint32(fd))
	}); err != nil {
		return fmt.Errorf("delete socket storage: %w", err)
	}
	// An entry already gone needs no delete.
	if deleteErr != nil && !errors.Is(deleteErr, ebpf.ErrKeyNotExist) {
		return fmt.Errorf("delete socket storage: %w", deleteErr)
	}
	return nil
}
