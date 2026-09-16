// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

//go:build linux

package ebpf

import (
	"debuglet/internal/executor/debuglet/socket/netutil"
	"net"
	"time"

	"github.com/google/uuid"
)

type BpfConn struct {
	count        *BpfCount
	conn         net.Conn
	socketID     uint32
	domain       string
	id           uuid.UUID
	resolvedIPv6 netutil.IPv6
}

func (bc *BpfConn) Read(b []byte) (n int, err error)   { return bc.conn.Read(b) }
func (bc *BpfConn) Write(b []byte) (n int, err error)  { return bc.conn.Write(b) }
func (bc *BpfConn) LocalAddr() net.Addr                { return bc.conn.LocalAddr() }
func (bc *BpfConn) RemoteAddr() net.Addr               { return bc.conn.RemoteAddr() }
func (bc *BpfConn) SetDeadline(t time.Time) error      { return bc.conn.SetDeadline(t) }
func (bc *BpfConn) SetReadDeadline(t time.Time) error  { return bc.conn.SetReadDeadline(t) }
func (bc *BpfConn) SetWriteDeadline(t time.Time) error { return bc.conn.SetWriteDeadline(t) }
func (bc *BpfConn) Close() error {
	// Close connection before detaching/removing ratelimit, otherwise ratelimited writes will
	// be passed through before the connection is actually closed
	err := bc.conn.Close()
	err2 := bc.count.Detach(bc.domain, bc.id, bc.resolvedIPv6)
	if err3 := bc.count.objs.DebugletSkMap.Delete(bc.socketID); err3 != nil {
		return err3
	}
	if err2 != nil {
		return err2
	}
	return err
}
