//go:build linux

package ebpf

import (
	"net"
	"time"
)

type BpfConn struct {
	count    *BpfCount
	conn     net.Conn
	socketID uint32
}

func (bc *BpfConn) Read(b []byte) (n int, err error)   { return bc.conn.Read(b) }
func (bc *BpfConn) Write(b []byte) (n int, err error)  { return bc.conn.Write(b) }
func (bc *BpfConn) LocalAddr() net.Addr                { return bc.conn.LocalAddr() }
func (bc *BpfConn) RemoteAddr() net.Addr               { return bc.conn.RemoteAddr() }
func (bc *BpfConn) SetDeadline(t time.Time) error      { return bc.conn.SetDeadline(t) }
func (bc *BpfConn) SetReadDeadline(t time.Time) error  { return bc.conn.SetReadDeadline(t) }
func (bc *BpfConn) SetWriteDeadline(t time.Time) error { return bc.conn.SetWriteDeadline(t) }
func (bc *BpfConn) Close() error {
	err := bc.conn.Close()
	if err2 := bc.count.objs.DebugletSkMap.Delete(bc.socketID); err2 != nil {
		return err2
	}
	return err
}
