// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package wasm

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/netsec-ethz/debuglet/internal/executor/debuglet/netpolicy"
	"github.com/netsec-ethz/debuglet/internal/executor/debuglet/socket"
	"github.com/netsec-ethz/debuglet/internal/guestio"
	"github.com/netsec-ethz/scion-apps/pkg/pan"
)

type scionExchangeConn struct {
	net.Conn
	local, remote pan.UDPAddr
	writtenPath   *pan.Path
	response      []byte
	readErr       error
	writes        int
}

func (c *scionExchangeConn) LocalAddr() net.Addr       { return c.local }
func (c *scionExchangeConn) RemoteAddr() net.Addr      { return c.remote }
func (*scionExchangeConn) SetDeadline(time.Time) error { return nil }
func (*scionExchangeConn) SetPolicy(pan.Policy)        {}
func (c *scionExchangeConn) WriteVia(path *pan.Path, data []byte) (int, error) {
	c.writtenPath = path
	c.writes++
	return len(data), nil
}
func (c *scionExchangeConn) Read(data []byte) (int, error) { return copy(data, c.response), c.readErr }
func (c *scionExchangeConn) ReadVia(data []byte) (int, *pan.Path, error) {
	n, err := c.Read(data)
	return n, nil, err
}
func (c *scionExchangeConn) GetPath() *pan.Path { return c.writtenPath }

func TestSCIONExchangeExactPathTruncationAndTimeout(t *testing.T) {
	spec := localSpec()
	spec.SCION = true
	env := policyEnv(t, spec, netpolicy.Run{Addresses: []string{"127.0.0.1"}})
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	address := "1-ff00:0:111,127.0.0.1:1234"
	match, err := scionDestination(ctx, env, address)
	if err != nil {
		t.Fatal(err)
	}
	path := &pan.Path{Fingerprint: "selected", Expiry: time.Now().Add(time.Hour)}
	conn := &scionExchangeConn{remote: pan.MustParseUDPAddr(address), response: []byte("complete packet")}
	req := guestio.SCIONRequest{Address: address, Payload: []byte("request"), MaxBytes: 4}
	reply, err := exchangeSCION(ctx, env, conn, path, "exact-id", match, req)
	if err != nil || conn.writtenPath != path || reply.PathID != "exact-id" || string(reply.Data) != "comp" || reply.Size != 15 || !reply.Truncated {
		t.Fatalf("reply=%+v err=%v path=%p", reply, err, conn.writtenPath)
	}
	conn.response = nil
	conn.readErr = context.DeadlineExceeded
	reply, err = exchangeSCION(ctx, env, conn, path, "exact-id", match, req)
	if !errors.Is(err, context.DeadlineExceeded) || reply.PathID != "exact-id" || reply.Sender != address {
		t.Fatalf("timeout lost transmitted path: %+v %v", reply, err)
	}
	path.Expiry = time.Now().Add(-time.Second)
	before := conn.writes
	if _, err = exchangeSCION(ctx, env, conn, path, "exact-id", match, req); !errors.Is(err, socket.ErrSCIONPathUnavailable) || conn.writes != before {
		t.Fatalf("expired path sent: %v", err)
	}
}

func TestSCIONRecoverableRefusalAndRequestBounds(t *testing.T) {
	env := policyEnv(t, localSpec(), netpolicy.Run{Addresses: []string{"127.0.0.1"}, ListenSCION: true})
	mem := newGuestModule(t).Memory()
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	for _, operation := range []string{guestio.SCIONPaths, guestio.SCIONSelectPath, guestio.SCIONExchangeFunction, guestio.SCIONListenerAddressFunction, guestio.SCIONReceive, guestio.SCIONReply} {
		req := guestio.SCIONRequest{Address: "1-ff00:0:110,127.0.0.1:1234", PathID: "6f6b", MaxBytes: 8}
		data, _ := json.Marshal(req)
		mem.Write(0, data)
		result := hostSCION(env, operation)(ctx, mem, 0, uint32(len(data)), 16384, guestio.SCIONBufferSize)
		if uint32(result>>32) != guestio.Denied {
			t.Fatalf("%s refusal status %x", operation, result)
		}
	}
	data, _ := json.Marshal(guestio.SCIONRequest{MaxBytes: guestio.SCIONMaxPayload + 1})
	mem.Write(0, data)
	if result := hostSCION(env, guestio.SCIONReceive)(ctx, mem, 0, uint32(len(data)), 16384, guestio.SCIONBufferSize); uint32(result>>32) != guestio.Failure {
		t.Fatalf("bad size accepted %x", result)
	}
}

func TestSCIONListenerLockRespectsDeadline(t *testing.T) {
	var lock scionOperationLock
	if err := lock.Lock(t.Context()); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), time.Millisecond)
	defer cancel()
	if err := lock.Lock(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("waiting lock: %v", err)
	}
	lock.Unlock()
	if err := lock.Lock(t.Context()); err != nil {
		t.Fatal(err)
	}
	lock.Unlock()
}

func TestSCIONSameASRequiresExplicitLocalPath(t *testing.T) {
	conn := &scionExchangeConn{local: pan.MustParseUDPAddr("1-ff00:0:110,127.0.0.1:1234"), remote: pan.MustParseUDPAddr("1-ff00:0:110,127.0.0.2:4321")}
	path, description, err := selectSCIONPath(conn, socket.NewPathSelector(), guestio.SCIONLocalPath)
	if err != nil || path != nil || description.ID != guestio.SCIONLocalPath {
		t.Fatalf("local path %v %+v %v", path, description, err)
	}
	if _, _, err = selectSCIONPath(conn, socket.NewPathSelector(), "other"); !errors.Is(err, socket.ErrSCIONPathUnavailable) {
		t.Fatalf("local silently accepted other path: %v", err)
	}
}
