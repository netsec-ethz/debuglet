// Copyright 2025 ETH Zurich
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package wasm

// Policy enforcement at the host imports. Every case runs the production host
// function against loopback peers the test owns; the refused side is checked
// by what the peer observed, not only by the error the guest would see.

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/netsec-ethz/debuglet/internal/executor/debuglet/netpolicy"
	"github.com/netsec-ethz/debuglet/internal/executor/debuglet/socket"
	"github.com/netsec-ethz/debuglet/internal/executor/debuglet/wasm/hostconn"
	"github.com/netsec-ethz/debuglet/internal/executor/ratelimit"
	"github.com/netsec-ethz/debuglet/internal/executor/ratelimit/app"
	"github.com/netsec-ethz/debuglet/internal/executor/ratelimit/fallback"
	"github.com/netsec-ethz/debuglet/internal/executor/scheduler"
)

// secondLoopback is a loopback address that is not the one the jobs in this
// file declare, so a peer can be refused without leaving the machine. Linux
// routes the whole 127.0.0.0/8 block to the loopback interface; a host that
// does not is skipped rather than guessed at.
const secondLoopback = "127.0.0.2"

// localSpec is the operator policy of an executor that measures against
// services on its own host. The shipped default denies loopback, so every
// fixture here that reaches one says so explicitly.
func localSpec() netpolicy.Spec {
	spec := netpolicy.Defaults()
	spec.LocalTargets = true
	return spec
}

// policyEnv builds an environment with the production limiter, packet counter
// and registry, and the given policy.
func policyEnv(t *testing.T, spec netpolicy.Spec, run netpolicy.Run, options ...netpolicy.Option) *WasmEnv {
	t.Helper()
	operator, err := netpolicy.Parse(spec)
	if err != nil {
		t.Fatalf("netpolicy.Parse: %v", err)
	}
	id := uuid.New()
	limiter := app.NewLimiter(zap.NewNop())
	limiter.SetExecutorCapacity(app.Gigabit)
	for _, addr := range run.Addresses {
		limiter.SetAddrCapacity(addr, app.Gigabit)
	}
	if err := limiter.InsertDebuglet(id, 0, app.Gigabit, run.Addresses); err != nil {
		t.Fatalf("InsertDebuglet: %v", err)
	}
	execLimit, _, err := limiter.GetExecLimit(id)
	if err != nil {
		t.Fatalf("GetExecLimit: %v", err)
	}
	counter, err := fallback.NewFallbackCount()
	if err != nil {
		t.Fatalf("NewFallbackCount: %v", err)
	}
	t.Cleanup(func() { _ = counter.Close() })
	if err := counter.SetExecLimit(id, execLimit); err != nil {
		t.Fatalf("SetExecLimit: %v", err)
	}
	env := &WasmEnv{
		DebugletID:  id,
		Policy:      scheduler.Policy{Addresses: run.Addresses, ListenTCP: run.ListenTCP, ListenUDP: run.ListenUDP},
		Net:         netpolicy.New(operator, run, options...),
		Limiter:     limiter,
		Accountant:  ratelimit.NewAccountant(limiter, id),
		PacketCount: counter,
		Registry:    &socket.SocketRegistry{},
		Logger:      zap.NewNop().Sugar(),
	}
	t.Cleanup(func() { _ = env.Close() })
	return env
}

// requireSecondLoopback ends the test unless this host lets a socket bind the
// second loopback address, which is what a refused peer needs.
func requireSecondLoopback(t *testing.T) {
	t.Helper()
	conn, err := net.ListenPacket("udp", net.JoinHostPort(secondLoopback, "0"))
	if err != nil {
		aliasUnavailable(t, err)
	}
	conn.Close()
}

// aliasUnavailable reports a host that cannot use the second loopback address:
// a failure where the runner promised one through CI_REQUIRE_LOOPBACK_ALIASES,
// a skip anywhere else.
func aliasUnavailable(t *testing.T, err error) {
	t.Helper()
	if os.Getenv("CI_REQUIRE_LOOPBACK_ALIASES") != "" {
		t.Fatalf("this host does not use %s: %v", secondLoopback, err)
	}
	t.Skipf("this host does not use %s: %v", secondLoopback, err)
}

// TestHostConnectRefusedDestinationIsNeverContacted covers the outbound half:
// a target that is reachable but outside the job's declared destinations is
// not connected to at all.
func TestHostConnectRefusedDestinationIsNeverContacted(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		accepted <- conn
	}()

	env := policyEnv(t, localSpec(), netpolicy.Run{Addresses: []string{secondLoopback}})
	mod := newGuestModule(t)
	addr := listener.Addr().String()
	if !mod.Memory().Write(1024, []byte(addr)) {
		t.Fatal("write guest address")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	trap := hostTrap(func() { _ = HostConnect(env, socket.SocketTypeTCP)(ctx, mod, 1024, uint32(len(addr))) })
	if trap == nil {
		t.Fatal("the guest reached a destination its job never declared")
	}
	if !errors.Is(trap, netpolicy.ErrNotInPolicy) {
		t.Errorf("trap = %v, want the job's refusal", trap)
	}
	select {
	case conn := <-accepted:
		conn.Close()
		t.Fatal("the target accepted a connection although the policy refused it")
	case <-time.After(300 * time.Millisecond):
	}
}

// TestHostConnectRefusesDisabledTransport covers an operator who switched a
// transport off: the job declared the destination and the target is up, and
// the connect still never happens.
func TestHostConnectRefusesDisabledTransport(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		accepted <- conn
	}()

	spec := localSpec()
	spec.TCP = false
	env := policyEnv(t, spec, netpolicy.Run{Addresses: []string{"127.0.0.1"}})
	mod := newGuestModule(t)
	addr := listener.Addr().String()
	if !mod.Memory().Write(1024, []byte(addr)) {
		t.Fatal("write guest address")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	trap := hostTrap(func() { _ = HostConnect(env, socket.SocketTypeTCP)(ctx, mod, 1024, uint32(len(addr))) })
	if !errors.Is(trap, netpolicy.ErrTransportUnavailable) {
		t.Fatalf("trap = %v, want the operator's refusal", trap)
	}
	select {
	case conn := <-accepted:
		conn.Close()
		t.Fatal("a disabled transport still reached the target")
	case <-time.After(300 * time.Millisecond):
	}
}

// TestHostConnectRefusesPortOutsideThePermittedRanges covers the port rule on
// the resolved destination.
func TestHostConnectRefusesPortOutsideThePermittedRanges(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	spec := localSpec()
	spec.PermittedPorts = "80,443"
	env := policyEnv(t, spec, netpolicy.Run{Addresses: []string{"127.0.0.1"}})
	mod := newGuestModule(t)
	addr := listener.Addr().String()
	if !mod.Memory().Write(1024, []byte(addr)) {
		t.Fatal("write guest address")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	trap := hostTrap(func() { _ = HostConnect(env, socket.SocketTypeTCP)(ctx, mod, 1024, uint32(len(addr))) })
	if !errors.Is(trap, netpolicy.ErrDenied) {
		t.Fatalf("trap = %v, want the port denial", trap)
	}
}

// TestHostAcceptTCPRefusesPeersOutsideThePolicy covers inbound admission: a
// peer the job never declared is closed without reaching the guest, and the
// call goes on to the next peer, which is admitted and accounted.
func TestHostAcceptTCPRefusesPeersOutsideThePolicy(t *testing.T) {
	requireSecondLoopback(t)
	listener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	env := policyEnv(t, localSpec(), netpolicy.Run{Addresses: []string{"127.0.0.1"}, ListenTCP: true})
	env.TcpServer = listener

	refusedDialer := &net.Dialer{LocalAddr: &net.TCPAddr{IP: net.ParseIP(secondLoopback)}, Timeout: 5 * time.Second}
	refused, err := refusedDialer.Dial("tcp", listener.Addr().String())
	if err != nil {
		aliasUnavailable(t, err)
	}
	defer refused.Close()

	// The refused peer must be closed by the host, not held open.
	closed := make(chan error, 1)
	go func() {
		_ = refused.SetReadDeadline(time.Now().Add(10 * time.Second))
		_, err := refused.Read(make([]byte, 1))
		closed <- err
	}()

	admitted, err := net.DialTimeout("tcp", listener.Addr().String(), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer admitted.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	handle := HostAcceptTCP(env)(ctx)
	if handle < 0 {
		t.Fatalf("accept returned handle %d", handle)
	}
	sock, err := env.Registry.Get(handle)
	if err != nil {
		t.Fatalf("the accepted socket is not registered: %v", err)
	}
	host, _, err := net.SplitHostPort(sock.RemoteAddr())
	if err != nil {
		t.Fatalf("accepted peer address %q: %v", sock.RemoteAddr(), err)
	}
	if host != "127.0.0.1" {
		t.Errorf("the guest received a connection from %s, want the declared peer", host)
	}
	// An accepted connection carries the run's bandwidth accounting like any
	// other socket; before it did not, and its address was empty.
	if _, ok := sock.(*hostconn.HostConn); !ok {
		t.Errorf("the accepted socket is a %T, want an accounted connection", sock)
	}
	if sock.Addr() != "127.0.0.1" {
		t.Errorf("the accepted socket reports peer %q, want the admitted peer", sock.Addr())
	}

	select {
	case err := <-closed:
		if err == nil {
			t.Error("the refused peer was not closed")
		}
	case <-time.After(5 * time.Second):
		t.Error("the refused peer was left open")
	}
}

// TestHostReceiveUDPFromRefusesSendersOutsideThePolicy covers the listener's
// datagrams: one from a sender the job never declared is dropped and never
// delivered, and the next admitted datagram is.
func TestHostReceiveUDPFromRefusesSendersOutsideThePolicy(t *testing.T) {
	requireSecondLoopback(t)
	server, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	env := policyEnv(t, localSpec(), netpolicy.Run{Addresses: []string{"127.0.0.1"}, ListenUDP: true})
	env.UdpServer = server

	refused, err := net.DialUDP("udp",
		&net.UDPAddr{IP: net.ParseIP(secondLoopback)}, server.LocalAddr().(*net.UDPAddr))
	if err != nil {
		aliasUnavailable(t, err)
	}
	defer refused.Close()
	if _, err := refused.Write([]byte("REFUSED")); err != nil {
		t.Fatal(err)
	}

	admitted, err := net.DialUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")}, server.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer admitted.Close()
	if _, err := admitted.Write([]byte("ADMITTED")); err != nil {
		t.Fatal(err)
	}

	mod := newGuestModule(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var n int32
	trap := hostTrap(func() { n = HostReceiveUDPFrom(env)(ctx, mod, 2048, 512, 4096, 128, 8192) })
	if trap != nil {
		t.Fatalf("receive_udp_from trapped: %v", trap)
	}
	payload, ok := mod.Memory().Read(2048, uint32(n))
	if !ok {
		t.Fatal("read the delivered datagram")
	}
	if string(payload) != "ADMITTED" {
		t.Errorf("the guest received %q, want only the admitted datagram", payload)
	}
	senderLen, ok := mod.Memory().ReadUint32Le(8192)
	if !ok {
		t.Fatal("read the sender address length")
	}
	sender, ok := mod.Memory().Read(4096, senderLen)
	if !ok {
		t.Fatal("read the sender address")
	}
	host, _, err := net.SplitHostPort(string(sender))
	if err != nil {
		t.Fatalf("sender address %q: %v", sender, err)
	}
	if host != "127.0.0.1" {
		t.Errorf("the guest was told the sender is %s, want the admitted peer", host)
	}
}

// TestHostReceiveUDPFromRefusesAnUnrequestedListener covers a job that reads
// from a listener it never asked for.
func TestHostReceiveUDPFromRefusesAnUnrequestedListener(t *testing.T) {
	env := policyEnv(t, localSpec(), netpolicy.Run{Addresses: []string{"127.0.0.1"}})
	mod := newGuestModule(t)
	trap := hostTrap(func() {
		_ = HostReceiveUDPFrom(env)(context.Background(), mod, 2048, 512, 4096, 128, 8192)
	})
	if !errors.Is(trap, netpolicy.ErrTransportUnavailable) {
		t.Fatalf("trap = %v, want the refusal of a listener the job did not request", trap)
	}
}

// TestHostSCIONIsDisabledInTheSupportedProfile covers the transport this
// profile does not support: its imports stay registered and refuse.
func TestHostSCIONIsDisabledInTheSupportedProfile(t *testing.T) {
	env := policyEnv(t, localSpec(), netpolicy.Run{Addresses: []string{"127.0.0.1"}, ListenSCION: true})
	mod := newGuestModule(t)
	addr := "1-ff00:0:110,127.0.0.1:1234"
	if !mod.Memory().Write(1024, []byte(addr)) {
		t.Fatal("write guest address")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	trap := hostTrap(func() {
		_ = HostSendSCIONUDPPacket(env)(ctx, mod, 1024, uint32(len(addr)), 2048, 4)
	})
	if !errors.Is(trap, netpolicy.ErrTransportUnavailable) {
		t.Fatalf("trap = %v, want the disabled transport's refusal", trap)
	}
	trap = hostTrap(func() {
		_, _ = HostReceiveSCIONServerUDPPacket(env)(ctx, mod, 2048, 512, 100)
	})
	if !errors.Is(trap, netpolicy.ErrTransportUnavailable) {
		t.Fatalf("trap = %v, want the disabled listener's refusal", trap)
	}
}

// TestHostReceiveUDPFromLeavesNothingFromARefusedDatagram covers the buffer a
// refused sender must not reach: the datagram is read into the host's memory,
// and only the admitted one is written into the guest's. A refused datagram
// that is longer than the admitted one must not survive as its tail.
func TestHostReceiveUDPFromLeavesNothingFromARefusedDatagram(t *testing.T) {
	requireSecondLoopback(t)
	server, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	env := policyEnv(t, localSpec(), netpolicy.Run{Addresses: []string{"127.0.0.1"}, ListenUDP: true})
	env.UdpServer = server

	refused, err := net.DialUDP("udp",
		&net.UDPAddr{IP: net.ParseIP(secondLoopback)}, server.LocalAddr().(*net.UDPAddr))
	if err != nil {
		aliasUnavailable(t, err)
	}
	defer refused.Close()
	long := bytes.Repeat([]byte("R"), 64)
	if _, err := refused.Write(long); err != nil {
		t.Fatal(err)
	}

	admitted, err := net.DialUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")}, server.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer admitted.Close()
	short := []byte("OKAY")
	if _, err := admitted.Write(short); err != nil {
		t.Fatal(err)
	}

	// The guest's buffer is filled with a pattern first, so anything the host
	// leaves behind is visible.
	const recvp, recvLen = 2048, 512
	pattern := bytes.Repeat([]byte{0xAA}, recvLen)
	mod := newGuestModule(t)
	if !mod.Memory().Write(recvp, pattern) {
		t.Fatal("fill the guest buffer")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var n int32
	trap := hostTrap(func() { n = HostReceiveUDPFrom(env)(ctx, mod, recvp, recvLen, 4096, 128, 8192) })
	if trap != nil {
		t.Fatalf("receive_udp_from trapped: %v", trap)
	}
	if int(n) != len(short) {
		t.Fatalf("the guest was told it received %d bytes, want the admitted datagram's %d", n, len(short))
	}
	buffer, ok := mod.Memory().Read(recvp, recvLen)
	if !ok {
		t.Fatal("read the guest buffer")
	}
	if !bytes.Equal(buffer[:n], short) {
		t.Errorf("the guest received %q, want %q", buffer[:n], short)
	}
	if !bytes.Equal(buffer[n:], pattern[n:]) {
		t.Errorf("the refused datagram left %q behind in the guest buffer", bytes.TrimRight(buffer[n:], "\xaa"))
	}
}

// TestHostConnectTriesEveryAdmittedAddress covers a destination with more than
// one address: the host tries them in order, as dialling the name would have,
// so an unreachable first address does not make the destination unreachable.
func TestHostConnectTriesEveryAdmittedAddress(t *testing.T) {
	requireSecondLoopback(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				_, _ = conn.Read(make([]byte, 1))
			}()
		}
	}()
	_, port, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}

	// The first address has nothing listening on that port; the second is the
	// target. Both are the job's declared destination.
	resolver := &fixedResolver{answers: map[string][]netip.Addr{
		"target.example": {netip.MustParseAddr(secondLoopback), netip.MustParseAddr("127.0.0.1")},
	}}
	env := policyEnv(t, localSpec(), netpolicy.Run{Addresses: []string{"target.example"}},
		netpolicy.WithResolver(resolver))

	mod := newGuestModule(t)
	addr := net.JoinHostPort("target.example", port)
	if !mod.Memory().Write(1024, []byte(addr)) {
		t.Fatal("write guest address")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var handle int32
	trap := hostTrap(func() { handle = HostConnect(env, socket.SocketTypeTCP)(ctx, mod, 1024, uint32(len(addr))) })
	if trap != nil {
		t.Fatalf("connect trapped although one admitted address answers: %v", trap)
	}
	sock, err := env.Registry.Get(handle)
	if err != nil {
		t.Fatalf("the connection is not registered: %v", err)
	}
	if sock.RemoteAddr() != listener.Addr().String() {
		t.Errorf("the guest reached %s, want the address that answered %s", sock.RemoteAddr(), listener.Addr())
	}
	if sock.Addr() != "127.0.0.1" {
		t.Errorf("the connection reports peer %q", sock.Addr())
	}
}

// fixedResolver answers from a table the test owns.
type fixedResolver struct{ answers map[string][]netip.Addr }

func (r *fixedResolver) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	addrs, ok := r.answers[host]
	if !ok {
		return nil, fmt.Errorf("no such host %q", host)
	}
	return addrs, nil
}
