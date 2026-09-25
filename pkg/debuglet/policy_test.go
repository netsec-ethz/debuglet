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

package debuglet_test

// End-to-end network policy checks. Each case compiles the frozen guest
// fixture, runs it on the executor's real engine and host imports, and checks
// the refused side from what the loopback peer observed: a refused
// destination must receive no connection, no handshake and no datagram, not a
// connection that is closed again afterwards.

import (
	"io"
	"net"
	"os"
	"testing"
	"time"

	"github.com/netsec-ethz/debuglet/internal/executor/debuglet/netpolicy"
)

// secondLoopback is a loopback address that is not the one most cases declare,
// so a peer can be outside a job's policy without leaving the machine. Linux
// routes the whole 127.0.0.0/8 block to the loopback interface; a host that
// does not is skipped rather than guessed at.
const secondLoopback = "127.0.0.2"

// requireSecondLoopback ends the test unless this host binds that address.
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

// policySpec returns the local profile with fn applied, so each case states
// only what it changes and is refused for the reason it is about. The local
// profile is the documented defaults plus the local-target switch: the
// defaults on their own already deny the loopback peers these cases own, which
// is what the_default_policy_denies_loopback covers.
func policySpec(fn func(*netpolicy.Spec)) *netpolicy.Spec {
	spec := netpolicy.Defaults()
	spec.LocalTargets = true
	fn(&spec)
	return &spec
}

// silentTCPTarget accepts connections on loopback and reports each one. The
// refused cases wait on the channel staying empty.
func silentTCPTarget(t *testing.T) (addr string, accepted chan string) {
	t.Helper()
	accepted = make(chan string, 4)
	listener, err := net.Listen("tcp", net.JoinHostPort(loopback, "0"))
	if err != nil {
		t.Fatalf("listen target: %v", err)
	}
	t.Cleanup(func() { listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			accepted <- conn.RemoteAddr().String()
			_ = conn.SetDeadline(time.Now().Add(peerDeadline))
			readAllFrom(conn)
			conn.Close()
		}
	}()
	return listener.Addr().String(), accepted
}

// requireUntouched fails when the target observed anything at all.
func requireUntouched[T any](t *testing.T, observed chan T, what string) {
	t.Helper()
	select {
	case value := <-observed:
		t.Fatalf("a refused destination observed %s: %v", what, value)
	case <-time.After(time.Second):
	}
}

// TestPolicyRefusesDestinationsEndToEnd runs the frozen guest against a
// loopback target that is up and reachable, under policies that refuse it for
// one reason each.
func TestPolicyRefusesDestinationsEndToEnd(t *testing.T) {
	wasm := buildGuest(t, abiV1Fixture)

	t.Run("operator_denies_the_destination", func(t *testing.T) {
		addr, accepted := silentTCPTarget(t)
		// The job declares the destination and the operator denies it.
		g := runGuest(t, wasm, hostOptions{
			addresses: []string{loopback},
			operator:  policySpec(func(s *netpolicy.Spec) { s.DeniedDestinations = loopback + "/32" }),
			args:      []string{"tcp_connect_only", addr},
		})
		if g.err() == nil {
			t.Error("the guest completed although the operator denies its destination")
		}
		requireContains(t, g, "connecting tcp "+addr+"\n")
		requireAbsent(t, g, "connected tcp", "connect tcp rc=")
		requireUntouched(t, accepted, "a connection")
	})

	t.Run("operator_denies_the_port", func(t *testing.T) {
		addr, accepted := silentTCPTarget(t)
		g := runGuest(t, wasm, hostOptions{
			addresses: []string{loopback},
			operator:  policySpec(func(s *netpolicy.Spec) { s.PermittedPorts = "80,443" }),
			args:      []string{"tcp_connect_only", addr},
		})
		if g.err() == nil {
			t.Error("the guest completed although its destination port is not permitted")
		}
		requireAbsent(t, g, "connected tcp")
		requireUntouched(t, accepted, "a connection")
	})

	t.Run("operator_disables_the_transport", func(t *testing.T) {
		addr, accepted := silentTCPTarget(t)
		g := runGuest(t, wasm, hostOptions{
			addresses: []string{loopback},
			operator:  policySpec(func(s *netpolicy.Spec) { s.TCP = false }),
			args:      []string{"tcp_connect_only", addr},
		})
		if g.err() == nil {
			t.Error("the guest completed although TCP is disabled")
		}
		requireAbsent(t, g, "connected tcp")
		requireUntouched(t, accepted, "a connection")
	})

	t.Run("no_handshake_reaches_a_denied_tls_destination", func(t *testing.T) {
		addr, accepted := silentTCPTarget(t)
		g := runGuest(t, wasm, hostOptions{
			addresses: []string{loopback},
			operator:  policySpec(func(s *netpolicy.Spec) { s.TLS = false }),
			args:      []string{"tls_connect_only", addr},
		})
		if g.err() == nil {
			t.Error("the guest completed although TLS is disabled")
		}
		requireAbsent(t, g, "connected tls")
		requireUntouched(t, accepted, "a handshake")
	})

	t.Run("the_default_policy_denies_loopback", func(t *testing.T) {
		addr, accepted := silentTCPTarget(t)
		shipped := netpolicy.Defaults()
		g := runGuest(t, wasm, hostOptions{
			addresses: []string{loopback},
			operator:  &shipped,
			args:      []string{"tcp_connect_only", addr},
		})
		if g.err() == nil {
			t.Error("the guest reached a loopback destination under the shipped default policy")
		}
		requireAbsent(t, g, "connected tcp")
		requireUntouched(t, accepted, "a connection")
	})

	t.Run("udp_datagrams_do_not_reach_a_denied_destination", func(t *testing.T) {
		received := make(chan string, 4)
		addr := startUDPTarget(t, func(data []byte) []byte {
			received <- string(data)
			return []byte("PONG")
		})
		g := runGuest(t, wasm, hostOptions{
			addresses: []string{loopback},
			operator:  policySpec(func(s *netpolicy.Spec) { s.UDP = false }),
			args:      []string{"udp_echo", addr},
		})
		if g.err() == nil {
			t.Error("the guest completed although UDP is disabled")
		}
		requireAbsent(t, g, "connected udp")
		requireUntouched(t, received, "a datagram")
	})
}

// TestPolicyAdmitsTheLocalProfileEndToEnd is the positive control for the
// policy: after every transport was made to admit its peer before it moves
// traffic, a destination the job declares must still be reached end to end.
func TestPolicyAdmitsTheLocalProfileEndToEnd(t *testing.T) {
	wasm := buildGuest(t, abiV1Fixture)
	request := make(chan string, 1)
	addr := startTCPTarget(t, func(conn net.Conn) {
		buf := make([]byte, 16)
		n, err := conn.Read(buf)
		if err != nil {
			request <- "read error"
			return
		}
		request <- string(buf[:n])
		conn.Write([]byte("PONG\n"))
	})
	g := runGuest(t, wasm, hostOptions{addresses: []string{loopback}, args: []string{"tcp_exchange", addr}})
	requireSuccess(t, g)
	if got := report(t, request, "the guest's request"); got != "PING\n" {
		t.Errorf("target received %q, want %q", got, "PING\n")
	}
	requireContains(t, g, "connected tcp handle=0\n", "remote="+addr+"\n")
}

// TestPolicyRefusesInboundPeersEndToEnd covers the listener half: a peer that
// is not one of the job's declared destinations never reaches the guest, and
// the guest's accept goes on waiting for one that is.
func TestPolicyRefusesInboundPeersEndToEnd(t *testing.T) {
	requireSecondLoopback(t)
	wasm := buildGuest(t, abiV1Fixture)

	// The job declares the second loopback address, so a peer that connects
	// from the first one is outside its policy.
	g := startGuest(t, wasm, hostOptions{
		addresses: []string{secondLoopback},
		listenTCP: true,
		args:      []string{"listen_tcp"},
	})
	published := publishedAddr(t, g, "listening tcp ")

	refused, err := dialGuestListener(t, published, nil)
	if err != nil {
		t.Fatalf("dial the guest's listener at %s: %v", published, err)
	}
	if _, err := refused.Write([]byte("HELLO\n")); err != nil {
		t.Fatalf("write to the guest: %v", err)
	}
	_ = refused.SetReadDeadline(time.Now().Add(10 * time.Second))
	if n, err := refused.Read(make([]byte, 8)); err == nil {
		t.Fatalf("the guest answered a peer outside its policy with %d bytes", n)
	}
	requireAbsent(t, g, "connected accept")

	// The admitted peer reaches the same guest through the same accept call.
	admitted, err := dialGuestListener(t, published, &net.TCPAddr{IP: net.ParseIP(secondLoopback)})
	if err != nil {
		aliasUnavailable(t, err)
	}
	if _, err := admitted.Write([]byte("HELLO\n")); err != nil {
		t.Fatalf("write to the guest: %v", err)
	}
	reply := make([]byte, 5)
	if _, err := io.ReadFull(admitted, reply); err != nil {
		t.Fatalf("read the guest's reply: %v", err)
	}
	if string(reply) != "PONG\n" {
		t.Errorf("guest replied %q, want %q", reply, "PONG\n")
	}
	admitted.Close()
	if !g.wait(20 * time.Second) {
		t.Fatalf("guest did not finish after the admitted client closed; output:\n%s", g.output())
	}
	requireSuccess(t, g)
	requireContains(t, g, "connected accept handle=0\n", "recv n=6 data=\"HELLO\\n\"\n")
}
