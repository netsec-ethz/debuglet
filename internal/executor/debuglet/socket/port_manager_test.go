// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 ETH Zurich

package socket

import (
	"errors"
	"net"
	"reflect"
	"strconv"
	"strings"
	"syscall"
	"testing"
)

func TestParsePortRanges(t *testing.T) {
	tests := []struct {
		name    string
		spec    string
		want    []int
		wantErr bool
	}{
		{name: "empty", spec: "", want: []int{}},
		{name: "single port", spec: "2022", want: []int{2022}},
		{name: "single range", spec: "2025-3005", want: seq(2025, 3005)},
		{name: "mixed", spec: "2022,2025-3005,56000-62000", want: append(append([]int{2022}, seq(2025, 3005)...), seq(56000, 62000)...)},
		{name: "whitespace", spec: " 2022 , 2025 - 3005 , 56000-62000 ", want: append(append([]int{2022}, seq(2025, 3005)...), seq(56000, 62000)...)},
		{name: "dedupe", spec: "2022,2022,2022-2024", want: []int{2022, 2023, 2024}},
		{name: "trailing comma", spec: "2022,", want: []int{2022}},
		{name: "out of range low", spec: "0", wantErr: true},
		{name: "out of range high", spec: "65536", wantErr: true},
		{name: "start greater than end", spec: "3005-2025", wantErr: true},
		{name: "non-numeric", spec: "abc", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParsePortRanges(tt.spec)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("ParsePortRanges(%q) expected error, got %v", tt.spec, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParsePortRanges(%q) unexpected error: %v", tt.spec, err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("ParsePortRanges(%q) = %v, want %v", tt.spec, got, tt.want)
			}
		})
	}
}

func seq(lo, hi int) []int {
	out := make([]int, 0, hi-lo+1)
	for p := lo; p <= hi; p++ {
		out = append(out, p)
	}
	return out
}

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatalf("failed to find a free port: %v", err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func freeUDPPort(t *testing.T) int {
	t.Helper()
	l, err := net.ListenUDP("udp", &net.UDPAddr{Port: 0})
	if err != nil {
		t.Fatalf("failed to find a free UDP port: %v", err)
	}
	defer l.Close()
	return l.LocalAddr().(*net.UDPAddr).Port
}

func TestPortManagerEnabled(t *testing.T) {
	s, err := NewPortManager("", "2022")
	if err != nil {
		t.Fatalf("NewPortManager: %v", err)
	}
	if s.Enabled() {
		t.Fatal("Enabled() should be false when publicAddr is empty")
	}

	s, err = NewPortManager("203.0.113.10", "2022")
	if err != nil {
		t.Fatalf("NewPortManager: %v", err)
	}
	if !s.Enabled() {
		t.Fatal("Enabled() should be true when publicAddr and ports are set")
	}

	s, err = NewPortManager("203.0.113.10", "")
	if err != nil {
		t.Fatalf("NewPortManager: %v", err)
	}
	if s.Enabled() {
		t.Fatal("Enabled() should be false when no ports are configured")
	}
}

func TestPortManagerListenTCPDistinctPorts(t *testing.T) {
	// Keep the first probe bound while selecting the second port: once a
	// probe is closed, the kernel may return that same ephemeral port again.
	first, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	p1, p2 := first.Addr().(*net.TCPAddr).Port, freePort(t)
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	s, err := NewPortManager("203.0.113.10", strconv.Itoa(p1)+","+strconv.Itoa(p2))
	if err != nil {
		t.Fatalf("NewPortManager: %v", err)
	}

	lis1, got1, addr1, err := s.ListenTCP(nil)
	if err != nil {
		t.Fatalf("ListenTCP: %v", err)
	}
	defer lis1.Close()
	lis2, got2, _, err := s.ListenTCP(nil)
	if err != nil {
		t.Fatalf("ListenTCP: %v", err)
	}
	defer lis2.Close()

	if got1 == got2 {
		t.Fatalf("ListenTCP returned the same port twice: %d", got1)
	}
	if addr1 != "203.0.113.10:"+strconv.Itoa(got1) {
		t.Fatalf("ListenTCP addr = %q, want %q", addr1, "203.0.113.10:"+strconv.Itoa(got1))
	}
}

func TestPortManagerListenTCPReleaseReusesPort(t *testing.T) {
	p := freePort(t)
	s, err := NewPortManager("203.0.113.10", strconv.Itoa(p))
	if err != nil {
		t.Fatalf("NewPortManager: %v", err)
	}

	lis1, got1, _, err := s.ListenTCP(nil)
	if err != nil {
		t.Fatalf("ListenTCP: %v", err)
	}
	lis1.Close()
	s.Release(got1)

	lis2, got2, _, err := s.ListenTCP(nil)
	if err != nil {
		t.Fatalf("ListenTCP after Release: %v", err)
	}
	defer lis2.Close()

	if got1 != got2 {
		t.Fatalf("Release did not free the port: got %d then %d", got1, got2)
	}
}

func TestPortManagerListenTCPExhausted(t *testing.T) {
	p := freePort(t)
	s, err := NewPortManager("203.0.113.10", strconv.Itoa(p))
	if err != nil {
		t.Fatalf("NewPortManager: %v", err)
	}

	lis, _, _, err := s.ListenTCP(nil)
	if err != nil {
		t.Fatalf("ListenTCP: %v", err)
	}
	defer lis.Close()

	if _, _, _, err := s.ListenTCP(nil); err == nil {
		t.Fatal("ListenTCP should error when all ports are taken")
	}
}

func TestPortManagerListenUDPDistinctPorts(t *testing.T) {
	// Reserve the first port until the second probe has selected another.
	first, err := net.ListenUDP("udp", &net.UDPAddr{Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	p1, p2 := first.LocalAddr().(*net.UDPAddr).Port, freeUDPPort(t)
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	s, err := NewPortManager("203.0.113.10", strconv.Itoa(p1)+","+strconv.Itoa(p2))
	if err != nil {
		t.Fatalf("NewPortManager: %v", err)
	}

	conn1, got1, addr1, err := s.ListenUDP(nil)
	if err != nil {
		t.Fatalf("ListenUDP: %v", err)
	}
	defer conn1.Close()
	conn2, got2, _, err := s.ListenUDP(nil)
	if err != nil {
		t.Fatalf("ListenUDP: %v", err)
	}
	defer conn2.Close()

	if got1 == got2 {
		t.Fatalf("ListenUDP returned the same port twice: %d", got1)
	}
	if addr1 != "203.0.113.10:"+strconv.Itoa(got1) {
		t.Fatalf("ListenUDP addr = %q, want %q", addr1, "203.0.113.10:"+strconv.Itoa(got1))
	}
}

func TestPortManagerListenUDPReleaseReusesPort(t *testing.T) {
	p := freeUDPPort(t)
	s, err := NewPortManager("203.0.113.10", strconv.Itoa(p))
	if err != nil {
		t.Fatalf("NewPortManager: %v", err)
	}

	conn1, got1, _, err := s.ListenUDP(nil)
	if err != nil {
		t.Fatalf("ListenUDP: %v", err)
	}
	conn1.Close()
	s.Release(got1)

	conn2, got2, _, err := s.ListenUDP(nil)
	if err != nil {
		t.Fatalf("ListenUDP after Release: %v", err)
	}
	defer conn2.Close()

	if got1 != got2 {
		t.Fatalf("Release did not free the port: got %d then %d", got1, got2)
	}
}

func TestPortManagerListenUDPExhausted(t *testing.T) {
	p := freeUDPPort(t)
	s, err := NewPortManager("203.0.113.10", strconv.Itoa(p))
	if err != nil {
		t.Fatalf("NewPortManager: %v", err)
	}

	conn, _, _, err := s.ListenUDP(nil)
	if err != nil {
		t.Fatalf("ListenUDP: %v", err)
	}
	defer conn.Close()

	if _, _, _, err := s.ListenUDP(nil); err == nil {
		t.Fatal("ListenUDP should error when all ports are taken")
	}
}

func TestPortManagerCrossProtocolSharedPool(t *testing.T) {
	p := freePort(t)
	s, err := NewPortManager("203.0.113.10", strconv.Itoa(p))
	if err != nil {
		t.Fatalf("NewPortManager: %v", err)
	}

	lis, got, _, err := s.ListenTCP(nil)
	if err != nil {
		t.Fatalf("ListenTCP: %v", err)
	}
	defer lis.Close()

	if _, _, _, err := s.ListenUDP(nil); err == nil {
		t.Fatalf("ListenUDP must not hand out port %d already allocated to TCP", got)
	}
}

// pmControl counts the sockets a listen control is called for and refuses
// them with fail. It requires every TCP listener socket to be plain TCP.
type pmControl struct {
	t     *testing.T
	calls int
	fail  error
}

func (c *pmControl) control(network, _ string, raw syscall.RawConn) error {
	c.calls++
	if strings.HasPrefix(network, "tcp") {
		var proto int
		var known bool
		var protoErr error
		if err := raw.Control(func(fd uintptr) {
			proto, known, protoErr = socketProtocol(int(fd))
		}); err != nil {
			protoErr = err
		}
		if protoErr != nil || (known && proto != syscall.IPPROTO_TCP) {
			c.t.Errorf("listener socket protocol = %d, %v; want plain TCP (%d)", proto, protoErr, syscall.IPPROTO_TCP)
		}
	}
	return c.fail
}

// pmFreePorts returns two distinct ports that are free for both TCP and UDP,
// in ascending order.
func pmFreePorts(t *testing.T) (int, int) {
	t.Helper()
	var ports []int
	for len(ports) < 2 {
		p := freePort(t)
		if len(ports) == 1 && ports[0] == p {
			continue
		}
		conn, err := net.ListenUDP("udp", &net.UDPAddr{Port: p})
		if err != nil {
			continue
		}
		conn.Close()
		ports = append(ports, p)
	}
	return min(ports[0], ports[1]), max(ports[0], ports[1])
}

func TestPortManagerListenControlBusyPortMovesOn(t *testing.T) {
	// The pool is tried in ascending order: the lower port is the busy one.
	lo, hi := pmFreePorts(t)
	busyTCP, err := net.Listen("tcp", ":"+strconv.Itoa(lo))
	if err != nil {
		t.Fatal(err)
	}
	defer busyTCP.Close()
	busyUDP, err := net.ListenPacket("udp", ":"+strconv.Itoa(lo))
	if err != nil {
		t.Fatal(err)
	}
	defer busyUDP.Close()
	s, err := NewPortManager("203.0.113.10", strconv.Itoa(lo)+","+strconv.Itoa(hi))
	if err != nil {
		t.Fatalf("NewPortManager: %v", err)
	}

	tcp := &pmControl{t: t}
	lis, got, _, err := s.ListenTCP(tcp.control)
	if err != nil {
		t.Fatalf("ListenTCP with %d busy: %v", lo, err)
	}
	defer lis.Close()
	if got != hi {
		t.Fatalf("ListenTCP port = %d, want %d after %d is in use", got, hi, lo)
	}
	if tcp.calls != 2 {
		t.Errorf("TCP control calls = %d, want one per socket tried (2)", tcp.calls)
	}
	s.Release(got)
	lis.Close()

	udp := &pmControl{t: t}
	conn, got, _, err := s.ListenUDP(udp.control)
	if err != nil {
		t.Fatalf("ListenUDP with %d busy: %v", lo, err)
	}
	defer conn.Close()
	if got != hi {
		t.Fatalf("ListenUDP port = %d, want %d after %d is in use", got, hi, lo)
	}
	if udp.calls != 2 {
		t.Errorf("UDP control calls = %d, want one per socket tried (2)", udp.calls)
	}
}

func TestPortManagerListenControlRefusalStops(t *testing.T) {
	refused := errors.New("socket refused")
	lo, hi := pmFreePorts(t)
	s, err := NewPortManager("203.0.113.10", strconv.Itoa(lo)+","+strconv.Itoa(hi))
	if err != nil {
		t.Fatalf("NewPortManager: %v", err)
	}

	tcp := &pmControl{t: t, fail: refused}
	if lis, got, _, err := s.ListenTCP(tcp.control); !errors.Is(err, refused) {
		if lis != nil {
			lis.Close()
		}
		t.Fatalf("ListenTCP = port %d, %v; want the control's refusal", got, err)
	}
	if tcp.calls != 1 {
		t.Errorf("TCP control calls = %d, want 1: a refused socket must not move on to the next port", tcp.calls)
	}
	udp := &pmControl{t: t, fail: refused}
	if conn, got, _, err := s.ListenUDP(udp.control); !errors.Is(err, refused) {
		if conn != nil {
			conn.Close()
		}
		t.Fatalf("ListenUDP = port %d, %v; want the control's refusal", got, err)
	}
	if udp.calls != 1 {
		t.Errorf("UDP control calls = %d, want 1: a refused socket must not move on to the next port", udp.calls)
	}

	// Nothing was allocated and the refused sockets are closed: the lower port
	// binds again, for either protocol, and then the higher one.
	lis, got, _, err := s.ListenTCP(nil)
	if err != nil {
		t.Fatalf("ListenTCP after refusals: %v", err)
	}
	if got != lo {
		t.Errorf("ListenTCP after refusals = port %d, want %d (allocated or left bound by a refusal)", got, lo)
	}
	lis.Close()
	s.Release(got)
	conn, got, _, err := s.ListenUDP(nil)
	if err != nil {
		t.Fatalf("ListenUDP after refusals: %v", err)
	}
	defer conn.Close()
	if got != lo {
		t.Errorf("ListenUDP after refusals = port %d, want %d (allocated or left bound by a refusal)", got, lo)
	}
	lis, got, _, err = s.ListenTCP(nil)
	if err != nil {
		t.Fatalf("second ListenTCP after refusals: %v", err)
	}
	defer lis.Close()
	if got != hi {
		t.Errorf("second ListenTCP after refusals = port %d, want %d", got, hi)
	}
}

// The IPv4-only listeners of a run that refuses IPv6 bind the IPv4 wildcard,
// so an IPv6 peer cannot reach them.
func TestPortManagerIPv4OnlyListeners(t *testing.T) {
	s, err := NewPortManager("203.0.113.10", strconv.Itoa(freePort(t))+","+strconv.Itoa(freePort(t)))
	if err != nil {
		t.Fatalf("NewPortManager: %v", err)
	}
	var none *PortManager
	if s.PublicHost() != "203.0.113.10" || none.PublicHost() != "" {
		t.Fatal("PublicHost")
	}
	lis, tcpPort, _, err := s.ListenTCP4(nil)
	if err != nil {
		t.Fatalf("ListenTCP4: %v", err)
	}
	defer lis.Close()
	conn, udpPort, _, err := s.ListenUDP4(nil)
	if err != nil {
		t.Fatalf("ListenUDP4: %v", err)
	}
	defer conn.Close()
	if ip := lis.Addr().(*net.TCPAddr).IP; ip.To4() == nil {
		t.Errorf("ListenTCP4 bound %v", ip)
	}
	if ip := conn.LocalAddr().(*net.UDPAddr).IP; ip.To4() == nil {
		t.Errorf("ListenUDP4 bound %v", ip)
	}
	if c, err := net.Dial("tcp6", "[::1]:"+strconv.Itoa(tcpPort)); err == nil {
		c.Close()
		t.Error("an IPv6 peer reached the IPv4-only listener")
	}
	s.Release(tcpPort)
	s.Release(udpPort)
}
