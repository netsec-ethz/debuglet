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

package socket

import (
	"net"
	"reflect"
	"strconv"
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
	p1, p2 := freePort(t), freePort(t)
	s, err := NewPortManager("203.0.113.10", strconv.Itoa(p1)+","+strconv.Itoa(p2))
	if err != nil {
		t.Fatalf("NewPortManager: %v", err)
	}

	lis1, got1, addr1, err := s.ListenTCP()
	if err != nil {
		t.Fatalf("ListenTCP: %v", err)
	}
	defer lis1.Close()
	lis2, got2, _, err := s.ListenTCP()
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

	lis1, got1, _, err := s.ListenTCP()
	if err != nil {
		t.Fatalf("ListenTCP: %v", err)
	}
	lis1.Close()
	s.Release(got1)

	lis2, got2, _, err := s.ListenTCP()
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

	lis, _, _, err := s.ListenTCP()
	if err != nil {
		t.Fatalf("ListenTCP: %v", err)
	}
	defer lis.Close()

	if _, _, _, err := s.ListenTCP(); err == nil {
		t.Fatal("ListenTCP should error when all ports are taken")
	}
}

func TestPortManagerListenUDPDistinctPorts(t *testing.T) {
	p1, p2 := freeUDPPort(t), freeUDPPort(t)
	s, err := NewPortManager("203.0.113.10", strconv.Itoa(p1)+","+strconv.Itoa(p2))
	if err != nil {
		t.Fatalf("NewPortManager: %v", err)
	}

	conn1, got1, addr1, err := s.ListenUDP()
	if err != nil {
		t.Fatalf("ListenUDP: %v", err)
	}
	defer conn1.Close()
	conn2, got2, _, err := s.ListenUDP()
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

	conn1, got1, _, err := s.ListenUDP()
	if err != nil {
		t.Fatalf("ListenUDP: %v", err)
	}
	conn1.Close()
	s.Release(got1)

	conn2, got2, _, err := s.ListenUDP()
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

	conn, _, _, err := s.ListenUDP()
	if err != nil {
		t.Fatalf("ListenUDP: %v", err)
	}
	defer conn.Close()

	if _, _, _, err := s.ListenUDP(); err == nil {
		t.Fatal("ListenUDP should error when all ports are taken")
	}
}

func TestPortManagerCrossProtocolSharedPool(t *testing.T) {
	p := freePort(t)
	s, err := NewPortManager("203.0.113.10", strconv.Itoa(p))
	if err != nil {
		t.Fatalf("NewPortManager: %v", err)
	}

	lis, got, _, err := s.ListenTCP()
	if err != nil {
		t.Fatalf("ListenTCP: %v", err)
	}
	defer lis.Close()

	if _, _, _, err := s.ListenUDP(); err == nil {
		t.Fatalf("ListenUDP must not hand out port %d already allocated to TCP", got)
	}
}
