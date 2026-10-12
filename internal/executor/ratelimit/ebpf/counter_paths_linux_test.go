// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

//go:build linux

package ebpf

import (
	"encoding/binary"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/netsec-ethz/debuglet/internal/bitrate"
	"golang.org/x/sys/unix"
)

// These owned loopback tests observe packets after the kernel's IP receive
// path. They do not establish guarantees for other interfaces or offloads.
func captureUDPFamily(t *testing.T, ipv6 bool) int {
	t.Helper()
	family := unix.AF_INET
	if ipv6 {
		family = unix.AF_INET6
	}
	fd, err := unix.Socket(family, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.IPPROTO_UDP)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Close(fd) })
	if err := unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{Sec: 2}); err != nil {
		t.Fatal(err)
	}
	return fd
}

func captureOwnedUDP(t *testing.T, fd, port int, ipv6 bool) {
	t.Helper()
	buf := make([]byte, 65536)
	for deadline := time.Now().Add(2 * time.Second); time.Now().Before(deadline); {
		n, _, err := unix.Recvfrom(fd, buf, 0)
		if err != nil {
			t.Fatal(err)
		}
		offset := 0
		if !ipv6 {
			if n < 20 || buf[9] != unix.IPPROTO_UDP {
				continue
			}
			offset = int(buf[0]&15) * 4
		}
		if n >= offset+8 && int(binary.BigEndian.Uint16(buf[offset+2:offset+4])) == port {
			if n != offset+8+countedPayloadSize {
				t.Fatalf("captured packet size %d, expected IP/UDP plus %d payload", n, countedPayloadSize)
			}
			return
		}
	}
	t.Fatal("owned datagram was not captured")
}

func TestBPFCounterUDPDirectionAndFamily(t *testing.T) {
	for _, network := range []string{"udp4", "udp6"} {
		for _, ingress := range []bool{false, true} {
			name := network + "/egress"
			if ingress {
				name = network + "/ingress"
			}
			t.Run(name, func(t *testing.T) {
				counter := loopbackCounter(t)
				ipv6 := network == "udp6"
				ip := net.ParseIP("127.0.0.1")
				packetBytes := countedPacketSize
				if ipv6 {
					ip = net.ParseIP("::1")
					packetBytes += 20
				}
				capture := captureUDPFamily(t, ipv6)
				server, err := net.ListenUDP(network, &net.UDPAddr{IP: ip})
				if err != nil {
					t.Fatal(err)
				}
				defer server.Close()
				client, err := net.DialUDP(network, nil, server.LocalAddr().(*net.UDPAddr))
				if err != nil {
					t.Fatal(err)
				}
				id := uuid.New()
				conn, err := counter.Attach(client, id, ip.String())
				if err != nil {
					_ = client.Close()
					t.Fatal(err)
				}
				defer conn.Close()
				if err := counter.SetLimit(ip.String(), id, 0); err != nil {
					t.Fatal(err)
				}
				if err := counter.SetExecLimit(id, 0); err != nil {
					t.Fatal(err)
				}
				receiver := server
				write := func(data []byte) error { _, err := conn.Write(data); return err }
				if ingress {
					receiver = client
					write = func(data []byte) error {
						_, err := server.WriteToUDP(data, client.LocalAddr().(*net.UDPAddr))
						return err
					}
				}
				received := receiveAll(receiver)
				for range countedDatagrams {
					if err := write(make([]byte, countedPayloadSize)); err != nil {
						t.Fatal(err)
					}
				}
				got := <-received
				want := initialBurst / packetBytes
				if got != want {
					t.Fatalf("zero-rate initial burst delivered %d packets, expected %d at %d skb bytes", got, want, packetBytes)
				}
				captureOwnedUDP(t, capture, receiver.LocalAddr().(*net.UDPAddr).Port, ipv6)
				address := netip.MustParseAddr(ip.String()).As16()
				var destination, executor countTbState
				if err := counter.objs.PacketSizeMap.Lookup(&countDebugletKey{Uuid: [16]byte(id), Ipv6: address}, &destination); err != nil {
					t.Fatal(err)
				}
				if err := counter.objs.ExecPacketSizeMap.Lookup(&countExecKey{Uuid: [16]byte(id)}, &executor); err != nil {
					t.Fatal(err)
				}
				remaining := uint64(initialBurst - got*packetBytes)
				if destination.Tokens != remaining || executor.Tokens != remaining {
					t.Fatalf("bucket charge destination=%d executor=%d, expected %d", destination.Tokens, executor.Tokens, remaining)
				}
				// A larger rate reuses the existing bucket, including its timestamp.
				if err := counter.SetLimit(ip.String(), id, bitrate.Gigabit); err != nil {
					t.Fatal(err)
				}
				if err := counter.SetExecLimit(id, bitrate.Gigabit); err != nil {
					t.Fatal(err)
				}
				received = receiveAll(receiver)
				for range 2 {
					if err := write(make([]byte, countedPayloadSize)); err != nil {
						t.Fatal(err)
					}
				}
				if got := <-received; got != 2 {
					t.Fatalf("increased cap delivered %d/2", got)
				}
				if err := counter.SetLimit(ip.String(), id, 0); err != nil {
					t.Fatal(err)
				}
				if err := counter.SetExecLimit(id, 0); err != nil {
					t.Fatal(err)
				}
				if err := counter.objs.PacketSizeMap.Lookup(&countDebugletKey{Uuid: [16]byte(id), Ipv6: address}, &destination); err != nil {
					t.Fatal(err)
				}
				if err := counter.objs.ExecPacketSizeMap.Lookup(&countExecKey{Uuid: [16]byte(id)}, &executor); err != nil {
					t.Fatal(err)
				}
				afterReduction := int(min(destination.Tokens, executor.Tokens)) / packetBytes
				received = receiveAll(receiver)
				for range countedDatagrams {
					if err := write(make([]byte, countedPayloadSize)); err != nil {
						t.Fatal(err)
					}
				}
				if got := <-received; got != afterReduction {
					t.Fatalf("reduced cap delivered %d, retained bucket permits %d", got, afterReduction)
				}
				t.Logf("captured %s; zero-rate initial burst=%d, exact bucket remainder=%d, increased-cap=2/2, reduced-cap=%d", name, want, remaining, afterReduction)
			})
		}
	}
}
