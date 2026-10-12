// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

//go:build linux && counter_matrix

package ebpf

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"runtime"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/google/uuid"
	"github.com/netsec-ethz/debuglet/internal/bitrate"
	"golang.org/x/sys/unix"
)

func isolatedCounterMatrix(t *testing.T) {
	t.Helper()
	if os.Getenv("DEBUGLET_ISOLATED_COUNTER_MATRIX") != "yes" {
		t.Fatal("requires the explicitly isolated kernel fixture")
	}
	if _, err := os.Stat("/.dockerenv"); err != nil {
		t.Fatal("interface mutation is restricted to the isolated container")
	}
}

func matrixCommand(t *testing.T, command string, args ...string) {
	t.Helper()
	if out, err := exec.Command(command, args...).CombinedOutput(); err != nil {
		t.Fatalf("%s %v: %v: %s", command, args, err, out)
	}
}

// ethtool_value and ifreq are the Linux SIOCETHTOOL ABI. Only the fixture's
// private loopback is changed, and every feature is restored before return.
func matrixOffload(iface string, command, value uint32) (uint32, error) {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return 0, err
	}
	defer unix.Close(fd)
	data := struct{ Command, Value uint32 }{command, value}
	request := struct {
		Name [16]byte
		Data unsafe.Pointer
		Pad  [16]byte
	}{Data: unsafe.Pointer(&data)}
	copy(request.Name[:], iface)
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), unix.SIOCETHTOOL, uintptr(unsafe.Pointer(&request)))
	runtime.KeepAlive(&data)
	runtime.KeepAlive(&request)
	if errno != 0 {
		return 0, errno
	}
	return data.Value, nil
}

type matrixCapture struct {
	Packets, Bytes, Largest, SYN int
	Error                        string
}

func matrixPacketCapture(t *testing.T, iface string, protocol uint8, port int) <-chan matrixCapture {
	t.Helper()
	device, err := net.InterfaceByName(iface)
	if err != nil {
		t.Fatal(err)
	}
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, int(uint16(unix.ETH_P_ALL)<<8))
	if err != nil {
		t.Fatal(err)
	}
	if err := unix.Bind(fd, &unix.SockaddrLinklayer{Ifindex: device.Index, Protocol: uint16(unix.ETH_P_ALL) << 8}); err != nil {
		_ = unix.Close(fd)
		t.Fatal(err)
	}
	if err := unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{Usec: 500000}); err != nil {
		t.Fatal(err)
	}
	result := make(chan matrixCapture, 1)
	go func() {
		defer unix.Close(fd)
		var observed matrixCapture
		data := make([]byte, 131072)
		for {
			n, from, err := unix.Recvfrom(fd, data, 0)
			if errors.Is(err, unix.EINTR) {
				continue
			}
			if err != nil {
				if !errors.Is(err, unix.EAGAIN) && !errors.Is(err, unix.EWOULDBLOCK) {
					observed.Error = err.Error()
				}
				result <- observed
				return
			}
			address, ok := from.(*unix.SockaddrLinklayer)
			if !ok || address.Pkttype != unix.PACKET_OUTGOING || n < 34 || data[12] != 8 || data[13] != 0 || data[23] != protocol {
				continue
			}
			offset := 14 + int(data[14]&15)*4
			if n < offset+20 || int(binary.BigEndian.Uint16(data[offset:offset+2])) != port && int(binary.BigEndian.Uint16(data[offset+2:offset+4])) != port {
				continue
			}
			observed.Packets++
			observed.Bytes += n
			observed.Largest = max(observed.Largest, n)
			if protocol == unix.IPPROTO_TCP && data[offset+13]&2 != 0 {
				observed.SYN++
			}
		}
	}()
	return result
}

func matrixBuckets(t *testing.T, counter *BpfCount, id uuid.UUID, ip string) (countTbState, countTbState) {
	t.Helper()
	var destination, executor countTbState
	key := countDebugletKey{Uuid: [16]byte(id), Ipv6: netip.MustParseAddr(ip).As16()}
	if err := counter.objs.PacketSizeMap.Lookup(&key, &destination); err != nil {
		t.Fatal(err)
	}
	if err := counter.objs.ExecPacketSizeMap.Lookup(&countExecKey{Uuid: [16]byte(id)}, &executor); err != nil {
		t.Fatal(err)
	}
	return destination, executor
}

func TestCounterMatrixSustainedRates(t *testing.T) {
	isolatedCounterMatrix(t)
	for _, bytesPerSecond := range []uint64{5000, 200000} {
		t.Run(fmt.Sprint(bytesPerSecond), func(t *testing.T) {
			counter := loopbackCounter(t)
			server, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if err != nil {
				t.Fatal(err)
			}
			defer server.Close()
			client, err := net.DialUDP("udp4", nil, server.LocalAddr().(*net.UDPAddr))
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			id := uuid.New()
			conn, err := counter.Attach(client, id, "127.0.0.1")
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			rate := bitrate.Bitrate(bytesPerSecond * 8)
			if err := counter.SetLimit("127.0.0.1", id, rate); err != nil {
				t.Fatal(err)
			}
			if err := counter.SetExecLimit(id, rate); err != nil {
				t.Fatal(err)
			}
			start := monotonicCounterTime(t)
			state := countTbState{T_last: start}
			key := countDebugletKey{Uuid: [16]byte(id), Ipv6: netip.MustParseAddr("127.0.0.1").As16()}
			if err := counter.objs.PacketSizeMap.Update(&key, &state, ebpf.UpdateAny); err != nil {
				t.Fatal(err)
			}
			if err := counter.objs.ExecPacketSizeMap.Update(&countExecKey{Uuid: [16]byte(id)}, &state, ebpf.UpdateAny); err != nil {
				t.Fatal(err)
			}
			received := receiveAll(server)
			ticker := time.NewTicker(time.Millisecond)
			defer ticker.Stop()
			deadline := time.NewTimer(2 * time.Second)
			defer deadline.Stop()
			sent := 0
		loop:
			for {
				select {
				case <-ticker.C:
					if _, err := conn.Write(make([]byte, 1000)); err != nil {
						t.Fatal(err)
					}
					sent++
				case <-deadline.C:
					break loop
				}
			}
			elapsed := monotonicCounterTime(t) - start
			got := <-received
			upper := int(bytesPerSecond * elapsed / uint64(time.Second) / 1042)
			if got > upper || got < upper*3/4 {
				t.Fatalf("rate=%d elapsed=%dns sent=%d delivered=%d expected75%%..100%% of%d", bytesPerSecond, elapsed, sent, got, upper)
			}
			t.Logf("exhausted initial bucket: rate=%d B/s elapsed=%dns sent=%d delivered=%d skb_bytes=%d bound=%d", bytesPerSecond, elapsed, sent, got, got*1042, bytesPerSecond*elapsed/uint64(time.Second))
		})
	}
}

func TestCounterMatrixRouteChange(t *testing.T) {
	isolatedCounterMatrix(t)
	for _, name := range []string{"dbgcounta", "dbgcountb"} {
		matrixCommand(t, "ip", "link", "add", name, "type", "dummy")
		t.Cleanup(func() { _ = exec.Command("ip", "link", "del", name).Run() })
		matrixCommand(t, "ip", "link", "set", name, "up")
	}
	matrixCommand(t, "ip", "addr", "add", "198.18.0.10/32", "dev", "dbgcounta")
	matrixCommand(t, "ip", "route", "add", "198.18.0.20/32", "dev", "dbgcounta", "src", "198.18.0.10")
	iface, err := net.InterfaceByName("dbgcounta")
	if err != nil {
		t.Fatal(err)
	}
	counter, err := NewBPFCount(iface)
	if err != nil {
		t.Fatal(err)
	}
	defer counter.Close()
	client, err := net.DialUDP("udp4", &net.UDPAddr{IP: net.ParseIP("198.18.0.10")}, &net.UDPAddr{IP: net.ParseIP("198.18.0.20"), Port: 23491})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	id := uuid.New()
	conn, err := counter.Attach(client, id, "198.18.0.20")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := counter.SetLimit("198.18.0.20", id, 0); err != nil {
		t.Fatal(err)
	}
	if err := counter.SetExecLimit(id, 0); err != nil {
		t.Fatal(err)
	}
	first := matrixPacketCapture(t, "dbgcounta", unix.IPPROTO_UDP, 23491)
	for range 100 {
		if _, err := conn.Write(make([]byte, countedPayloadSize)); err != nil {
			t.Fatal(err)
		}
	}
	a := <-first
	d, e := matrixBuckets(t, counter, id, "198.18.0.20")
	if a.Packets != 45 || d.Tokens != 646 || e.Tokens != 646 {
		t.Fatalf("first route capture=%+v destination=%d executor=%d", a, d.Tokens, e.Tokens)
	}
	matrixCommand(t, "ip", "route", "replace", "198.18.0.20/32", "dev", "dbgcountb", "src", "198.18.0.10")
	second := matrixPacketCapture(t, "dbgcountb", unix.IPPROTO_UDP, 23491)
	for range 100 {
		if _, err := conn.Write(make([]byte, countedPayloadSize)); err != nil {
			t.Fatal(err)
		}
	}
	b := <-second
	afterD, afterE := matrixBuckets(t, counter, id, "198.18.0.20")
	if b.Packets != 100 || afterD.Tokens != d.Tokens || afterE.Tokens != e.Tokens {
		t.Fatalf("changed route capture=%+v balances=%d/%d", b, afterD.Tokens, afterE.Tokens)
	}
	if counter.AttachmentState() != "present" {
		t.Fatal("original attachment unexpectedly missing")
	}
	t.Logf("active route moved between owned dummy interfaces: charged route=%+v; uninstrumented route=%+v; attachment still present; remaining=%d", a, b, d.Tokens)
}

func matrixTCPPair(t *testing.T, mss int) (*net.TCPConn, *net.TCPConn, int) {
	t.Helper()
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	dialer := net.Dialer{Timeout: time.Second}
	if mss > 0 {
		dialer.Control = func(_, _ string, raw syscall.RawConn) error {
			var setErr error
			err := raw.Control(func(fd uintptr) { setErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_MAXSEG, mss) })
			if err != nil {
				return err
			}
			return setErr
		}
	}
	dialed, err := dialer.Dial("tcp4", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	client := dialed.(*net.TCPConn)
	t.Cleanup(func() { _ = client.Close() })
	server, err := listener.AcceptTCP()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Close() })
	return client, server, listener.Addr().(*net.TCPAddr).Port
}

func matrixTCPInfo(t *testing.T, client *net.TCPConn) *unix.TCPInfo {
	t.Helper()
	raw, err := client.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var info *unix.TCPInfo
	var socketErr error
	if err := raw.Control(func(fd uintptr) { info, socketErr = unix.GetsockoptTCPInfo(int(fd), unix.IPPROTO_TCP, unix.TCP_INFO) }); err != nil {
		t.Fatal(err)
	}
	if socketErr != nil {
		t.Fatal(socketErr)
	}
	return info
}

func TestCounterMatrixRetransmissions(t *testing.T) {
	isolatedCounterMatrix(t)
	counter := loopbackCounter(t)
	client, server, _ := matrixTCPPair(t, 0)
	id := uuid.New()
	conn, err := counter.Attach(client, id, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := counter.SetLimit("127.0.0.1", id, 0); err != nil {
		t.Fatal(err)
	}
	if err := counter.SetExecLimit(id, 0); err != nil {
		t.Fatal(err)
	}
	matrixCommand(t, "tc", "qdisc", "add", "dev", "lo", "root", "netem", "loss", "100%")
	t.Cleanup(func() { _ = exec.Command("tc", "qdisc", "del", "dev", "lo", "root").Run() })
	before := matrixTCPInfo(t, client).Total_retrans
	if _, err := conn.Write(make([]byte, 1024)); err != nil {
		t.Fatal(err)
	}
	d, e := matrixBuckets(t, counter, id, "127.0.0.1")
	deadline := time.NewTimer(2 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	var info *unix.TCPInfo
loop:
	for {
		select {
		case <-ticker.C:
			info = matrixTCPInfo(t, client)
			if info.Total_retrans > before {
				break loop
			}
		case <-deadline.C:
			t.Fatal("no retransmission within fixture deadline")
		}
	}
	afterD, afterE := matrixBuckets(t, counter, id, "127.0.0.1")
	if afterD.Tokens > d.Tokens-1024 || afterE.Tokens > e.Tokens-1024 {
		t.Fatalf("retransmission not charged: before=%d/%d after=%d/%d", d.Tokens, e.Tokens, afterD.Tokens, afterE.Tokens)
	}
	matrixCommand(t, "tc", "qdisc", "del", "dev", "lo", "root")
	_ = server.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := io.ReadFull(server, make([]byte, 1024)); err != nil {
		t.Fatal(err)
	}
	t.Logf("TCP retransmissions=%d; original+retry socket-buffer charge=%d/%d; payload delivered after owned qdisc loss removed", info.Total_retrans-before, initialBurst-afterD.Tokens, initialBurst-afterE.Tokens)
}

func TestCounterMatrixOffloads(t *testing.T) {
	isolatedCounterMatrix(t)
	for _, enabled := range []uint32{0, 1} {
		t.Run(fmt.Sprint(enabled), func(t *testing.T) {
			for _, feature := range []struct {
				name     string
				get, set uint32
			}{{"GSO", 0x23, 0x24}, {"GRO", 0x2b, 0x2c}} {
				old, err := matrixOffload("lo", feature.get, 0)
				if err != nil {
					t.Fatalf("read%s: %v", feature.name, err)
				}
				if _, err := matrixOffload("lo", feature.set, enabled); err != nil {
					t.Fatalf("set%s: %v", feature.name, err)
				}
				t.Cleanup(func() {
					if _, err := matrixOffload("lo", feature.set, old); err != nil {
						t.Error(err)
					}
					if restored, err := matrixOffload("lo", feature.get, 0); err != nil || restored != old {
						t.Errorf("restore %s: value=%d want=%d err=%v", feature.name, restored, old, err)
					}
				})
				got, err := matrixOffload("lo", feature.get, 0)
				if err != nil || got != enabled {
					t.Fatalf("%s=%d want%d err=%v", feature.name, got, enabled, err)
				}
			}
			counter := loopbackCounter(t)
			client, server, port := matrixTCPPair(t, 1400)
			id := uuid.New()
			conn, err := counter.Attach(client, id, "127.0.0.1")
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			if err := counter.SetLimit("127.0.0.1", id, bitrate.Gigabit); err != nil {
				t.Fatal(err)
			}
			if err := counter.SetExecLimit(id, bitrate.Gigabit); err != nil {
				t.Fatal(err)
			}
			capture := matrixPacketCapture(t, "lo", unix.IPPROTO_TCP, port)
			_ = conn.SetDeadline(time.Now().Add(6 * time.Second))
			_ = server.SetDeadline(time.Now().Add(6 * time.Second))
			payload := bytes.Repeat([]byte{17}, 1024*1024)
			written := make(chan error, 1)
			go func() { _, err := conn.Write(payload); written <- err }()
			got := make([]byte, len(payload))
			n, readErr := io.ReadFull(server, got)
			writeErr := <-written
			observed := <-capture
			verdicts, dropBytes, dropErr := counter.DropTotals()
			if readErr != nil || writeErr != nil || !bytes.Equal(got, payload) {
				t.Fatalf("offloads=%d read=%d err=%v write=%v capture=%+v drop_verdicts=%v drop_bytes=%v drop_error=%v", enabled, n, readErr, writeErr, observed, verdicts, dropBytes, dropErr)
			}
			if observed.Packets == 0 || observed.Error != "" {
				t.Fatalf("missing packet capture: %+v", observed)
			}
			info := matrixTCPInfo(t, client)
			t.Logf("offloads=%d payload=%d captured=%+v snd_mss=%d retransmissions=%d tcp_bytes_sent=%d drop_verdicts=%v drop_bytes=%v", enabled, n, observed, info.Snd_mss, info.Total_retrans, info.Bytes_sent, verdicts, dropBytes)
		})
	}
}
