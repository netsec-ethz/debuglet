// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

//go:build linux

package ebpf

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strings"
	"syscall"
	"testing"
	"time"

	"go.uber.org/zap"
	"golang.org/x/sys/unix"

	"github.com/netsec-ethz/debuglet/internal/executor/tagger"
	"github.com/netsec-ethz/debuglet/internal/executor/tagger/tesla"
)

// captureSeed fixes the key chain, so a failure is reproducible.
var captureSeed = []byte("capture-test-seed-0123456789abcd")

// captureTagger attaches a tagger for measurementID to iface, skipping the
// test where eBPF is not permitted.
func captureTagger(t *testing.T, iface *net.Interface, ks *tesla.KeySchedule, measurementID []byte) *BPFTagger {
	t.Helper()
	bt, err := NewBPFTagger(zap.NewNop(), iface, ks, measurementID)
	if err != nil {
		if strings.Contains(err.Error(), "operation not permitted") {
			t.Skipf("skipping test: insufficient privileges for eBPF: %v", err)
		}
		t.Fatalf("NewBPFTagger: %v", err)
	}
	t.Cleanup(func() { bt.Close() })
	return bt
}

// captureMark is a socket control hook that marks the socket with bt before
// it is bound or connected, as the executor's listeners and dialer do.
func captureMark(bt *BPFTagger) func(network, address string, c syscall.RawConn) error {
	return func(_, _ string, c syscall.RawConn) error {
		var markErr error
		if err := c.Control(func(fd uintptr) { markErr = bt.SetSocketMark(int(fd)) }); err != nil {
			return err
		}
		return markErr
	}
}

// captureRawTCP returns a raw socket that receives a copy of every IPv4 TCP
// packet arriving on this host, IP header included. On loopback every packet
// sent is also received, so it sees both directions of a connection.
func captureRawTCP(t *testing.T) int {
	t.Helper()
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.IPPROTO_TCP)
	if err != nil {
		t.Fatalf("capture socket: %v", err)
	}
	t.Cleanup(func() { unix.Close(fd) })
	timeout := unix.NsecToTimeval(int64(200 * time.Millisecond))
	if err := unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &timeout); err != nil {
		t.Fatalf("capture timeout: %v", err)
	}
	return fd
}

// captureSegment is one captured IPv4 TCP packet and the fields that identify
// it.
type captureSegment struct {
	pkt          []byte
	sport, dport int
	syn, ack     bool
	payloadLen   int
}

func captureParse(pkt []byte) (captureSegment, bool) {
	if len(pkt) < 20 || pkt[0]>>4 != 4 || pkt[9] != unix.IPPROTO_TCP {
		return captureSegment{}, false
	}
	ihl := int(pkt[0]&0x0f) * 4
	total := int(binary.BigEndian.Uint16(pkt[2:4]))
	if ihl < 20 || total > len(pkt) || total < ihl+20 {
		return captureSegment{}, false
	}
	tcp := pkt[ihl:total]
	doff := int(tcp[12]>>4) * 4
	if doff < 20 || doff > len(tcp) {
		return captureSegment{}, false
	}
	flags := tcp[13]
	return captureSegment{
		pkt:        pkt[:total],
		sport:      int(binary.BigEndian.Uint16(tcp[0:2])),
		dport:      int(binary.BigEndian.Uint16(tcp[2:4])),
		syn:        flags&0x02 != 0,
		ack:        flags&0x10 != 0,
		payloadLen: len(tcp) - doff,
	}, true
}

// captureUntil reads captured packets until match has seen everything it
// wants or the deadline passes.
func captureUntil(t *testing.T, fd int, match func(captureSegment) (done bool)) {
	t.Helper()
	buf := make([]byte, 65536)
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); {
		n, _, err := unix.Recvfrom(fd, buf, 0)
		if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			t.Fatalf("capture: %v", err)
		}
		seg, ok := captureParse(append([]byte(nil), buf[:n]...))
		if ok && match(seg) {
			return
		}
	}
}

// captureVerifies reports whether pkt carries a tag that verifies for
// measurementID under the key of now's epoch.
func captureVerifies(t *testing.T, ks *tesla.KeySchedule, now time.Time, measurementID, pkt []byte) bool {
	t.Helper()
	ok, err := tesla.VerifyTag(ks.CurrentKey(now), 1, measurementID, pkt, tagger.ReadIPID(pkt))
	if err != nil {
		t.Fatalf("VerifyTag: %v", err)
	}
	return ok
}

// TestCaptureTCPTagsVerifyAtReceiver runs a TCP exchange between a listener
// marked before listen() and a dialer marked before connect(), each under its
// own measurement, and verifies the tags of the packets as the receiver sees
// them: the client's SYN, the listener's SYN-ACK, and one data segment each
// way, the server's from the accepted socket, which inherits the listener's
// mark. An unmarked connection is the control.
func TestCaptureTCPTagsVerifyAtReceiver(t *testing.T) {
	now := time.Now()
	ks, err := tesla.NewKeySchedule(tesla.Config{Seed: captureSeed, EpochLength: time.Hour, Epoch: now.Add(-time.Hour)})
	if err != nil {
		t.Fatalf("NewKeySchedule: %v", err)
	}
	lo, err := net.InterfaceByName("lo")
	if err != nil {
		t.Fatalf("InterfaceByName: %v", err)
	}
	clientID := []byte("capture-client-measurement")
	serverID := []byte("capture-server-measurement")
	client := captureTagger(t, lo, ks, clientID)
	server := captureTagger(t, lo, ks, serverID)
	if client.MapKey() == server.MapKey() {
		t.Fatal("client and server measurements share a socket mark")
	}
	fd := captureRawTCP(t)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	lc := net.ListenConfig{Control: captureMark(server)}
	// A plain TCP listener, as the executor's listeners are.
	lc.SetMultipathTCP(false)
	ln, err := lc.Listen(ctx, "tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	serverPort := ln.Addr().(*net.TCPAddr).Port

	request := []byte("request from the dialled socket")
	reply := []byte("reply from the accepted socket")
	served := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			served <- err
			return
		}
		defer conn.Close()
		if _, err := io.ReadFull(conn, make([]byte, len(request))); err != nil {
			served <- err
			return
		}
		_, err = conn.Write(reply)
		served <- err
	}()

	dialer := net.Dialer{Control: captureMark(client)}
	conn, err := dialer.DialContext(ctx, "tcp4", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	clientPort := conn.LocalAddr().(*net.TCPAddr).Port
	if _, err := conn.Write(request); err != nil {
		t.Fatalf("write request: %v", err)
	}
	if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(conn, make([]byte, len(reply))); err != nil {
		t.Fatalf("read reply: %v", err)
	}
	if err := <-served; err != nil {
		t.Fatalf("server: %v", err)
	}

	var syn, synAck, clientData, serverData []byte
	captureUntil(t, fd, func(s captureSegment) bool {
		switch {
		case s.sport == clientPort && s.dport == serverPort && s.syn && !s.ack && syn == nil:
			syn = s.pkt
		case s.sport == serverPort && s.dport == clientPort && s.syn && s.ack && synAck == nil:
			synAck = s.pkt
		case s.sport == clientPort && s.dport == serverPort && s.payloadLen > 0 && clientData == nil:
			clientData = s.pkt
		case s.sport == serverPort && s.dport == clientPort && s.payloadLen > 0 && serverData == nil:
			serverData = s.pkt
		}
		return syn != nil && synAck != nil && clientData != nil && serverData != nil
	})

	for _, c := range []struct {
		what         string
		pkt          []byte
		owner, other []byte
	}{
		{"client SYN", syn, clientID, serverID},
		{"listener SYN-ACK", synAck, serverID, clientID},
		{"client data", clientData, clientID, serverID},
		{"accepted socket data", serverData, serverID, clientID},
	} {
		if c.pkt == nil {
			t.Errorf("%s: not captured", c.what)
			continue
		}
		if !captureVerifies(t, ks, now, c.owner, c.pkt) {
			t.Errorf("%s: tag %04x does not verify under %q", c.what, tagger.ReadIPID(c.pkt), c.owner)
		}
		if captureVerifies(t, ks, now, c.other, c.pkt) {
			t.Errorf("%s: tag %04x also verifies under %q", c.what, tagger.ReadIPID(c.pkt), c.other)
		}
		ihl := int(c.pkt[0]&0x0f) * 4
		if sum := tagger.IPv4Checksum(c.pkt[:ihl]); sum != 0 {
			t.Errorf("%s: IPv4 header checksum does not verify (residue %04x)", c.what, sum)
		}
	}

	// Control: a connection whose sockets carry no mark leaves its SYN
	// untagged, so the verifications above are not a property of every packet.
	plain, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer plain.Close()
	plainPort := plain.Addr().(*net.TCPAddr).Port
	unmarked, err := net.DialTimeout("tcp4", plain.Addr().String(), 5*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer unmarked.Close()
	unmarkedPort := unmarked.LocalAddr().(*net.TCPAddr).Port
	var plainSyn []byte
	captureUntil(t, fd, func(s captureSegment) bool {
		if s.sport == unmarkedPort && s.dport == plainPort && s.syn && !s.ack {
			plainSyn = s.pkt
		}
		return plainSyn != nil
	})
	if plainSyn == nil {
		t.Fatal("control: the unmarked SYN was not captured")
	}
	for _, id := range [][]byte{clientID, serverID} {
		if captureVerifies(t, ks, now, id, plainSyn) {
			t.Errorf("control: the unmarked SYN (IPID %04x) verifies under %q", tagger.ReadIPID(plainSyn), id)
		}
	}
}
