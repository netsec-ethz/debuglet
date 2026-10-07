// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

//go:build linux

package ebpf

import (
	"bytes"
	"errors"
	"math"
	"net"
	"net/netip"
	"syscall"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/google/uuid"
	"github.com/netsec-ethz/debuglet/internal/executor/debuglet/socket/netutil"
)

type dropReader struct {
	fail     bool
	overflow bool
}

func (r dropReader) Lookup(key, out any) error {
	if r.fail && *key.(*uint32) == 1 {
		return errors.New("map read failed")
	}
	values := *out.(*[]countDropTotals)
	values[0] = countDropTotals{Verdicts: 2, Bytes: 40}
	values[1] = countDropTotals{Verdicts: 3, Bytes: 60}
	if r.overflow {
		values[1].Bytes = math.MaxUint64
	}
	return nil
}

func TestDropObservationsRejectPartialAndOverflow(t *testing.T) {
	verdicts, sizes, err := readDropTotals(dropReader{}, 2)
	if err != nil || verdicts != [2]uint64{5, 5} || sizes != [2]uint64{100, 100} {
		t.Fatalf("per-CPU aggregate %v %v: %v", verdicts, sizes, err)
	}
	for _, r := range []dropReader{{fail: true}, {overflow: true}} {
		verdicts, sizes, err := readDropTotals(r, 2)
		if err == nil || verdicts != [2]uint64{} || sizes != [2]uint64{} {
			t.Fatalf("failed map read exposed partial totals: %v %v %v", verdicts, sizes, err)
		}
	}
	for _, cpus := range []int{0, 65537} {
		if _, _, err := readDropTotals(dropReader{}, cpus); err == nil {
			t.Fatal("unbounded CPU observation")
		}
	}
	if _, _, err := new(BpfCount).DropTotals(); err == nil {
		t.Fatal("uninitialized counter reported known zero")
	}
}

// This exercises the actual TCX program and map against owned loopback UDP
// sockets. The fixture registers each endpoint separately to select which hook
// refuses a datagram; it does not infer enforcement from successful attachment.
func TestKernelCounterDropObservations(t *testing.T) {
	iface, err := net.InterfaceByName("lo")
	if err != nil {
		t.Fatal(err)
	}
	counter, err := NewBPFCount(iface)
	if err != nil {
		for _, errno := range []syscall.Errno{syscall.EPERM, syscall.EACCES, syscall.EINVAL} {
			if errors.Is(err, errno) {
				t.Skipf("counter load requires kernel capabilities: %v", err)
			}
		}
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := counter.Close(); err != nil {
			t.Error(err)
		}
	})
	check := func(wantVerdicts, wantBytes [2]uint64) {
		t.Helper()
		verdicts, sizes, err := counter.DropTotals()
		if err != nil || verdicts != wantVerdicts || sizes != wantBytes {
			t.Fatalf("drop observations = %v/%v, want %v/%v: %v", verdicts, sizes, wantVerdicts, wantBytes, err)
		}
	}
	check([2]uint64{}, [2]uint64{})
	receiver, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer receiver.Close()
	sender, err := net.DialUDP("udp4", nil, receiver.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer sender.Close()
	register := func(conn *net.UDPConn) uuid.UUID {
		t.Helper()
		id := uuid.New()
		raw, err := conn.SyscallConn()
		if err != nil {
			t.Fatal(err)
		}
		var updateErr error
		if err := raw.Control(func(fd uintptr) {
			updateErr = counter.objs.DebugletSkMap.Update(uint32(fd), &countDebugletUuid{Uuid: [16]byte(id)}, ebpf.UpdateAny)
		}); err != nil {
			t.Fatal(err)
		}
		if updateErr != nil {
			t.Fatal(updateErr)
		}
		return id
	}
	allow := func(id uuid.UUID) {
		t.Helper()
		ip := netutil.ToIPv6(netip.MustParseAddr("127.0.0.1"))
		if err := counter.setIPv6Limit(ip, id, 1<<30); err != nil {
			t.Fatal(err)
		}
		if err := counter.SetExecLimit(id, 1<<30); err != nil {
			t.Fatal(err)
		}
	}
	payload := bytes.Repeat([]byte{0x64}, 37)
	send := func(delivered bool) {
		t.Helper()
		if _, err := sender.Write(payload); err != nil {
			t.Fatal(err)
		}
		if err := receiver.SetReadDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
			t.Fatal(err)
		}
		buffer := make([]byte, 128)
		n, err := receiver.Read(buffer)
		if delivered {
			if err != nil || !bytes.Equal(buffer[:n], payload) {
				t.Fatalf("allowed datagram %d: %v", n, err)
			}
			return
		}
		var timeout net.Error
		if !errors.As(err, &timeout) || !timeout.Timeout() {
			t.Fatalf("refused datagram reached receiver: %d %v", n, err)
		}
	}
	sendID := register(sender)
	send(false)                                     // No rate for the sender: an egress drop.
	skbLength := uint64(len(payload) + 14 + 20 + 8) // Ethernet, IPv4 and UDP headers on loopback.
	check([2]uint64{0, 1}, [2]uint64{0, skbLength})
	allow(sendID)
	receiveID := register(receiver)
	send(false) // Sender allowed, receiver has no rate: an ingress drop.
	check([2]uint64{1, 1}, [2]uint64{skbLength, skbLength})
	allow(receiveID)
	send(true)
	check([2]uint64{1, 1}, [2]uint64{skbLength, skbLength})
	t.Logf("owned UDP: ingress and egress each observed one TCX drop, %d skb bytes; accepted traffic added no drops", skbLength)
	if err := counter.attachmentLinks[0].(link.Link).Detach(); err != nil {
		t.Fatal(err)
	}
	if verdicts, sizes, err := counter.DropTotals(); err == nil || verdicts != [2]uint64{} || sizes != [2]uint64{} {
		t.Fatalf("detached counter retained a numeric observation: %v %v %v", verdicts, sizes, err)
	}
}
