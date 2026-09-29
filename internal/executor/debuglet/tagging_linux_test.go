// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

//go:build linux

package debuglet

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/netsec-ethz/debuglet/internal/executor/debuglet/netpolicy"
	"github.com/netsec-ethz/debuglet/internal/executor/debuglet/socket"
	"github.com/netsec-ethz/debuglet/internal/executor/scheduler"
	"github.com/netsec-ethz/debuglet/internal/executor/tagger"
	"github.com/netsec-ethz/debuglet/internal/executor/tagger/ebpf"
	"github.com/netsec-ethz/debuglet/internal/executor/tagger/tesla"
)

func taggingSchedule(t *testing.T) *tesla.KeySchedule {
	t.Helper()
	schedule, err := tesla.NewKeySchedule(tesla.Config{Seed: bytes.Repeat([]byte{0x73}, 32), Delay: 10 * time.Second, ChainLength: 64})
	if err != nil {
		t.Fatal(err)
	}
	return schedule
}

// freePorts returns a pool of two consecutive ports that were free a moment
// ago, for both TCP and UDP.
func freePorts(t *testing.T) string {
	t.Helper()
	for range 20 {
		l, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		port := l.Addr().(*net.TCPAddr).Port
		_ = l.Close()
		if port < 65535 {
			return fmt.Sprintf("%d-%d", port, port+1)
		}
	}
	t.Fatal("no free port")
	return ""
}

// A run whose kernel tagger loaded refuses IPv6 destinations with ErrUntagged
// and refuses a listener it would advertise under an IPv6 public host. The
// kernel tagger here is an unattached fixture, so no socket is marked; the
// kernel lane's TestKernelTaggedRunBindsIPv4Only covers the listeners.
func TestEBPFRunRefusesIPv6(t *testing.T) {
	operator, err := netpolicy.Parse(localProfile())
	if err != nil {
		t.Fatal(err)
	}
	ports, err := socket.NewPortManager("2001:db8::7", freePorts(t))
	if err != nil {
		t.Fatal(err)
	}
	policy := scheduler.Policy{Addresses: []string{"::1", "127.0.0.1"}, ListenTCP: true, ListenUDP: true}
	d := newWithBPFTagger(zap.NewNop(), uuid.New(), "transaction", policy, operator, taggingSchedule(t), nil, nil,
		&net.Interface{Index: 17, Name: "fixture"}, ports,
		func(*zap.Logger, *net.Interface, *tesla.KeySchedule, []byte) (*ebpf.BPFTagger, error) {
			return &ebpf.BPFTagger{Attachment: "tcx"}, nil
		})
	// The fixture holds no key map, so its release reports one missing.
	t.Cleanup(func() { _ = d.Close(context.Background()) })
	if want := (tagger.Mode{IPv4: tagger.ModeEBPF, IPv6: tagger.ModeNone, SCION: tagger.ModeNone}); d.Tagging() != want {
		t.Fatalf("tagging %+v, want %+v", d.Tagging(), want)
	}
	if !d.env.Net.RefusesIPv6() {
		t.Fatal("kernel-tagged run admits IPv6")
	}
	for _, transport := range []netpolicy.Transport{netpolicy.TCP, netpolicy.TLS, netpolicy.UDP} {
		if _, err := d.env.Net.AdmitDestination(context.Background(), transport, "[::1]:80"); !errors.Is(err, netpolicy.ErrUntagged) {
			t.Errorf("%s to [::1]: %v, want ErrUntagged", transport, err)
		}
		if _, err := d.env.Net.AdmitDestination(context.Background(), transport, "127.0.0.1:80"); err != nil {
			t.Errorf("%s to 127.0.0.1: %v", transport, err)
		}
	}
	for _, req := range []StartServersReq{{TCP: true}, {UDP: true}} {
		err := d.StartServers(context.Background(), req)
		if !errors.Is(err, netpolicy.ErrUntagged) || !strings.Contains(err.Error(), "2001:db8::7") {
			t.Errorf("listener %+v under an IPv6 public host: %v, want ErrUntagged", req, err)
		}
	}
	if d.env.TcpServer != nil || d.env.UdpServer != nil {
		t.Fatal("a refused listener was installed")
	}
}

// The kernel lane requires this to pass: a run on an interface where the eBPF
// tagger loads gets the kernel mode, refuses IPv6 destinations, and binds its
// listeners to IPv4 only, marked before their first reply, so no IPv6 peer
// can reach them and receive untagged packets.
func TestKernelTaggedRunBindsIPv4Only(t *testing.T) {
	lo, err := net.InterfaceByName("lo")
	if err != nil {
		t.Fatal(err)
	}
	schedule := taggingSchedule(t)
	probe, err := ebpf.NewBPFTagger(zap.NewNop(), lo, schedule, []byte("tagging-probe"))
	if err != nil {
		if strings.Contains(err.Error(), "operation not permitted") {
			t.Skipf("eBPF tagger requires kernel capabilities: %v", err)
		}
		t.Fatal(err)
	}
	if err := probe.Close(); err != nil {
		t.Fatal(err)
	}
	operator, err := netpolicy.Parse(localProfile())
	if err != nil {
		t.Fatal(err)
	}
	ports, err := socket.NewPortManager("127.0.0.1", freePorts(t))
	if err != nil {
		t.Fatal(err)
	}
	policy := scheduler.Policy{Addresses: []string{"::1", "127.0.0.1"}, ListenTCP: true, ListenUDP: true}
	d := New(zap.NewNop(), uuid.New(), "transaction", policy, operator, schedule, nil, nil, lo, ports)
	t.Cleanup(func() {
		if err := d.Close(context.Background()); err != nil {
			t.Error(err)
		}
	})
	if want := (tagger.Mode{IPv4: tagger.ModeEBPF, IPv6: tagger.ModeNone, SCION: tagger.ModeNone}); d.Tagging() != want {
		t.Fatalf("tagging %+v, want %+v", d.Tagging(), want)
	}
	if _, err := d.env.Net.AdmitDestination(context.Background(), netpolicy.TCP, "[::1]:80"); !errors.Is(err, netpolicy.ErrUntagged) {
		t.Fatalf("IPv6 destination: %v, want ErrUntagged", err)
	}
	if err := d.StartServers(context.Background(), StartServersReq{TCP: true, UDP: true}); err != nil {
		t.Fatal(err)
	}
	tcp := d.env.TcpServer.Addr().(*net.TCPAddr)
	udp := d.env.UdpServer.LocalAddr().(*net.UDPAddr)
	if tcp.IP.To4() == nil || udp.IP.To4() == nil {
		t.Fatalf("listeners bound dual-stack: tcp %v udp %v", tcp, udp)
	}
	if conn, err := net.DialTimeout("tcp6", fmt.Sprintf("[::1]:%d", tcp.Port), time.Second); err == nil {
		_ = conn.Close()
		t.Fatal("an IPv6 peer reached the IPv4-only listener")
	}
	conn, err := net.DialTimeout("tcp4", fmt.Sprintf("127.0.0.1:%d", tcp.Port), time.Second)
	if err != nil {
		t.Fatalf("IPv4 peer: %v", err)
	}
	_ = conn.Close()
}
