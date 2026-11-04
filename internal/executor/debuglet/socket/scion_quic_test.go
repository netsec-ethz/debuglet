// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package socket

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/netsec-ethz/scion-apps/pkg/pan"
	"github.com/quic-go/quic-go"
)

func TestSCIONQUICCertificateAndFrames(t *testing.T) {
	certificate, pin, err := scionQUICCertificate()
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(certificate.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	config, err := scionQUICClientTLS(pin)
	if err != nil {
		t.Fatal(err)
	}
	if err := config.VerifyConnection(tls.ConnectionState{PeerCertificates: []*x509.Certificate{leaf}}); err != nil {
		t.Fatal(err)
	}
	bad, err := scionQUICClientTLS(strings.Repeat("00", 32))
	if err != nil {
		t.Fatal(err)
	}
	if err := bad.VerifyConnection(tls.ConnectionState{PeerCertificates: []*x509.Certificate{leaf}}); !errors.Is(err, ErrSCIONQUICCertificate) {
		t.Fatalf("wrong pin accepted: %v", err)
	}
	if _, err := scionQUICClientTLS("missing"); !errors.Is(err, ErrSCIONQUICCertificate) {
		t.Fatalf("malformed pin: %v", err)
	}
	for _, input := range [][]byte{nil, []byte("echo"), bytes.Repeat([]byte{'x'}, 4096)} {
		var frame bytes.Buffer
		if err := writeSCIONQUICFrame(&frame, input); err != nil {
			t.Fatal(err)
		}
		output, err := readSCIONQUICFrame(&frame)
		if err != nil || !bytes.Equal(output, input) {
			t.Fatalf("frame = %q, %v", output, err)
		}
	}
	if _, err := readSCIONQUICFrame(bytes.NewReader([]byte{0, 0, 0x10, 1})); err == nil {
		t.Fatal("oversized frame accepted")
	}
}

// This fixture exercises real QUIC and TLS over local UDP. The PAN adapter
// supplies same-AS SCION addresses; cross-AS forwarding is tested separately.
type localQUICPAN struct{ net.PacketConn }

func (c *localQUICPAN) LocalAddr() net.Addr { return localQUICAddress(c.PacketConn.LocalAddr()) }
func localQUICAddress(addr net.Addr) pan.UDPAddr {
	a := addr.(*net.UDPAddr).AddrPort()
	return pan.UDPAddr{IA: 1, IP: a.Addr(), Port: a.Port()}
}
func (c *localQUICPAN) ReadFromVia(b []byte) (int, pan.UDPAddr, *pan.Path, error) {
	n, addr, err := c.PacketConn.ReadFrom(b)
	if err != nil {
		return n, pan.UDPAddr{}, nil, err
	}
	return n, localQUICAddress(addr), nil, nil
}
func (c *localQUICPAN) WriteToVia(b []byte, addr pan.UDPAddr, _ *pan.Path) (int, error) {
	return c.PacketConn.WriteTo(b, net.UDPAddrFromAddrPort(netip.AddrPortFrom(addr.IP, addr.Port)))
}
func newLocalQUICPAN(t *testing.T) *localQUICPAN {
	t.Helper()
	conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return &localQUICPAN{conn}
}

func TestSCIONQUICAccountedEcho(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var received, sent atomic.Int64
	hooks := SCIONQUICHooks{Admit: func(context.Context, pan.UDPAddr) error { return nil }, Account: func(_ context.Context, _ pan.UDPAddr, out bool, n int) error {
		if out {
			sent.Add(int64(n))
		} else {
			received.Add(int64(n))
		}
		return nil
	}}
	server, err := NewSCIONQUICEcho(ctx, newLocalQUICPAN(t), hooks)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	remote, err := pan.ParseUDPAddr(server.Address())
	if err != nil {
		t.Fatal(err)
	}
	packet := newSCIONQUICPacketConn(ctx, newLocalQUICPAN(t), hooks)
	packet.target = &remote
	transport := &quic.Transport{Conn: packet}
	defer func() { _ = packet.Close(); _ = transport.Close() }()
	tlsConfig, err := scionQUICClientTLS(server.CertificateSHA256())
	if err != nil {
		t.Fatal(err)
	}
	connection, err := transport.Dial(ctx, remote, tlsConfig, scionQUICConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer connection.CloseWithError(0, "test complete")
	stream, err := connection.OpenStreamSync(ctx)
	if err != nil {
		t.Fatal(err)
	}
	deadline, _ := ctx.Deadline()
	_ = stream.SetDeadline(deadline)
	payload := []byte("authenticated SCION echo")
	if err := writeSCIONQUICFrame(stream, payload); err != nil {
		t.Fatal(err)
	}
	got, err := readSCIONQUICFrame(stream)
	if err != nil || !bytes.Equal(got, payload) {
		t.Fatalf("echo %q: %v", got, err)
	}
	if _, err := stream.Write([]byte{1}); err != nil {
		t.Fatal(err)
	}
	var ack [1]byte
	if _, err := io.ReadFull(stream, ack[:]); err != nil || ack[0] != 1 {
		t.Fatalf("confirmation %v: %v", ack, err)
	}
	if sent.Load() <= int64(2*len(payload)) || received.Load() <= int64(2*len(payload)) {
		t.Fatalf("encrypted transport not accounted: sent=%d received=%d", sent.Load(), received.Load())
	}
}

func TestSCIONQUICPacketAdmissionAndExpiry(t *testing.T) {
	ctx := context.Background()
	denied := errors.New("budget denied")
	hooks := SCIONQUICHooks{Admit: func(context.Context, pan.UDPAddr) error { return nil }, Account: func(context.Context, pan.UDPAddr, bool, int) error { return denied }}
	packet := newSCIONQUICPacketConn(ctx, newLocalQUICPAN(t), hooks)
	defer packet.Close()
	peer := pan.UDPAddr{IA: 1, IP: netip.MustParseAddr("127.0.0.1"), Port: 1234}
	packet.target = &peer
	if _, err := packet.WriteTo([]byte("unbilled"), peer); !errors.Is(err, denied) {
		t.Fatalf("denied accounting: %v", err)
	}
	peer.IA = 2
	packet.target = &peer
	packet.path = &pan.Path{Source: 1, Destination: 2, Expiry: time.Now().Add(-time.Second)}
	if _, err := packet.WriteTo([]byte("expired"), peer); !errors.Is(err, ErrSCIONPathUnavailable) {
		t.Fatalf("expired path: %v", err)
	}
}

func TestSCIONQUICCloseCancelsAccounting(t *testing.T) {
	entered := make(chan struct{})
	hooks := SCIONQUICHooks{
		Admit: func(context.Context, pan.UDPAddr) error { return nil },
		Account: func(ctx context.Context, _ pan.UDPAddr, _ bool, _ int) error {
			close(entered)
			<-ctx.Done()
			return context.Cause(ctx)
		},
	}
	packet := newSCIONQUICPacketConn(context.Background(), newLocalQUICPAN(t), hooks)
	peer := pan.UDPAddr{IA: 1, IP: netip.MustParseAddr("127.0.0.1"), Port: 1234}
	packet.target = &peer
	completed := make(chan error, 1)
	go func() { _, err := packet.WriteTo([]byte("pending"), peer); completed <- err }()
	<-entered
	if err := packet.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-completed:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("close did not cancel accounting: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("accounting remained blocked after close")
	}
}
