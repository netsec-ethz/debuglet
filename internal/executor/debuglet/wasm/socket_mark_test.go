// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package wasm

// Packet attribution of a run's sockets. The tagger marks by socket, so a
// socket must carry its mark before it sends anything: a mark set after
// connect leaves the handshake, and everything queued before it, unattributed.

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/netsec-ethz/debuglet/internal/executor/debuglet/netpolicy"
	"github.com/netsec-ethz/debuglet/internal/executor/debuglet/socket"
	"github.com/netsec-ethz/debuglet/internal/executor/tagger/tesla"
)

var smErrMark = errors.New("socket mark refused")

// smMark is one SetSocketMark call: the socket and whether it had a peer at
// that moment (nil peerErr means it was already connected).
type smMark struct {
	fd      int
	peerErr error
}

// smTagger records every socket it is asked to mark, or refuses them all.
type smTagger struct {
	mu     sync.Mutex
	fail   error
	onMark func(fd int)
	marks  []smMark
}

func (s *smTagger) TagPacket(pkt []byte) ([]byte, error) { return pkt, nil }
func (s *smTagger) Close() error                         { return nil }
func (s *smTagger) Schedule() *tesla.KeySchedule         { return nil }

func (s *smTagger) SetSocketMark(fd int) error {
	_, peerErr := syscall.Getpeername(fd)
	s.mu.Lock()
	s.marks = append(s.marks, smMark{fd: fd, peerErr: peerErr})
	onMark := s.onMark
	s.mu.Unlock()
	if onMark != nil {
		onMark(fd)
	}
	return s.fail
}

func (s *smTagger) recorded() []smMark {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]smMark(nil), s.marks...)
}

// smRequireUnconnected asserts exactly one mark, made while the socket had no
// peer yet.
func smRequireUnconnected(t *testing.T, tg *smTagger) {
	t.Helper()
	marks := tg.recorded()
	if len(marks) != 1 {
		t.Fatalf("socket marked %d times, want once", len(marks))
	}
	if !errors.Is(marks[0].peerErr, syscall.ENOTCONN) {
		t.Fatalf("socket marked with peer state %v, want ENOTCONN (marked before connect)", marks[0].peerErr)
	}
}

func smConnect(t *testing.T, env *WasmEnv, socketType socket.SocketType, addr string) (int32, error) {
	t.Helper()
	mod := newGuestModule(t)
	if !mod.Memory().Write(1024, []byte(addr)) {
		t.Fatal("write guest address")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var handle int32 = -1
	trap := hostTrap(func() { handle = HostConnect(env, socketType)(ctx, mod, 1024, uint32(len(addr))) })
	return handle, trap
}

func smLocalEnv(t *testing.T, tg *smTagger) *WasmEnv {
	t.Helper()
	env := policyEnv(t, localSpec(), netpolicy.Run{Addresses: []string{"127.0.0.1"}, ListenTCP: true})
	env.Tagger = tg
	return env
}

func TestSocketMarkDialedTCPBeforeConnect(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		if conn, err := listener.Accept(); err == nil {
			accepted <- conn
		}
	}()
	defer func() {
		select {
		case conn := <-accepted:
			conn.Close()
		case <-time.After(time.Second):
		}
	}()

	tg := &smTagger{}
	env := smLocalEnv(t, tg)
	if _, trap := smConnect(t, env, socket.SocketTypeTCP, listener.Addr().String()); trap != nil {
		t.Fatalf("connect trapped: %v", trap)
	}
	smRequireUnconnected(t, tg)
}

func TestSocketMarkDialedUDPBeforeFirstSend(t *testing.T) {
	server, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	tg := &smTagger{}
	env := smLocalEnv(t, tg)
	handle, trap := smConnect(t, env, socket.SocketTypeUDP, server.LocalAddr().String())
	if trap != nil {
		t.Fatalf("connect trapped: %v", trap)
	}
	smRequireUnconnected(t, tg)

	sock, err := env.Registry.Get(handle)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sock.Write([]byte("first")); err != nil {
		t.Fatalf("send: %v", err)
	}
	if got := len(tg.recorded()); got != 1 {
		t.Errorf("socket marked %d times after the first send, want once", got)
	}
}

func smSelfSigned(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "127.0.0.1"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, pool
}

func TestSocketMarkTLSBeforeHandshake(t *testing.T) {
	cert, pool := smSelfSigned(t)
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	served := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			served <- err
			return
		}
		defer conn.Close()
		served <- conn.(*tls.Conn).Handshake()
		_, _ = conn.Read(make([]byte, 1))
	}()

	tg := &smTagger{}
	env := smLocalEnv(t, tg)
	env.TlsCfg = &tls.Config{RootCAs: pool}
	handle, trap := smConnect(t, env, socket.SocketTypeTLS, listener.Addr().String())
	if trap != nil {
		t.Fatalf("connect trapped: %v", trap)
	}
	smRequireUnconnected(t, tg)
	if err := <-served; err != nil {
		t.Fatalf("server handshake: %v", err)
	}
	_ = env.Registry.Close(handle)
}

func TestSocketMarkFailureFailsTheDial(t *testing.T) {
	listener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	env := smLocalEnv(t, &smTagger{fail: smErrMark})
	handle, trap := smConnect(t, env, socket.SocketTypeTCP, listener.Addr().String())
	if trap == nil {
		t.Fatalf("connect returned handle %d although the socket could not be marked", handle)
	}
	if !errors.Is(trap, smErrMark) {
		t.Errorf("trap = %v, want the mark failure", trap)
	}
	if err := listener.SetDeadline(time.Now().Add(300 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if conn, err := listener.Accept(); err == nil {
		conn.Close()
		t.Fatal("the target was connected to although the socket could not be marked")
	}
}

func TestSocketMarkListenerBeforePublication(t *testing.T) {
	lis, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	tg := &smTagger{}
	env := smLocalEnv(t, tg)
	published := true
	tg.onMark = func(int) { published = env.TcpServer != nil }
	if err := env.InstallTCP(lis, 0, lis.Addr().String()); err != nil {
		t.Fatalf("InstallTCP: %v", err)
	}
	if got := len(tg.recorded()); got != 1 {
		t.Fatalf("listener marked %d times, want once", got)
	}
	if published {
		t.Error("the listener was published before it was marked")
	}
	tg.onMark = nil

	// An accepted socket is marked before the guest receives it.
	peer, err := net.DialTimeout("tcp", lis.Addr().String(), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var handle int32 = -1
	if trap := hostTrap(func() { handle = HostAcceptTCP(env)(ctx) }); trap != nil {
		t.Fatalf("accept trapped: %v", trap)
	}
	if got := len(tg.recorded()); got != 2 {
		t.Errorf("accepted socket marks = %d, want one more than the listener's", got-1)
	}
	_ = env.Registry.Close(handle)
}

func TestSocketMarkListenerFailureClosesIt(t *testing.T) {
	lis, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer lis.Close()
	env := smLocalEnv(t, &smTagger{fail: smErrMark})
	if err := env.InstallTCP(lis, 0, lis.Addr().String()); !errors.Is(err, smErrMark) {
		t.Fatalf("InstallTCP = %v, want the mark failure", err)
	}
	if env.TcpServer != nil {
		t.Error("an unmarked listener was published")
	}
	if _, err := lis.Accept(); !errors.Is(err, net.ErrClosed) {
		t.Errorf("accept on the unmarked listener = %v, want it closed", err)
	}
}
