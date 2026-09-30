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
	"strconv"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/netsec-ethz/debuglet/internal/executor/debuglet/netpolicy"
	"github.com/netsec-ethz/debuglet/internal/executor/debuglet/socket"
	"github.com/netsec-ethz/debuglet/internal/executor/debuglet/wasm/hostconn"
	"github.com/netsec-ethz/debuglet/internal/executor/tagger/tesla"
)

var smErrMark = errors.New("socket mark refused")

// smMark is one SetSocketMark call: the socket and, at that moment, whether it
// had a peer (nil peerErr means it was already connected), whether it had a
// local port, and whether it was already listening.
type smMark struct {
	fd        int
	peerErr   error
	bound     bool
	listening bool
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
	bound := false
	switch local, _ := syscall.Getsockname(fd); sa := local.(type) {
	case *syscall.SockaddrInet4:
		bound = sa.Port != 0
	case *syscall.SockaddrInet6:
		bound = sa.Port != 0
	}
	accepting, _ := syscall.GetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_ACCEPTCONN)
	s.mu.Lock()
	s.marks = append(s.marks, smMark{fd: fd, peerErr: peerErr, bound: bound, listening: accepting == 1})
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

// smListenControl is the listen control the executor passes to the
// PortManager for a run's listeners: it marks the socket through the same
// hostconn.MarkSocket the dialer uses.
func smListenControl(tg *smTagger) func(network, address string, c syscall.RawConn) error {
	return func(_, _ string, c syscall.RawConn) error { return hostconn.MarkSocket(c, tg) }
}

// smPortManager returns a PortManager with one port free for both TCP and
// UDP, attached to env so that a refused install releases it.
func smPortManager(t *testing.T, env *WasmEnv) (*socket.PortManager, int) {
	t.Helper()
	port := 0
	for port == 0 {
		free, err := net.ListenTCP("tcp", &net.TCPAddr{})
		if err != nil {
			t.Fatal(err)
		}
		candidate := free.Addr().(*net.TCPAddr).Port
		if err := free.Close(); err != nil {
			t.Fatal(err)
		}
		if udp, err := net.ListenUDP("udp", &net.UDPAddr{Port: candidate}); err == nil {
			udp.Close()
			port = candidate
		}
	}
	pm, err := socket.NewPortManager("127.0.0.1", strconv.Itoa(port))
	if err != nil {
		t.Fatal(err)
	}
	env.PortManager = pm
	return pm, port
}

// smRequireUnbound asserts exactly one mark, made before the socket had a
// local port, so before it could listen or send.
func smRequireUnbound(t *testing.T, tg *smTagger) {
	t.Helper()
	marks := tg.recorded()
	if len(marks) != 1 {
		t.Fatalf("listener marked %d times, want once", len(marks))
	}
	if marks[0].listening {
		t.Fatal("listener marked after listen(): a SYN arriving before the mark is answered with an unmarked SYN-ACK")
	}
	if marks[0].bound {
		t.Fatal("listener marked after bind(): it could already receive and answer")
	}
}

func TestSocketMarkListenerBeforeListen(t *testing.T) {
	tg := &smTagger{}
	env := smLocalEnv(t, tg)
	pm, _ := smPortManager(t, env)
	published := true
	tg.onMark = func(int) { published = env.TcpServer != nil }
	lis, port, addr, err := pm.ListenTCP(smListenControl(tg))
	if err != nil {
		t.Fatalf("ListenTCP: %v", err)
	}
	smRequireUnbound(t, tg)
	if published {
		t.Error("the listener was published before it was marked")
	}
	tg.onMark = nil
	if err := env.InstallTCP(lis, port, addr, nil); err != nil {
		t.Fatalf("InstallTCP: %v", err)
	}
	if got := len(tg.recorded()); got != 1 {
		t.Fatalf("listener marks after install = %d, want the one made at listen time", got)
	}

	// An accepted socket is marked before the guest receives it.
	peer, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), 5*time.Second)
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

func TestSocketMarkUDPListenerBeforeBind(t *testing.T) {
	tg := &smTagger{}
	env := smLocalEnv(t, tg)
	pm, _ := smPortManager(t, env)
	conn, port, addr, err := pm.ListenUDP(smListenControl(tg))
	if err != nil {
		t.Fatalf("ListenUDP: %v", err)
	}
	smRequireUnbound(t, tg)
	if err := env.InstallUDP(conn, port, addr, nil); err != nil {
		t.Fatalf("InstallUDP: %v", err)
	}
	if got := len(tg.recorded()); got != 1 {
		t.Errorf("listener marks after install = %d, want the one made at bind time", got)
	}
}

func TestSocketMarkListenerFailureClosesIt(t *testing.T) {
	for _, proto := range []string{"tcp", "udp"} {
		t.Run(proto, func(t *testing.T) {
			tg := &smTagger{fail: smErrMark}
			env := smLocalEnv(t, tg)
			pm, port := smPortManager(t, env)
			var err error
			if proto == "tcp" {
				var lis *net.TCPListener
				lis, _, _, err = pm.ListenTCP(smListenControl(tg))
				if lis != nil {
					lis.Close()
				}
			} else {
				var conn *net.UDPConn
				conn, _, _, err = pm.ListenUDP(smListenControl(tg))
				if conn != nil {
					conn.Close()
				}
			}
			if !errors.Is(err, smErrMark) {
				t.Fatalf("listen = %v, want the mark failure", err)
			}
			if got := len(tg.recorded()); got != 1 {
				t.Errorf("mark attempts = %d, want 1 (a refused mark does not try another port)", got)
			}
			if env.TcpServer != nil || env.UdpServer != nil {
				t.Error("an unmarked listener was published")
			}
			// The port was not allocated and the unmarked socket is closed:
			// an unmarked listen on the same port succeeds.
			if proto == "tcp" {
				lis, got, _, err := pm.ListenTCP(nil)
				if err != nil {
					t.Fatalf("port %d still held after the refused mark: %v", port, err)
				}
				lis.Close()
				if got != port {
					t.Errorf("port = %d, want %d", got, port)
				}
			} else {
				conn, got, _, err := pm.ListenUDP(nil)
				if err != nil {
					t.Fatalf("port %d still held after the refused mark: %v", port, err)
				}
				conn.Close()
				if got != port {
					t.Errorf("port = %d, want %d", got, port)
				}
			}
		})
	}
}
