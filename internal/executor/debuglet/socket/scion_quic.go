// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package socket

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/netsec-ethz/scion-apps/pkg/pan"
	"github.com/quic-go/quic-go"
)

const scionQUICALPN = "debuglet-scion-echo/1"
const scionQUICMaxPayload = 4096

var ErrSCIONQUICCertificate = errors.New("SCION server certificate verification failed")

// SCIONQUICHooks admit and account encrypted QUIC datagrams, including
// handshakes, ACKs and retransmissions. Callbacks must be concurrency-safe.
type SCIONQUICHooks struct {
	Admit   func(context.Context, pan.UDPAddr) error
	Account func(context.Context, pan.UDPAddr, bool, int) error
}

// SCIONQUICResult separates confirmed application echo from transport traffic.
type SCIONQUICResult struct {
	Data         []byte
	HandshakeMS  float64
	DurationMS   float64
	Verified     bool
	OutboundSent bool
}

// SCIONQUICEcho owns its supplied listener permanently; it cannot be reused for
// raw datagrams. Close releases both the QUIC transport and the PAN socket.
type SCIONQUICEcho struct {
	packet      *scionQUICPacketConn
	transport   *quic.Transport
	listener    *quic.Listener
	fingerprint string
	done        chan struct{}
	once        sync.Once
	closeErr    error
	workers     sync.WaitGroup
}

func NewSCIONQUICEcho(ctx context.Context, conn pan.ListenConn, hooks SCIONQUICHooks) (*SCIONQUICEcho, error) {
	if conn == nil {
		return nil, errors.New("SCION listener unavailable")
	}
	if err := ctx.Err(); err != nil {
		_ = conn.Close()
		return nil, context.Cause(ctx)
	}
	if err := validateSCIONQUICHooks(hooks); err != nil {
		_ = conn.Close()
		return nil, err
	}
	certificate, fingerprint, err := scionQUICCertificate()
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	packet := newSCIONQUICPacketConn(ctx, conn, hooks)
	transport := &quic.Transport{Conn: packet, VerifySourceAddress: func(net.Addr) bool { return true }}
	listener, err := transport.Listen(&tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{certificate}, NextProtos: []string{scionQUICALPN}}, scionQUICConfig())
	if err != nil {
		_ = packet.Close()
		_ = transport.Close()
		return nil, err
	}
	service := &SCIONQUICEcho{packet: packet, transport: transport, listener: listener, fingerprint: fingerprint, done: make(chan struct{})}
	service.workers.Add(1)
	go service.serve(packet.ctx)
	go func() {
		select {
		case <-ctx.Done():
			_ = service.Close()
		case <-service.done:
		}
	}()
	return service, nil
}

func (s *SCIONQUICEcho) Address() string           { return s.packet.LocalAddr().String() }
func (s *SCIONQUICEcho) CertificateSHA256() string { return s.fingerprint }
func (s *SCIONQUICEcho) Close() error {
	s.once.Do(func() {
		close(s.done)
		s.closeErr = errors.Join(s.packet.Close(), s.listener.Close(), s.transport.Close())
		s.workers.Wait()
	})
	return s.closeErr
}

func (s *SCIONQUICEcho) serve(ctx context.Context) {
	defer s.workers.Done()
	slots := make(chan struct{}, 8)
	for {
		select {
		case slots <- struct{}{}:
		case <-s.done:
			return
		case <-ctx.Done():
			return
		}
		conn, err := s.listener.Accept(ctx)
		if err != nil {
			<-slots
			return
		}
		s.workers.Add(1)
		go func() {
			defer s.workers.Done()
			defer func() { <-slots; s.packet.forget(conn.RemoteAddr()) }()
			defer conn.CloseWithError(0, "echo complete")
			operation, cancel := context.WithTimeout(ctx, 10*time.Second)
			defer cancel()
			stream, err := conn.AcceptStream(operation)
			if err != nil {
				return
			}
			deadline, _ := operation.Deadline()
			_ = stream.SetDeadline(deadline)
			payload, err := readSCIONQUICFrame(stream)
			if err != nil {
				stream.CancelRead(1)
				stream.CancelWrite(1)
				return
			}
			if err := writeSCIONQUICFrame(stream, payload); err != nil {
				stream.CancelWrite(1)
				return
			}
			// An application acknowledgement proves the peer consumed the echo;
			// stream Close alone only queues a FIN and may leave data in flight.
			var ack [1]byte
			if _, err := io.ReadFull(stream, ack[:]); err != nil || ack[0] != 1 {
				return
			}
			if _, err := stream.Write([]byte{1}); err != nil {
				return
			}
			_ = stream.Close()
			select {
			case <-conn.Context().Done():
			case <-operation.Done():
			}
		}()
	}
}

// SCIONQUICExchange authenticates the exact peer certificate SHA-256 digest,
// uses one immutable outbound path and confirms a bounded framed echo. The
// entire operation is limited to ten seconds, including the TLS handshake.
func SCIONQUICExchange(ctx context.Context, local netip.AddrPort, target pan.UDPAddr, path *pan.Path, pin string, payload []byte, hooks SCIONQUICHooks) (result SCIONQUICResult, err error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if len(payload) > scionQUICMaxPayload {
		return result, errors.New("SCION echo payload exceeds 4096 bytes")
	}
	if err := validateSCIONQUICHooks(hooks); err != nil {
		return result, err
	}
	if err := hooks.Admit(ctx, target); err != nil {
		return result, err
	}
	tlsConfig, err := scionQUICClientTLS(pin)
	if err != nil {
		return result, err
	}
	if path != nil && !path.Expiry.After(time.Now()) {
		return result, ErrSCIONPathUnavailable
	}
	conn, err := pan.ListenUDP(ctx, local, &scionQUICNoopReplySelector{})
	if err != nil {
		return result, err
	}
	packet := newSCIONQUICPacketConn(ctx, conn, hooks)
	packet.target, packet.path = &target, path
	transport := &quic.Transport{Conn: packet}
	defer func() { _ = packet.Close(); _ = transport.Close() }()
	started := time.Now()
	defer func() {
		result.OutboundSent = packet.sent.Load()
		result.DurationMS = float64(time.Since(started)) / float64(time.Millisecond)
	}()
	session, err := transport.Dial(ctx, target, tlsConfig, scionQUICConfig())
	if err != nil {
		return result, err
	}
	defer session.CloseWithError(0, "echo complete")
	result.HandshakeMS = float64(time.Since(started)) / float64(time.Millisecond)
	stream, err := session.OpenStreamSync(ctx)
	if err != nil {
		return result, err
	}
	deadline, _ := ctx.Deadline()
	_ = stream.SetDeadline(deadline)
	stop := context.AfterFunc(ctx, func() { stream.CancelRead(1); stream.CancelWrite(1) })
	defer stop()
	if err := writeSCIONQUICFrame(stream, payload); err != nil {
		return result, err
	}
	result.Data, err = readSCIONQUICFrame(stream)
	if err != nil {
		return result, err
	}
	if subtle.ConstantTimeCompare(result.Data, payload) != 1 {
		return result, errors.New("SCION echo payload mismatch")
	}
	if _, err = stream.Write([]byte{1}); err != nil {
		return result, err
	}
	var acknowledged [1]byte
	if _, err = io.ReadFull(stream, acknowledged[:]); err != nil {
		return result, err
	}
	if acknowledged[0] != 1 {
		return result, errors.New("SCION echo acknowledgement mismatch")
	}
	if err = stream.Close(); err != nil {
		return result, err
	}
	result.Verified = true
	return result, nil
}

func validateSCIONQUICHooks(hooks SCIONQUICHooks) error {
	if hooks.Admit == nil || hooks.Account == nil {
		return errors.New("SCION QUIC requires admission and accounting")
	}
	return nil
}

func scionQUICConfig() *quic.Config {
	return &quic.Config{
		HandshakeIdleTimeout: 3 * time.Second, MaxIdleTimeout: 10 * time.Second,
		MaxIncomingStreams: 1, MaxIncomingUniStreams: -1,
		InitialStreamReceiveWindow: 8192, MaxStreamReceiveWindow: 8192,
		InitialConnectionReceiveWindow: 16384, MaxConnectionReceiveWindow: 16384,
		DisablePathMTUDiscovery: true,
	}
}

func scionQUICCertificate() (tls.Certificate, string, error) {
	pub, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return tls.Certificate{}, "", err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, "", err
	}
	template := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "Debuglet SCION echo"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, pub, private)
	if err != nil {
		return tls.Certificate{}, "", err
	}
	digest := sha256.Sum256(der)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: private}, hex.EncodeToString(digest[:]), nil
}

func scionQUICClientTLS(pin string) (*tls.Config, error) {
	expected, err := hex.DecodeString(pin)
	if err != nil || len(expected) != sha256.Size {
		return nil, ErrSCIONQUICCertificate
	}
	return &tls.Config{MinVersion: tls.VersionTLS13, NextProtos: []string{scionQUICALPN},
		// The expected certificate must come from trusted out-of-band or operator
		// configuration. Its exact DER digest replaces DNS/CA identity here.
		InsecureSkipVerify: true,
		VerifyConnection: func(state tls.ConnectionState) error {
			if len(state.PeerCertificates) == 0 {
				return ErrSCIONQUICCertificate
			}
			leaf := state.PeerCertificates[0]
			digest := sha256.Sum256(leaf.Raw)
			if subtle.ConstantTimeCompare(digest[:], expected) != 1 {
				return ErrSCIONQUICCertificate
			}
			now := time.Now()
			if now.Before(leaf.NotBefore) || now.After(leaf.NotAfter) {
				return ErrSCIONQUICCertificate
			}
			return nil
		}}, nil
}

func readSCIONQUICFrame(reader io.Reader) ([]byte, error) {
	var header [4]byte
	if _, err := io.ReadFull(reader, header[:]); err != nil {
		return nil, err
	}
	size := binary.BigEndian.Uint32(header[:])
	if size > scionQUICMaxPayload {
		return nil, errors.New("SCION echo frame exceeds 4096 bytes")
	}
	payload := make([]byte, size)
	_, err := io.ReadFull(reader, payload)
	return payload, err
}

func writeSCIONQUICFrame(writer io.Writer, payload []byte) error {
	if len(payload) > scionQUICMaxPayload {
		return fmt.Errorf("SCION echo frame exceeds %d bytes", scionQUICMaxPayload)
	}
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], uint32(len(payload)))
	for _, part := range [][]byte{header[:], payload} {
		for len(part) > 0 {
			n, err := writer.Write(part)
			if err != nil {
				return err
			}
			if n <= 0 || n > len(part) {
				return io.ErrShortWrite
			}
			part = part[n:]
		}
	}
	return nil
}
