package rpc

import (
	"crypto/tls"
	"errors"
	"net"
	"sync"
	"sync/atomic"

	"github.com/soheilhy/cmux"
	"go.uber.org/zap"
)

// ErrUnverifiedControlPeer refuses a control connection that completed its
// handshake without a client certificate the configured authority verified.
var ErrUnverifiedControlPeer = errors.New("control connection carries no verified client certificate")

// VerifiedClientListener admits only connections whose TLS handshake produced a
// client certificate chain the dispatcher's configured authority verified.
//
// The direct gRPC listener refuses a missing identity during the handshake,
// because nothing but an executor speaks to it. The reverse control stream
// cannot: it shares a port with the HTTP API, where a submitter holds no
// certificate, so the requirement is applied to the connections the protocol
// multiplexer routes here. A refused connection is closed and logged; the
// listener keeps serving, so one unenrolled peer cannot end the control plane.
func VerifiedClientListener(lis net.Listener, logger *zap.Logger) net.Listener {
	return &verifiedClientListener{Listener: lis, logger: logger}
}

type verifiedClientListener struct {
	net.Listener
	logger *zap.Logger
}

func (l *verifiedClientListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return &verifiedConn{Conn: conn, logger: l.logger}, nil
}

// verifiedConn refuses a peer whose handshake produced no verified client
// certificate. The decision is taken on first use rather than on accept: an
// unfinished handshake must not hold up the accept loop, and the multiplexer in
// front of this listener completes it with its own first read. Until the
// handshake finishes there is nothing to decide and nothing has been carried.
//
// The decision is taken once. Go's TLS server supports neither renegotiation
// nor post-handshake client authentication, so the chains a handshake produced
// cannot change afterwards, and every later frame of a multiplexed session
// reads one atomic word instead of copying the connection state behind a lock
// that both of a session's directions would otherwise share.
type verifiedConn struct {
	net.Conn
	logger *zap.Logger
	state  atomic.Int32
	mu     sync.Mutex // Held only while an undecided connection is decided.
}

// The decision this connection carries for the rest of its life.
const (
	undecidedPeer int32 = iota
	admittedPeer
	refusedPeer
)

func (c *verifiedConn) Read(b []byte) (int, error) {
	decided, err := c.admit()
	if err != nil {
		return 0, err
	}
	n, err := c.Conn.Read(b)
	if decided {
		return n, err
	}
	// This read completed the handshake; decide before its bytes are used.
	if _, refused := c.admit(); refused != nil {
		return 0, refused
	}
	return n, err
}

func (c *verifiedConn) Write(b []byte) (int, error) {
	decided, err := c.admit()
	if err != nil {
		return 0, err
	}
	n, err := c.Conn.Write(b)
	if decided {
		return n, err
	}
	if _, refused := c.admit(); refused != nil {
		return 0, refused
	}
	return n, err
}

// admit reports the standing decision, taking it when the handshake has
// completed. It reports an undecided connection while the handshake is still in
// flight, which is the only state in which nothing has been settled and nothing
// has been carried. A connection that carries no handshake at all, including
// one this package cannot unwrap, is refused.
func (c *verifiedConn) admit() (bool, error) {
	switch c.state.Load() {
	case admittedPeer:
		return true, nil
	case refusedPeer:
		return true, ErrUnverifiedControlPeer
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	switch c.state.Load() {
	case admittedPeer:
		return true, nil
	case refusedPeer:
		return true, ErrUnverifiedControlPeer
	}
	state, ok := tlsState(c.Conn)
	if ok && !state.HandshakeComplete {
		return false, nil
	}
	if ok && len(state.VerifiedChains) > 0 {
		c.state.Store(admittedPeer)
		return true, nil
	}
	c.state.Store(refusedPeer)
	if c.logger != nil {
		c.logger.Warn("Refused a control connection without a verified client certificate",
			zap.String("remote_addr", c.Conn.RemoteAddr().String()))
	}
	c.Conn.Close()
	return true, ErrUnverifiedControlPeer
}

// tlsState reports the handshake state of an accepted connection, and reports
// a connection that terminates no handshake at all as carrying none.
func tlsState(conn net.Conn) (tls.ConnectionState, bool) {
	if c := tlsConn(conn); c != nil {
		return c.ConnectionState(), true
	}
	return tls.ConnectionState{}, false
}

// tlsConn unwraps the terminating TLS connection under an accepted one. The
// protocol multiplexer and this package's own wrappers hand the matched
// protocol their own connection, so the one underneath is unwrapped explicitly
// rather than assumed; an unwrappable connection is reported as nil.
func tlsConn(conn net.Conn) *tls.Conn {
	for range 6 {
		switch c := conn.(type) {
		case *tls.Conn:
			return c
		case *cmux.MuxConn:
			conn = c.Conn
		case *verifiedConn:
			conn = c.Conn
		case *sessionConn:
			conn = c.Conn
		default:
			return nil
		}
	}
	return nil
}
