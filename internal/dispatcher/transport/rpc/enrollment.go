package rpc

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"net"

	"github.com/netsec-ethz/debuglet/internal/controlrpc"
	"go.uber.org/zap"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/peer"
)

// NodeAuthority decides which enrolled node may act as an executor ID. It
// answers who the peer is; session generations, tokens and leases stay separate
// and keep fencing stale messages.
type NodeAuthority interface {
	// Admit is called on the Hello a reverse control connection answered,
	// before an owner exists and therefore before any replacement,
	// registration or run effect. A nonempty token is the peer's one-time
	// enrollment credential.
	Admit(ctx context.Context, executorID, fingerprint, token string) error
	// Bound re-checks a session that was admitted earlier, so a rotated or
	// revoked credential stops renewing its lease.
	Bound(ctx context.Context, executorID, fingerprint string) error
}

// EnforceEnrollment binds executor IDs to enrolled node credentials. It must be
// called before this transport serves. Without it — the local development
// profile, where the listeners ask for no client certificate and there is no
// credential to bind to — an executor ID stays a self-assertion.
func (b *BidiServer) EnforceEnrollment(nodes NodeAuthority) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.nodes = nodes
}

func (b *BidiServer) nodeAuthority() NodeAuthority {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.nodes
}

// admitNode verifies a claimed executor ID against the credential its reverse
// control connection carries. It runs before the caller creates an owner or
// retires the current one, so a refused peer never evicts a healthy node.
func (b *BidiServer) admitNode(ctx context.Context, executorID, fingerprint, token string) error {
	nodes := b.nodeAuthority()
	if nodes == nil {
		return nil
	}
	if err := nodes.Admit(ctx, executorID, fingerprint, token); err != nil {
		b.logger.Warn("Refused an executor identity",
			zap.String("executor_id", executorID), zap.Error(err))
		return controlrpc.Denied()
	}
	return nil
}

// boundNode requires a direct-channel request to arrive over the same node
// credential its reverse session was enrolled with. A fingerprint names public
// certificate material and is compared directly; the session token is the
// secret, and controlrpc.Credentials.Matches has already compared that in
// constant time.
func (b *BidiServer) boundNode(ctx context.Context, fingerprint string) bool {
	if b.nodeAuthority() == nil {
		return true
	}
	return fingerprint != "" && fingerprint == contextFingerprint(ctx)
}

// stillEnrolled re-reads the binding of an open session. A rotation or a
// revocation is refused here rather than by ending the session: the peer loses
// its lease at this check and is retired when the lease runs out.
func (b *BidiServer) stillEnrolled(ctx context.Context, executorID, fingerprint string) error {
	nodes := b.nodeAuthority()
	if nodes == nil {
		return nil
	}
	if err := nodes.Bound(ctx, executorID, fingerprint); err != nil {
		b.logger.Warn("Refused a lease renewal for an unenrolled node",
			zap.String("executor_id", executorID), zap.Error(err))
		return controlrpc.Denied()
	}
	return nil
}

// nodeCredential names the verified client certificate an accepted control
// connection carries. The listener chain finishes a handshake lazily, on the
// connection's first use, and the credential a session is bound to has to be
// known before that session is offered, so the handshake is completed here. A
// connection that terminates no TLS carries no credential.
func nodeCredential(ctx context.Context, conn net.Conn) (string, error) {
	c := tlsConn(conn)
	if c == nil {
		return "", nil
	}
	if err := c.HandshakeContext(ctx); err != nil {
		return "", err
	}
	return chainFingerprint(c.ConnectionState().VerifiedChains), nil
}

// terminatedTLS reports the identity of a direct-channel connection whose TLS
// the listener in front of this server already terminated. It runs no
// handshake of its own beyond completing that one, and invents no identity: a
// connection that terminates no TLS is admitted with none, which is the
// plaintext profile. Without it the peer of a direct request carries no
// certificate at all, because the server itself holds no TLS configuration.
type terminatedTLS struct{}

func (terminatedTLS) ServerHandshake(conn net.Conn) (net.Conn, credentials.AuthInfo, error) {
	c := tlsConn(conn)
	if c == nil {
		return insecure.NewCredentials().ServerHandshake(conn)
	}
	if err := c.Handshake(); err != nil {
		return nil, nil, err
	}
	return conn, credentials.TLSInfo{
		State:          c.ConnectionState(),
		CommonAuthInfo: credentials.CommonAuthInfo{SecurityLevel: credentials.PrivacyAndIntegrity},
	}, nil
}

func (terminatedTLS) ClientHandshake(context.Context, string, net.Conn) (net.Conn, credentials.AuthInfo, error) {
	return nil, nil, errors.New("control transport credentials are server-side only")
}
func (terminatedTLS) Info() credentials.ProtocolInfo {
	return credentials.ProtocolInfo{SecurityProtocol: "tls"}
}
func (t terminatedTLS) Clone() credentials.TransportCredentials { return t }
func (terminatedTLS) OverrideServerName(string) error           { return nil }

// contextFingerprint names the verified client certificate of the direct gRPC
// connection a request arrived on.
func contextFingerprint(ctx context.Context) string {
	p, ok := peer.FromContext(ctx)
	if !ok || p.AuthInfo == nil {
		return ""
	}
	info, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok {
		return ""
	}
	return chainFingerprint(info.State.VerifiedChains)
}

// chainFingerprint names the leaf of a verified chain by the SHA-256 digest of
// its DER bytes. Only a chain the configured authority verified is used.
func chainFingerprint(chains [][]*x509.Certificate) string {
	if len(chains) == 0 || len(chains[0]) == 0 {
		return ""
	}
	sum := sha256.Sum256(chains[0][0].Raw)
	return hex.EncodeToString(sum[:])
}
