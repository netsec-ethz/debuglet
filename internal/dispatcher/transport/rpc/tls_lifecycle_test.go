package rpc

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	dispatcherconfig "github.com/netsec-ethz/debuglet/internal/dispatcher/config"
	executorrpc "github.com/netsec-ethz/debuglet/internal/executor/transport/rpc"
	"github.com/netsec-ethz/debuglet/internal/testtls"
	pb "github.com/netsec-ethz/debuglet/protocol"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
)

// controlTLS runs both dispatcher control listeners over real TLS sockets and
// connects executors through the production client transport. Nothing here is
// simulated: the certificates are issued in the process, the listeners are the
// ones the command builds, and the peers are the executor's own BidiClient.
type controlTLS struct {
	t                       *testing.T
	ca, foreign             *testtls.Authority
	server, client          *testtls.Identity
	state                   *lifecycleState
	b                       *BidiServer
	direct, reverse         net.Listener
	ctx                     context.Context
	cancel                  context.CancelFunc
	directDone, reverseDone chan struct{}
	directErr, reverseErr   error
	peers                   []*lifecyclePeerOwner
	stopOnce                sync.Once
}

// controlTLSOptions selects the listener profile a scenario needs.
type controlTLSOptions struct {
	// requireClientIdentity is the dispatcher's tls.require_client_cert.
	requireClientIdentity bool
	// identity replaces the served certificate, so a scenario can present one
	// that the startup check would have refused, such as an expired one.
	identity *testtls.Identity
	// plaintext serves both listeners in the clear, for the boundary where a
	// reverse proxy in front terminates TLS instead.
	plaintext bool
	// nodes enforces enrolled executor identities on both channels.
	nodes NodeAuthority
}

func newControlTLS(t *testing.T, opts controlTLSOptions) *controlTLS {
	t.Helper()
	dir := t.TempDir()
	ca, err := testtls.NewAuthority(dir, "authority")
	if err != nil {
		t.Fatalf("create authority: %v", err)
	}
	foreign, err := testtls.NewAuthority(t.TempDir(), "foreign")
	if err != nil {
		t.Fatalf("create foreign authority: %v", err)
	}
	server, err := ca.Issue("dispatcher", testtls.Options{Hosts: []string{"127.0.0.1", "localhost", "dispatcher.example.org"}, Server: true})
	if err != nil {
		t.Fatalf("issue dispatcher identity: %v", err)
	}
	client, err := ca.Issue("executor", testtls.Options{Hosts: []string{"executor.example.org"}, Client: true})
	if err != nil {
		t.Fatalf("issue executor identity: %v", err)
	}
	served := server
	if opts.identity != nil {
		served = opts.identity
	}
	f := &controlTLS{t: t, ca: ca, foreign: foreign, server: server, client: client, state: newLifecycleState()}
	f.b = newTestBidiServer(t, zap.NewNop(), f.state, "00000000-0000-4000-8000-000000000001")
	if opts.nodes != nil {
		f.b.EnforceEnrollment(opts.nodes)
	}
	f.ctx, f.cancel = context.WithCancel(context.Background())
	f.direct, f.reverse = listenLoopback(t), listenLoopback(t)
	if !opts.plaintext {
		security := f.security(served, opts.requireClientIdentity)
		f.direct = tls.NewListener(f.direct, security.Direct)
		f.reverse = tls.NewListener(f.reverse, security.Combined)
		if security.RequireClientIdentity {
			f.reverse = VerifiedClientListener(f.reverse, zap.NewNop())
		}
	}
	f.directDone, f.reverseDone = make(chan struct{}), make(chan struct{})
	t.Cleanup(f.shutdown)
	go func() { defer close(f.directDone); f.directErr = f.b.ServeGRPCListener(f.ctx, f.direct) }()
	go func() { defer close(f.reverseDone); f.reverseErr = f.b.ServeYamux(f.ctx, f.reverse) }()
	return f
}

// security builds the listener profiles the dispatcher command builds, from the
// configuration keys an operator writes.
func (f *controlTLS) security(identity *testtls.Identity, requireClientIdentity bool) *dispatcherconfig.ServerTLS {
	f.t.Helper()
	security, err := dispatcherconfig.LoadServerTLS(dispatcherconfig.TLSConfig{
		CertFile: identity.CertFile, KeyFile: identity.KeyFile, CAFile: f.ca.CertFile, RequireClientCert: requireClientIdentity,
	})
	if err != nil {
		// An expired identity is refused at startup, so a scenario that serves
		// one builds the profile the running listener would still hold.
		if identity == f.server {
			f.t.Fatalf("load transport security: %v", err)
		}
		security = &dispatcherconfig.ServerTLS{
			Combined:              f.ca.ServerConfig(identity, false),
			Direct:                f.ca.ServerConfig(identity, requireClientIdentity),
			RequireClientIdentity: requireClientIdentity,
		}
		security.Direct.NextProtos = []string{"h2"}
	}
	return security
}

func listenLoopback(t *testing.T) net.Listener {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	return lis
}

// peer connects one executor through the production client transport, with the
// verification profile the scenario configured.
func (f *controlTLS) peer(peer *lifecyclePeer, cfg *tls.Config, direct, reverse string) *lifecyclePeerOwner {
	f.t.Helper()
	opts := executorrpc.BidiOptions{Address: direct, YamuxAddress: reverse, Logger: zap.NewNop()}
	if cfg != nil {
		opts.TLSConfig, opts.TLSCreds = cfg, credentials.NewTLS(cfg.Clone())
	}
	client, err := executorrpc.NewBidiClient(opts, peer)
	if err != nil {
		f.t.Fatal(err)
	}
	owned := &lifecyclePeerOwner{client: client, joined: make(chan struct{})}
	f.peers = append(f.peers, owned)
	go func() { defer close(owned.joined); _ = client.ConnectAndServe(f.ctx) }()
	return owned
}

// connectedPeer connects through the fixture's own listeners.
func (f *controlTLS) connectedPeer(peer *lifecyclePeer, cfg *tls.Config) *lifecyclePeerOwner {
	f.t.Helper()
	return f.peer(peer, cfg, f.direct.Addr().String(), f.reverse.Addr().String())
}

// registered waits for the transport to publish and register an owner.
func (f *controlTLS) registered(version string) *SessionOwner {
	f.t.Helper()
	select {
	case event := <-f.state.connected:
		select {
		case <-event.owner.Registered():
		case <-event.owner.Done():
			f.t.Fatalf("owner %s retired before registration", version)
		case <-time.After(sessionTestWait):
			f.t.Fatalf("owner %s did not register", version)
		}
		if event.version != version {
			f.t.Fatalf("registered version %q, want %q", event.version, version)
		}
		return event.owner
	case <-time.After(sessionTestWait):
		f.t.Fatalf("executor %s did not connect", version)
	}
	return nil
}

// refused asserts that a peer never registered and that its transport ended
// with the reason a verification failure produces.
func (f *controlTLS) refused(owned *lifecyclePeerOwner, want string) {
	f.t.Helper()
	awaitSessionSignal(f.t, owned.joined)
	cause := owned.client.Cause()
	if cause == nil {
		f.t.Fatal("refused connection reported no cause")
	}
	if want != "" && !strings.Contains(cause.Error(), want) {
		f.t.Fatalf("cause %q does not report %q", cause, want)
	}
	if count := f.state.connectedCount(); count != 0 {
		f.t.Fatalf("unverified peer reached registration (%d connections)", count)
	}
}

func (f *controlTLS) shutdown() {
	f.stopOnce.Do(func() {
		f.cancel()
		f.b.Close()
		for _, peer := range f.peers {
			peer.client.Close()
			awaitSessionSignal(f.t, peer.joined)
		}
		awaitSessionSignal(f.t, f.directDone)
		awaitSessionSignal(f.t, f.reverseDone)
		if f.directErr != nil {
			f.t.Errorf("ServeGRPCListener: %v", f.directErr)
		}
		if f.reverseErr != nil {
			f.t.Errorf("ServeYamux: %v", f.reverseErr)
		}
	})
}

// TestControlTLSVerifiedSession runs one executor session over verified TLS on
// both control channels and exercises each direction: a direct call from the
// executor over the gRPC listener, and a reverse call from the dispatcher over
// the yamux stream inside the same connection.
func TestControlTLSVerifiedSession(t *testing.T) {
	f := newControlTLS(t, controlTLSOptions{requireClientIdentity: true})
	peer := &lifecyclePeer{id: "executor", version: "A"}
	owned := f.connectedPeer(peer, f.ca.ClientConfig(f.client, ""))
	owner := f.registered("A")

	ctx, cancel := context.WithTimeout(context.Background(), sessionTestWait)
	defer cancel()
	if err := owned.client.WaitReadyContext(ctx); err != nil {
		t.Fatalf("bind acknowledgement over TLS: %v", err)
	}
	binding, live := owned.client.Binding()
	if !live {
		t.Fatal("no live binding after a verified handshake")
	}
	direct, err := owned.client.ClientFor(binding)
	if err != nil {
		t.Fatalf("bound direct client: %v", err)
	}
	if _, err := direct.Heartbeat(ctx, &pb.HeartbeatRequest{ExecutorId: "executor"}); err != nil {
		t.Fatalf("direct gRPC call over TLS: %v", err)
	}
	if f.state.heartbeats.Load() != 1 {
		t.Fatalf("heartbeats through the direct listener: %d", f.state.heartbeats.Load())
	}
	reverse, ok := f.b.GetClientFor(owner)
	if !ok {
		t.Fatal("reverse client unavailable for a registered owner")
	}
	if _, err := reverse.Abort(ctx, &pb.AbortRequest{DebugletId: "fixture"}); err != nil {
		t.Fatalf("reverse call over the TLS yamux stream: %v", err)
	}
	if peer.aborts.Load() != 1 {
		t.Fatalf("reverse calls delivered: %d", peer.aborts.Load())
	}
}

// TestControlTLSRejectsUnusableDispatcherIdentity keeps the executor from
// talking to a dispatcher it cannot verify: an untrusted root, a certificate
// issued for another name, and an expired one are all refused before any
// control session exists.
func TestControlTLSRejectsUnusableDispatcherIdentity(t *testing.T) {
	t.Run("untrusted root", func(t *testing.T) {
		f := newControlTLS(t, controlTLSOptions{requireClientIdentity: true})
		client, err := f.foreign.Issue("executor", testtls.Options{Client: true})
		if err != nil {
			t.Fatalf("issue foreign identity: %v", err)
		}
		owned := f.connectedPeer(&lifecyclePeer{id: "executor", version: "A"}, f.foreign.ClientConfig(client, ""))
		f.refused(owned, "certificate")
	})
	t.Run("wrong hostname", func(t *testing.T) {
		f := newControlTLS(t, controlTLSOptions{requireClientIdentity: true})
		cfg := f.ca.ClientConfig(f.client, "other.example.org")
		owned := f.connectedPeer(&lifecyclePeer{id: "executor", version: "A"}, cfg)
		f.refused(owned, "certificate is valid for")
	})
	t.Run("expired certificate", func(t *testing.T) {
		dir := t.TempDir()
		ca, err := testtls.NewAuthority(dir, "authority")
		if err != nil {
			t.Fatalf("create authority: %v", err)
		}
		expired, err := ca.Issue("dispatcher", testtls.Options{
			Hosts:     []string{"127.0.0.1"},
			Server:    true,
			NotBefore: time.Now().Add(-48 * time.Hour),
			NotAfter:  time.Now().Add(-24 * time.Hour),
		})
		if err != nil {
			t.Fatalf("issue expired identity: %v", err)
		}
		f := newControlTLS(t, controlTLSOptions{identity: expired})
		// The authority is the fixture's own; only the served identity expired.
		cfg := f.ca.ClientConfig(f.client, "")
		cfg.RootCAs = ca.Pool()
		owned := f.connectedPeer(&lifecyclePeer{id: "executor", version: "A"}, cfg)
		f.refused(owned, "expired")
	})
}

// TestControlTLSRequiresClientIdentity covers a missing and a foreign executor
// identity on both control channels while the dispatcher requires one.
func TestControlTLSRequiresClientIdentity(t *testing.T) {
	t.Run("reverse stream without an identity", func(t *testing.T) {
		f := newControlTLS(t, controlTLSOptions{requireClientIdentity: true})
		owned := f.connectedPeer(&lifecyclePeer{id: "executor", version: "A"}, f.ca.ClientConfig(nil, ""))
		f.refused(owned, "")
	})
	t.Run("reverse stream with a server-only identity", func(t *testing.T) {
		// An identity the authority issued for serving is not an executor
		// identity: the extended key usage decides what a certificate admits.
		f := newControlTLS(t, controlTLSOptions{requireClientIdentity: true})
		serving, err := f.ca.Issue("serving", testtls.Options{Hosts: []string{"executor.example.org"}, Server: true})
		if err != nil {
			t.Fatalf("issue serving identity: %v", err)
		}
		owned := f.connectedPeer(&lifecyclePeer{id: "executor", version: "A"}, f.ca.ClientConfig(serving, ""))
		f.refused(owned, "")
	})
	t.Run("reverse stream with a foreign identity", func(t *testing.T) {
		f := newControlTLS(t, controlTLSOptions{requireClientIdentity: true})
		client, err := f.foreign.Issue("executor", testtls.Options{Client: true})
		if err != nil {
			t.Fatalf("issue foreign identity: %v", err)
		}
		cfg := f.ca.ClientConfig(client, "")
		owned := f.connectedPeer(&lifecyclePeer{id: "executor", version: "A"}, cfg)
		f.refused(owned, "")
	})
	t.Run("direct channel", func(t *testing.T) {
		f := newControlTLS(t, controlTLSOptions{requireClientIdentity: true})
		foreignClient, err := f.foreign.Issue("executor", testtls.Options{Client: true})
		if err != nil {
			t.Fatalf("issue foreign identity: %v", err)
		}
		serving, err := f.ca.Issue("serving", testtls.Options{Hosts: []string{"executor.example.org"}, Server: true})
		if err != nil {
			t.Fatalf("issue serving identity: %v", err)
		}
		for _, tc := range []struct {
			name string
			cfg  *tls.Config
			want codes.Code
		}{
			// The handshake is refused, so the call never reaches a handler.
			{"missing identity", f.ca.ClientConfig(nil, ""), codes.Unavailable},
			{"foreign identity", f.ca.ClientConfig(foreignClient, ""), codes.Unavailable},
			// Issued by the right authority, but not for this use.
			{"server-only identity", f.ca.ClientConfig(serving, ""), codes.Unavailable},
			// A verified peer reaches the handler, which then refuses the call
			// for the separate reason that it carries no control session.
			{"verified identity", f.ca.ClientConfig(f.client, ""), codes.FailedPrecondition},
		} {
			t.Run(tc.name, func(t *testing.T) {
				ctx, cancel := context.WithTimeout(context.Background(), sessionTestWait)
				defer cancel()
				gconn, err := grpc.NewClient(f.direct.Addr().String(), grpc.WithTransportCredentials(credentials.NewTLS(tc.cfg)))
				if err != nil {
					t.Fatal(err)
				}
				defer gconn.Close()
				_, err = pb.NewDispatcherServiceClient(gconn).BindSession(ctx, &pb.BindSessionRequest{ExecutorId: "executor"})
				if status.Code(err) != tc.want {
					t.Fatalf("BindSession status=%v want=%v (%v)", status.Code(err), tc.want, err)
				}
			})
		}
	})
}

// TestControlTLSReconnect keeps the reconnect lifecycle working over TLS: a
// lost session is retired and the executor's next connection registers again,
// each one completing its own handshake.
func TestControlTLSReconnect(t *testing.T) {
	f := newControlTLS(t, controlTLSOptions{requireClientIdentity: true})
	cfg := f.ca.ClientConfig(f.client, "")
	first := f.connectedPeer(&lifecyclePeer{id: "executor", version: "A"}, cfg)
	owner := f.registered("A")
	ctx, cancel := context.WithTimeout(context.Background(), sessionTestWait)
	defer cancel()
	if err := first.client.WaitReadyContext(ctx); err != nil {
		t.Fatalf("first session: %v", err)
	}
	first.client.Close()
	awaitSessionSignal(t, first.joined)
	awaitSessionSignal(t, owner.Done())
	deadline := time.NewTimer(sessionTestWait)
	defer deadline.Stop()
	for f.state.disconnectCount(owner) == 0 {
		f.state.mu.Lock()
		changed := f.state.changed
		f.state.mu.Unlock()
		select {
		case <-changed:
		case <-deadline.C:
			t.Fatal("lost session was not reported as disconnected")
		}
	}

	second := f.connectedPeer(&lifecyclePeer{id: "executor", version: "B"}, cfg)
	renewed := f.registered("B")
	if renewed == owner {
		t.Fatal("reconnect reused the retired owner")
	}
	if err := second.client.WaitReadyContext(ctx); err != nil {
		t.Fatalf("reconnected session: %v", err)
	}
	binding, live := second.client.Binding()
	if !live {
		t.Fatal("reconnected session has no live binding")
	}
	direct, err := second.client.ClientFor(binding)
	if err != nil {
		t.Fatalf("bound direct client after reconnect: %v", err)
	}
	if _, err := direct.Heartbeat(ctx, &pb.HeartbeatRequest{ExecutorId: "executor"}); err != nil {
		t.Fatalf("direct call after reconnect: %v", err)
	}
	if f.state.connectedCount() != 2 {
		t.Fatalf("connections observed: %d", f.state.connectedCount())
	}
}

// TestControlTLSReverseProxyBoundary covers the supported deployment where a
// reverse proxy terminates TLS and reaches the dispatcher's plaintext listeners
// over a network only it can use. The executor still pins the deployment's
// authority and verifies the proxy's name, and a peer pinning another authority
// is refused at that boundary.
func TestControlTLSReverseProxyBoundary(t *testing.T) {
	f := newControlTLS(t, controlTLSOptions{plaintext: true})
	directCfg := f.ca.ServerConfig(f.server, true)
	directCfg.NextProtos = []string{"h2"}
	direct := terminate(t, directCfg, f.direct.Addr().String())
	reverse := terminate(t, f.ca.ServerConfig(f.server, true), f.reverse.Addr().String())

	owned := f.peer(&lifecyclePeer{id: "executor", version: "A"}, f.ca.ClientConfig(f.client, "dispatcher.example.org"), direct, reverse)
	f.registered("A")
	ctx, cancel := context.WithTimeout(context.Background(), sessionTestWait)
	defer cancel()
	if err := owned.client.WaitReadyContext(ctx); err != nil {
		t.Fatalf("session through the terminator: %v", err)
	}
	binding, live := owned.client.Binding()
	if !live {
		t.Fatal("no live binding through the terminator")
	}
	client, err := owned.client.ClientFor(binding)
	if err != nil {
		t.Fatalf("bound direct client: %v", err)
	}
	if _, err := client.Heartbeat(ctx, &pb.HeartbeatRequest{ExecutorId: "executor"}); err != nil {
		t.Fatalf("direct call through the terminator: %v", err)
	}

	foreign, err := f.foreign.Issue("executor", testtls.Options{Client: true})
	if err != nil {
		t.Fatalf("issue foreign identity: %v", err)
	}
	unpinned := f.peer(&lifecyclePeer{id: "other", version: "B"}, f.foreign.ClientConfig(foreign, "dispatcher.example.org"), direct, reverse)
	awaitSessionSignal(t, unpinned.joined)
	if cause := unpinned.client.Cause(); cause == nil || !strings.Contains(cause.Error(), "certificate") {
		t.Fatalf("unpinned peer was not refused at the boundary: %v", cause)
	}
	if f.state.connectedCount() != 1 {
		t.Fatalf("connections observed: %d", f.state.connectedCount())
	}
}

// terminate runs a TLS terminator in front of a plaintext daemon listener and
// returns the address a peer connects to. It splices the two connections byte
// for byte, which is what the deployed stream proxy does on the control port:
// one connection in, one connection out, no protocol of its own. It is not a
// gRPC proxy that re-originates HTTP/2, so it covers the boundary a terminator
// creates for identity and verification, not a terminator's own framing.
func terminate(t *testing.T, cfg *tls.Config, backend string) string {
	t.Helper()
	lis := tls.NewListener(listenLoopback(t), cfg)
	var mu sync.Mutex
	var live []net.Conn
	var sessions sync.WaitGroup
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			front, err := lis.Accept()
			if err != nil {
				return
			}
			back, err := net.Dial("tcp", backend)
			if err != nil {
				front.Close()
				continue
			}
			mu.Lock()
			live = append(live, front, back)
			mu.Unlock()
			sessions.Add(2)
			go func() { defer sessions.Done(); io.Copy(back, front); back.Close() }()
			go func() { defer sessions.Done(); io.Copy(front, back); front.Close() }()
		}
	}()
	t.Cleanup(func() {
		lis.Close()
		<-done
		mu.Lock()
		for _, conn := range live {
			conn.Close()
		}
		mu.Unlock()
		sessions.Wait()
	})
	return lis.Addr().String()
}
