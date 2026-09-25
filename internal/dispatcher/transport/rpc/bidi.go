// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package rpc

import (
	"context"
	"crypto/rand"
	"fmt"
	"github.com/netsec-ethz/debuglet/internal/controlrpc"
	"github.com/netsec-ethz/debuglet/internal/controlsession"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	pb "github.com/netsec-ethz/debuglet/protocol"

	"github.com/hashicorp/yamux"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/reflection"
)

type ExecutorConn struct {
	owner   *SessionOwner
	gconn   *grpc.ClientConn
	client  BoundExecutorClient
	offer   *controlOffer
	session *yamux.Session
}

// BidiServer serves direct DispatcherService RPCs and reverse executor callbacks.
// One negotiated owner binds direct calls and reverse callbacks.
type BidiServer struct {
	grpcServer  *grpc.Server
	logger      *zap.Logger
	state       DispatcherState
	incarnation string
	lease       controlsession.LeaseTiming
	now         func() time.Time

	nodes        NodeAuthority // Enrollment authority, nil where it is not enforced; mu
	clients      map[string]ExecutorConn
	offers       map[string]*controlOffer
	lanes        map[string]*sessionLane
	mu           sync.RWMutex
	invocations  sync.WaitGroup
	closed       bool
	stop         chan struct{}
	closeOnce    sync.Once
	grpcStopOnce sync.Once

	// reverseListeners and directListeners count the control listeners
	// currently accepting. They are counted apart because an executor needs
	// both: it dials the reverse listener to open the session this dispatcher
	// calls back on, and the direct listener to renew that session's lease.
	reverseListeners atomic.Int64
	directListeners  atomic.Int64
}

func NewBidiServer(l *zap.Logger, state DispatcherState, incarnation string, duration time.Duration) (*BidiServer, error) {
	return NewBidiServerWithClock(l, state, incarnation, duration, time.Now)
}

// NewBidiServerWithClock fixes one receiver-local clock for all of its owners.
// It is never negotiated or changed by a peer.
func NewBidiServerWithClock(l *zap.Logger, state DispatcherState, incarnation string, duration time.Duration, now func() time.Time) (*BidiServer, error) {
	if now == nil {
		return nil, fmt.Errorf("control transport requires a clock")
	}
	if _, err := controlsession.ParseBinding(incarnation, incarnation); err != nil {
		return nil, err
	}
	lease, err := controlsession.NewLeaseTiming(duration)
	if err != nil {
		return nil, err
	}
	b := &BidiServer{
		grpcServer:  grpc.NewServer(grpc.WaitForHandlers(true), grpc.Creds(terminatedTLS{})),
		logger:      l,
		state:       state,
		incarnation: incarnation,
		lease:       lease, now: now,
		clients: make(map[string]ExecutorConn),
		offers:  make(map[string]*controlOffer),
		lanes:   make(map[string]*sessionLane),
		stop:    make(chan struct{}),
	}
	pb.RegisterDispatcherServiceServer(b.grpcServer, &server{state: state, bidi: b})
	reflection.Register(b.grpcServer)
	return b, nil
}

// Close retires current owners, stops serving and joins every admitted listener
// invocation and session, including unpublished and replaced connections.
// Concurrent callers join the same shutdown. Callbacks must not call Close.
func (b *BidiServer) Close() {
	b.closeOnce.Do(func() {
		b.mu.Lock()
		b.closed = true
		close(b.stop)
		for _, conn := range b.clients {
			b.retireLocked(conn.owner)
		}
		b.mu.Unlock()
		b.stopGRPC()
		b.invocations.Wait()
	})
}

// stopGRPC starts forceful transport stopping after two seconds. Joining the
// graceful-stop worker still depends on RPC handlers returning; a handler that
// ignores cancellation can outlive that grace period. The demo supervisor owns
// the separate hard process-lifetime deadline.
func (b *BidiServer) stopGRPC() {
	b.grpcStopOnce.Do(func() {
		done := make(chan struct{})
		go func() { b.grpcServer.GracefulStop(); close(done) }()
		timer := time.NewTimer(2 * time.Second)
		defer timer.Stop()
		select {
		case <-done:
		case <-timer.C:
			b.grpcServer.Stop()
			<-done
		}
	})
}

// Serving reports whether this transport currently accepts executor control
// sessions: it has not been stopped and both of its control listeners are
// accepting, half a control channel being no service. It is read from the
// transport itself, never from a record written once at startup.
func (b *BidiServer) Serving() bool {
	return b != nil && !b.stopping() && b.reverseListeners.Load() > 0 && b.directListeners.Load() > 0
}

// GetClientFor never substitutes another owner with the same executor ID.
func (b *BidiServer) GetClientFor(owner *SessionOwner) (BoundExecutorClient, bool) {
	if owner == nil {
		return nil, false
	}
	b.mu.RLock()
	defer b.mu.RUnlock()
	conn, exists := b.clients[owner.ExecutorID()]
	if !exists || conn.owner != owner || !owner.Available() {
		return nil, false
	}
	return conn.client, true
}

// RemoveClient retires only the exact current owner. Its tracked handler
// performs cancellation and cleanup independently; this return is not a join.
func (b *BidiServer) RemoveClient(owner *SessionOwner) bool {
	if owner == nil {
		return false
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if conn, exists := b.clients[owner.ExecutorID()]; exists && conn.owner == owner {
		b.retireLocked(owner)
		return true
	}
	return false
}

// Admission and Close's Wait share one mutex. Invocations own their listener
// and accepted handlers, including sessions absent from the current-client map.
func (b *BidiServer) beginInvocation() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return false
	}
	b.invocations.Add(1)
	return true
}

func (b *BidiServer) ServeGRPC(parent context.Context, addr string) error {
	if !b.beginInvocation() {
		return net.ErrClosed
	}
	defer b.invocations.Done()
	ctx, cancel := context.WithCancel(parent)
	joined := make(chan struct{})
	go func() {
		defer close(joined)
		select {
		case <-ctx.Done():
		case <-b.stop:
			cancel()
		}
	}()
	defer func() { cancel(); <-joined }()
	var lc net.ListenConfig
	lis, err := lc.Listen(ctx, "tcp", addr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", addr, err)
	}
	return b.serveGRPCListener(ctx, lis)
}

// ServeGRPCListener takes ownership of lis, including when admission fails.
func (b *BidiServer) ServeGRPCListener(ctx context.Context, lis net.Listener) error {
	if !b.beginInvocation() {
		lis.Close()
		return net.ErrClosed
	}
	defer b.invocations.Done()
	return b.serveGRPCListener(ctx, lis)
}

func (b *BidiServer) serveGRPCListener(ctx context.Context, listener net.Listener) error {
	lis := &sessionListener{Listener: listener}
	defer lis.Close()
	b.directListeners.Add(1)
	defer b.directListeners.Add(-1)
	done, joined := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(joined)
		select {
		case <-ctx.Done():
			lis.Close()
			b.stopGRPC()
		case <-b.stop:
			lis.Close()
		case <-done:
		}
	}()
	defer func() { close(done); <-joined }()
	b.logger.Info("gRPC server listening", zap.String("address", lis.Addr().String()))
	err := b.grpcServer.Serve(lis)
	if ctx.Err() != nil || b.stopping() {
		return nil
	}
	return err
}

// ServeYamux owns lis and joins all accepted handlers before returning.
func (b *BidiServer) ServeYamux(parent context.Context, listener net.Listener) error {
	if !b.beginInvocation() {
		listener.Close()
		return net.ErrClosed
	}
	defer b.invocations.Done()
	lis := &sessionListener{Listener: listener}
	ctx, cancel := context.WithCancel(parent)
	joined := make(chan struct{})
	go func() {
		defer close(joined)
		select {
		case <-ctx.Done():
		case <-b.stop:
			cancel()
		}
		lis.Close()
	}()
	var sessions sync.WaitGroup
	defer func() { cancel(); <-joined; sessions.Wait() }()
	b.reverseListeners.Add(1)
	defer b.reverseListeners.Add(-1)
	b.logger.Info("Yamux listener started", zap.String("address", lis.Addr().String()))
	for {
		conn, err := lis.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("accept yamux connection: %w", err)
		}
		b.mu.Lock()
		if b.closed || ctx.Err() != nil {
			b.mu.Unlock()
			conn.Close()
			return nil
		}
		sessions.Add(1)
		b.mu.Unlock()
		go func() {
			defer sessions.Done()
			b.handleSession(ctx, conn)
		}()
	}
}

// handleSession owns one reverse connection for its whole life, in this order:
// negotiate Hello and publish an owner, admit the setup mutation, wait for the
// predecessors of that executor ID to drain, call registration, wait for the
// executor to confirm the offer over the direct channel, and only then mark the
// owner registered. Every step rechecks that this is still the current owner, so
// a session that has been replaced marks nothing registered.
//
// Its deferred teardown is the reverse, and is a join rather than a signal: the
// owner is retired, Connected is canceled before any Close that could block, the
// session and its I/O watcher are closed, the setup mutation is finished, and
// only after the owner has drained are the offer and the lane forgotten.
func (b *BidiServer) handleSession(parent context.Context, raw net.Conn) {
	ctx, cancel := context.WithCancel(parent)
	conn := &sessionConn{Conn: raw}
	ioJoined := make(chan struct{})
	go func() {
		defer close(ioJoined)
		<-ctx.Done()
		conn.Close()
	}()
	var session *yamux.Session
	var gconn *grpc.ClientConn
	var owner *SessionOwner
	var ownerJoined <-chan struct{}
	var setup *Mutation
	defer func() {
		if owner != nil {
			b.RemoveClient(owner)
		}
		cancel() // Cancel Connected before any possibly blocking Close.
		if session != nil {
			session.Close()
		}
		if gconn != nil {
			gconn.Close()
		}
		conn.Close()
		<-ioJoined
		if ownerJoined != nil {
			<-ownerJoined
		}
		if setup != nil {
			setup.Finish()
		}
		if owner != nil {
			b.state.OnExecutorDisconnected(owner)
			<-owner.MutationsDrained()
			b.mu.Lock()
			delete(b.offers, owner.Binding().SessionID)
			b.sweepLaneLocked(owner.ExecutorID())
			b.mu.Unlock()
		}
	}()

	// The verified client certificate of this connection is fixed by its
	// handshake and is the node credential every later check compares against.
	fingerprint, err := nodeCredential(ctx, raw)
	if err != nil {
		b.logger.Debug("Control connection handshake did not complete", zap.Error(err))
		return
	}

	session, err = b.acceptYamux(conn)
	if err != nil {
		b.logger.Error("failed to listen for yamux", zap.Error(err))
		return
	}
	gconn, err = b.createExecutorClient(session)
	if err != nil {
		b.logger.Error("failed to create gRPC connection", zap.Error(err))
		return
	}
	var hello *pb.HelloResponse
	owner, hello, err = b.registerExecutor(ctx, gconn, session, fingerprint)
	if err != nil {
		b.logger.Error("failed to register executor", zap.Error(err))
		return
	}
	joined := make(chan struct{})
	ownerJoined = joined
	go func() {
		defer close(joined)
		select {
		case <-owner.Done():
		case <-session.CloseChan():
		case <-ctx.Done():
		}
		b.RemoveClient(owner)
		cancel()
	}()

	// The one setup mutation of a registration. It stays counted through the
	// callback below, cancelled or not, so a replacement waits for its work.
	setup, err = owner.AdmitSetup(ctx)
	if err != nil {
		return
	}
	if err = b.waitPredecessors(ctx, owner); err != nil {
		return
	}
	if err = b.state.OnExecutorConnected(setup.Context(), owner, hello, remoteIP(conn.RemoteAddr())); err != nil {
		b.logger.Warn("executor registration callback failed")
		return
	}
	b.mu.RLock()
	offer := b.offers[owner.Binding().SessionID]
	b.mu.RUnlock()
	select {
	case <-offer.confirmed:
	case <-ctx.Done():
		return
	}
	b.mu.Lock()
	current, exists := b.clients[owner.ExecutorID()]
	active := exists && current.owner == owner && ctx.Err() == nil && owner.MarkRegistered()
	if active {
		close(offer.activated)
	}
	b.mu.Unlock()
	if !active {
		return
	}
	setup.Finish()
	<-ctx.Done()
}

func (b *BidiServer) acceptYamux(conn net.Conn) (*yamux.Session, error) {
	b.logger.Debug("Accepted connection", zap.String("remote_addr", conn.RemoteAddr().String()))
	session, err := yamux.Server(conn, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create yamux session: %w", err)
	}
	return session, nil
}

func (b *BidiServer) createExecutorClient(session *yamux.Session) (*grpc.ClientConn, error) {
	dial := func(context.Context, string) (net.Conn, error) { return session.Open() }
	gconn, err := grpc.NewClient("passthrough:///unused",
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(dial),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create gRPC client: %w", err)
	}
	return gconn, nil
}

func (b *BidiServer) registerExecutor(ctx context.Context, gconn *grpc.ClientConn, session *yamux.Session, fingerprint string) (*SessionOwner, *pb.HelloResponse, error) {
	binding, err := controlsession.NewBinding(b.incarnation)
	if err != nil {
		return nil, nil, fmt.Errorf("create control session identity: %w", err)
	}
	offer := &controlOffer{credentials: controlrpc.Credentials{Binding: binding}, fingerprint: fingerprint, published: make(chan struct{}), confirmed: make(chan struct{}), activated: make(chan struct{})}
	if _, err := rand.Read(offer.credentials.Token[:]); err != nil {
		return nil, nil, fmt.Errorf("create control session token: %w", err)
	}
	b.mu.Lock()
	if b.closed || ctx.Err() != nil {
		b.mu.Unlock()
		return nil, nil, controlrpc.Unavailable()
	}
	b.offers[binding.SessionID] = offer
	b.mu.Unlock()
	published := false
	defer func() {
		if !published {
			b.mu.Lock()
			delete(b.offers, binding.SessionID)
			close(offer.published)
			b.mu.Unlock()
		}
	}()
	client := pb.NewExecutorServiceClient(gconn)
	helloCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	out, err := client.Hello(helloCtx, &pb.HelloRequest{ControlVersion: controlsession.ProtocolVersion, DispatcherIncarnation: binding.Incarnation, SessionId: binding.SessionID, SessionToken: append([]byte(nil), offer.credentials.Token[:]...), LeaseDurationMs: b.lease.Duration.Milliseconds()})
	if err != nil {
		return nil, nil, controlrpc.Unavailable()
	}
	if out.GetControlVersion() != controlsession.ProtocolVersion || out.GetDispatcherIncarnation() != binding.Incarnation || out.GetSessionId() != binding.SessionID || out.GetLeaseDurationMs() != b.lease.Duration.Milliseconds() {
		return nil, nil, controlrpc.Unavailable()
	}
	// The claimed ID is checked against the enrolled node before an owner
	// exists, so a peer that is not this executor replaces nothing.
	if err := b.admitNode(ctx, out.GetExecutorId(), fingerprint, out.GetEnrollmentToken()); err != nil {
		return nil, nil, err
	}
	owner, err := NewSessionOwnerWithClock(out.GetExecutorId(), binding, b.lease.Duration, b.now)
	if err != nil {
		return nil, nil, controlrpc.Unavailable()
	}
	b.mu.Lock()
	if b.closed || ctx.Err() != nil {
		b.mu.Unlock()
		owner.Retire()
		return nil, nil, controlrpc.Unavailable()
	}
	if old, exists := b.clients[owner.ExecutorID()]; exists {
		b.retireLocked(old.owner)
	}
	lane := b.lanes[owner.ExecutorID()]
	if lane == nil {
		lane = &sessionLane{predecessors: make(map[*SessionOwner]struct{})}
		b.lanes[owner.ExecutorID()] = lane
	}
	lane.current = owner
	offer.owner = owner
	b.clients[owner.ExecutorID()] = ExecutorConn{owner: owner, gconn: gconn, client: &boundExecutorClient{client: client, credentials: offer.credentials}, offer: offer, session: session}
	close(offer.published)
	published = true
	b.mu.Unlock()
	return owner, out, nil
}

func (b *BidiServer) stopping() bool {
	select {
	case <-b.stop:
		return true
	default:
		return false
	}
}

// Protocol libraries also close their inputs, so one release is shared and
// repeat callers join it, including while a wrapped Close is still blocked.
type sessionConn struct {
	net.Conn
	once sync.Once
	err  error
}

func (c *sessionConn) Close() error {
	c.once.Do(func() { c.err = c.Conn.Close() })
	return c.err
}

type sessionListener struct {
	net.Listener
	once sync.Once
	err  error
}

func (l *sessionListener) Close() error {
	l.once.Do(func() { l.err = l.Listener.Close() })
	return l.err
}

// remoteIP extracts a bare IP, dropping the port and IPv6 zone.
func remoteIP(addr net.Addr) string {
	if addr == nil {
		return ""
	}
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		host = addr.String()
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return ""
	}
	return ip.WithZone("").Unmap().String()
}
