// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package rpc

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"github.com/netsec-ethz/debuglet/internal/controlrpc"
	"github.com/netsec-ethz/debuglet/internal/controlsession"
	pb "github.com/netsec-ethz/debuglet/protocol"
	"io"
	"net"
	"sync"
	"time"

	"github.com/hashicorp/yamux"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/reflection"
)

const bindConfirmationTimeout = 5 * time.Second

type BidiOptions struct {
	Logger       *zap.Logger
	Address      string
	YamuxAddress string
	TLSCreds     credentials.TransportCredentials
	TLSConfig    *tls.Config
	// Receiver-local clock seams fixed at construction; production uses Go time.
	LeaseNow       func() time.Time
	NewLeaseTicker func(time.Duration) (<-chan time.Time, func())
}

// BidiClient connects to the dispatcher and sets up a bidirectional stream allowing
// for the dispatcher to call the executor's gRPC server's methods.
//
// It is the one authority over this executor's control binding: the binding is
// armed when Bind is sent inside the startup deadline, renewed only by an
// acknowledgement of this client's own renewal and counted from the moment that
// renewal was sent, and revoked once, keeping the cause that revoked it.
// Admission and each step of execution recheck that authority, and the
// scheduler's insert and start commits (CommitUpload, CommitLease) are guarded
// by it atomically, so a reply arriving after the lease ran out starts nothing.
// A client is bound once; direct senders use ClientFor after negotiation.
type BidiClient struct {
	client              pb.DispatcherServiceClient
	mu                  sync.Mutex
	started             bool
	closed              bool
	invocations         sync.WaitGroup
	control             *controlrpc.Credentials
	armed               bool
	hello               *pb.HelloResponse
	helloErr            error
	helloDone           chan struct{}
	offered             chan struct{}
	serving             chan struct{}
	negotiated          bool
	confirmationTimeout time.Duration
	startupTimeout      time.Duration
	startupDeadline     time.Time
	bindDeadline        time.Time
	deadline            time.Time
	lease               controlsession.LeaseTiming
	sequence            uint64
	cause               error
	now                 func() time.Time
	newLeaseTicker      func(time.Duration) (<-chan time.Time, func())
	grpcServer          *grpc.Server
	gconn               *grpc.ClientConn
	opts                BidiOptions
	state               ExecutorState
	ready               chan struct{}
	done                chan struct{}
	serveErr            error // published by closing done
	stop                chan struct{}
	closeOnce           sync.Once
	grpcStopOnce        sync.Once
}

func NewBidiClient(opts BidiOptions, state ExecutorState) (*BidiClient, error) {
	// The direct channel takes its security from TLSCreds and the reverse
	// channel from TLSConfig. Each falls back to cleartext on its own, so a
	// caller that sets one and not the other would connect one verified and one
	// plaintext channel to the same dispatcher without either side saying so.
	if (opts.TLSConfig == nil) != (opts.TLSCreds == nil) {
		return nil, errors.New("control transport needs a TLS profile and its credentials together, or neither: the direct and reverse channels cannot differ")
	}
	grpcServer := grpc.NewServer(
		grpc.WaitForHandlers(true),
		grpc.MaxRecvMsgSize(32*1024*1024),
		grpc.MaxSendMsgSize(32*1024*1024),
	)

	grpcCreds := insecure.NewCredentials()
	if opts.TLSCreds != nil {
		grpcCreds = opts.TLSCreds
	}
	gconn, err := grpc.NewClient(opts.Address, grpc.WithTransportCredentials(grpcCreds))
	if err != nil {
		return nil, err
	}

	if opts.YamuxAddress == "" {
		opts.YamuxAddress = opts.Address
	}

	now := opts.LeaseNow
	if now == nil {
		now = time.Now
	}
	ticker := opts.NewLeaseTicker
	if ticker == nil {
		ticker = func(period time.Duration) (<-chan time.Time, func()) { t := time.NewTicker(period); return t.C, t.Stop }
	}
	b := &BidiClient{
		client:              pb.NewDispatcherServiceClient(gconn),
		helloDone:           make(chan struct{}),
		offered:             make(chan struct{}),
		confirmationTimeout: bindConfirmationTimeout,
		startupTimeout:      preOfferTimeout,
		now:                 now,
		newLeaseTicker:      ticker,
		serving:             make(chan struct{}),
		grpcServer:          grpcServer,
		gconn:               gconn,
		opts:                opts,
		state:               state,
		ready:               make(chan struct{}),
		done:                make(chan struct{}),
		stop:                make(chan struct{}),
	}
	pb.RegisterExecutorServiceServer(grpcServer, &server{state: state, bidi: b})
	reflection.Register(grpcServer)
	return b, nil
}

func (b *BidiClient) Close() {
	b.closeOnce.Do(func() {
		b.Stop(nil)
		b.gconn.Close()
		b.stopGRPC()
		b.invocations.Wait()
	})
}

// stopGRPC starts forceful transport stopping after two seconds. Joining the
// graceful-stop worker still depends on RPC handlers returning; a handler that
// ignores cancellation can outlive that grace period. The demo supervisor owns
// the separate hard process-lifetime deadline.
func (b *BidiClient) stopGRPC() {
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

// WaitReadyContext also resolves when the initial connection fails. Readiness
// describes completed Hello/Bind negotiation, not a Resources acknowledgement.
func (b *BidiClient) WaitReadyContext(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-b.stop:
		return b.Cause()
	case <-b.ready:
		b.mu.Lock()
		defer b.mu.Unlock()
		return b.leaseLocked(b.control.Binding, false)
	}
}

// Binding includes the live armed pre-acknowledgement Upload interval.
func (b *BidiClient) Binding() (controlsession.Binding, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.control == nil {
		return controlsession.Binding{}, false
	}
	if err := b.leaseLocked(b.control.Binding, true); err != nil {
		return controlsession.Binding{}, false
	}
	return b.control.Binding, true
}

func (b *BidiClient) ClientFor(binding controlsession.Binding) (pb.DispatcherServiceClient, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if err := b.leaseLocked(binding, false); err != nil {
		return nil, err
	}
	return &boundDispatcherClient{client: b.client, credentials: *b.control, owner: b}, nil
}

// stopFor selects the caller's already-observed cancellation before a newly
// detected transport error. Once another cause was selected it stays immutable.
func (b *BidiClient) stopFor(parent context.Context, kind controlsession.EndKind, err error) {
	if parent.Err() != nil {
		kind, err = controlsession.ParentStopped, context.Cause(parent)
	}
	b.Stop(endCause(kind, err))
}

// ConnectAndServe owns one invocation and all renewal, watchdog, serving and
// cancellation helpers. Lost is independent of the joins in its finalizer.
func (b *BidiClient) ConnectAndServe(parent context.Context) (result error) {
	b.mu.Lock()
	if b.started || b.closed {
		b.mu.Unlock()
		return controlrpc.Unavailable()
	}
	b.started = true
	b.startupDeadline = b.now().Add(b.startupTimeout)
	b.invocations.Add(1)
	b.mu.Unlock()
	defer b.invocations.Done()
	ctx, cancel := context.WithCancel(parent)
	watchDone, leaseDone, renewDone := make(chan struct{}), make(chan struct{}), make(chan struct{})
	go func() {
		defer close(watchDone)
		select {
		case <-parent.Done():
			b.stopFor(parent, controlsession.ParentStopped, context.Cause(parent))
		case <-b.stop:
		}
		cancel()
	}()
	go b.watchLease(ctx, leaseDone)
	go b.renewLoop(ctx, renewDone)
	var conn net.Conn
	var session *yamux.Session
	var ioDone, serveDone, bindDone chan struct{}
	defer func() {
		if result == nil {
			result = io.EOF
		}
		b.stopFor(parent, controlsession.TransportUnavailable, result)
		cancel()
		// Signal is already published, so a blocked handler cannot hide loss from
		// the session owner which must cancel its scheduler in parallel.
		b.gconn.Close()
		if session != nil {
			session.Close()
		}
		if conn != nil {
			conn.Close()
		}
		b.stopGRPC()
		if serveDone != nil {
			<-serveDone
		}
		if bindDone != nil {
			<-bindDone
		}
		if ioDone != nil {
			<-ioDone
		}
		<-leaseDone
		<-renewDone
		<-watchDone
		result = b.Cause()
		b.serveErr = result
		close(b.done)
	}()
	var err error
	if b.opts.TLSConfig != nil {
		d := tls.Dialer{Config: b.opts.TLSConfig}
		conn, err = d.DialContext(ctx, "tcp", b.opts.YamuxAddress)
	} else {
		d := net.Dialer{}
		conn, err = d.DialContext(ctx, "tcp", b.opts.YamuxAddress)
	}
	if err != nil {
		return fmt.Errorf("connect dispatcher yamux: %w", err)
	}
	ioDone = make(chan struct{})
	go func() { defer close(ioDone); <-ctx.Done(); conn.Close() }()
	session, err = yamux.Client(conn, nil)
	if err != nil {
		return fmt.Errorf("create yamux session: %w", err)
	}
	if _, err = session.Ping(); err != nil {
		return fmt.Errorf("ping yamux session: %w", err)
	}
	serveDone = make(chan struct{})
	var serveErr error
	go func() { defer close(serveDone); close(b.serving); serveErr = b.grpcServer.Serve(session) }()
	bindDone = make(chan struct{})
	go func() { defer close(bindDone); b.confirmLease(ctx, parent) }()
	select {
	case <-ctx.Done():
		return context.Cause(ctx)
	case <-serveDone:
		if serveErr != nil {
			return fmt.Errorf("grpc callback server exited: %w", serveErr)
		}
		return io.EOF
	}
}

func (b *BidiClient) confirmLease(ctx, parent context.Context) {
	select {
	case <-b.offered:
	case <-ctx.Done():
		return
	}
	b.mu.Lock()
	if b.closed || ctx.Err() != nil {
		b.mu.Unlock()
		return
	}
	sent := b.now()
	if !sent.Before(b.startupDeadline) {
		b.stopLocked(endCause(controlsession.TransportUnavailable, context.DeadlineExceeded))
		b.mu.Unlock()
		return
	}
	b.deadline = sent.Add(b.lease.Duration)
	b.bindDeadline = sent.Add(min(b.confirmationTimeout, b.lease.Duration))
	b.armed = true // Same guard as the first Bind-send deadline; Hello alone cannot admit.
	credentials := *b.control
	executorID := b.hello.GetExecutorId()
	duration := b.lease.Duration
	timeout := min(b.confirmationTimeout, duration)
	b.mu.Unlock()
	bindCtx, cancel := context.WithTimeout(ctx, timeout)
	ack, err := b.client.BindSession(credentials.Outgoing(bindCtx), &pb.BindSessionRequest{ExecutorId: executorID})
	defer cancel()
	callErr := bindCtx.Err()
	if err != nil || callErr != nil {
		kind := controlsession.TransportUnavailable
		if observedUnsupported(err) {
			kind = controlsession.IncompatibleProfile
		}
		if callErr != nil {
			err = callErr
		}
		b.stopFor(parent, kind, credentials.RedactError(err))
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if bindCtx.Err() != nil {
		kind, cause := controlsession.TransportUnavailable, error(bindCtx.Err())
		if parent.Err() != nil {
			kind, cause = controlsession.ParentStopped, context.Cause(parent)
		}
		b.stopLocked(endCause(kind, cause))
		return
	}
	if b.leaseLocked(credentials.Binding, true) != nil {
		return
	}
	if ctx.Err() != nil {
		b.stopLocked(endCause(controlsession.ParentStopped, context.Cause(parent)))
		return
	}
	if ack.GetLeaseDurationMs() != duration.Milliseconds() {
		b.stopLocked(endCause(controlsession.LocalFailure, fmt.Errorf("invalid initial control lease acknowledgement")))
		return
	}
	// Promote the original pending deadline; receiving an ACK never restarts it.
	b.negotiated = true
	close(b.ready)
}
