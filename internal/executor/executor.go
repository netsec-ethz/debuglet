// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

// Package executor runs guest programs for one dispatcher control session at a
// time.
//
// A node holds what must survive a reconnect: the packet counter, the TESLA key
// schedule and this executor's configured identity. It reserves one session at a
// time, so a successor exists only after the previous session's cleanup has
// joined. A session owns what belongs to one control binding: the executor
// state, the control transport and the scheduler loop.
//
// The transport decides whether a binding still holds authority. A binding is
// armed while its lease is valid; admission and each step of execution recheck
// it, and the scheduler's insert and start commits are guarded by it, because an
// Allocate reply, a compilation or a STARTED acknowledgement can return after
// the authority that ordered it has expired. Work keeps the
// binding it was admitted under: after a reconnect the successor quarantines the
// rows of the session it replaced instead of running them, and it neither
// delivers nor releases the terminal results that session retained.
//
// Stopping a session cancels running work and starts both cleanup domains, the
// scheduler's and the transport's, before joining either. A bounded Wait that
// expires abandons neither: the local outcome stays unknown, the node
// reservation is kept, and nothing may be deleted, upgraded or closed on the
// strength of it. What storage still holds afterwards is that executor's
// disposition: accepted queued rows stay persisted and are never replayed, and a
// terminal result whose delivery was not acknowledged stays retained for a later
// reconciliation pass under its own binding.
package executor

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/netsec-ethz/debuglet/internal/controlsession"
	"github.com/netsec-ethz/debuglet/internal/executor/config"
	"github.com/netsec-ethz/debuglet/internal/executor/debuglet/socket"
	"github.com/netsec-ethz/debuglet/internal/executor/ratelimit"
	"github.com/netsec-ethz/debuglet/internal/executor/ratelimit/app"
	"github.com/netsec-ethz/debuglet/internal/executor/scheduler"
	"github.com/netsec-ethz/debuglet/internal/executor/tagger/tesla"
	"github.com/netsec-ethz/debuglet/internal/executor/transport/rpc"
	"github.com/netsec-ethz/debuglet/protocol"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"net"
	"os"
	"sync"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"
	"google.golang.org/grpc/credentials"
)

type Executor struct {
	cfg           config.ExecutorConfig
	teslaSchedule *tesla.KeySchedule
	logger        *zap.Logger
	// scheduler is responsible for storing full debuglet specs
	// until the debuglet should be started. It will call OnStart
	// when a debuglet is to be started.
	scheduler   scheduler.Scheduler
	running     map[uuid.UUID]RunningDebuglet
	mu          sync.RWMutex
	limiter     *app.Limiter
	packetCount ratelimit.PacketCount
	iface       *net.Interface
	portManager *socket.PortManager
	// Tests can hold individual resource boundaries; nil uses the real runtime.
	newRuntime func(scheduler.Spec) runtimeDebuglet
	// clientFor is a construction-fixed seam for scripted direct gRPC peers, which
	// answer only the binding they were asked for. Production leaves it nil.
	clientFor func(context.Context, controlsession.Binding) (protocol.DispatcherServiceClient, error)

	// delivering names the runs whose terminal result is being delivered right
	// now, so reporting and reconciliation never settle the same row twice.
	deliveringMu sync.Mutex
	delivering   map[uuid.UUID]struct{}
	// reconcileKick requests one reconciliation pass without waiting for it.
	reconcileKick chan struct{}

	// resourcesOnce resolves the competing readiness outcomes once, whichever of
	// the acknowledgement and the startup failure arrives first.
	resourcesOnce sync.Once
	resourcesDone chan struct{}
	resourcesErr  error // published by closing resourcesDone
	listenMu      sync.Mutex
	listenClosed  bool
	listenWG      sync.WaitGroup

	session *Session
	Bidi    *rpc.BidiClient
}

// newExecutor builds the complete session-local state: every map and channel it
// uses exists before it is published. The daemon node keeps the resources that
// outlive one session, and the session adds the one control transport that
// carries this session's authority.
func newExecutor(node *Node, storage scheduler.Scheduler) (*Executor, error) {
	if storage == nil {
		return nil, errors.New("scheduler is required")
	}
	limiter := app.NewLimiter(node.logger)
	limiter.SetExecutorCapacity(app.Gigabit)
	ports, err := socket.NewPortManager(node.cfg.Network.PublicHost, node.cfg.Network.PublicPorts)
	if err != nil {
		return nil, err
	}
	e := &Executor{cfg: node.cfg, logger: node.logger, teslaSchedule: node.schedule,
		scheduler: storage, running: make(map[uuid.UUID]RunningDebuglet), limiter: limiter,
		packetCount: node.packetCount, iface: node.iface, portManager: ports,
		delivering: make(map[uuid.UUID]struct{}), reconcileKick: make(chan struct{}, 1),
		resourcesDone: make(chan struct{})}
	storage.RegisterOnStart(e.OnDebugletStart)
	storage.RegisterFailed(e.OnDebugletFailed)
	return e, nil
}

func (e *Executor) Listen(parent context.Context) error {
	e.listenMu.Lock()
	if e.listenClosed {
		e.listenMu.Unlock()
		return sessionEnd(controlsession.ParentStopped, context.Canceled)
	}
	e.listenWG.Add(1)
	e.listenMu.Unlock()
	defer e.listenWG.Done()
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	workerDone := make(chan struct{})
	go func() {
		defer close(workerDone)
		if err := e.Bidi.WaitReadyContext(ctx); err != nil {
			e.resolveResources(err)
			return
		}
		binding, ok := e.Bidi.Binding()
		if !ok {
			e.resolveResources(status.Error(codes.FailedPrecondition, "control session unavailable"))
			return
		}
		if err := e.announceResources(ctx, binding); err != nil {
			e.resolveResources(err)
			e.Bidi.Stop(sessionEnd(controlsession.TransportUnavailable, err))
			return
		}
		e.resolveResources(nil)
		// Reconciliation runs here rather than in the heartbeat loop, and is
		// joined below, so no pass outlives the transport and database it uses.
		var passes sync.WaitGroup
		passes.Add(1)
		go func() {
			defer passes.Done()
			e.reconcileLoop(ctx, binding)
		}()
		defer passes.Wait()
		e.startHeartbeatLoop(ctx, binding)
	}()
	defer e.Bidi.Close()
	err := e.Bidi.ConnectAndServe(ctx)
	readyErr := err
	if readyErr == nil {
		readyErr = fmt.Errorf("executor connection closed before Resources acknowledgement")
	}
	e.resolveResources(readyErr)
	cancel()
	<-workerDone
	return err
}

// closeTransport ends this executor's transport ownership: no later Listen can
// start, the control client is closed, and every Listen already running has
// returned before this call does.
func (e *Executor) closeTransport() {
	e.listenMu.Lock()
	e.listenClosed = true
	e.listenMu.Unlock()
	e.Bidi.Close()
	e.listenWG.Wait()
}

// WaitResourcesReady waits for the first successful positive-capacity Resources
// acknowledgement, or the terminal startup error. Discovery heartbeat readiness
// is deliberately a separate dispatcher state.
func (e *Executor) WaitResourcesReady(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-e.resourcesDone:
		if e.resourcesErr != nil {
			return e.resourcesErr
		}
		if e.Bidi != nil {
			binding, ok := e.Bidi.Binding()
			if !ok {
				return status.Error(codes.FailedPrecondition, "control session unavailable")
			}
			return e.Bidi.CheckLease(binding)
		}
		return nil // Standalone readiness-only fixtures own no Bidi transport.
	}
}

func (e *Executor) resolveResources(err error) {
	e.resourcesOnce.Do(func() {
		e.resourcesErr = err
		close(e.resourcesDone)
	})
}

func (e *Executor) setResources(ctx context.Context, binding controlsession.Binding, capacity app.Bitrate) (*protocol.ResourcesResponse, error) {
	client, err := e.dispatcherClient(ctx, binding)
	if err != nil {
		return nil, err
	}
	e.limiter.SetExecutorCapacity(capacity)
	// A capacity change moves the executor share of everything already running.
	e.publishLimits(nil)
	return client.Resources(ctx, &protocol.ResourcesRequest{
		BandwidthCapacity: int64(capacity),
		ExecutorId:        e.cfg.Identity.ExecutorID,
	})
}

// announceResources reports capacity after lease negotiation. Its retries are
// bounded per session, and each call also has its own deadline.
func (e *Executor) announceResources(ctx context.Context, binding controlsession.Binding) error {
	return e.announceResourcesWith(ctx, func(ctx context.Context) error {
		capacity := e.limiter.ExecutorCapacity()
		if capacity <= 0 {
			return fmt.Errorf("cannot announce non-positive executor capacity")
		}
		callCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
		defer cancel()
		_, err := e.setResources(callCtx, binding, capacity)
		return err
	}, func(ctx context.Context) error {
		timer := time.NewTimer(time.Second)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
			return nil
		}
	})
}

// announceResourcesWith keeps production's ten attempts and one-second waits
// behind private seams, so retry and cancellation tests need no sleeps.
func (e *Executor) announceResourcesWith(ctx context.Context, announce, wait func(context.Context) error) error {
	for i := 0; i < 10; i++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := announce(ctx); err == nil {
			e.logger.Info("Announced resources")
			return nil
		} else if i == 9 {
			e.logger.Error("Failed to announce resources", zap.Error(err))
			return fmt.Errorf("announce resources after 10 attempts: %w", err)
		} else {
			e.logger.Debug("Failed to announce resources, retrying", zap.Error(err), zap.Int("attempt", i+1))
		}
		if err := wait(ctx); err != nil {
			return err
		}
	}
	panic("unreachable")
}

func (e *Executor) startHeartbeatLoop(ctx context.Context, binding controlsession.Binding) {
	interval := 30 * time.Second
	if disclosureInterval := e.teslaSchedule.Config().Delay / 2; disclosureInterval < interval {
		interval = disclosureInterval
	}
	e.logger.Info("Starting heartbeat loop", zap.Duration("interval", interval))
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			now := time.Now()
			if e.teslaSchedule.Exhausted(now) {
				e.logger.Error("TESLA key chain exhausted: outgoing packets can no longer be verified; restart the executor or raise tesla.chain_length",
					zap.Time("expired_at", e.teslaSchedule.Expiry()))
			} else if remaining := time.Until(e.teslaSchedule.Expiry()); remaining < time.Hour {
				e.logger.Warn("TESLA key chain nearly exhausted",
					zap.Duration("remaining", remaining),
					zap.Time("expires_at", e.teslaSchedule.Expiry()))
			}
			epoch, key, _ := e.teslaSchedule.DisclosedKey(now)
			req := &protocol.HeartbeatRequest{
				ExecutorId:    e.cfg.Identity.ExecutorID,
				TimestampNs:   now.UnixNano(),
				TeslaKeyEpoch: epoch,
				TeslaKey:      key,
			}

			e.logger.Debug("Sending heartbeat", zap.Time("timestamp", now), zap.Int64("epoch", epoch))
			client, err := e.dispatcherClient(ctx, binding)
			if err == nil {
				callCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
				_, err = client.Heartbeat(callCtx, req)
				cancel()
			}
			if err != nil {
				e.logger.Error("Failed to send heartbeat", zap.Error(err))
			}
			e.kickReconcile()
		}
	}
}

// getClientCredentials loads the executor identity and the roots that verify
// the dispatcher. The returned configuration is used for both control channels:
// directly for the reverse yamux connection, and through gRPC credentials for
// the direct channel, so one name and one trust root cover both. Verification is
// never skipped; an unusable file fails node construction naming the key that
// holds it, before the executor acquires a packet counter or connects anywhere.
//
// The dispatcher name that is verified is tls.server_name when it is set, and
// otherwise the host each channel dials. An omitted credentials.ca_cert keeps
// the host's trust store, which is what a dispatcher certificate issued by a
// public authority needs; a named one replaces it, which is what pinning a
// deployment's own authority means.
func getClientCredentials(cfg *config.ExecutorConfig) (*tls.Config, credentials.TransportCredentials, error) {
	cert, err := tls.LoadX509KeyPair(
		cfg.Credentials.ClientCert,
		cfg.Credentials.ClientKey,
	)
	if err != nil {
		return nil, nil, fmt.Errorf("credentials.client_cert %q with credentials.client_key %q: %w",
			cfg.Credentials.ClientCert, cfg.Credentials.ClientKey, err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
		ServerName:   cfg.TLS.ServerName,
	}
	if cfg.Credentials.CACert != "" {
		roots, err := trustRoots("credentials.ca_cert", cfg.Credentials.CACert, time.Now())
		if err != nil {
			return nil, nil, err
		}
		tlsConfig.RootCAs = roots
	}

	creds := credentials.NewTLS(tlsConfig.Clone())
	return tlsConfig, creds, nil
}

// trustRoots reads the configured authority file and refuses one that cannot
// verify anything: a file holding no certificate, a certificate that does not
// parse, and a root outside its validity window, which would fail every chain
// built on it. A file may hold several roots, which is what an authority
// rotation needs while old and new leaves are both in use.
func trustRoots(field, path string, now time.Time) (*x509.CertPool, error) {
	pemBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", field, err)
	}
	pool := x509.NewCertPool()
	roots := 0
	for rest := pemBytes; ; {
		var block *pem.Block
		if block, rest = pem.Decode(rest); block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		root, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("%s %q: %w", field, path, err)
		}
		if now.Before(root.NotBefore) || now.After(root.NotAfter) {
			return nil, fmt.Errorf("%s %q: authority %q is valid from %s to %s, which does not include %s; renew it before starting",
				field, path, root.Subject.CommonName, root.NotBefore.UTC().Format(time.RFC3339), root.NotAfter.UTC().Format(time.RFC3339), now.UTC().Format(time.RFC3339))
		}
		pool.AddCert(root)
		roots++
	}
	if roots == 0 {
		return nil, fmt.Errorf("%s %q holds no PEM certificate", field, path)
	}
	return pool, nil
}

// dispatcherClient waits for ordinary negotiation without losing the run's
// captured authority. In particular, a due pre-ack Upload stays owned while
// waiting instead of failing Allocate or borrowing a later session.
func (e *Executor) dispatcherClient(ctx context.Context, binding controlsession.Binding) (protocol.DispatcherServiceClient, error) {
	if !binding.Valid() {
		return nil, status.Error(codes.FailedPrecondition, "control session unavailable")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if e.clientFor != nil {
		return e.clientFor(ctx, binding)
	}
	if e.Bidi == nil {
		return nil, status.Error(codes.FailedPrecondition, "control session unavailable")
	}
	if err := e.Bidi.WaitReadyContext(ctx); err != nil {
		return nil, err
	}
	return e.Bidi.ClientFor(binding)
}

// checkControlBinding accepts nothing but the session the transport currently
// holds. The reverse transport has already admitted that session; this guards
// callers that reach a handler directly, and it does not wait for the Bind
// acknowledgement.
func (e *Executor) checkControlBinding(ctx context.Context, binding controlsession.Binding) error {
	if !binding.Valid() {
		return status.Error(codes.FailedPrecondition, "control session unavailable")
	}
	if e.Bidi != nil {
		current, ok := e.Bidi.Binding()
		if !ok || current != binding {
			return status.Error(codes.FailedPrecondition, "control session unavailable")
		}
		return nil
	}
	if e.clientFor != nil {
		_, err := e.clientFor(ctx, binding)
		return err
	}
	return status.Error(codes.FailedPrecondition, "control session unavailable")
}

func (e *Executor) checkExecutionLease(ctx context.Context, binding controlsession.Binding) error {
	if err := ctx.Err(); err != nil {
		return context.Cause(ctx)
	}
	if e.Bidi != nil {
		return e.Bidi.CheckLease(binding)
	}
	// A direct-RPC fixture carries its binding in clientFor and holds no lease.
	if e.clientFor != nil {
		_, err := e.clientFor(ctx, binding)
		return err
	}
	return status.Error(codes.FailedPrecondition, "control session unavailable")
}
