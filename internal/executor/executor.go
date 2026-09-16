// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package executor

import (
	"context"
	"crypto/tls"
	"debuglet/internal/executor/config"
	"debuglet/internal/executor/debuglet/socket"
	"debuglet/internal/executor/ratelimit"
	"debuglet/internal/executor/ratelimit/app"
	"debuglet/internal/executor/scheduler"
	"debuglet/internal/executor/tagger/tesla"
	"debuglet/internal/executor/transport/rpc"
	"debuglet/protocol"
	"fmt"
	"net"
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

	Bidi *rpc.BidiClient
}

func New(cfg *config.ExecutorConfig, l *zap.Logger, s scheduler.Scheduler) (*Executor, error) {
	schedule, err := tesla.NewKeySchedule(tesla.Config{
		Seed:        []byte(cfg.Tesla.Seed),
		Delay:       time.Duration(cfg.Tesla.Delay) * time.Second,
		ChainLength: cfg.Tesla.ChainLength,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create Tesla key schedule: %w", err)
	}
	l.Info("Initialized TESLA key schedule",
		zap.Duration("epoch_length", schedule.Config().Delay),
		zap.Int64("chain_length", schedule.ChainLength()),
		zap.Time("expires_at", schedule.Expiry()))

	var iface *net.Interface
	l.Debug("Network interface for packet counting", zap.String("interface", cfg.Network.Interface))
	if cfg.Network.Interface != "" {
		f, err := net.InterfaceByName(cfg.Network.Interface)
		if err != nil {
			return nil, fmt.Errorf("failed to get '%s' network interface: %w", cfg.Network.Interface, err)
		}
		iface = f
	}
	pc, err := ratelimit.New(iface, l)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize packet count: %w", err)
	}
	l.Info("Initialized packet counter", zap.String("type", pc.Type()))

	limiter := app.NewLimiter(l)
	limiter.SetExecutorCapacity(app.Gigabit)

	portManager, err := socket.NewPortManager(cfg.Network.PublicHost, cfg.Network.PublicPorts)
	if err != nil {
		return nil, fmt.Errorf("invalid public_ports: %w", err)
	}

	e := &Executor{
		teslaSchedule: schedule,
		logger:        l,
		cfg:           *cfg,
		scheduler:     s,
		running:       make(map[uuid.UUID]RunningDebuglet),
		limiter:       limiter,
		packetCount:   pc,
		iface:         iface,
		portManager:   portManager,
	}
	s.RegisterOnStart(e.OnDebugletStart)
	s.RegisterFailed(e.OnDebugletFailed)

	var creds credentials.TransportCredentials
	var tlsCfg *tls.Config
	if !cfg.TLS.Disable {
		tlsCfg, creds, err = getClientCredentials(cfg)
		if err != nil {
			return nil, fmt.Errorf("failed to get client credentials: %w", err)
		}
	}
	opts := rpc.BidiOptions{Logger: l, Address: cfg.Dispatcher.Addr, YamuxAddress: cfg.Dispatcher.YamuxAddr, TLSCreds: creds, TLSConfig: tlsCfg}
	bidi, err := rpc.NewBidiClient(opts, e)
	if err != nil {
		return nil, err
	}
	e.Bidi = bidi
	return e, nil
}

func (e *Executor) Listen(ctx context.Context) error {
	go func() {
		e.Bidi.WaitReady()
		e.announceResources(ctx)
		e.startHeartbeatLoop(ctx)
	}()

	defer e.Bidi.Close()
	return e.Bidi.ConnectAndServe(ctx)
}

func (e *Executor) setResources(ctx context.Context, capacity app.Bitrate) (*protocol.ResourcesResponse, error) {
	e.limiter.SetExecutorCapacity(capacity)
	return e.Bidi.Client.Resources(ctx, &protocol.ResourcesRequest{
		BandwidthCapacity: int64(capacity),
		ExecutorId:        e.cfg.Identity.ExecutorID,
	})
}

// announceResources reports this executor's bandwidth capacity to the
// dispatcher, retrying while the dispatcher does not know us yet.
//
// The control channel becomes ready as soon as the yamux session is up, which
// is before the dispatcher has finished its Hello handshake and registered the
// executor. A single attempt therefore races and can leave the executor
// registered with zero capacity, in which case every debuglet submitted to it
// is rejected as "insufficient capacity" until it reconnects.
func (e *Executor) announceResources(ctx context.Context) {
	const (
		attempts = 10
		backoff  = time.Second
	)
	for i := 0; i < attempts; i++ {
		if _, err := e.setResources(ctx, e.limiter.ExecutorCapacity()); err == nil {
			e.logger.Info("Announced resources", zap.String("capacity", e.limiter.ExecutorCapacity().String()))
			return
		} else if i == attempts-1 {
			e.logger.Error("Failed to announce resources", zap.Error(err))
			return
		} else {
			e.logger.Debug("Failed to announce resources, retrying", zap.Error(err), zap.Int("attempt", i+1))
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
	}
}

func (e *Executor) startHeartbeatLoop(ctx context.Context) {
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
			if _, err := e.Bidi.Client.Heartbeat(ctx, req); err != nil {
				e.logger.Error("Failed to send heartbeat", zap.Error(err))
			}
		}
	}
}

func getClientCredentials(cfg *config.ExecutorConfig) (*tls.Config, credentials.TransportCredentials, error) {
	cert, err := tls.LoadX509KeyPair(
		cfg.Credentials.ClientCert,
		cfg.Credentials.ClientKey,
	)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to load client certificate: %w", err)
	}

	tlsConfig := &tls.Config{
		Certificates:       []tls.Certificate{cert},
		InsecureSkipVerify: true, // skip server cert verification - insecure! TODO: server authentication
	}

	creds := credentials.NewTLS(tlsConfig.Clone())
	return tlsConfig, creds, nil
}
