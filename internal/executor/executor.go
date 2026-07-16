package executor

import (
	"context"
	"crypto/tls"
	"debuglet/internal/executor/config"
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

	"go.uber.org/zap"
	"google.golang.org/grpc/credentials"
)

type Executor struct {
	cfg           config.Config
	teslaSchedule *tesla.KeySchedule
	logger        *zap.Logger
	// scheduler is responsible for storing full debuglet specs
	// until the debuglet should be started. It will call OnStart
	// when a debuglet is to be started.
	scheduler   scheduler.Scheduler
	running     map[string]RunningDebuglet
	mu          sync.RWMutex
	limiter     *app.Limiter
	packetCount ratelimit.PacketCount
	iface       *net.Interface

	Bidi *rpc.BidiClient
}

func New(cfg *config.Config, l *zap.Logger, s scheduler.Scheduler) (*Executor, error) {
	schedule, err := tesla.NewKeySchedule(tesla.Config{
		Seed:  []byte(cfg.TeslaSeed),
		Delay: time.Duration(cfg.TeslaDelay) * time.Second,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create Tesla key schedule: %w", err)
	}

	var iface *net.Interface
	if cfg.NetworkInterface != "" {
		f, err := net.InterfaceByName(cfg.NetworkInterface)
		if err != nil {
			return nil, fmt.Errorf("failed to get '%s' network interface: %w", cfg.NetworkInterface, err)
		}
		iface = f
	}
	pc, err := ratelimit.New(iface)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize packet count: %w", err)
	}
	l.Info("Initialized packet counter", zap.String("type", pc.Type()))

	limiter := app.NewLimiter(l)
	limiter.SetExecutorCapacity(app.Gigabit)

	e := &Executor{
		teslaSchedule: schedule,
		logger:        l,
		cfg:           *cfg,
		scheduler:     s,
		running:       make(map[string]RunningDebuglet),
		limiter:       limiter,
		packetCount:   pc,
	}
	s.RegisterOnStart(e.OnDebugletStart)

	var creds credentials.TransportCredentials
	var tlsCfg *tls.Config
	if !cfg.DisableTLS {
		tlsCfg, creds, err = getClientCredentials(cfg)
		if err != nil {
			return nil, fmt.Errorf("failed to get client credentials: %w", err)
		}
	}
	opts := rpc.BidiOptions{Logger: l, Address: cfg.DispatcherAddr, YamuxAddress: cfg.DispatcherYamuxAddr, TLSCreds: creds, TLSConfig: tlsCfg}
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
		if _, err := e.setResources(ctx, e.limiter.ExecutorCapacity()); err != nil {
			e.logger.Error("Failed to announce resources", zap.Error(err))
		}
		e.startHeartbeatLoop(ctx)
	}()

	defer e.Bidi.Close()
	return e.Bidi.ConnectAndServe(ctx)
}

func (e *Executor) setResources(ctx context.Context, capacity app.Bitrate) (*protocol.ResourcesResponse, error) {
	e.limiter.SetExecutorCapacity(capacity)
	return e.Bidi.Client.Resources(ctx, &protocol.ResourcesRequest{BandwidthCapacity: int64(capacity)})
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
			epoch, key, _ := e.teslaSchedule.DisclosedKey(now)
			req := &protocol.HeartbeatRequest{
				ExecutorId:    e.cfg.ExecutorID,
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

func getClientCredentials(cfg *config.Config) (*tls.Config, credentials.TransportCredentials, error) {
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
