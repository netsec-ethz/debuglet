package executor

import (
	"context"
	"debuglet/internal/executor/config"
	"debuglet/internal/executor/storage"
	"debuglet/internal/executor/transport/rpc"
	"debuglet/pkg/tesla"
	"fmt"
	"time"

	"go.uber.org/zap"
)

type Executor struct {
	cfg           config.Config
	control       *rpc.ControlClient
	teslaSchedule *tesla.KeySchedule
	logger        *zap.Logger
	// storage is responsible for storing full debuglet specs
	// until the debuglet is to be started and then calling OnStart
	storage storage.Storage
	running map[string]*rpc.DebugletClient
}

var _ rpc.ExecutorControlHandler = (*Executor)(nil)

func New(cfg *config.Config, l *zap.Logger, s storage.Storage) (*Executor, error) {
	schedule, err := tesla.NewKeySchedule(tesla.Config{
		Seed:  []byte(cfg.TeslaSeed),
		Delay: time.Duration(cfg.TeslaDelay) * time.Second,
	})

	executor := &Executor{
		teslaSchedule: schedule,
		logger:        l,
		cfg:           *cfg,
		storage:       s,
	}

	s.RegisterOnStart(executor.OnStart)

	client, err := rpc.NewControlClient(cfg, l, executor)
	if err != nil {
		return nil, err
	}
	executor.control = client
	return executor, nil
}

func (e *Executor) Listen(ctx context.Context) error {
	ctx, cancel := context.WithCancelCause(ctx)

	go func() {
		if err := e.control.Listen(ctx); err != nil {
			cancel(fmt.Errorf("failed to open control stream: %w", err))
		}
		e.control.Close()
	}()

	select {
	case <-ctx.Done():
		return context.Cause(ctx)
	case <-e.control.Ready():
	}

	e.hello()
	go e.startHeartbeatLoop(ctx)

	<-ctx.Done()
	return nil
}

func (e *Executor) hello() error {
	h := rpc.Hello{
		ExecutorID:           e.cfg.ExecutorID,
		Version:              e.cfg.Version,
		SourceIP:             "127.0.0.1", // TODO: detect public IP
		TeslaDelay:           e.teslaSchedule.Config().Delay,
		TeslaAnchorTimestamp: e.teslaSchedule.Config().Epoch,
		TeslaAnchorKey:       e.teslaSchedule.Anchor(),
	}
	return e.control.SendHello(h)
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
			if err := e.control.SendHeartbeat(e.teslaSchedule); err != nil {
				e.logger.Error("Failed to send heartbeat", zap.Error(err))
			}
		}
	}
}
