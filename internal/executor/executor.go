package executor

import (
	"context"
	"debuglet/internal/executor/config"
	"debuglet/internal/executor/db"
	"debuglet/internal/executor/transport"
	"debuglet/pkg/tesla"
	"errors"
	"time"

	"go.uber.org/zap"
)

type Executor struct {
	cfg           config.Config
	control       *transport.ControlClient
	teslaSchedule *tesla.KeySchedule
	logger        *zap.Logger
	// storage is responsible for storing full debuglet specs
	// until the debuglet is to be started and then calling OnStart
	storage db.Storage
}

var _ transport.ControlHandler = (*Executor)(nil)

func New(cfg *config.Config, l *zap.Logger, s db.Storage) (*Executor, error) {
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

	client, err := transport.NewControlClient(cfg, l, executor)
	if err != nil {
		return nil, err
	}
	executor.control = client
	return executor, nil
}

func (e *Executor) Start(ctx context.Context) error {
	ctx, cancel := context.WithCancelCause(ctx)

	errCh := make(chan error, 1)
	go func() {
		errCh <- e.control.Listen(ctx)
		cancel(errors.New("failed to open control stream"))
		e.control.Close()
	}()

	if err := e.control.Wait(ctx); err != nil {
		return err
	}
	e.hello()
	go e.startHeartbeatLoop(ctx)

	return <-errCh
}

func (e *Executor) hello() error {
	h := transport.Hello{
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
