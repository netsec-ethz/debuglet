package executor

import (
	"context"
	"debuglet/internal/executor/config"
	"debuglet/internal/executor/transport"

	"go.uber.org/zap"
)

type Executor struct {
	control *transport.ControlClient
}

func New(cfg *config.Config, logger *zap.Logger) (*Executor, error) {
	executor := &Executor{}

	client, err := transport.NewControlClient(cfg, logger, executor)
	if err != nil {
		return nil, err
	}
	executor.control = client
	return executor, nil
}

func (e *Executor) Start(ctx context.Context) error {
	return e.control.Listen(ctx)
}
