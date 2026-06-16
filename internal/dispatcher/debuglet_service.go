package dispatcher

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"go.uber.org/zap"
	"golang.org/x/sync/errgroup"
)

func (d *Dispatcher) SubmitDebuglets(ctx context.Context, specs []DebugletSpec) ([]string, error) {
	g, subCtx := errgroup.WithContext(ctx)
	debugletIDS := make([]string, len(specs))

	// =========== SUBMISSION CHECKS ===========
	d.mu.RLock()
	for _, spec := range specs {
		_, exists := d.executors[spec.ExecutorID]
		if !exists {
			d.mu.RUnlock()
			return nil, fmt.Errorf("executor '%s' not found", spec.ExecutorID)
		}
	}
	d.mu.RUnlock()

	// =========== INSERT ===========
	for i, spec := range specs {
		debugletID := uuid.New().String()
		debugletIDS[i] = debugletID
		d.executors[spec.ExecutorID].AppendDebugletID(debugletID)
		g.Go(d.uploadToExecutor(subCtx, i, debugletID, spec))
	}

	if err := g.Wait(); err != nil {
		for i, id := range debugletIDS {
			if err := d.AbortDebuglet(ctx, specs[i].ExecutorID, id, "failed to batch upload all debuglets"); err != nil {
				d.logger.Error("Failed to abort debuglet: " + err.Error())
			}
		}
		return nil, fmt.Errorf("failed to upload debuglets: %w", err)
	}

	return debugletIDS, nil
}

func (d *Dispatcher) uploadToExecutor(ctx context.Context, i int, debugletID string, spec DebugletSpec) func() error {
	d.logger.Debug("Uploading to executor", zap.String("debugletID", debugletID), zap.String("executorID", spec.ExecutorID))
	return func() error {
		if err := d.sender.UploadDebuglet(ctx, debugletID, spec); err != nil {
			return fmt.Errorf("failed to upload debuglet i=%d", i)
		}
		return nil
	}
}

func (d *Dispatcher) AbortDebuglet(ctx context.Context, executorID, debugletID, reason string) error {
	if err := d.sender.AbortDebuglet(ctx, executorID, debugletID, reason); err != nil {
		return errors.New("failed to forward abort to executor")
	}
	return nil
}
