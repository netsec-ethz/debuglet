package dispatcher

import (
	"context"
	pb "debuglet/protocol"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"
	"golang.org/x/sync/errgroup"
)

func (d *Dispatcher) SubmitDebuglets(ctx context.Context, specs []DebugletSpec) ([]string, error) {
	g, subCtx := errgroup.WithContext(ctx)
	debugletIDS := make([]string, len(specs))

	// =========== SUBMISSION CHECKS ===========
	err := func() error {
		d.mu.RLock()
		defer d.mu.RUnlock()

		for _, spec := range specs {
			p := spec.Policy
			if p.FloorBW > p.CeilBW {
				return fmt.Errorf("floorBW (%s) greater than ceilBW (%s)", p.FloorBW.String(), p.CeilBW.String())
			}
			if spec.StartTime != nil && spec.StartTime.Before(time.Now()) {
				spec.StartTime = nil
			}

			_, exists := d.executors[spec.ExecutorID]
			if !exists {
				return fmt.Errorf("executor '%s' not found", spec.ExecutorID)
			}
		}
		return nil
	}()
	if err != nil {
		return nil, err
	}

	// =========== INSERT ===========
	d.mu.Lock()
	for i, spec := range specs {
		debugletID := uuid.New().String()
		debugletIDS[i] = debugletID
		d.executors[spec.ExecutorID].AppendDebugletID(debugletID)
		d.debugletStores[debugletID] = &DebugletStore{
			Logs:       []byte{},
			Policy:     spec.Policy,
			ExecutorID: spec.ExecutorID,
			State:      RunStateUploading,
		}
		g.Go(d.uploadToExecutor(subCtx, i, debugletID, spec))
	}
	d.mu.Unlock()

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
	d.OnDebugletExit(ctx, &pb.DebugletExitRequest{DebugletId: debugletID, ExitCode: -1, ErrorMessage: &reason})
	return nil
}
