package dispatcher

import (
	"context"
	pb "debuglet/protocol"
	"fmt"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"
	"golang.org/x/sync/errgroup"
	"google.golang.org/protobuf/types/known/timestamppb"
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
		client, ok := d.Bidi.GetClient(spec.ExecutorID)
		if !ok {
			return fmt.Errorf("executor '%s' not connected", spec.ExecutorID)
		}
		var startTime *timestamppb.Timestamp
		if spec.StartTime != nil {
			startTime = timestamppb.New(*spec.StartTime)
		}
		req := &pb.UploadRequest{
			Id:        debugletID,
			StartTime: startTime,
			Args:      spec.Args,
			Wasm:      spec.Wasm,
			Policy: &pb.DebugletPolicy{
				FloorBw:   int64(spec.Policy.FloorBW),
				CeilBw:    int64(spec.Policy.CeilBW),
				TimeoutMs: int64(spec.Policy.Timeout.Milliseconds()),
				Addresses: spec.Policy.Addresses,
			},
		}
		if _, err := client.Upload(ctx, req); err != nil {
			return fmt.Errorf("failed to upload debuglet i=%d: %w", i, err)
		}
		return nil
	}
}

func (d *Dispatcher) AbortDebuglet(ctx context.Context, executorID, debugletID, reason string) error {
	client, ok := d.Bidi.GetClient(executorID)
	if !ok {
		return fmt.Errorf("executor '%s' not connected", executorID)
	}
	if _, err := client.Abort(ctx, &pb.AbortRequest{DebugletId: debugletID, Reason: reason}); err != nil {
		return fmt.Errorf("failed to abort debuglet: %w", err)
	}
	d.OnDebugletExit(ctx, &pb.DebugletExitRequest{DebugletId: debugletID, ExitCode: -1, ErrorMessage: &reason})
	return nil
}
