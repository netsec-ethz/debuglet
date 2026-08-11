package dispatcher

import (
	"context"
	"debuglet/internal/dispatcher/resource/schedule"
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
	// debuglet IDs in the same order as the submission
	debugletIDS := make([]string, len(specs))

	d.mu.Lock()

	now := time.Now()
	var stores []DebugletStore
	var sreqs []schedule.Request

	// =========== SUBMISSION CHECKS ===========
	err := func() error {
		for i, spec := range specs {
			p := spec.Policy
			if p.FloorBW > p.CeilBW {
				return fmt.Errorf("floorBW (%s) greater than ceilBW (%s)", p.FloorBW.String(), p.CeilBW.String())
			}
			// ignore passed start times and set them to 'now'
			if spec.StartTime != nil && spec.StartTime.Before(time.Now()) {
				spec.StartTime = nil
				specs[i] = spec
			}

			exec, exists := d.executors[spec.ExecutorID]
			if !exists {
				return fmt.Errorf("executor '%s' not found", spec.ExecutorID)
			}

			// Create the stores and determine if the range [from,to] has enough capacity
			var from time.Time
			if spec.StartTime == nil {
				from = now
			} else {
				from = *spec.StartTime
			}
			// NOTE: We add another 10 negligible seconds to account for any potential delays in the executor's processing time
			to := from.Add(spec.Policy.Timeout).Add(10 * time.Second)

			debugletID := uuid.New().String()
			debugletIDS[i] = debugletID
			stores = append(stores, DebugletStore{
				Logs:       []byte{},
				Policy:     spec.Policy,
				ExecutorID: spec.ExecutorID,
				State:      RunStateUploading,
				From:       from,
				To:         to,
			})
			r := schedule.Request{
				Executor:    spec.ExecutorID,
				Destination: spec.Policy.Addresses,
				From:        from,
				To:          to,
				Use:         spec.Policy.FloorBW,
			}
			sreqs = append(sreqs, r)

			if d.scheduler.QueryMaxExec(r.Executor, from, to)+r.Use > exec.capacity {
				return fmt.Errorf("time [%s, %s] executor '%s' capacity exceeded: %w", from, to, exec.ID, ErrNoCapacity)
			}

			for _, dest := range spec.Policy.Addresses {
				if d.scheduler.QueryMaxDest(dest, from, to)+r.Use > d.destinations.Cap(dest) {
					return fmt.Errorf("time [%s, %s] destination '%s' capacity exceeded: %w", from, to, dest, ErrNoCapacity)
				}
			}
		}

		return nil
	}()
	if err != nil {
		d.mu.Unlock()
		return nil, err
	}

	// =========== INSERT ===========
	for i, store := range stores {
		d.executors[store.ExecutorID].AppendDebugletID(debugletIDS[i])
		d.debugletStores[debugletIDS[i]] = &store
		d.scheduler.Submit(sreqs[i])
		g.Go(d.uploadToExecutor(subCtx, i, debugletIDS[i], specs[i]))
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
			Id:            debugletID,
			TransactionId: spec.TransactionID,
			StartTime:     startTime,
			Args:          spec.Args,
			Wasm:          spec.Wasm,
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
