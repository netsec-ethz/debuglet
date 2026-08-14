package dispatcher

import (
	"context"
	"debuglet/internal/dispatcher/database/ddb"
	"debuglet/internal/dispatcher/models"
	"debuglet/internal/dispatcher/resource"
	"debuglet/internal/dispatcher/resource/schedule"
	pb "debuglet/protocol"
	"fmt"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"
	"golang.org/x/sync/errgroup"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func (d *Dispatcher) SubmitDebuglets(ctx context.Context, specs []models.DebugletSpec) ([]string, error) {
	g, subCtx := errgroup.WithContext(ctx)
	// debuglet IDs in the same order as the submission
	debugletIDS := make([]string, len(specs))

	d.mu.Lock()

	var stores []DebugletStore
	var sreqs []schedule.Request

	// =========== SUBMISSION CHECKS ===========
	for i := range specs {
		if store, r, err := d.validateDebugletSpec(&specs[i]); err != nil {
			d.mu.Unlock()
			return nil, fmt.Errorf("invalid debuglet spec (i=%d): %w", i, err)
		} else {
			debugletID := uuid.New().String()
			debugletIDS[i] = debugletID
			stores = append(stores, *store)
			sreqs = append(sreqs, *r)
		}
	}

	// =========== INSERT ===========
	// If any debuglets fail to be uploaded, the whole request fails and all debuglets are aborted
	tx, err := d.db.BeginTx(ctx, nil)
	if err != nil {
		d.mu.Unlock()
		return nil, fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	qtx := ddb.New(d.db).WithTx(tx)
	for i, store := range stores {
		if _, err := qtx.CreateDebuglet(ctx, ddb.CreateDebugletParams{
			ID:         debugletIDS[i],
			StartTime:  models.NewUTCTime(store.From),
			EndTime:    models.NewUTCTime(store.To),
			ExecutorID: store.ExecutorID,
			Usage:      int64(store.Policy.FloorBW),
			State:      store.State,
			Addresses:  store.Policy.Addresses,
		}); err != nil {
			d.mu.Unlock()
			return nil, fmt.Errorf("failed to create debuglet in database: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		d.mu.Unlock()
		return nil, fmt.Errorf("failed to commit transaction: %w", err)
	}

	for i, store := range stores {
		d.executors[store.ExecutorID].AppendDebugletID(debugletIDS[i])
		d.debugletStores[debugletIDS[i]] = &store
		d.scheduler.Submit(sreqs[i])
		g.Go(d.uploadToExecutor(subCtx, i, debugletIDS[i], specs[i]))
	}

	d.mu.Unlock()

	if err := g.Wait(); err != nil {
		for i, id := range debugletIDS {
			// TODO: cleanup the database and scheduler for the aborted debuglets
			if err := d.AbortDebuglet(context.Background(), specs[i].ExecutorID, id, "failed to batch upload all debuglets"); err != nil {
				d.logger.Error("Failed to abort debuglet: " + err.Error())
			}
		}
		return nil, fmt.Errorf("failed to upload debuglets: %w", err)
	}

	return debugletIDS, nil
}

func (d *Dispatcher) validateDebugletSpec(spec *models.DebugletSpec) (*DebugletStore, *schedule.Request, error) {
	now := time.Now()

	p := spec.Policy
	if p.FloorBW > p.CeilBW {
		return nil, nil, fmt.Errorf("floorBW (%s) greater than ceilBW (%s)", p.FloorBW.String(), p.CeilBW.String())
	}
	// ignore passed start times and set them to 'now'
	if spec.StartTime != nil && spec.StartTime.Before(time.Now()) {
		spec.StartTime = nil
	}

	exec, exists := d.executors[spec.ExecutorID]
	if !exists {
		return nil, nil, fmt.Errorf("executor '%s' not found", spec.ExecutorID)
	}

	if (spec.Policy.RequireICMP || spec.Policy.ListenICMP) && !exec.ICMPEnabled {
		return nil, nil, fmt.Errorf("executor '%s' does not support ICMP, but policy requires it", spec.ExecutorID)
	}

	if spec.Policy.ListenTCP && exec.PublicHost() == "" {
		return nil, nil, fmt.Errorf("executor '%s' has no public host, but policy requires a TCP listener", spec.ExecutorID)
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

	store := DebugletStore{
		Policy:     spec.Policy,
		ExecutorID: spec.ExecutorID,
		State:      models.RunStateUploading,
		From:       from,
		To:         to,
	}
	r := schedule.Request{
		Executor:    spec.ExecutorID,
		Destination: spec.Policy.Addresses,
		From:        from,
		To:          to,
		Use:         spec.Policy.FloorBW,
	}

	if d.scheduler.QueryMaxExec(r.Executor, from, to)+r.Use > exec.capacity {
		return nil, nil, fmt.Errorf("time [%s, %s] executor '%s' capacity exceeded: %w", from, to, exec.ID, resource.ErrCapacityFull)
	}

	for _, dest := range spec.Policy.Addresses {
		if d.scheduler.QueryMaxDest(dest, from, to)+r.Use > d.destinations.Cap(dest) {
			return nil, nil, fmt.Errorf("time [%s, %s] destination '%s' capacity exceeded: %w", from, to, dest, resource.ErrCapacityFull)
		}
	}

	return &store, &r, nil
}

func (d *Dispatcher) uploadToExecutor(ctx context.Context, i int, debugletID string, spec models.DebugletSpec) func() error {
	return func() error {
		d.logger.Debug("Uploading to executor", zap.String("debugletID", debugletID), zap.String("executorID", spec.ExecutorID))
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
				FloorBw:     int64(spec.Policy.FloorBW),
				CeilBw:      int64(spec.Policy.CeilBW),
				TimeoutMs:   int64(spec.Policy.Timeout.Milliseconds()),
				Addresses:   spec.Policy.Addresses,
				RequireIcmp: spec.Policy.RequireICMP,
				ListenUdp:   spec.Policy.ListenUDP,
				ListenTcp:   spec.Policy.ListenTCP,
				ListenIcmp:  spec.Policy.ListenICMP,
				ListenScion: spec.Policy.ListenSCION,
			},
		}
		if _, err := client.Upload(ctx, req); err != nil {
			return fmt.Errorf("failed to upload debuglet i=%d: %w", i, err)
		}
		d.logger.Debug("Upload successful", zap.String("debugletID", debugletID), zap.String("executorID", spec.ExecutorID))

		d.mu.Lock()
		d.debugletStores[debugletID].State = models.RunStateUploaded
		d.mu.Unlock()

		queries := ddb.New(d.db)
		if _, err := queries.UpdateDebugletState(ctx, ddb.UpdateDebugletStateParams{
			ID:    debugletID,
			State: models.RunStateUploaded,
		}); err != nil {
			return fmt.Errorf("failed to update debuglet state in database: %w", err)
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
