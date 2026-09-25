// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package dispatcher

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/database"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/models"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/resource"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/resource/schedule"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/transport/rpc"
	pb "github.com/netsec-ethz/debuglet/protocol"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"math"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"
	"golang.org/x/sync/errgroup"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func (d *Dispatcher) SubmitDebuglets(ctx context.Context, specs []models.DebugletSpec, userID *uuid.UUID) (uuid.UUIDs, error) {
	if err := AdmissionPaused(); err != nil {
		return nil, err
	}
	g, subCtx := errgroup.WithContext(ctx)
	// debuglet IDs in the same order as the submission
	debugletIDS := make(uuid.UUIDs, len(specs))
	selected := make([]*submissionOwner, len(specs))
	// Every return below releases d.mu first: finishing a mutation cancels and
	// joins its watcher, and must never run under the map/transaction lock.
	defer func() {
		for _, selection := range selected {
			if selection != nil {
				selection.mutation.Finish()
			}
		}
	}()

	d.mu.Lock()
	if d.closed {
		d.mu.Unlock()
		return nil, ErrDispatcherClosed
	}

	var sreqs []schedule.Request
	rollbackReservations := func() {
		for i := len(sreqs) - 1; i >= 0; i-- {
			d.scheduler.Remove(sreqs[i])
		}
		sreqs = nil
	}
	failLocked := func() {
		rollbackReservations()
		d.mu.Unlock()
	}

	// =========== SUBMISSION CHECKS ===========
	for i := range specs {
		if r, err := d.validateDebugletSpec(&specs[i]); err != nil {
			failLocked()
			return nil, fmt.Errorf("invalid debuglet spec (i=%d): %w", i, err)
		} else {
			entry := d.executors[specs[i].ExecutorID]
			mutation, admitErr := entry.owner.AdmitMutation(ctx)
			if admitErr != nil {
				failLocked()
				return nil, admitErr
			}
			selected[i] = &submissionOwner{owner: entry.owner, mutation: mutation, entry: entry}
			debugletIDS[i] = uuid.New()
			sreqs = append(sreqs, *r)
			d.scheduler.Submit(*r)
		}
	}

	// =========== INSERT ===========
	// If any debuglets fail to be uploaded, the whole request fails and all debuglets are aborted
	tx, err := d.db.BeginTx(ctx, nil)
	if err != nil {
		failLocked()
		return nil, fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	qtx := database.New(d.db).WithTx(tx)
	for i := range sreqs {
		if _, err := qtx.CreateDebuglet(ctx, database.CreateDebugletParams{
			Uuid:                  debugletIDS[i],
			StartTime:             models.NewUTCTime(sreqs[i].From),
			EndTime:               models.NewUTCTime(sreqs[i].To),
			ExecutorID:            specs[i].ExecutorID,
			Usage:                 int64(specs[i].Policy.FloorBW),
			CeilBw:                int64(specs[i].Policy.CeilBW),
			State:                 models.RunStateUploading,
			Addresses:             specs[i].Policy.Addresses,
			TransactionID:         specs[i].TransactionID,
			OrderID:               specs[i].OrderID,
			DispatcherIncarnation: selected[i].owner.Binding().Incarnation,
			SessionID:             selected[i].owner.Binding().SessionID,
		}); err != nil {
			failLocked()
			return nil, fmt.Errorf("failed to create debuglet in database: %w", err)
		}

		if userID != nil {
			if err := qtx.InsertDebugletUser(ctx, database.InsertDebugletUserParams{
				DebUuid:  debugletIDS[i],
				UserUuid: *userID,
			}); err != nil {
				failLocked()
				return nil, fmt.Errorf("failed to associate debuglet with user in database: %w", err)
			}
		}
	}

	if err := tx.Commit(); err != nil {
		failLocked()
		return nil, fmt.Errorf("failed to commit transaction: %w", err)
	}

	for i := range sreqs {
		selected[i].entry.AppendDebugletID(debugletIDS[i])
	}

	d.mu.Unlock()
	for i := range sreqs {
		g.Go(d.uploadToExecutor(subCtx, selected[i], i, debugletIDS[i], specs[i]))
	}

	if err := g.Wait(); err != nil {
		cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		for i, id := range debugletIDS {
			// TODO: cleanup the database and scheduler for the aborted debuglets
			// The original mutation stays live even when a sibling's failure or a
			// retirement canceled its execution context, so cleanup uses its own
			// bounded context and the client this upload captured.
			if err := d.abortCaptured(cleanupCtx, selected[i].mutation, selected[i].client, id, "failed to batch upload all debuglets"); err != nil {
				d.logger.Error("Failed to abort debuglet", zap.Error(err))
			}
		}
		return nil, fmt.Errorf("failed to upload debuglets: %w", err)
	}

	return debugletIDS, nil
}

// schedulingGrace is added to every reserved window to absorb delays in the
// executor's processing time.
const schedulingGrace = 10 * time.Second

// The scheduler reserves capacity on a Unix nanosecond timeline, so an admitted
// window has to lie inside the range such a timestamp expresses.
var (
	minReservableTime = time.Unix(0, 0)
	maxReservableTime = time.Unix(0, math.MaxInt64)
)

// ErrInvalidPolicy marks a submission the dispatcher refuses because of the
// numbers it carries, rather than because of anything the dispatcher is or
// does. It is a rejection of the request, so a caller can answer it as one:
// the HTTP boundary reports it as an invalid policy and not as a failure of
// the server.
var ErrInvalidPolicy = errors.New("invalid policy")

// validatePolicyNumbers rejects a policy whose numbers are outside the ranges
// [models.CheckPolicyNumbers] admits. It runs before any duration, window or
// aggregate is computed from them, so no derived value can depend on a number
// the dispatcher rejects. Messages name the contract field a caller sees rather
// than the internal one, because they are what the HTTP boundary reports back.
func validatePolicyNumbers(p models.DebugletPolicy) error {
	switch models.CheckPolicyNumbers(int64(p.FloorBW), int64(p.CeilBW), p.Timeout.Milliseconds()) {
	case models.PolicyBoundFloor:
		return fmt.Errorf("floor_bw (%d) must be between 0 and %d bits per second: %w",
			int64(p.FloorBW), models.MaxPolicyBandwidthBPS, ErrInvalidPolicy)
	case models.PolicyBoundCeil:
		return fmt.Errorf("ceil_bw (%d) must be between 0 and %d bits per second: %w",
			int64(p.CeilBW), models.MaxPolicyBandwidthBPS, ErrInvalidPolicy)
	case models.PolicyBoundCeilBelowFloor:
		return fmt.Errorf("ceil_bw (%s) must be at least floor_bw (%s): %w",
			p.CeilBW.String(), p.FloorBW.String(), ErrInvalidPolicy)
	case models.PolicyBoundTimeout:
		return fmt.Errorf("timeout_ms (%s) must be between 1 millisecond and %s: %w",
			p.Timeout, models.MaxPolicyTimeout, ErrInvalidPolicy)
	}
	return nil
}

// admissionWindowEnd is the end of the window a run reserves: its start plus
// the run budget and the grace. Every step is checked, so a budget or a start
// time whose sum leaves the reservable range is reported here rather than
// wrapping into an arbitrary earlier instant the scheduler would accept.
//
// The window is what has to fit, not each field on its own: start_time and
// timeout_ms may each be at their documented maximum and still not be
// admissible together. A window that does not fit is a rejected request like
// any other out-of-range number, so it carries [ErrInvalidPolicy] too.
func admissionWindowEnd(from time.Time, timeout time.Duration) (time.Time, error) {
	budget := timeout + schedulingGrace
	if budget < timeout {
		return time.Time{}, fmt.Errorf("timeout_ms (%s) with the %s grace of the reserved window overflows a duration: %w",
			timeout, schedulingGrace, ErrInvalidPolicy)
	}
	to := from.Add(budget)
	if !to.After(from) {
		return time.Time{}, fmt.Errorf("the window reserved from start_time %s over timeout_ms and the %s grace overflows: %w",
			from, schedulingGrace, ErrInvalidPolicy)
	}
	if from.Before(minReservableTime) || to.After(maxReservableTime) {
		return time.Time{}, fmt.Errorf("the window [%s, %s] reserved from start_time and timeout_ms must lie within [%s, %s]: %w",
			from, to, minReservableTime, maxReservableTime, ErrInvalidPolicy)
	}
	return to, nil
}

func (d *Dispatcher) validateDebugletSpec(spec *models.DebugletSpec) (*schedule.Request, error) {
	now := time.Now()

	p := spec.Policy
	if err := validatePolicyNumbers(p); err != nil {
		return nil, err
	}
	// ignore passed start times and set them to 'now'
	if spec.StartTime != nil && spec.StartTime.Before(time.Now()) {
		spec.StartTime = nil
	}

	exec, exists := d.executors[spec.ExecutorID]
	if d.closed || !exists || !exec.owner.Available() {
		return nil, fmt.Errorf("executor '%s' not found", spec.ExecutorID)
	}

	if spec.Policy.RequireICMP && !exec.ICMPEnabled {
		return nil, fmt.Errorf("executor '%s' does not support ICMP, but policy requires it", spec.ExecutorID)
	}

	if (spec.Policy.ListenTCP || spec.Policy.ListenUDP) && exec.PublicHost() == "" {
		return nil, fmt.Errorf("executor '%s' has no public host, but policy requires a listener", spec.ExecutorID)
	}

	var from time.Time
	if spec.StartTime == nil {
		from = now
	} else {
		from = *spec.StartTime
	}
	to, err := admissionWindowEnd(from, spec.Policy.Timeout)
	if err != nil {
		return nil, err
	}

	r := schedule.Request{
		Executor:    spec.ExecutorID,
		Destination: spec.Policy.Addresses,
		From:        from,
		To:          to,
		Use:         spec.Policy.FloorBW,
	}

	// The reserved floors of the window plus this one decide admission. A sum
	// that does not fit is not a capacity that is available: it is rejected
	// exactly like an exceeded one, never admitted against a wrapped total.
	if total, exact := resource.AddBitrate(d.scheduler.QueryMaxExec(r.Executor, from, to), r.Use); !exact || total > exec.capacity {
		return nil, fmt.Errorf("time [%s, %s] executor '%s' capacity exceeded: %w", from, to, exec.ID, resource.ErrCapacityFull)
	}

	for _, dest := range spec.Policy.Addresses {
		if total, exact := resource.AddBitrate(d.scheduler.QueryMaxDest(dest, from, to), r.Use); !exact || total > d.destinations.Cap(dest) {
			return nil, fmt.Errorf("time [%s, %s] destination '%s' capacity exceeded: %w", from, to, dest, resource.ErrCapacityFull)
		}
	}

	return &r, nil
}

type submissionOwner struct {
	owner    *rpc.SessionOwner
	mutation *rpc.Mutation
	entry    *executorEntry
	client   rpc.BoundExecutorClient // assigned by its sole upload caller, read after g.Wait
}

func (d *Dispatcher) uploadToExecutor(ctx context.Context, selected *submissionOwner, i int, debugletID uuid.UUID, spec models.DebugletSpec) func() error {
	return func() error {
		ctx, finish := mutationCallContext(ctx, selected.mutation)
		defer finish()
		d.logger.Debug("Uploading to executor", zap.String("debugletID", debugletID.String()), zap.String("executorID", spec.ExecutorID))
		client, ok := d.Bidi.GetClientFor(selected.owner)
		if !ok {
			return status.Error(codes.FailedPrecondition, "upload session is unavailable")
		}
		selected.client = client
		var startTime *timestamppb.Timestamp
		if spec.StartTime != nil {
			startTime = timestamppb.New(*spec.StartTime)
		}
		req := &pb.UploadRequest{
			ControlBinding: &pb.ControlBinding{DispatcherIncarnation: selected.owner.Binding().Incarnation, SessionId: selected.owner.Binding().SessionID},
			Id:             debugletID.String(),
			TransactionId:  spec.TransactionID,
			StartTime:      startTime,
			Args:           spec.Args,
			Wasm:           spec.Wasm,
			Policy: &pb.DebugletPolicy{
				FloorBw:     int64(spec.Policy.FloorBW),
				CeilBw:      int64(spec.Policy.CeilBW),
				TimeoutMs:   int64(spec.Policy.Timeout.Milliseconds()),
				Addresses:   spec.Policy.Addresses,
				RequireIcmp: spec.Policy.RequireICMP,
				ListenUdp:   spec.Policy.ListenUDP,
				ListenTcp:   spec.Policy.ListenTCP,
				ListenScion: spec.Policy.ListenSCION,
			},
		}
		if _, err := client.Upload(ctx, req); err != nil {
			return fmt.Errorf("failed to upload debuglet i=%d: %w", i, err)
		}
		d.logger.Debug("Upload successful", zap.String("debugletID", debugletID.String()), zap.String("executorID", spec.ExecutorID))

		// Guarded ordinary update: an executor may report the exit before
		// acknowledging the upload, and that terminal result must not be
		// overwritten. A terminal row keeps the upload a success; a missing
		// row or a database failure remains a failure.
		queries := database.New(d.db)
		if _, err := queries.UpdateDebugletState(ctx, database.UpdateDebugletStateParams{
			State:                 models.RunStateUploaded,
			StateRank:             models.RunStateUploaded.SemanticRank(),
			Uuid:                  debugletID,
			ExitedState:           models.RunStateExited,
			ExecutorID:            selected.owner.ExecutorID(),
			DispatcherIncarnation: selected.owner.Binding().Incarnation,
			SessionID:             selected.owner.Binding().SessionID,
		}); err != nil {
			if !errors.Is(err, sql.ErrNoRows) {
				return fmt.Errorf("failed to update debuglet state in database: %w", err)
			}
			existing, err := d.ownedDebuglet(ctx, selected.owner, debugletID)
			if err != nil {
				if errors.Is(err, sql.ErrNoRows) {
					return fmt.Errorf("failed to update debuglet state in database: debuglet '%s' does not exist: %w", debugletID.String(), err)
				}
				return fmt.Errorf("failed to classify uploaded debuglet '%s': %w", debugletID.String(), err)
			}
			if existing.State.SemanticRank() < models.RunStateUploaded.SemanticRank() {
				return fmt.Errorf("upload state of debuglet '%s' was rejected although it is in state %s", debugletID.String(), existing.State.String())
			}
			d.logger.Debug("Debuglet advanced before its upload was acknowledged", zap.String("debugletID", debugletID.String()), zap.String("executorID", spec.ExecutorID), zap.String("state", existing.State.String()))
		}

		return nil
	}
}

func (d *Dispatcher) AbortDebuglet(ctx context.Context, executorID string, debugletID uuid.UUID, reason string) error {
	// Reserve the registry's current owner before the read. The persisted
	// binding then rejects a same-ID replacement or another executor's run.
	d.mu.RLock()
	entry := d.executors[executorID]
	if d.closed || entry == nil {
		d.mu.RUnlock()
		return status.Error(codes.FailedPrecondition, "abort session is unavailable")
	}
	mutation, err := entry.owner.AdmitMutation(ctx)
	d.mu.RUnlock()
	if err != nil {
		return status.Error(codes.FailedPrecondition, "abort session is unavailable")
	}
	defer mutation.Finish()
	if _, err := d.ownedDebuglet(mutation.Context(), mutation.Owner(), debugletID); err != nil {
		return err
	}
	client, ok := d.Bidi.GetClientFor(mutation.Owner())
	if !ok {
		return status.Error(codes.FailedPrecondition, "abort session is unavailable")
	}
	return d.abortCaptured(mutation.Context(), mutation, client, debugletID, reason)
}

func (d *Dispatcher) abortCaptured(ctx context.Context, mutation *rpc.Mutation, client rpc.BoundExecutorClient, id uuid.UUID, reason string) error {
	owner, err := requireMutation(mutation, "")
	if err != nil {
		return err
	}
	if _, err := d.ownedDebuglet(ctx, owner, id); err != nil {
		return err
	}
	if client == nil {
		return status.Error(codes.FailedPrecondition, "abort session is unavailable")
	}
	if _, err := client.Abort(ctx, &pb.AbortRequest{DebugletId: id.String(), Reason: reason}); err != nil {
		return fmt.Errorf("failed to abort debuglet: %w", err)
	}
	// One local terminal attempt follows the remote acknowledgement, under the
	// same live mutation. It is no durable terminal or refund guarantee.
	_, _ = d.OnDebugletExit(ctx, mutation, &pb.DebugletExitRequest{DebugletId: id.String(), ExitCode: -1, ErrorMessage: &reason})
	return nil
}
