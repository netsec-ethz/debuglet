// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package dispatcher

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"github.com/netsec-ethz/debuglet/internal/bitrate"
	"github.com/netsec-ethz/debuglet/internal/controlsession"
	"github.com/netsec-ethz/debuglet/internal/daemonlog"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/database"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/models"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/resource"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/resource/schedule"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/transport/rpc"
	"github.com/netsec-ethz/debuglet/internal/storageheadroom"
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
	// A batch this dispatcher already admitted is answered with the runs it
	// recorded, before anything is validated, scheduled or inserted, so a
	// repeated submission neither admits nor uploads the work again. This
	// comes before the closed check: a retry during shutdown is still an
	// admitted batch, and answering it with a failure would have its payment
	// refunded while its runs execute.
	if len(specs) > 0 {
		recorded, err := d.admittedRuns(ctx, specs)
		if err != nil || recorded != nil {
			d.mu.Unlock()
			return recorded, err
		}
	}
	if err := AdmissionPaused(); err != nil {
		d.mu.Unlock()
		return nil, err
	}
	if d.closed {
		d.mu.Unlock()
		return nil, ErrDispatcherClosed
	}
	admissionBytes, err := validateSubmissionSize(specs)
	if err != nil {
		d.mu.Unlock()
		return nil, err
	}

	var sreqs []schedule.Request
	rollbackReservations := func() {
		for i := len(sreqs) - 1; i >= 0; i-- {
			d.releaseFloor(debugletIDS[i])
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
			d.reserveFloor(debugletIDS[i], *r)
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

	if err := storageheadroom.Check(ctx, tx, d.outputLimits.ControlReserveBytes, admissionBytes); err != nil {
		failLocked()
		return nil, errors.Join(ErrOutputCapacity, err)
	}
	qtx := database.New(d.db).WithTx(tx)
	for i := range sreqs {
		row, err := qtx.CreateDebuglet(ctx, database.CreateDebugletParams{
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
		})
		if err != nil {
			failLocked()
			return nil, fmt.Errorf("failed to create debuglet in database: %w", err)
		}
		// The order records its run. An order that already records one, or
		// that has no row, refuses the whole batch.
		claimed, err := qtx.ClaimDebugletOrder(ctx, database.ClaimDebugletOrderParams{
			OutstandingState: int64(models.Outstanding), PaidStatus: int64(models.Paid),
			DebugletID:    sql.NullInt64{Int64: row.ID, Valid: true},
			TransactionID: specs[i].TransactionID,
			OrderID:       specs[i].OrderID,
		})
		if err != nil {
			failLocked()
			return nil, fmt.Errorf("failed to record the run of order %d in database: %w", specs[i].OrderID, err)
		}
		if claimed != 1 {
			failLocked()
			return nil, fmt.Errorf("order %d of transaction %s is not admissible: %w", specs[i].OrderID, specs[i].TransactionID, ErrPaymentInUse)
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
		if err := recordRunActivity(ctx, qtx, row.ID, selected[i].entry, sreqs[i]); err != nil {
			failLocked()
			return nil, fmt.Errorf("record run attribution interval: %w", err)
		}
		if err := d.recordProvenance(ctx, qtx, row.ID, debugletIDS[i], specs[i], selected[i]); err != nil {
			failLocked()
			return nil, fmt.Errorf("record admission provenance: %w", err)
		}
		if err := recordMeasurementRequest(ctx, qtx, row.ID, specs[i].Requested); err != nil {
			failLocked()
			return nil, fmt.Errorf("record submitted measurement: %w", err)
		}
		if err := d.createOutputMetadata(ctx, qtx, debugletIDS[i], selected[i].owner.OutputVersion(), selected[i].owner.CredentialFingerprint()); err != nil {
			failLocked()
			return nil, fmt.Errorf("reserve output storage: %w", err)
		}
	}

	if err := d.reserveAccountRuns(ctx, qtx, debugletIDS, specs, userID); err != nil {
		failLocked()
		return nil, err
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
		fields := daemonlog.RunFields(ctx, debugletIDS[i], specs[i].ExecutorID, selected[i].owner.Binding())
		if userID != nil {
			fields = append(fields, zap.String("user_id", userID.String()))
		}
		d.logger.Info("Run admitted", fields...)
		g.Go(d.uploadToExecutor(subCtx, selected[i], i, debugletIDS[i], specs[i]))
	}

	if err := g.Wait(); err != nil {
		cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		reason := "failed to batch upload all debuglets"
		for i, id := range debugletIDS {
			// The original mutation stays live even when a sibling's failure or a
			// retirement canceled its execution context, so cleanup uses its own
			// bounded context and the client this upload captured. A run whose
			// cancellation is not confirmed, because the executor refused it,
			// the call failed in transport or no client was captured, keeps
			// its reservation and is marked unreconciled; nothing is retried.
			// Its executor's later report supersedes the mark, and a run still
			// unfinished when its window ends has its allocation reclaimed
			// without changing the outcome, see sweepEndedWindows.
			err := d.abortCaptured(cleanupCtx, selected[i].mutation, selected[i].client, id, reason)
			if err == nil {
				continue
			}
			// An executor that refused the run's own upload and does not know
			// it at the cancellation holds no such run: it takes the terminal
			// path of an acknowledged cancellation.
			if errors.Is(err, ErrAbortRefused) && status.Code(err) == codes.NotFound && uploadRefused(selected[i].uploadErr) {
				if _, err := d.OnDebugletExit(cleanupCtx, selected[i].mutation, &pb.DebugletExitRequest{DebugletId: id.String(), ExitCode: -1, ErrorMessage: &reason}); err != nil {
					d.logger.Error("Batch cleanup cancellation was not recorded", append(daemonlog.RunFields(cleanupCtx, id, selected[i].owner.ExecutorID(), selected[i].owner.Binding()), zap.String("grpc_code", status.Code(err).String()), zap.Bool("recording_failed", true), zap.String("cleanup_outcome", "unknown"))...)
				} else if err := d.finishRefusedOutput(cleanupCtx, selected[i].mutation, id); err != nil {
					d.logger.Error("Failed to finalize refused debuglet output", zap.String("debugletID", id.String()))
					d.logger.Debug("Private runtime diagnostic", zap.String("debugletID", id.String()), zap.String("operation", "Failed to finalize refused debuglet output"), zap.String("error", daemonlog.Diagnostic(err)))
				}
				continue
			}
			d.logger.Error("Batch cleanup cancellation unconfirmed", append(daemonlog.RunFields(cleanupCtx, id, selected[i].owner.ExecutorID(), selected[i].owner.Binding()), zap.String("grpc_code", status.Code(err).String()), zap.Bool("recording_failed", errors.Is(err, ErrCancellationNotRecorded)), zap.String("cleanup_outcome", "unknown"))...)
			d.markUnreconciled(cleanupCtx, selected[i].owner, id)
		}
		// Admission committed before upload began. Keep the receipt and marker
		// so inspection and the single admitted-batch refund remain distinct.
		return debugletIDS, fmt.Errorf("%w: failed to upload debuglets: %w", ErrAdmissionCommitted, err)
	}

	return debugletIDS, nil
}

// ErrAdmissionCommitted identifies an upload failure from the call that
// committed the new runs. Receipt lookup and pre-admission refusals cannot
// authorize the admitted-batch refund path.
var ErrAdmissionCommitted = errors.New("new admission committed")

// admittedRuns returns the runs recorded for the orders of a batch, in the
// order of its specs, or nil when none of them has a run yet. A batch of which
// only some orders have runs is refused rather than partly answered.
func (d *Dispatcher) admittedRuns(ctx context.Context, specs []models.DebugletSpec) (uuid.UUIDs, error) {
	transactionID := specs[0].TransactionID
	rows, err := database.New(d.db).GetAdmittedRuns(ctx, transactionID)
	if err != nil {
		return nil, fmt.Errorf("failed to look up the runs of transaction %s: %w", transactionID, errors.Join(ErrPaymentInUse, err))
	}
	if len(rows) == 0 {
		return nil, nil
	}
	runs := make(map[int64]uuid.UUID, len(rows))
	for _, row := range rows {
		runs[row.OrderID] = row.Uuid
	}
	ids := make(uuid.UUIDs, len(specs))
	for i := range specs {
		id, ok := runs[specs[i].OrderID]
		if !ok || specs[i].TransactionID != transactionID {
			return nil, fmt.Errorf("order %d of transaction %s is not admissible: %w", specs[i].OrderID, specs[i].TransactionID, ErrPaymentInUse)
		}
		ids[i] = id
	}
	return ids, nil
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

// ErrUnknownExecutor marks a submission for an executor that is not
// registered, or no longer available, when the batch is admitted. It is a
// rejection of the request, not a failure of the dispatcher.
var ErrUnknownExecutor = errors.New("executor is not registered")

// ErrPaymentInUse marks a submission refused where the transaction's orders
// already carry runs, or where the dispatcher could not tell whether they do.
// Those runs may be executing or already credited to their executor, so the
// caller must not refund the transaction on such a refusal.
var ErrPaymentInUse = errors.New("payment order already has admitted runs")

// ErrCancellationNotRecorded marks a cancellation its executor acknowledged
// but whose terminal result the dispatcher failed to record. It is no
// refusal: the run may already be stopping, while its stored state does not
// show the cancellation.
var ErrCancellationNotRecorded = errors.New("cancellation acknowledged but its result was not recorded")

// ErrAbortRefused marks a cancellation its executor answered with a refusal,
// as distinct from a cancellation that did not reach it.
var ErrAbortRefused = errors.New("executor refused the cancellation")

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
		return nil, fmt.Errorf("executor '%s' not found: %w", spec.ExecutorID, ErrUnknownExecutor)
	}

	if err := validateExecutorCapabilities(spec, exec, d.now()); err != nil {
		return nil, err
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
	if total, exact := bitrate.Add(d.scheduler.QueryMaxExec(r.Executor, from, to), r.Use); !exact || total > exec.capacity {
		return nil, fmt.Errorf("time [%s, %s] executor '%s' capacity exceeded: %w", from, to, exec.ID, resource.ErrCapacityFull)
	}

	for _, dest := range spec.Policy.Addresses {
		// A denied destination admits nothing, whatever the floor; it is
		// refused like exhausted capacity, which every caller already maps.
		if d.destinations.Denied(dest) {
			return nil, fmt.Errorf("destination '%s': %w: %w", dest, resource.ErrDenied, resource.ErrCapacityFull)
		}
		if total, exact := bitrate.Add(d.scheduler.QueryMaxDest(dest, from, to), r.Use); !exact || total > d.destinations.Cap(dest) {
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
	// uploadErr is the executor's answer to this run's Upload when it failed,
	// assigned by its sole upload caller and read after g.Wait.
	uploadErr error
}

func (d *Dispatcher) uploadToExecutor(ctx context.Context, selected *submissionOwner, i int, debugletID uuid.UUID, spec models.DebugletSpec) func() error {
	return func() error {
		ctx, finish := mutationCallContext(ctx, selected.mutation)
		defer finish()
		fields := daemonlog.RunFields(ctx, debugletID, spec.ExecutorID, selected.owner.Binding())
		d.logger.Debug("Uploading to executor", fields...)
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
			selected.uploadErr = err
			return fmt.Errorf("failed to upload debuglet i=%d: %w", i, err)
		}
		d.logger.Debug("Upload successful", fields...)

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

// AbortDebuglet asks the run's executor to cancel it and records the
// cancellation as the run's terminal result. A nil error means that result is
// recorded, or that the run was already terminal and keeps its own. An error
// wrapping ErrCancellationNotRecorded means the executor acknowledged the
// cancellation but its result is not recorded. Other errors do not confirm
// that the cancellation was recorded.
//
// A run whose control session has ended, because the dispatcher restarted or
// the executor registered again in a new session, has no executor to ask: its
// cancellation is recorded locally, see cancelUnbound.
func (d *Dispatcher) AbortDebuglet(ctx context.Context, executorID string, debugletID uuid.UUID, reason string) error {
	identity, err := database.New(d.db).GetDebugletIdentityByUUID(ctx, debugletID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return status.Error(codes.NotFound, "debuglet does not exist")
		}
		return status.Error(codes.Internal, "failed to classify debuglet ownership")
	}
	d.logger.Info("Cancellation requested", daemonlog.RunFields(ctx, debugletID, identity.ExecutorID, controlsession.Binding{Incarnation: identity.DispatcherIncarnation, SessionID: identity.SessionID})...)
	// Reserve the registry's current owner before the owned read. The
	// persisted binding then rejects a same-ID replacement or another
	// executor's run.
	d.mu.RLock()
	entry := d.executors[executorID]
	if !d.closed && identity.ExecutorID == executorID && !bindingLive(entry, identity) {
		d.mu.RUnlock()
		return d.cancelUnbound(ctx, identity, debugletID, reason)
	}
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
	client, _ := d.Bidi.GetClientFor(mutation.Owner())
	return d.abortCaptured(mutation.Context(), mutation, client, debugletID, reason)
}

// unobservedCancellation extends the caller's reason in the stored error of a
// run cancelled after its control session had ended.
const unobservedCancellation = "; the control session had ended and the executor's outcome was not observed"

// bindingLive reports whether the stored binding of a run is the one the
// registered owner of its executor holds. Called with d.mu held.
func bindingLive(entry *executorEntry, identity database.GetDebugletIdentityByUUIDRow) bool {
	if entry == nil {
		return false
	}
	binding := entry.owner.Binding()
	return binding.Incarnation == identity.DispatcherIncarnation && binding.SessionID == identity.SessionID
}

// cancelUnbound retains the request without delivering it to a replacement.
// A persisted acknowledgement confirms earlier delivery; a missing one stays unknown.
func (d *Dispatcher) cancelUnbound(ctx context.Context, identity database.GetDebugletIdentityByUUIDRow, id uuid.UUID, reason string) error {
	run, err := database.New(d.db).GetDebugletByUUID(ctx, id)
	if err != nil {
		return status.Errorf(codes.Internal, "failed to read cancellation run: %v", err)
	}
	record, err := d.requestCancellation(ctx, run.ID, reason)
	if err != nil {
		return err
	}
	if run.State == models.RunStateExited {
		if !record.AcknowledgedAt.Valid && !record.AttemptedAt.Valid && record.Failure == "" {
			if err := d.failCancellation(ctx, run.ID, "already_terminal"); err != nil {
				return err
			}
		}
		// Release by run identity, a no-op if the winner already did.
		d.releaseTerminal(run)
		return nil
	}
	// Keep an earlier, more specific failure such as executor_refused or
	// transport_outcome_unknown: losing the binding later does not explain it.
	if !record.AcknowledgedAt.Valid && record.Failure == "" {
		if err := d.failCancellation(ctx, run.ID, "original_binding_unavailable"); err != nil {
			return err
		}
	}
	if identity.DispatcherIncarnation == "" || identity.SessionID == "" {
		return status.Error(codes.FailedPrecondition, "run has no control binding to cancel under")
	}
	reason = record.Reason
	if !record.AcknowledgedAt.Valid {
		reason += unobservedCancellation
	}
	return d.recordCancellationResult(ctx, identity, id, reason)
}

// recordCancellationResult uses only the run's original binding. Terminal
// selection and cleanup are shared with exits; payment runs only for the winner.
func (d *Dispatcher) recordCancellationResult(ctx context.Context, identity database.GetDebugletIdentityByUUIDRow, id uuid.UUID, reason string) error {
	msg := reason
	queries := database.New(d.db)
	deb, err := queries.CompleteDebuglet(ctx, database.CompleteDebugletParams{
		ExitedState:           models.RunStateExited,
		Error:                 terminalError(-1, &msg),
		Uuid:                  id,
		ExecutorID:            identity.ExecutorID,
		DispatcherIncarnation: identity.DispatcherIncarnation,
		SessionID:             identity.SessionID,
	})
	if err != nil {
		if !errors.Is(err, sql.ErrNoRows) {
			return status.Errorf(codes.Internal, "failed to record cancellation: %v", err)
		}
		// The guard rejected the write: the row is terminal or missing.
		// Classify with a read; never retry the write.
		existing, err := queries.GetDebugletByUUID(ctx, id)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return status.Error(codes.NotFound, "debuglet does not exist")
			}
			return status.Errorf(codes.Internal, "failed to classify rejected cancellation: %v", err)
		}
		if existing.State != models.RunStateExited {
			return fmt.Errorf("cancellation of debuglet '%s' was rejected although it is in state %s", id.String(), existing.State.String())
		}
		// The winning write may have committed without its caller seeing
		// the result; release by run identity, a no-op if already done.
		d.releaseTerminal(existing)
		return nil
	}
	d.logger.Info("Recorded cancellation of a debuglet", daemonlog.RunFields(ctx, id, identity.ExecutorID, controlsession.Binding{Incarnation: identity.DispatcherIncarnation, SessionID: identity.SessionID})...)
	d.settleTerminalPayment(ctx, &deb, -1)
	d.releaseTerminal(deb)
	return nil
}

func (d *Dispatcher) abortCaptured(ctx context.Context, mutation *rpc.Mutation, client rpc.BoundExecutorClient, id uuid.UUID, reason string) error {
	owner, err := requireMutation(mutation, "")
	if err != nil {
		return err
	}
	run, err := d.ownedDebuglet(ctx, owner, id)
	if err != nil {
		return err
	}
	record, err := d.requestCancellation(ctx, run.ID, reason)
	if err != nil {
		return err
	}
	if run.State == models.RunStateExited {
		if !record.AcknowledgedAt.Valid && !record.AttemptedAt.Valid && record.Failure == "" {
			if err := d.failCancellation(ctx, run.ID, "already_terminal"); err != nil {
				return err
			}
		}
		// Release by run identity, a no-op if the winner already did.
		d.releaseTerminal(run)
		return nil
	}
	reason = record.Reason
	if !record.AcknowledgedAt.Valid {
		if client == nil {
			if err := d.failCancellation(ctx, run.ID, "original_binding_unavailable"); err != nil {
				return err
			}
			return status.Error(codes.FailedPrecondition, "abort session is unavailable")
		}
		q := database.New(d.db)
		if err := q.AttemptCancellation(ctx, database.AttemptCancellationParams{DebugletID: run.ID, AttemptedAt: sql.NullInt64{Int64: d.now().UTC().UnixNano(), Valid: true}}); err != nil {
			return status.Errorf(codes.Internal, "failed to record cancellation attempt: %v", err)
		}
		if _, err := client.Abort(ctx, &pb.AbortRequest{DebugletId: id.String(), Reason: reason}); err != nil {
			failure := "executor_refused"
			switch status.Code(err) {
			case codes.Unavailable, codes.DeadlineExceeded, codes.Canceled:
				failure = "transport_outcome_unknown"
			}
			if recordErr := d.failCancellation(ctx, run.ID, failure); recordErr != nil {
				return recordErr
			}
			if failure == "transport_outcome_unknown" {
				return fmt.Errorf("failed to abort debuglet: %w", err)
			}
			return fmt.Errorf("failed to abort debuglet: %w: %w", ErrAbortRefused, err)
		}
		if err := q.AcknowledgeCancellation(ctx, database.AcknowledgeCancellationParams{DebugletID: run.ID, AcknowledgedAt: sql.NullInt64{Int64: d.now().UTC().UnixNano(), Valid: true}}); err != nil {
			return status.Errorf(codes.Internal, "failed to record cancellation acknowledgement: %v", err)
		}
	}
	if _, err := d.OnDebugletExit(ctx, mutation, &pb.DebugletExitRequest{DebugletId: id.String(), ExitCode: -1, ErrorMessage: &reason}); err != nil {
		return fmt.Errorf("%w: %w", ErrCancellationNotRecorded, err)
	}
	d.logger.Info("Cancellation recorded", daemonlog.RunFields(ctx, id, owner.ExecutorID(), owner.Binding())...)
	return nil
}

// uploadRefused reports whether an Upload failed with an answer the executor
// gives before or at accepting the run, rather than with a transport failure
// or an outcome it does not classify.
func uploadRefused(err error) bool {
	switch status.Code(err) {
	case codes.InvalidArgument, codes.FailedPrecondition, codes.PermissionDenied,
		codes.ResourceExhausted, codes.Unauthenticated, codes.OutOfRange:
		return true
	}
	return false
}

// markUnreconciled records that a run of a failed submission may still execute
// because the dispatcher could not confirm its cancellation. The guarded update
// leaves a run the executor already advanced or finished as it is, and the
// executor's later reports supersede the mark.
func (d *Dispatcher) markUnreconciled(ctx context.Context, owner *rpc.SessionOwner, id uuid.UUID) {
	if _, err := database.New(d.db).UpdateDebugletState(ctx, database.UpdateDebugletStateParams{
		State:                 models.RunStateUnreconciled,
		StateRank:             models.RunStateUnreconciled.SemanticRank(),
		Uuid:                  id,
		ExitedState:           models.RunStateExited,
		ExecutorID:            owner.ExecutorID(),
		DispatcherIncarnation: owner.Binding().Incarnation,
		SessionID:             owner.Binding().SessionID,
	}); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			d.logger.Debug("Debuglet advanced before its unconfirmed cancellation was recorded", zap.String("debugletID", id.String()))
			return
		}
		d.logger.Error("Failed to mark debuglet unreconciled", zap.String("debugletID", id.String()))
		d.logger.Debug("Private runtime diagnostic", zap.String("debugletID", id.String()), zap.String("operation", "Failed to mark debuglet unreconciled"), zap.String("error", daemonlog.Diagnostic(err)))
	}
}
