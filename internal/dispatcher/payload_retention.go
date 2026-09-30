// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package dispatcher

import (
	"context"
	"database/sql"
	"errors"
	"github.com/netsec-ethz/debuglet/internal/daemonlog"
	"time"

	"github.com/google/uuid"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/database"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/models"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/transport/rpc"
	pb "github.com/netsec-ethz/debuglet/protocol"
	"go.uber.org/zap"
	"google.golang.org/grpc"
)

var ErrPayloadNotDeletable = errors.New("payload requires completed output and confirmed executor retirement")

// confirmRunRetirement reuses the existing metadata-only inspection. It never
// cancels, deletes, starts or replays executor work. Terminal reports precede
// scheduler deletion, so only an authenticated ABSENT observation proves that
// no retained/quarantined execution row still owns this reservation.
func (d *Dispatcher) confirmRunRetirement(ctx context.Context, id uuid.UUID) error {
	q := database.New(d.db)
	run, err := q.GetDebugletByUUID(ctx, id)
	if err != nil {
		return err
	}
	reservation, err := q.GetAccountRunReservation(ctx, run.ID)
	if err != nil {
		return err
	}
	if reservation.RetiredAt.Valid {
		return nil
	}
	if run.State != models.RunStateExited {
		return ErrPayloadNotDeletable
	}
	output, err := q.GetDebugletOutput(ctx, id)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if err := q.MarkRetirementCheck(ctx, database.MarkRetirementCheckParams{DebugletID: run.ID, LastRetirementCheck: d.now().Unix()}); err != nil {
		return err
	}
	d.mu.RLock()
	var owner *rpc.SessionOwner
	if entry := d.executors[run.ExecutorID]; !d.closed && entry != nil && entry.owner.Available() {
		owner = entry.owner
	}
	d.mu.RUnlock()
	if owner == nil {
		return ErrPayloadNotDeletable
	}
	original := owner.Binding().Incarnation == run.DispatcherIncarnation && owner.Binding().SessionID == run.SessionID
	if !original && (output.OwnerFingerprint == "" || owner.CredentialFingerprint() != output.OwnerFingerprint) {
		return ErrPayloadNotDeletable
	}
	if owner.CredentialFingerprint() != "" {
		fingerprint, err := q.GetExecutorEnrollment(ctx, run.ExecutorID)
		if errors.Is(err, sql.ErrNoRows) || (err == nil && fingerprint != owner.CredentialFingerprint()) {
			return ErrPayloadNotDeletable
		}
		if err != nil {
			return err
		}
	}
	lookup, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	mutation, err := owner.AdmitMutation(lookup)
	if err != nil {
		return ErrPayloadNotDeletable
	}
	defer mutation.Finish()
	client, available := d.Bidi.GetClientFor(owner)
	if !available {
		return ErrPayloadNotDeletable
	}
	binding := owner.Binding()
	reply, err := client.InspectRetainedRun(mutation.Context(), &pb.InspectRetainedRunRequest{
		DebugletId: id.String(), ControlBinding: &pb.ControlBinding{DispatcherIncarnation: binding.Incarnation, SessionId: binding.SessionID},
	}, grpc.MaxCallRecvMsgSize(4096))
	if err != nil || reply == nil || reply.Status != pb.RetainedRunStatus_RETAINED_RUN_STATUS_ABSENT || reply.Run != nil {
		return ErrPayloadNotDeletable
	}
	// Retain the original mutation until the write finishes. A replacement or
	// ended lease cannot turn an old observation into fresh authority.
	d.mu.RLock()
	defer d.mu.RUnlock()
	entry := d.executors[run.ExecutorID]
	if d.closed || entry == nil || entry.owner != owner || !owner.Available() || mutation.Context().Err() != nil {
		return ErrPayloadNotDeletable
	}
	_, err = q.RetireAccountRun(mutation.Context(), database.RetireAccountRunParams{DebugletID: run.ID, RetiredAt: sql.NullInt64{Int64: d.now().Unix(), Valid: true}})
	return err
}

// DeleteCompletedPayload preserves durable ownership/accounting/verification
// references. Authorization belongs to the HTTP boundary. Repeated deletion
// succeeds without releasing storage twice.
func (d *Dispatcher) DeleteCompletedPayload(ctx context.Context, id uuid.UUID, expired bool) error {
	q := database.New(d.db)
	if _, err := q.GetPayloadTombstone(ctx, id); err == nil {
		return nil
	} else if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if err := d.confirmRunRetirement(ctx, id); err != nil {
		return err
	}
	tx, err := d.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	q = database.New(tx)
	if _, err := q.GetPayloadTombstone(ctx, id); err == nil {
		return nil
	} else if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	run, err := q.GetDebugletByUUID(ctx, id)
	if err != nil {
		return err
	}
	reservation, err := q.GetAccountRunReservation(ctx, run.ID)
	if err != nil {
		return err
	}
	output, err := q.GetDebugletOutput(ctx, id)
	if errors.Is(err, sql.ErrNoRows) {
		// Older runs can lack finality metadata even after executor retirement.
		// Missing evidence does not establish that their payload is deletable.
		return ErrPayloadNotDeletable
	}
	if err != nil {
		return err
	}
	if run.State != models.RunStateExited || !reservation.RetiredAt.Valid || !output.FinalSequence.Valid {
		return ErrPayloadNotDeletable
	}
	reason := "owner_requested"
	if expired {
		reason = "retention_expired"
	}
	if err := q.CreatePayloadTombstone(ctx, database.CreatePayloadTombstoneParams{DebugletID: run.ID, DeletedAt: d.now().Unix(), Reason: reason}); err != nil {
		return err
	}
	if err := q.DeleteMeasurementLogs(ctx, run.ID); err != nil {
		return err
	}
	if err := q.DeleteMeasurementProvenance(ctx, run.ID); err != nil {
		return err
	}
	// Original requested policy/arguments added by measurement admission are
	// payload too; retry lineage and transaction references are separate.
	if _, err := tx.ExecContext(ctx, "DELETE FROM measurement_requests WHERE debuglet_id = ?", run.ID); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, "UPDATE measurement_execution SET tcp_endpoint = '' WHERE debuglet_id = ?", run.ID); err != nil {
		return err
	}
	publicError := run.Error
	if publicError.Valid {
		publicError.String = PublicTerminalError(publicError.String)
	}
	if err := q.DeleteMeasurementTargets(ctx, database.DeleteMeasurementTargetsParams{DebugletID: run.ID, PublicError: publicError}); err != nil {
		return err
	}
	charge := output.ByteCount + output.FrameCount*pb.OutputFrameCharge + pb.OutputRunCharge
	if err := chargeOutput(ctx, q, output.AccountID, -charge, -output.FrameCount); err != nil {
		return err
	}
	return tx.Commit()
}

// sweepPayloadRetention shares the dispatcher's existing maintenance lifetime.
// Four metadata lookups share a one-second budget; expiry deletes at most 100
// already-retired payloads and never causes a new network lookup for a listing.
func (d *Dispatcher) sweepPayloadRetention() {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	q := database.New(d.db)
	ids, err := q.ListRetirementCandidates(ctx)
	if err != nil {
		d.logger.Warn("Failed to list account retirement candidates")
		d.logger.Debug("Private runtime diagnostic", zap.String("operation", "Failed to list account retirement candidates"), zap.String("error", daemonlog.Diagnostic(err)))
		return
	}
	for _, id := range ids {
		if ctx.Err() != nil {
			return
		}
		if err := d.confirmRunRetirement(ctx, id); err != nil && !errors.Is(err, ErrPayloadNotDeletable) && ctx.Err() == nil {
			d.logger.Warn("Failed to retain account retirement observation", zap.String("run_id", id.String()))
			d.logger.Debug("Private runtime diagnostic", zap.String("run_id", id.String()), zap.String("operation", "Failed to retain account retirement observation"), zap.String("error", daemonlog.Diagnostic(err)))
		}
	}
	age := d.retention.PayloadMaxAge()
	if age == 0 || ctx.Err() != nil {
		return
	}
	ids, err = q.ListExpiredPayloads(ctx, sql.NullInt64{Int64: d.now().Add(-age).Unix(), Valid: true})
	if err != nil {
		d.logger.Warn("Failed to list expired measurement payloads")
		d.logger.Debug("Private runtime diagnostic", zap.String("operation", "Failed to list expired measurement payloads"), zap.String("error", daemonlog.Diagnostic(err)))
		return
	}
	for _, id := range ids {
		if ctx.Err() != nil {
			return
		}
		if err := d.DeleteCompletedPayload(ctx, id, true); err != nil && ctx.Err() == nil {
			d.logger.Warn("Failed to expire measurement payload", zap.String("run_id", id.String()))
			d.logger.Debug("Private runtime diagnostic", zap.String("run_id", id.String()), zap.String("operation", "Failed to expire measurement payload"), zap.String("error", daemonlog.Diagnostic(err)))
		}
	}
}
