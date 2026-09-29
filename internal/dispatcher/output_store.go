// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package dispatcher

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/netsec-ethz/debuglet/internal/controlsession"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/config"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/database"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/models"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/transport/rpc"
	pb "github.com/netsec-ethz/debuglet/protocol"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var ErrOutputCapacity = errors.New("output storage capacity exhausted")

// ConfigureOutputLimits fixes output storage limits before registration starts.
func (d *Dispatcher) ConfigureOutputLimits(limits config.OutputConfig) error {
	if err := limits.Validate(); err != nil {
		return err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed || d.restored || len(d.executors) != 0 || len(d.registrations) != 0 {
		return errors.New("output limits must be configured before dispatcher startup")
	}
	d.outputLimits = limits
	return nil
}

type outputWriter struct {
	executorID  string
	binding     controlsession.Binding
	original    controlsession.Binding
	fingerprint string
	version     uint32
}

func outputWriterFor(owner *rpc.SessionOwner, original *pb.ControlBinding) (outputWriter, error) {
	writer := outputWriter{executorID: owner.ExecutorID(), binding: owner.Binding(),
		fingerprint: owner.CredentialFingerprint(), version: owner.OutputVersion()}
	writer.original = writer.binding
	if writer.version == pb.OutputVersion {
		var err error
		writer.original, err = controlsession.ParseBinding(original.GetDispatcherIncarnation(), original.GetSessionId())
		if err != nil {
			return outputWriter{}, status.Error(codes.InvalidArgument, "invalid original output binding")
		}
	}
	return writer, nil
}

// createOutputMetadata runs inside the existing run-admission transaction.
func (d *Dispatcher) createOutputMetadata(ctx context.Context, q *database.Queries, id uuid.UUID, version uint32, fingerprint string) error {
	if err := q.CreateDebugletOutput(ctx, database.CreateDebugletOutputParams{
		Uuid: id, OutputVersion: int64(version), OwnerFingerprint: fingerprint,
	}); err != nil {
		return err
	}
	row, err := q.GetDebugletOutput(ctx, id)
	if err != nil {
		return err
	}
	if err := q.EnsureOutputAccountUsage(ctx, row.AccountID); err != nil {
		return err
	}
	if full, err := d.outputStorageFull(ctx, q, row.AccountID, pb.OutputRunCharge); err != nil {
		return err
	} else if full {
		return ErrOutputCapacity
	}
	return chargeOutput(ctx, q, row.AccountID, pb.OutputRunCharge, 0)
}

func (d *Dispatcher) outputStorageFull(ctx context.Context, q *database.Queries, accountID, charge int64) (bool, error) {
	account, err := q.GetOutputAccountUsage(ctx, accountID)
	if err != nil {
		return false, err
	}
	node, err := q.GetOutputNodeUsage(ctx)
	if err != nil {
		return false, err
	}
	return exceedsOptionalLimit(account.ChargedBytes, charge, d.outputLimits.AccountBytes) ||
		exceedsOptionalLimit(node.ChargedBytes, charge, d.outputLimits.NodeBytes), nil
}

func exceedsOutputLimit(used, added, limit int64) bool {
	return used > limit || added > limit-used
}

// exceedsOptionalLimit treats a zero account or node cap as disabled.
func exceedsOptionalLimit(used, added, limit int64) bool {
	return limit > 0 && exceedsOutputLimit(used, added, limit)
}

func chargeOutput(ctx context.Context, q *database.Queries, accountID, bytes, frames int64) error {
	if err := q.AddOutputAccountUsage(ctx, database.AddOutputAccountUsageParams{AccountID: accountID, Bytes: bytes, Frames: frames}); err != nil {
		return err
	}
	return q.AddOutputNodeUsage(ctx, database.AddOutputNodeUsageParams{Bytes: bytes, Frames: frames})
}

// finishRefusedOutput records an empty end only after this upload was explicitly
// refused and its original executor confirmed absence. Existing output wins.
func (d *Dispatcher) finishRefusedOutput(ctx context.Context, mutation *rpc.Mutation, id uuid.UUID) error {
	owner, err := requireMutation(mutation, "")
	if err != nil {
		return err
	}
	if owner.OutputVersion() != pb.OutputVersion {
		return nil
	}
	writer := outputWriter{executorID: owner.ExecutorID(), binding: owner.Binding(), original: owner.Binding(),
		fingerprint: owner.CredentialFingerprint(), version: owner.OutputVersion()}
	tx, err := d.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	q := database.New(d.db).WithTx(tx)
	row, err := q.GetDebugletOutput(ctx, id)
	if err != nil {
		return err
	}
	if err := authorizeOutput(ctx, q, row, writer); err != nil {
		return err
	}
	if row.FinalSequence.Valid || row.CommittedSequence != 0 || row.ByteCount != 0 || row.FrameCount != 0 || row.LastLogID != 0 {
		return nil
	}
	if err := finishOutput(ctx, q, &row, &pb.DebugletOutputEnd{Status: pb.DebugletOutputStatus_DEBUGLET_OUTPUT_STATUS_COMPLETE}); err != nil {
		return err
	}
	return tx.Commit()
}

// storeOutput returns a receipt only after its transaction commits. A nil frame
// and end identify a stream; that read uses the same authority checks as writes.
func (d *Dispatcher) storeOutput(ctx context.Context, writer outputWriter, id uuid.UUID, frame *pb.DebugletOutput, end *pb.DebugletOutputEnd) (*pb.DebugletStreamResponse, error) {
	if frame != nil && (frame.GetTimestamp() == nil || frame.GetTimestamp().CheckValid() != nil ||
		(writer.version == pb.OutputVersion && (len(frame.Output) > pb.MaxOutputFrameBytes || frame.Sequence <= 0))) {
		return nil, status.Error(codes.InvalidArgument, "invalid stream output frame")
	}
	if end != nil && (writer.version != pb.OutputVersion || !pb.ValidOutputEnd(end)) {
		return nil, status.Error(codes.InvalidArgument, "invalid output end")
	}
	tx, err := d.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	q := database.New(d.db).WithTx(tx)
	row, err := q.GetDebugletOutput(ctx, id)
	if errors.Is(err, sql.ErrNoRows) && writer.version == 0 {
		// Legacy bookkeeping cannot create durable-output authority or infer a
		// certificate. Its run must still belong to this exact live session.
		_, err = q.GetOwnedDebugletByUUID(ctx, database.GetOwnedDebugletByUUIDParams{
			Uuid: id, ExecutorID: writer.executorID, DispatcherIncarnation: writer.binding.Incarnation, SessionID: writer.binding.SessionID,
		})
		if errors.Is(err, sql.ErrNoRows) {
			if _, lookupErr := q.GetDebugletIdentityByUUID(ctx, id); lookupErr == nil {
				return nil, status.Error(codes.PermissionDenied, "run does not belong to session")
			} else {
				err = lookupErr
			}
		}
		if err == nil {
			err = d.createOutputMetadata(ctx, q, id, 0, "")
		}
		if err == nil {
			row, err = q.GetDebugletOutput(ctx, id)
		}
	}
	if errors.Is(err, sql.ErrNoRows) {
		return nil, status.Error(codes.NotFound, "output run not found")
	}
	if err != nil {
		return nil, err
	}
	if err := authorizeOutput(ctx, q, row, writer); err != nil {
		return nil, err
	}
	if frame != nil {
		if err := d.appendOutput(ctx, q, &row, frame); err != nil {
			return nil, err
		}
	} else if end != nil {
		if err := finishOutput(ctx, q, &row, end); err != nil {
			return nil, err
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return outputReceipt(row), nil
}

func authorizeOutput(ctx context.Context, q *database.Queries, row database.GetDebugletOutputRow, writer outputWriter) error {
	binding, err := controlsession.ParseBinding(row.DispatcherIncarnation, row.SessionID)
	if err != nil || writer.executorID != row.ExecutorID || writer.original != binding || int64(writer.version) != row.OutputVersion {
		return status.Error(codes.PermissionDenied, "output identity does not match admitted run")
	}
	if writer.version == 0 {
		if writer.binding != binding {
			return status.Error(codes.PermissionDenied, "legacy output cannot resume another session")
		}
		return nil
	}
	if writer.fingerprint != row.OwnerFingerprint || (writer.binding != binding && writer.fingerprint == "") {
		return status.Error(codes.PermissionDenied, "output credential does not match admitted run")
	}
	if writer.fingerprint != "" {
		fingerprint, err := q.GetExecutorEnrollment(ctx, writer.executorID)
		if errors.Is(err, sql.ErrNoRows) || (err == nil && fingerprint != writer.fingerprint) {
			return status.Error(codes.PermissionDenied, "output credential is no longer enrolled")
		}
		if err != nil {
			return err
		}
	}
	return nil
}

func (d *Dispatcher) appendOutput(ctx context.Context, q *database.Queries, row *database.GetDebugletOutputRow, frame *pb.DebugletOutput) error {
	if row.FinalSequence.Valid {
		return status.Error(codes.FailedPrecondition, "output is finalized")
	}
	sequenced := row.OutputVersion == pb.OutputVersion
	if sequenced && frame.Sequence <= row.CommittedSequence {
		previous, err := q.GetSequencedDebugletLog(ctx, database.GetSequencedDebugletLogParams{
			DebugletID: row.DebugletID, SourceSequence: sql.NullInt64{Int64: frame.Sequence, Valid: true},
		})
		if err != nil {
			return err
		}
		if !previous.Timestamp.Equal(frame.Timestamp.AsTime()) || !bytes.Equal(previous.Output, frame.Output) {
			return status.Error(codes.InvalidArgument, "conflicting output sequence")
		}
		return nil
	}
	if sequenced && frame.Sequence != row.CommittedSequence+1 {
		return status.Error(codes.FailedPrecondition, "output sequence has a gap")
	}
	count := int64(len(frame.Output))
	reason := ""
	if exceedsOutputLimit(row.ByteCount, count, d.outputLimits.RunBytes) || exceedsOutputLimit(row.FrameCount, 1, d.outputLimits.RunFrames) {
		reason = pb.OutputReasonLimit
	} else if full, err := d.outputStorageFull(ctx, q, row.AccountID, count+pb.OutputFrameCharge); err != nil {
		return err
	} else if full {
		reason = pb.OutputReasonStorageLimit
	}
	if reason != "" {
		return finishOutput(ctx, q, row, &pb.DebugletOutputEnd{LastSequence: row.CommittedSequence,
			Status: pb.DebugletOutputStatus_DEBUGLET_OUTPUT_STATUS_TRUNCATED, Reason: reason})
	}
	payload := frame.Output
	if payload == nil {
		payload = []byte{}
	}
	log, err := q.CreateSequencedDebugletLog(ctx, database.CreateSequencedDebugletLogParams{
		DebugletID: row.DebugletID, Timestamp: models.NewUTCTime(frame.Timestamp.AsTime()), Output: payload,
		SourceSequence: sql.NullInt64{Int64: frame.Sequence, Valid: sequenced},
	})
	if err != nil {
		return err
	}
	var changed int64
	if sequenced {
		changed, err = q.AdvanceDebugletOutput(ctx, database.AdvanceDebugletOutputParams{
			DebugletID: row.DebugletID, Sequence: frame.Sequence, Bytes: count, LogID: log.ID,
		})
	} else {
		changed, err = q.AdvanceLegacyDebugletOutput(ctx, database.AdvanceLegacyDebugletOutputParams{DebugletID: row.DebugletID, Bytes: count, LogID: log.ID})
	}
	if err != nil {
		return err
	}
	if changed != 1 {
		return fmt.Errorf("output progress changed during append")
	}
	if err := chargeOutput(ctx, q, row.AccountID, count+pb.OutputFrameCharge, 1); err != nil {
		return err
	}
	if sequenced {
		row.CommittedSequence = frame.Sequence
	}
	row.ByteCount += count
	row.FrameCount++
	row.LastLogID = log.ID
	return nil
}

func finishOutput(ctx context.Context, q *database.Queries, row *database.GetDebugletOutputRow, end *pb.DebugletOutputEnd) error {
	state := "complete"
	if end.Status == pb.DebugletOutputStatus_DEBUGLET_OUTPUT_STATUS_TRUNCATED {
		state = "truncated"
	}
	if row.FinalSequence.Valid {
		if row.FinalSequence.Int64 == end.LastSequence && row.Status == state && row.Reason == end.Reason {
			return nil
		}
		return status.Error(codes.FailedPrecondition, "conflicting output end")
	}
	if end.LastSequence != row.CommittedSequence {
		return status.Error(codes.FailedPrecondition, "output end does not match committed prefix")
	}
	changed, err := q.FinishDebugletOutput(ctx, database.FinishDebugletOutputParams{
		DebugletID: row.DebugletID, Sequence: end.LastSequence, Status: state, Reason: end.Reason,
	})
	if err != nil {
		return err
	}
	if changed != 1 {
		return errors.New("output progress changed during finalization")
	}
	row.FinalSequence = sql.NullInt64{Int64: end.LastSequence, Valid: true}
	row.FinalCursor = sql.NullInt64{Int64: row.LastLogID, Valid: true}
	row.Status, row.Reason = state, end.Reason
	return nil
}

func outputReceipt(row database.GetDebugletOutputRow) *pb.DebugletStreamResponse {
	receipt := &pb.DebugletStreamResponse{CommittedSequence: row.CommittedSequence}
	if row.FinalSequence.Valid {
		state := pb.DebugletOutputStatus_DEBUGLET_OUTPUT_STATUS_COMPLETE
		if row.Status == "truncated" {
			state = pb.DebugletOutputStatus_DEBUGLET_OUTPUT_STATUS_TRUNCATED
		}
		receipt.End = &pb.DebugletOutputEnd{LastSequence: row.FinalSequence.Int64, Status: state, Reason: row.Reason}
	}
	return receipt
}
