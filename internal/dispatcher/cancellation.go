// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package dispatcher

import (
	"context"
	"database/sql"
	"time"

	"github.com/google/uuid"
	"github.com/netsec-ethz/debuglet/internal/controlsession"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/database"
	"github.com/netsec-ethz/debuglet/pkg/wire"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// requestCancellation commits before either remote delivery or local terminal
// selection. The run key makes concurrent retries share the first reason.
func (d *Dispatcher) requestCancellation(ctx context.Context, run int64, reason string) (database.DebugletCancellation, error) {
	q := database.New(d.db)
	if err := q.CreateCancellation(ctx, database.CreateCancellationParams{
		DebugletID: run, RequestID: uuid.NewString(), Reason: reason, RequestedAt: d.now().UTC().UnixNano(),
	}); err != nil {
		return database.DebugletCancellation{}, status.Errorf(codes.Internal, "failed to record cancellation request: %v", err)
	}
	record, err := q.GetCancellation(ctx, run)
	if err != nil {
		return database.DebugletCancellation{}, status.Errorf(codes.Internal, "failed to read cancellation request: %v", err)
	}
	return record, nil
}

func (d *Dispatcher) failCancellation(ctx context.Context, run int64, reason string) error {
	if err := database.New(d.db).FailCancellation(ctx, database.FailCancellationParams{DebugletID: run, Failure: reason}); err != nil {
		return status.Errorf(codes.Internal, "failed to record cancellation disposition: %v", err)
	}
	return nil
}

// Cancellation is a read-only snapshot. It never retries delivery, repairs a
// terminal result, or infers remote success from a locally cancelled run.
func (d *Dispatcher) Cancellation(ctx context.Context, id uuid.UUID) (wire.Cancellation, error) {
	tx, err := d.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return wire.Cancellation{}, err
	}
	defer tx.Rollback()
	q := database.New(tx)
	run, err := q.GetDebugletByUUID(ctx, id)
	if err != nil {
		return wire.Cancellation{}, err
	}
	record, err := q.GetCancellation(ctx, run.ID)
	if err != nil {
		return wire.Cancellation{}, err
	}
	if err := tx.Commit(); err != nil {
		return wire.Cancellation{}, err
	}
	doc := wire.Cancellation{
		ID: id.String(), RequestID: record.RequestID, ExecutorID: run.ExecutorID,
		OriginalBinding: recoveryBinding(controlsession.Binding{Incarnation: run.DispatcherIncarnation, SessionID: run.SessionID}),
		RequestedAt:     time.Unix(0, record.RequestedAt).UTC(),
		AttemptedAt:     cancellationTime(record.AttemptedAt), AcknowledgedAt: cancellationTime(record.AcknowledgedAt),
		Disposition: "requested", Reason: record.Failure, State: run.State.String(), Error: run.Error.String,
	}
	d.mu.RLock()
	entry := d.executors[run.ExecutorID]
	current := !d.closed && entry != nil && entry.owner.Available() &&
		entry.owner.Binding().Incarnation == run.DispatcherIncarnation && entry.owner.Binding().SessionID == run.SessionID
	doc.CheckedAt = d.now().UTC()
	d.mu.RUnlock()
	switch {
	case record.AcknowledgedAt.Valid:
		doc.Disposition, doc.Reason = "acknowledged", ""
	case record.Failure != "":
		doc.Disposition = "unresolved"
	case !current:
		doc.Disposition, doc.Reason = "unresolved", "original_binding_unavailable"
	case record.AttemptedAt.Valid:
		doc.Disposition = "delivery_attempted"
	}
	return doc, nil
}

func cancellationTime(value sql.NullInt64) *time.Time {
	if !value.Valid {
		return nil
	}
	date := time.Unix(0, value.Int64).UTC()
	return &date
}
