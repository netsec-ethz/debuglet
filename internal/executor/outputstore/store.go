// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

// Package outputstore persists output independently of execution scheduling.
package outputstore

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/netsec-ethz/debuglet/internal/controlsession"
	"github.com/netsec-ethz/debuglet/internal/executor/database"
	"github.com/netsec-ethz/debuglet/internal/storageheadroom"
	pb "github.com/netsec-ethz/debuglet/protocol"
)

var (
	ErrOutputLimit     = errors.New("run output limit reached")
	ErrSpoolLimit      = errors.New("executor output storage limit reached")
	ErrFinalized       = errors.New("output already finalized")
	ErrIdentity        = errors.New("output identity differs from admission")
	ErrAcknowledgement = errors.New("output acknowledgement conflicts with retained output")
)

type Limits struct {
	ControlReserveBytes int64
	RunBytes            int64
	RunFrames           int64
	NodeBytes           int64
	Runs                int64
}

func DefaultLimits() Limits {
	return Limits{ControlReserveBytes: storageheadroom.DefaultReserveBytes, RunBytes: 8 << 20, RunFrames: 65536, NodeBytes: 64 << 20, Runs: 65536}
}

type Store struct {
	db     *sql.DB
	limits Limits
}

func New(db *sql.DB, limits Limits) (*Store, error) {
	if limits.ControlReserveBytes == 0 {
		limits.ControlReserveBytes = storageheadroom.DefaultReserveBytes
	}
	if limits.ControlReserveBytes < 0 || db == nil || limits.RunBytes <= 0 || limits.RunFrames <= 0 || limits.NodeBytes < pb.OutputRunCharge || limits.Runs <= 0 {
		return nil, errors.New("invalid output storage limits or database")
	}
	return &Store{db: db, limits: limits}, nil
}

type Run struct {
	ID                   uuid.UUID
	Binding              controlsession.Binding
	Version              uint32
	LastSequence         int64
	AcknowledgedSequence int64
	EmittedBytes         int64
	QueuedBytes          int64
	QueuedFrames         int64
	End                  *pb.DebugletOutputEnd
	EndAcknowledged      bool
	Receipt              *pb.DebugletOutputEnd
}

type Frame struct {
	Sequence  int64
	Timestamp time.Time
	Output    []byte
}

func run(row database.OutputRun) (Run, error) {
	id, err := uuid.Parse(row.RunID)
	if err != nil {
		return Run{}, err
	}
	r := Run{ID: id, Binding: controlsession.Binding{Incarnation: row.DispatcherIncarnation, SessionID: row.SessionID}, Version: uint32(row.OutputVersion), LastSequence: row.LastSequence, AcknowledgedSequence: row.AcknowledgedSequence, EmittedBytes: row.EmittedBytes, QueuedBytes: row.QueuedBytes, QueuedFrames: row.QueuedFrames, EndAcknowledged: row.EndAcknowledged}
	if row.Status != "open" {
		status := pb.DebugletOutputStatus_DEBUGLET_OUTPUT_STATUS_COMPLETE
		if row.Status == "truncated" {
			status = pb.DebugletOutputStatus_DEBUGLET_OUTPUT_STATUS_TRUNCATED
		}
		r.End = &pb.DebugletOutputEnd{LastSequence: row.LastSequence, Status: status, Reason: row.Reason}
	}
	if row.ReceiptSequence.Valid {
		r.Receipt = &pb.DebugletOutputEnd{LastSequence: row.ReceiptSequence.Int64, Status: pb.DebugletOutputStatus_DEBUGLET_OUTPUT_STATUS_TRUNCATED, Reason: row.ReceiptReason}
	}
	return r, nil
}

func (s *Store) Admit(ctx context.Context, id uuid.UUID, binding controlsession.Binding, version uint32) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := s.AdmitTx(ctx, tx, id, binding, version); err != nil {
		return err
	}
	return tx.Commit()
}

// AdmitTx reserves output identity and quota in the caller's admission transaction.
// The scheduler uses this so an accepted queued run cannot lack output metadata.
func (s *Store) AdmitTx(ctx context.Context, tx *sql.Tx, id uuid.UUID, binding controlsession.Binding, version uint32) error {
	if id == uuid.Nil || !binding.Valid() || version != pb.OutputVersion {
		return ErrIdentity
	}
	q := database.New(tx)
	existing, err := q.GetOutputRun(ctx, id.String())
	if err == nil {
		if existing.DispatcherIncarnation != binding.Incarnation || existing.SessionID != binding.SessionID || existing.OutputVersion != int64(version) {
			return ErrIdentity
		}
		return nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	used, err := q.GetOutputUsage(ctx)
	if err != nil {
		return err
	}
	count, err := q.CountOutputRuns(ctx)
	if err != nil {
		return err
	}
	if used > s.limits.NodeBytes-pb.OutputRunCharge || count >= s.limits.Runs {
		return ErrSpoolLimit
	}
	if err := storageheadroom.Check(ctx, tx, s.limits.ControlReserveBytes, pb.OutputRunCharge); err != nil {
		return errors.Join(ErrSpoolLimit, err)
	}
	if err := q.CreateOutputRun(ctx, database.CreateOutputRunParams{RunID: id.String(), DispatcherIncarnation: binding.Incarnation, SessionID: binding.SessionID, OutputVersion: int64(version)}); err != nil {
		return err
	}
	if err := q.AddOutputUsage(ctx, pb.OutputRunCharge); err != nil {
		return err
	}
	return nil
}

// Append returns only after the frame and its quota charge commit together.
func (s *Store) Append(ctx context.Context, id uuid.UUID, timestamp time.Time, data []byte) (Frame, error) {
	if len(data) == 0 || len(data) > pb.MaxOutputFrameBytes || !time.Unix(0, timestamp.UnixNano()).Equal(timestamp) {
		return Frame{}, errors.New("invalid output frame")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Frame{}, err
	}
	defer tx.Rollback()
	q := database.New(tx)
	r, err := q.GetOutputRun(ctx, id.String())
	if err != nil {
		return Frame{}, err
	}
	if r.Status != "open" {
		return Frame{}, ErrFinalized
	}
	if int64(len(data)) > s.limits.RunBytes-r.EmittedBytes || r.LastSequence >= s.limits.RunFrames {
		return Frame{}, ErrOutputLimit
	}
	used, err := q.GetOutputUsage(ctx)
	if err != nil {
		return Frame{}, err
	}
	charge := int64(len(data)) + pb.OutputFrameCharge
	if charge > s.limits.NodeBytes || used > s.limits.NodeBytes-charge {
		return Frame{}, ErrSpoolLimit
	}
	if err := storageheadroom.Check(ctx, tx, s.limits.ControlReserveBytes, int64(len(data))); err != nil {
		return Frame{}, errors.Join(ErrSpoolLimit, err)
	}
	sequence := r.LastSequence + 1
	if err := q.CreateOutputFrame(ctx, database.CreateOutputFrameParams{RunID: id.String(), Sequence: sequence, TimestampNs: timestamp.UnixNano(), Output: data}); err != nil {
		return Frame{}, err
	}
	if err := q.AdvanceOutputRun(ctx, database.AdvanceOutputRunParams{RunID: id.String(), Bytes: int64(len(data))}); err != nil {
		return Frame{}, err
	}
	if err := q.AddOutputUsage(ctx, charge); err != nil {
		return Frame{}, err
	}
	if err := tx.Commit(); err != nil {
		return Frame{}, err
	}
	return Frame{Sequence: sequence, Timestamp: timestamp.UTC(), Output: append([]byte(nil), data...)}, nil
}

func (s *Store) Get(ctx context.Context, id uuid.UUID) (Run, error) {
	row, err := database.New(s.db).GetOutputRun(ctx, id.String())
	if err != nil {
		return Run{}, err
	}
	return run(row)
}

// Pending is keyset-paged so a caller can make fair, bounded delivery passes.
func (s *Store) Pending(ctx context.Context, afterRunID string, limit int) ([]Run, error) {
	if limit < 1 || limit > 100 {
		return nil, errors.New("invalid output page size")
	}
	rows, err := database.New(s.db).ListPendingOutputRuns(ctx, database.ListPendingOutputRunsParams{RunID: afterRunID, Limit: int64(limit)})
	if err != nil {
		return nil, err
	}
	out := make([]Run, 0, len(rows))
	for _, row := range rows {
		r, err := run(row)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, nil
}

func (s *Store) Frames(ctx context.Context, id uuid.UUID, after int64, limit int) ([]Frame, error) {
	if after < 0 || limit < 1 || limit > 64 {
		return nil, errors.New("invalid output frame page")
	}
	rows, err := database.New(s.db).ListOutputFrames(ctx, database.ListOutputFramesParams{RunID: id.String(), Sequence: after, Limit: int64(limit)})
	if err != nil {
		return nil, err
	}
	out := make([]Frame, 0, len(rows))
	for _, row := range rows {
		out = append(out, Frame{Sequence: row.Sequence, Timestamp: time.Unix(0, row.TimestampNs).UTC(), Output: row.Output})
	}
	return out, nil
}

func (s *Store) Finish(ctx context.Context, id uuid.UUID, status pb.DebugletOutputStatus, reason string) (*pb.DebugletOutputEnd, error) {
	if !pb.ValidOutputEnd(&pb.DebugletOutputEnd{Status: status, Reason: reason}) {
		return nil, errors.New("invalid output end")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	q := database.New(tx)
	row, err := q.GetOutputRun(ctx, id.String())
	if err != nil {
		return nil, err
	}
	r, err := run(row)
	if err != nil {
		return nil, err
	}
	end := &pb.DebugletOutputEnd{LastSequence: row.LastSequence, Status: status, Reason: reason}
	if r.End != nil {
		if !sameEnd(r.End, end) {
			return nil, ErrFinalized
		}
		return r.End, tx.Commit()
	}
	stored := "complete"
	if status == pb.DebugletOutputStatus_DEBUGLET_OUTPUT_STATUS_TRUNCATED {
		stored = "truncated"
	}
	if err := q.FinishOutputRun(ctx, database.FinishOutputRunParams{RunID: id.String(), Status: stored, Reason: reason}); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return end, nil
}

func sameEnd(a, b *pb.DebugletOutputEnd) bool {
	return a != nil && b != nil && a.LastSequence == b.LastSequence && a.Status == b.Status && a.Reason == b.Reason
}

func (s *Store) Acknowledge(ctx context.Context, id uuid.UUID, sequence int64, end *pb.DebugletOutputEnd) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	q := database.New(tx)
	row, err := q.GetOutputRun(ctx, id.String())
	if err != nil {
		return err
	}
	r, err := run(row)
	if err != nil {
		return err
	}
	if r.Receipt != nil {
		if sequence == r.Receipt.LastSequence && sameEnd(end, r.Receipt) {
			return tx.Commit()
		}
		return ErrAcknowledgement
	}
	if sequence < 0 || sequence > r.LastSequence || (end != nil && (sequence != r.LastSequence || !sameEnd(end, r.End))) {
		return ErrAcknowledgement
	}
	if sequence < r.AcknowledgedSequence {
		sequence = r.AcknowledgedSequence
	}
	count, err := q.SumAcknowledgedOutput(ctx, database.SumAcknowledgedOutputParams{RunID: id.String(), Sequence: sequence})
	if err != nil {
		return err
	}
	if err := q.DeleteAcknowledgedOutput(ctx, database.DeleteAcknowledgedOutputParams{RunID: id.String(), Sequence: sequence}); err != nil {
		return err
	}
	if err := q.AcknowledgeOutputRun(ctx, database.AcknowledgeOutputRunParams{RunID: id.String(), AcknowledgedSequence: sequence, Bytes: count.ByteCount, Frames: count.FrameCount, EndAcknowledged: r.EndAcknowledged || end != nil}); err != nil {
		return err
	}
	released := count.ByteCount + count.FrameCount*pb.OutputFrameCharge
	if end != nil && !r.EndAcknowledged {
		// The dispatcher now holds the durable end, so the run's admission
		// charge returns with its last frames.
		released += pb.OutputRunCharge
	}
	if err := q.AddOutputUsage(ctx, -released); err != nil {
		return err
	}
	return tx.Commit()
}

// AcceptTruncation records a dispatcher quota receipt separately from the
// producer's immutable end. The caller must first cancel and join the producer.
func (s *Store) AcceptTruncation(ctx context.Context, id uuid.UUID, end *pb.DebugletOutputEnd) error {
	if !pb.ValidOutputEnd(end) || end.Status != pb.DebugletOutputStatus_DEBUGLET_OUTPUT_STATUS_TRUNCATED ||
		(end.Reason != pb.OutputReasonLimit && end.Reason != pb.OutputReasonStorageLimit) {
		return ErrAcknowledgement
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	q := database.New(tx)
	row, err := q.GetOutputRun(ctx, id.String())
	if err != nil {
		return err
	}
	r, err := run(row)
	if err != nil {
		return err
	}
	if r.Receipt != nil {
		if sameEnd(r.Receipt, end) {
			return tx.Commit()
		}
		return ErrAcknowledgement
	}
	if r.End == nil || r.EndAcknowledged || end.LastSequence < r.AcknowledgedSequence || end.LastSequence > r.LastSequence {
		return ErrAcknowledgement
	}
	if err := q.AcceptOutputTruncation(ctx, database.AcceptOutputTruncationParams{RunID: id.String(), Sequence: sql.NullInt64{Int64: end.LastSequence, Valid: true}, Reason: end.Reason}); err != nil {
		return err
	}
	if err := q.DeleteAcknowledgedOutput(ctx, database.DeleteAcknowledgedOutputParams{RunID: id.String(), Sequence: r.LastSequence}); err != nil {
		return err
	}
	if err := q.AddOutputUsage(ctx, -r.QueuedBytes-r.QueuedFrames*pb.OutputFrameCharge-pb.OutputRunCharge); err != nil {
		return err
	}
	return tx.Commit()
}

// Abandon releases a finished run's spool when the dispatcher can no longer
// accept it: output bound to an ended session resumes only over an enrolled
// credential, and the dispatcher finalizes the rest as interrupted itself.
func (s *Store) Abandon(ctx context.Context, id uuid.UUID) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	q := database.New(tx)
	row, err := q.GetOutputRun(ctx, id.String())
	if err != nil {
		return err
	}
	r, err := run(row)
	if err != nil {
		return err
	}
	if r.EndAcknowledged {
		return tx.Commit()
	}
	if r.End == nil {
		return ErrAcknowledgement
	}
	if err := q.DeleteAcknowledgedOutput(ctx, database.DeleteAcknowledgedOutputParams{RunID: id.String(), Sequence: r.LastSequence}); err != nil {
		return err
	}
	if err := q.AbandonOutputRun(ctx, id.String()); err != nil {
		return err
	}
	if err := q.AddOutputUsage(ctx, -r.QueuedBytes-r.QueuedFrames*pb.OutputFrameCharge-pb.OutputRunCharge); err != nil {
		return err
	}
	return tx.Commit()
}

// InterruptOpen records uncertainty about producers that died with the process.
// It grants no permission to replay their workloads.
func (s *Store) InterruptOpen(ctx context.Context) error {
	if err := database.New(s.db).InterruptOpenOutputRuns(ctx); err != nil {
		return fmt.Errorf("mark interrupted output: %w", err)
	}
	return nil
}
