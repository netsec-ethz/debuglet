// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package dispatcher

import (
 "bytes"
 "context"
 "time"

 "github.com/netsec-ethz/debuglet/internal/dispatcher/database"
 "github.com/netsec-ethz/debuglet/internal/dispatcher/models"
 "github.com/netsec-ethz/debuglet/internal/dispatcher/transport/rpc"
 "github.com/netsec-ethz/debuglet/pkg/wire"
 pb "github.com/netsec-ethz/debuglet/protocol"
 "google.golang.org/grpc/codes"
 "google.golang.org/grpc/status"
)

const experimentLead = 2 * time.Second
const experimentWait = 30 * time.Second

// OnExperimentReady performs one bounded poll. SQLite serializes readiness,
// release and cancellation; a committed release is immutable across restarts.
func (d *Dispatcher) OnExperimentReady(ctx context.Context, mutation *rpc.Mutation, req *pb.ExperimentReadyRequest) (*pb.ExperimentReadyResponse, error) {
 if req.GetExecutorId() == "" { return nil, status.Error(codes.PermissionDenied, "executor identity required") }
 owner, err := requireMutation(mutation, req.GetExecutorId())
 if err != nil { return nil, err }
 if len(req.GetMetadata()) > wire.MaxExperimentMetadata { return nil, status.Error(codes.ResourceExhausted, "experiment metadata exceeds 4096 bytes") }
 id, err := parseRunID(req.GetDebugletId())
 if err != nil { return nil, err }
 // Classify ownership before reading any transaction or peer metadata.
 run, err := d.ownedDebuglet(ctx, owner, id)
 if err != nil { return nil, err }
 d.mu.Lock()
 defer d.mu.Unlock()
 tx, err := d.db.BeginTx(ctx, nil)
 if err != nil { return nil, err }
 defer tx.Rollback()
 q := database.New(tx)
 members, err := q.GetExperimentMembers(ctx, run.TransactionID)
 if err != nil { return nil, err }
 orders, err := q.CountExperimentOrders(ctx, run.TransactionID)
 if err != nil { return nil, err }
 if len(members) == 0 || len(members) > wire.MaxExperimentParticipants || int64(len(members)) != orders {
  return nil, status.Error(codes.FailedPrecondition, "experiment membership is not fully admitted")
 }
 now := d.now()
 deadline := now.Add(experimentWait)
 ready := 0
 found := false
 for _, member := range members {
  row := member.Debuglet
  entry := d.executors[row.ExecutorID]
  if d.closed || entry == nil || !entry.owner.Available() || entry.owner.Binding().Incarnation != row.DispatcherIncarnation || entry.owner.Binding().SessionID != row.SessionID {
   return nil, status.Error(codes.FailedPrecondition, "experiment participant session is unavailable")
  }
  if row.State == models.RunStateExited || member.Cancelled || member.Reclaimed {
   return nil, status.Error(codes.FailedPrecondition, "experiment participant is no longer active")
  }
  if end := row.EndTime.Time.Add(-experimentLead); end.Before(deadline) { deadline = end }
  if member.ReadyAtNs.Valid { ready++ }
  if row.ID == run.ID {
   found = true
   if row.State != models.RunStateStarted || now.Before(row.StartTime.Time) { return nil, status.Error(codes.FailedPrecondition, "participant has not started") }
   if entry.owner != owner { return nil, status.Error(codes.PermissionDenied, "run does not belong to session") }
   if member.ReadyAtNs.Valid && !bytes.Equal(member.Metadata, req.GetMetadata()) {
    return nil, status.Error(codes.AlreadyExists, "readiness metadata is immutable")
   }
   if !member.ReadyAtNs.Valid { ready++ }
  }
 }
 if !found { return nil, status.Error(codes.PermissionDenied, "run is not an experiment participant") }
 if err := q.CreateExperimentBarrier(ctx, database.CreateExperimentBarrierParams{TransactionID: run.TransactionID, DeadlineNs: deadline.UnixNano()}); err != nil { return nil, err }
 barrier, err := q.GetExperimentBarrier(ctx, run.TransactionID)
 if err != nil { return nil, err }
 if now.UnixNano() >= barrier.DeadlineNs || !now.Before(deadline) {
  // Preserve the original deadline even when the first call already expired.
  if err := tx.Commit(); err != nil { return nil, err }
  return nil, status.Error(codes.DeadlineExceeded, "experiment readiness deadline expired")
 }
 metadata := req.GetMetadata()
 if metadata == nil { metadata = []byte{} }
 if err := q.RecordExperimentReady(ctx, database.RecordExperimentReadyParams{DebugletID: run.ID, Metadata: metadata, ReadyAtNs: now.UnixNano()}); err != nil { return nil, err }
 start := barrier.StartTimeNs
 if start == 0 && ready == len(members) {
  start = now.Add(experimentLead).UnixNano()
  if err := q.ReleaseExperiment(ctx, database.ReleaseExperimentParams{StartTimeNs: start, TransactionID: run.TransactionID}); err != nil { return nil, err }
 }
 out := &pb.ExperimentReadyResponse{ExperimentId: run.TransactionID, StartTimeNs: start}
 // Pending callers learn no partial metadata and never wait inside a mutation.
 if start != 0 {
  for _, member := range members {
   m := &pb.ExperimentParticipant{Id: member.Debuglet.Uuid.String(), ExecutorId: member.Debuglet.ExecutorID, Metadata: member.Metadata, ReadyAtNs: member.ReadyAtNs.Int64}
   if member.Debuglet.ID == run.ID && !member.ReadyAtNs.Valid { m.Metadata, m.ReadyAtNs = metadata, now.UnixNano() }
   out.Participants = append(out.Participants, m)
  }
 }
 if err := tx.Commit(); err != nil { return nil, err }
 return out, nil
}

