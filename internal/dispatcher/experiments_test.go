// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package dispatcher

import (
 "bytes"
 "testing"
 "time"

 "github.com/google/uuid"
 "github.com/netsec-ethz/debuglet/internal/dispatcher/database"
 "github.com/netsec-ethz/debuglet/internal/dispatcher/models"
 "github.com/netsec-ethz/debuglet/internal/dispatcher/transport/rpc"
 "github.com/netsec-ethz/debuglet/internal/sqlitedb"
 "github.com/netsec-ethz/debuglet/pkg/wire"
 pb "github.com/netsec-ethz/debuglet/protocol"
 "google.golang.org/grpc/codes"
 "google.golang.org/grpc/status"
)

func experimentFixture(t *testing.T, count int) (*tgFixture, []uuid.UUID, string, *time.Time) {
 t.Helper()
 f := newTGFixture(t, nil)
 first := f.seedDirect(t, tgFloorA)
 now := time.Now()
 f.d.now = func() time.Time { return now }
 ids := []uuid.UUID{first.id}
 if _, err := f.db.Exec("UPDATE debuglets SET start_time = ?, end_time = ?, state = ? WHERE id = ?", models.NewUTCTime(now.Add(-time.Second)), models.NewUTCTime(now.Add(2*time.Minute)), models.RunStateStarted, first.row.ID); err != nil { t.Fatal(err) }
 if _, err := f.db.Exec("UPDATE debuglet_order SET debuglet_id = ? WHERE transaction_id = ?", first.row.ID, first.txID); err != nil { t.Fatal(err) }
 for i := 1; i < count; i++ {
  id := uuid.New()
  row, err := f.q.CreateDebuglet(f.ctx, database.CreateDebugletParams{Uuid:id, StartTime:models.NewUTCTime(now.Add(-time.Second)), EndTime:models.NewUTCTime(now.Add(2*time.Minute)), ExecutorID:tgExecutorID, State:models.RunStateStarted, TransactionID:first.txID, OrderID:int64(i+1), DispatcherIncarnation:first.row.DispatcherIncarnation, SessionID:first.row.SessionID})
  if err != nil { t.Fatal(err) }
  if _, err := f.q.CreateDebugletOrder(f.ctx, database.CreateDebugletOrderParams{TransactionID:first.txID, OrderID:int64(i+1), ExecutorID:tgExecutorID, State:int64(models.Outstanding)}); err != nil { t.Fatal(err) }
  if _, err := f.db.Exec("UPDATE debuglet_order SET debuglet_id = ? WHERE transaction_id = ? AND order_id = ?", row.ID, first.txID, i+1); err != nil { t.Fatal(err) }
  ids = append(ids, id)
 }
 return f, ids, first.txID, &now
}

func experimentReady(t *testing.T, f *tgFixture, id uuid.UUID, metadata []byte) (*pb.ExperimentReadyResponse, error) {
 t.Helper()
 mutation := effectTestMutation(t, f.d, tgExecutorID)
 defer mutation.Finish()
 return f.d.OnExperimentReady(f.ctx, mutation, &pb.ExperimentReadyRequest{DebugletId:id.String(), ExecutorId:tgExecutorID, Metadata:metadata})
}

func TestExperimentFiveMemberReleaseAndRestart(t *testing.T) {
 f, ids, group, now := experimentFixture(t, 5)
 for i, id := range ids {
  got, err := experimentReady(t, f, id, []byte{byte(i)})
  if err != nil { t.Fatal(err) }
  if i < 4 && (got.StartTimeNs != 0 || len(got.Participants) != 0) { t.Fatalf("early release: %+v", got) }
 }
 first, err := experimentReady(t, f, ids[0], []byte{0})
 if err != nil || first.ExperimentId != group || first.StartTimeNs != now.Add(experimentLead).UnixNano() || len(first.Participants) != 5 { t.Fatalf("release=%+v err=%v", first, err) }
 for i, member := range first.Participants {
  if member.Id != ids[i].String() || !bytes.Equal(member.Metadata, []byte{byte(i)}) || member.ReadyAtNs != now.UnixNano() { t.Fatalf("participant=%+v", member) }
 }
 *now = now.Add(time.Second)
 again, err := experimentReady(t, f, ids[0], []byte{0})
 if err != nil || again.StartTimeNs != first.StartTimeNs { t.Fatalf("duplicate reset release: %+v %v", again, err) }
 if _, err := experimentReady(t, f, ids[0], []byte("changed")); status.Code(err) != codes.AlreadyExists { t.Fatalf("metadata replacement: %v", err) }
 // A new dispatcher reconstructs no live original sessions. Durable release
 // survives, but a replacement control identity cannot replay the old run.
 var path string
 if err := f.db.QueryRow("SELECT file FROM pragma_database_list WHERE name = 'main'").Scan(&path); err != nil { t.Fatal(err) }
 reopened, err := sqlitedb.Open(path)
 if err != nil { t.Fatal(err) }
 defer reopened.Close()
 restarted, err := New(f.d.logger, reopened, "restart", time.Minute, time.Minute, f.ph)
 if err != nil { t.Fatal(err) }
 defer restarted.Close()
 barrier, err := database.New(reopened).GetExperimentBarrier(f.ctx, group)
 if err != nil || barrier.StartTimeNs != first.StartTimeNs { t.Fatalf("lost persisted release: %+v %v", barrier, err) }
 owner, err := rpc.NewSessionOwner(tgExecutorID, effectTestBinding(t), time.Minute)
 if err != nil { t.Fatal(err) }
 if !owner.MarkRegistered() { t.Fatal("register replacement") }
 mutation, err := owner.AdmitMutation(f.ctx)
 if err != nil { t.Fatal(err) }
 defer mutation.Finish()
 _, err = restarted.OnExperimentReady(f.ctx, mutation, &pb.ExperimentReadyRequest{DebugletId:ids[0].String(), ExecutorId:tgExecutorID})
 if status.Code(err) != codes.PermissionDenied { t.Fatalf("restart replay: %v", err) }
}

func TestExperimentDeadlineCancellationAndBounds(t *testing.T) {
 for _, kind := range []string{"deadline", "cancelled", "terminal", "retired", "oversize", "unstarted", "unadmitted"} {
  t.Run(kind, func(t *testing.T) {
   f, ids, group, now := experimentFixture(t, 2)
   if _, err := experimentReady(t, f, ids[0], nil); err != nil { t.Fatal(err) }
   want := codes.FailedPrecondition
   var metadata []byte
   switch kind {
   case "deadline": *now = now.Add(experimentWait); want = codes.DeadlineExceeded
   case "cancelled":
    row, _ := f.q.GetDebugletByUUID(f.ctx, ids[0]); if _, err := f.d.requestCancellation(f.ctx, row.ID, "test"); err != nil { t.Fatal(err) }
   case "terminal": if _, err := f.db.Exec("UPDATE debuglets SET state = ? WHERE uuid = ?", models.RunStateExited, ids[0]); err != nil { t.Fatal(err) }
   case "retired": f.d.executors[tgExecutorID].owner.Retire()
   case "oversize": metadata = make([]byte, wire.MaxExperimentMetadata+1); want = codes.ResourceExhausted
   case "unstarted": if _, err := f.db.Exec("UPDATE debuglets SET state = ? WHERE uuid = ?", models.RunStateUploaded, ids[1]); err != nil { t.Fatal(err) }
   case "unadmitted": if _, err := f.db.Exec("UPDATE debuglet_order SET debuglet_id = NULL WHERE transaction_id = ? AND order_id = 1", group); err != nil { t.Fatal(err) }
   }
   var err error
   if kind == "retired" {
    _, err = f.d.OnExperimentReady(f.ctx, nil, &pb.ExperimentReadyRequest{DebugletId:ids[1].String(), ExecutorId:tgExecutorID})
   } else { _, err = experimentReady(t, f, ids[1], metadata) }
   if status.Code(err) != want { t.Fatalf("got=%v want=%v", err, want) }
   barrier, err := f.q.GetExperimentBarrier(f.ctx, group)
   if err != nil || barrier.StartTimeNs != 0 { t.Fatalf("late release=%+v %v", barrier, err) }
   *now = now.Add(2*time.Minute)
   f.d.sweepEndedWindows(time.Time{})
   var retained int
   if err := f.db.QueryRow("SELECT COUNT(*) FROM experiment_readiness").Scan(&retained); err != nil || retained != 0 { t.Fatalf("retained=%d %v", retained, err) }
  })
 }
}

func TestExperimentForeignOwnerAndGroupIsolation(t *testing.T) {
 f, ids, group, _ := experimentFixture(t, 2)
 foreign := f.seedDirect(t, tgFloorA)
 mutation := effectTestMutation(t, f.d, tgExecutorID)
 defer mutation.Finish()
 for _, req := range []*pb.ExperimentReadyRequest{
  {DebugletId:ids[0].String(), ExecutorId:"foreign"},
  {DebugletId:ids[0].String()},
 } {
  if _, err := f.d.OnExperimentReady(f.ctx, mutation, req); status.Code(err) != codes.PermissionDenied { t.Fatalf("foreign owner: %v", err) }
 }
 if _, err := experimentReady(t, f, ids[0], []byte("private")); err != nil { t.Fatal(err) }
 // Another admitted transaction receives only its own fixed participant.
 if _, err := f.db.Exec("UPDATE debuglet_order SET debuglet_id = ? WHERE transaction_id = ?", foreign.row.ID, foreign.txID); err != nil { t.Fatal(err) }
 if _, err := f.db.Exec("UPDATE debuglets SET state = ?, start_time = ? WHERE id = ?", models.RunStateStarted, models.NewUTCTime(f.d.now().Add(-time.Second)), foreign.row.ID); err != nil { t.Fatal(err) }
 other, err := experimentReady(t, f, foreign.id, nil)
 if err != nil || other.ExperimentId != foreign.txID || len(other.Participants) != 1 || other.Participants[0].Id != foreign.id.String() || len(other.Participants[0].Metadata) != 0 { t.Fatalf("group leak: %+v %v", other, err) }
 got, err := f.q.GetExperimentBarrier(f.ctx, group)
 if err != nil || got.StartTimeNs != 0 { t.Fatalf("foreign readiness released group: %v %v", got, err) }
}
