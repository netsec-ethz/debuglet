// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package dispatcher

import (
	"context"
	"database/sql"
	"errors"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/netsec-ethz/debuglet/internal/bitrate"
	"github.com/netsec-ethz/debuglet/internal/controlsession"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/database"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/models"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/resource/schedule"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/transport/rpc"
	"github.com/netsec-ethz/debuglet/pkg/wire"
	pb "github.com/netsec-ethz/debuglet/protocol"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type recoveryPeer struct {
	pb.UnimplementedExecutorServiceServer
	calls   atomic.Int64
	respond func(context.Context, *pb.InspectRetainedRunRequest) (*pb.InspectRetainedRunResponse, error)
}

func (p *recoveryPeer) Hello(context.Context, *pb.HelloRequest) (*pb.HelloResponse, error) {
	return &pb.HelloResponse{ExecutorId: "recovery-executor", Currency: "TEST"}, nil
}
func (p *recoveryPeer) InspectRetainedRun(ctx context.Context, req *pb.InspectRetainedRunRequest) (*pb.InspectRetainedRunResponse, error) {
	p.calls.Add(1)
	return p.respond(ctx, req)
}

func TestRecoveryUsesOneBoundReadWithoutChangingTheRun(t *testing.T) {
	for _, classification := range []string{"not_attempted", "unavailable", "retained_unstarted", "started_unknown", "legacy", "absent", "filtered", "unsupported", "failed", "invalid"} {
		t.Run(classification, func(t *testing.T) {
			d := newTerminalPeerDispatcher(t)
			original := controlsession.Binding{Incarnation: uuid.NewString(), SessionID: uuid.NewString()}
			if classification == "legacy" {
				original = controlsession.Binding{}
			}
			id := uuid.New()
			peer := &recoveryPeer{respond: func(ctx context.Context, req *pb.InspectRetainedRunRequest) (*pb.InspectRetainedRunResponse, error) {
				if req.DebugletId != id.String() || req.GetControlBinding().GetDispatcherIncarnation() != d.incarnation || req.GetControlBinding().GetSessionId() == "" {
					t.Error("inspection did not use the captured session")
				}
				switch classification {
				case "unsupported":
					return nil, status.Error(codes.Unimplemented, "unsupported")
				case "failed":
					return nil, status.Error(codes.Internal, "private database detail")
				case "absent":
					return &pb.InspectRetainedRunResponse{Status: pb.RetainedRunStatus_RETAINED_RUN_STATUS_ABSENT}, nil
				case "filtered":
					return &pb.InspectRetainedRunResponse{Status: pb.RetainedRunStatus_RETAINED_RUN_STATUS_FILTERED}, nil
				case "invalid":
					return &pb.InspectRetainedRunResponse{}, nil
				}
				run := &pb.RetainedRun{DebugletId: id.String(), TransactionId: "transaction", OriginalBinding: &pb.ControlBinding{DispatcherIncarnation: original.Incarnation, SessionId: original.SessionID}}
				if classification == "started_unknown" {
					run.Started = true
					run.StartedAt = timestamppb.Now()
				}
				return &pb.InspectRetainedRunResponse{Status: pb.RetainedRunStatus_RETAINED_RUN_STATUS_FOUND, Run: run}, nil
			}}
			stop, err := startTerminalPeer(t.Context(), d, bitrate.Megabit, peer)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				if err := stop(ctx); err != nil {
					t.Error(err)
				}
			})
			if classification == "not_attempted" {
				d.mu.RLock()
				original = d.executors["recovery-executor"].owner.Binding()
				d.mu.RUnlock()
			}
			if classification == "unavailable" {
				d.mu.RLock()
				d.executors["recovery-executor"].owner.Retire()
				d.mu.RUnlock()
			}
			start := time.Now().Add(time.Hour).Truncate(time.Second)
			row, err := database.New(d.db).CreateDebuglet(t.Context(), database.CreateDebugletParams{Uuid: id, StartTime: models.NewUTCTime(start), EndTime: models.NewUTCTime(start.Add(time.Minute)), Usage: 100, CeilBw: 100, ExecutorID: "recovery-executor", State: models.RunStateStarted, TransactionID: "transaction", DispatcherIncarnation: original.Incarnation, SessionID: original.SessionID})
			if err != nil {
				t.Fatal(err)
			}
			d.scheduler.Submit(schedule.Request{Executor: row.ExecutorID, From: start, To: row.EndTime.Time, Use: 100})
			snapshot := (&tgFixture{db: d.db}).snapshot(t)
			doc, err := d.Recovery(t.Context(), id)
			if err != nil {
				t.Fatal(err)
			}
			if doc.Observation.Classification != classification || doc.State != models.RunStateStarted.String() || doc.CheckedAt.IsZero() {
				t.Fatalf("unexpected observation: %+v", doc)
			}
			wantCalls := int64(1)
			if classification == "not_attempted" || classification == "unavailable" {
				wantCalls = 0
			}
			if peer.calls.Load() != wantCalls {
				t.Fatalf("inspection count %d, want %d", peer.calls.Load(), wantCalls)
			}
			valid := classification == "retained_unstarted" || classification == "started_unknown" || classification == "legacy" || classification == "absent" || classification == "filtered"
			if valid != (doc.Observation.Observer != nil) || valid != (doc.Observation.ReceivedAt != nil) || valid != (doc.Observation.CurrentAtCheck != nil) {
				t.Fatalf("false provenance: %+v", doc.Observation)
			}
			if valid && !*doc.Observation.CurrentAtCheck {
				t.Fatal("current observer classified as historical")
			}
			if got := (&tgFixture{db: d.db}).snapshot(t); got != snapshot {
				t.Fatal("inspection changed outcome, orders or earnings")
			}
			if d.scheduler.QueryMaxExec(row.ExecutorID, start, row.EndTime.Time) != 100 {
				t.Fatal("inspection changed reservation")
			}
			if _, err := d.Recovery(t.Context(), uuid.New()); !errors.Is(err, sql.ErrNoRows) {
				t.Fatalf("unknown run: %v", err)
			}
			if peer.calls.Load() != wantCalls {
				t.Fatal("unknown run caused orphan discovery")
			}
		})
	}
}

func TestRecoveryKeepsHistoricalReplyAndRejectsInconsistentMetadata(t *testing.T) {
	d := newTerminalPeerDispatcher(t)
	original := controlsession.Binding{Incarnation: uuid.NewString(), SessionID: uuid.NewString()}
	observed := controlsession.Binding{Incarnation: d.incarnation, SessionID: uuid.NewString()}
	owner, err := rpc.NewSessionOwner("recovery-executor", observed, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	owner.MarkRegistered()
	row := database.Debuglet{Uuid: uuid.New(), ExecutorID: owner.ExecutorID(), TransactionID: "transaction", DispatcherIncarnation: original.Incarnation, SessionID: original.SessionID}
	reply := &pb.InspectRetainedRunResponse{Status: pb.RetainedRunStatus_RETAINED_RUN_STATUS_FOUND, Run: &pb.RetainedRun{DebugletId: row.Uuid.String(), TransactionId: row.TransactionID, OriginalBinding: &pb.ControlBinding{DispatcherIncarnation: original.Incarnation, SessionId: original.SessionID}}}
	received := time.Now().UTC()
	observation := validateRecoveryReply(row, owner, reply, received)
	owner.Retire()
	replacement, err := rpc.NewSessionOwner(owner.ExecutorID(), controlsession.Binding{Incarnation: d.incarnation, SessionID: uuid.NewString()}, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	replacement.MarkRegistered()
	d.mu.Lock()
	d.executors[owner.ExecutorID()] = &executorEntry{RegisteredExecutor: &RegisteredExecutor{ID: owner.ExecutorID()}, owner: replacement}
	d.mu.Unlock()
	doc := wire.Recovery{ExecutorID: row.ExecutorID, Observation: observation}
	d.finishRecovery(&doc, owner, original)
	if doc.Observation.CurrentAtCheck == nil || *doc.Observation.CurrentAtCheck || doc.Observation.Classification != "retained_unstarted" || *doc.Observation.ReceivedAt != received || doc.Observation.Observer.Binding.SessionID != observed.SessionID {
		t.Fatalf("historical observation erased or relabeled: %+v", doc.Observation)
	}
	for name, change := range map[string]func(*pb.InspectRetainedRunResponse){
		"wrong id":          func(r *pb.InspectRetainedRunResponse) { r.Run.DebugletId = uuid.NewString() },
		"wrong transaction": func(r *pb.InspectRetainedRunResponse) { r.Run.TransactionId = "other" },
		"wrong binding":     func(r *pb.InspectRetainedRunResponse) { r.Run.OriginalBinding.SessionId = observed.SessionID },
		"missing marker":    func(r *pb.InspectRetainedRunResponse) { r.Run.Started = true },
		"invalid timestamp": func(r *pb.InspectRetainedRunResponse) { r.Run.StartTime = &timestamppb.Timestamp{Nanos: -1} },
		"missing run":       func(r *pb.InspectRetainedRunResponse) { r.Run = nil },
		"extra run":         func(r *pb.InspectRetainedRunResponse) { r.Status = pb.RetainedRunStatus_RETAINED_RUN_STATUS_ABSENT },
	} {
		t.Run(name, func(t *testing.T) {
			r := proto.Clone(reply).(*pb.InspectRetainedRunResponse)
			change(r)
			got := validateRecoveryReply(row, owner, r, received)
			if !reflect.DeepEqual(got, wire.RecoveryObservation{Classification: "invalid"}) {
				t.Fatalf("invalid metadata has provenance: %+v", got)
			}
		})
	}
}
