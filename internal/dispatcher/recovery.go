// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package dispatcher

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/netsec-ethz/debuglet/internal/controlsession"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/database"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/models"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/transport/rpc"
	"github.com/netsec-ethz/debuglet/pkg/wire"
	pb "github.com/netsec-ethz/debuglet/protocol"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// Recovery reads a known run and makes at most one retained-run lookup against
// the captured current executor. It changes neither that run nor its charges.
func (d *Dispatcher) Recovery(ctx context.Context, id uuid.UUID) (wire.Recovery, error) {
	row, err := database.New(d.db).GetDebugletByUUID(ctx, id)
	if err != nil {
		return wire.Recovery{}, err
	}
	original := controlsession.Binding{Incarnation: row.DispatcherIncarnation, SessionID: row.SessionID}
	doc := wire.Recovery{ID: id.String(), ExecutorID: row.ExecutorID, State: row.State.String(), Error: PublicTerminalError(row.Error.String), OriginalBinding: recoveryBinding(original)}
	if reclaimed, err := database.New(d.db).GetAllocationReclamation(ctx, id); err == nil {
		doc.AllocationReclaimedAt = &reclaimed.Time
	} else if !errors.Is(err, sql.ErrNoRows) {
		return wire.Recovery{}, err
	}
	doc.Observation.Classification = "unavailable"

	d.mu.RLock()
	var owner *rpc.SessionOwner
	if entry := d.executors[row.ExecutorID]; !d.closed && entry != nil && entry.owner.Available() {
		owner = entry.owner
	}
	d.mu.RUnlock()
	// Active work still belongs to its live control session. A terminal report
	// precedes executor retirement, so a current terminal run needs the same
	// explicit metadata lookup as an interrupted run to observe actual absence.
	if owner != nil && original.Valid() && original == owner.Binding() && row.State != models.RunStateExited {
		doc.Observation.Classification = "not_attempted"
	} else if owner != nil {
		lookup, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		call, admitted := owner.AdmitMutation(lookup)
		if admitted == nil {
			defer call.Finish()
			if client, available := d.Bidi.GetClientFor(owner); available {
				binding := owner.Binding()
				response, callErr := client.InspectRetainedRun(call.Context(), &pb.InspectRetainedRunRequest{
					DebugletId: id.String(), ControlBinding: &pb.ControlBinding{DispatcherIncarnation: binding.Incarnation, SessionId: binding.SessionID},
				}, grpc.MaxCallRecvMsgSize(4096))
				received := d.now().UTC()
				switch {
				case callErr == nil:
					doc.Observation = validateRecoveryReply(row, owner, response, received)
				case status.Code(callErr) == codes.Unimplemented:
					doc.Observation.Classification = "unsupported"
				default:
					doc.Observation.Classification = "failed"
				}
			}
		}
	}
	if err := ctx.Err(); err != nil {
		return wire.Recovery{}, err
	}
	d.finishRecovery(&doc, owner, original)
	return doc, nil
}

// finishRecovery dates availability independently of the stored outcome. A
// replacement cannot erase a valid reply or acquire its predecessor's identity.
func (d *Dispatcher) finishRecovery(doc *wire.Recovery, observer *rpc.SessionOwner, original controlsession.Binding) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	doc.CheckedAt = d.now().UTC()
	doc.ControlStatus = "unavailable"
	if !original.Valid() {
		doc.ControlStatus = "legacy"
	}
	entry := d.executors[doc.ExecutorID]
	available := !d.closed && entry != nil && entry.owner.Available()
	if available && original.Valid() && entry.owner.Binding() == original {
		doc.ControlStatus = "current"
	}
	if doc.Observation.Observer != nil {
		current := available && entry.owner == observer
		doc.Observation.CurrentAtCheck = &current
	}
}

func validateRecoveryReply(row database.Debuglet, owner *rpc.SessionOwner, reply *pb.InspectRetainedRunResponse, received time.Time) wire.RecoveryObservation {
	invalid := wire.RecoveryObservation{Classification: "invalid"}
	if reply == nil {
		return invalid
	}
	observation := wire.RecoveryObservation{}
	switch reply.GetStatus() {
	case pb.RetainedRunStatus_RETAINED_RUN_STATUS_ABSENT, pb.RetainedRunStatus_RETAINED_RUN_STATUS_FILTERED:
		if reply.Run != nil {
			return invalid
		}
		observation.Classification = "absent"
		if reply.GetStatus() == pb.RetainedRunStatus_RETAINED_RUN_STATUS_FILTERED {
			observation.Classification = "filtered"
		}
	case pb.RetainedRunStatus_RETAINED_RUN_STATUS_FOUND:
		run := reply.Run
		if run == nil || run.DebugletId != row.Uuid.String() || len(run.TransactionId) > 256 || run.TransactionId != row.TransactionID {
			return invalid
		}
		binding := controlsession.Binding{Incarnation: run.GetOriginalBinding().GetDispatcherIncarnation(), SessionID: run.GetOriginalBinding().GetSessionId()}
		if binding.Incarnation != row.DispatcherIncarnation || binding.SessionID != row.SessionID || binding == owner.Binding() {
			return invalid
		}
		if (binding.Incarnation != "" || binding.SessionID != "") && !binding.Valid() {
			return invalid
		}
		startedAt, ok := recoveryTime(run.StartedAt)
		if !ok || run.Started != (startedAt != nil) {
			return invalid
		}
		startTime, ok := recoveryTime(run.StartTime)
		if !ok {
			return invalid
		}
		observation.Retained = &wire.RetainedRun{OriginalBinding: recoveryBinding(binding), Started: run.Started, StartedAt: startedAt, StartTime: startTime}
		observation.Classification = "retained_unstarted"
		if run.Started {
			observation.Classification = "started_unknown"
		}
		if !binding.Valid() {
			observation.Classification = "legacy"
		}
	default:
		return invalid
	}
	observation.Observer = &wire.RecoveryObserver{ExecutorID: owner.ExecutorID(), Binding: *recoveryBinding(owner.Binding())}
	observation.ReceivedAt = &received
	return observation
}

func recoveryTime(value *timestamppb.Timestamp) (*time.Time, bool) {
	if value == nil {
		return nil, true
	}
	if value.CheckValid() != nil {
		return nil, false
	}
	date := value.AsTime().UTC()
	if date.IsZero() {
		return nil, false
	}
	return &date, true
}

func recoveryBinding(binding controlsession.Binding) *wire.ControlBinding {
	if !binding.Valid() {
		return nil
	}
	return &wire.ControlBinding{DispatcherIncarnation: binding.Incarnation, SessionID: binding.SessionID}
}
