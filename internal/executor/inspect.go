package executor

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/netsec-ethz/debuglet/internal/controlsession"
	"github.com/netsec-ethz/debuglet/internal/executor/scheduler"
	"github.com/netsec-ethz/debuglet/internal/executor/transport/rpc"
	"github.com/netsec-ethz/debuglet/internal/ids"
	pb "github.com/netsec-ethz/debuglet/protocol"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// maxInspectedTransactionID bounds the only variable-length field an answer
// carries. The rest is a run identity, at most one binding of two identities,
// two timestamps and a flag, all fixed in size, so bounding the transaction
// identifier bounds the whole response. A row that cannot be described within
// it fails with a bounded diagnostic instead of an oversized or truncated
// reply.
const maxInspectedTransactionID = 256

// OnInspectRetainedRun reads one stored run under the caller's exact session.
// It schedules, starts, finalizes, deletes and pays for nothing, and it never
// loads the stored program. A read failure or an unsupported backend is an
// error, never a successful missing-row answer.
func (e *Executor) OnInspectRetainedRun(ctx context.Context, binding controlsession.Binding, req *pb.InspectRetainedRunRequest) (*pb.InspectRetainedRunResponse, error) {
	if err := e.checkExecutionLease(ctx, binding); err != nil {
		return nil, err
	}
	if err := rpc.CheckPayloadBinding(req.GetControlBinding(), binding); err != nil {
		return nil, err
	}
	id, ok := ids.ParseCanonical(req.GetDebugletId())
	if !ok {
		return nil, status.Error(codes.InvalidArgument, "invalid debuglet ID")
	}
	inspector, ok := e.scheduler.(scheduler.RunInspection)
	if !ok {
		return nil, status.Error(codes.Unimplemented, "retained run inspection is unavailable")
	}
	lookupCtx, end := context.WithTimeout(ctx, scheduler.CleanupTimeout)
	defer end()
	run, err := inspector.InspectRetainedRun(lookupCtx, id, binding)
	if err != nil {
		return nil, inspectionFailure(err)
	}
	resp := &pb.InspectRetainedRunResponse{}
	switch run.Status {
	case scheduler.RetainedRunAbsent:
		resp.Status = pb.RetainedRunStatus_RETAINED_RUN_STATUS_ABSENT
	case scheduler.RetainedRunFiltered:
		resp.Status = pb.RetainedRunStatus_RETAINED_RUN_STATUS_FILTERED
	case scheduler.RetainedRunFound:
		metadata, err := retainedRunMetadata(run)
		if err != nil {
			return nil, err
		}
		resp.Status, resp.Run = pb.RetainedRunStatus_RETAINED_RUN_STATUS_FOUND, metadata
	default:
		return nil, status.Error(codes.Internal, "retained run lookup produced no classification")
	}
	return resp, nil
}

// retainedRunMetadata validates what the backend read before it is described
// on the wire. A row too large or malformed to describe is a bounded error.
func retainedRunMetadata(run scheduler.RetainedRun) (*pb.RetainedRun, error) {
	if run.DebugletID == uuid.Nil {
		return nil, status.Error(codes.Internal, "retained run has no identity")
	}
	if len(run.TransactionID) > maxInspectedTransactionID {
		return nil, status.Errorf(codes.ResourceExhausted, "retained transaction identifier needs %d bytes, limit is %d",
			len(run.TransactionID), maxInspectedTransactionID)
	}
	metadata := &pb.RetainedRun{
		DebugletId:    run.DebugletID.String(),
		TransactionId: run.TransactionID,
		Started:       run.Started(),
	}
	// Rows stored before run bindings existed keep an empty original binding.
	if run.Binding.Valid() {
		metadata.OriginalBinding = &pb.ControlBinding{
			DispatcherIncarnation: run.Binding.Incarnation,
			SessionId:             run.Binding.SessionID,
		}
	}
	if !run.StartedAt.IsZero() {
		metadata.StartedAt = timestamppb.New(run.StartedAt.UTC())
	}
	if !run.StartTime.IsZero() {
		metadata.StartTime = timestamppb.New(run.StartTime.UTC())
	}
	return metadata, nil
}

// inspectionFailure keeps a failed read distinguishable from a missing row.
func inspectionFailure(err error) error {
	switch {
	case errors.Is(err, scheduler.ErrClosed):
		return status.Error(codes.FailedPrecondition, "executor storage is shutting down")
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return status.FromContextError(err).Err()
	default:
		return status.Error(codes.Internal, "failed to inspect retained run")
	}
}
