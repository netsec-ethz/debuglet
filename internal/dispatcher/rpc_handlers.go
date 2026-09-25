// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package dispatcher

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/database"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/models"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/resource"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/resource/schedule"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/transport/rpc"
	pb "github.com/netsec-ethz/debuglet/protocol"
	"io"
	"maps"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// ============================================================
// ==================== CONTROL MESSAGES ======================
// ============================================================

func (d *Dispatcher) OnHeartbeat(ctx context.Context, mutation *rpc.Mutation, req *pb.HeartbeatRequest) (*pb.HeartbeatResponse, error) {
	if req.GetExecutorId() == "" {
		return nil, status.Error(codes.PermissionDenied, "executor identity does not match session")
	}
	owner, err := requireMutation(mutation, req.GetExecutorId())
	if err != nil {
		return nil, err
	}
	execID := owner.ExecutorID()
	d.logger.Debug("Heartbeat received", zap.String("executor_id", execID))
	seen := d.now()
	// The anchor names the chain the disclosed key belongs to; a re-registered
	// executor announces a new one.
	var anchor []byte
	d.mu.Lock()
	if exec, exists := d.executors[execID]; !d.closed && exists && exec.owner == owner {
		// Concurrent requests may acquire the lock out of receipt order. A later
		// local observation must not be replaced by an earlier one.
		if seen.After(exec.LastSeen) {
			exec.LastSeen = seen
		}
		exec.Ready = true
		anchor = bytes.Clone(exec.TeslaAnchorKey)
	} else {
		d.mu.Unlock()
		return nil, status.Error(codes.FailedPrecondition, "executor session is unavailable")
	}
	d.mu.Unlock()

	queries := database.New(d.db)
	earnings, _ := queries.GetEarningsIn(ctx, database.GetEarningsInParams{
		ExecutorID: execID,
		Currency:   "USDC",
	})
	d.logger.Info("Earnings", zap.Int64("amount", earnings.TotalIncome), zap.Int64("next payout", earnings.CurrentBalance))
	err = d.keystore.Store(execID, anchor, req.GetTeslaKeyEpoch(), req.GetTeslaKey())
	if err != nil {
		return nil, fmt.Errorf("failed to store Tesla key: %w", err)
	}
	return &pb.HeartbeatResponse{}, nil
}

func (d *Dispatcher) OnResources(ctx context.Context, mutation *rpc.Mutation, req *pb.ResourcesRequest) (*pb.ResourcesResponse, error) {
	if req.GetExecutorId() == "" {
		return nil, status.Error(codes.PermissionDenied, "executor identity does not match session")
	}
	owner, err := requireMutation(mutation, req.GetExecutorId())
	if err != nil {
		return nil, err
	}
	execID := owner.ExecutorID()
	bw := resource.Bitrate(req.GetBandwidthCapacity())
	d.logger.Debug("Resource update received", zap.String("executor_id", execID), zap.String("capacity", bw.String()))
	d.mu.Lock()
	if exec, ok := d.executors[execID]; d.closed || !ok || exec.owner != owner {
		d.mu.Unlock()
		return nil, status.Error(codes.FailedPrecondition, "executor session is unavailable")
	} else {
		exec.capacity = bw
	}
	d.mu.Unlock()
	return &pb.ResourcesResponse{}, nil
}

func (d *Dispatcher) OnExecutorConnected(ctx context.Context, owner *rpc.SessionOwner, hello *pb.HelloResponse, sourceIP string) error {
	return d.RegisterExecutor(ctx, owner, hello, sourceIP)
}

func (d *Dispatcher) OnExecutorDisconnected(owner *rpc.SessionOwner) {
	if owner == nil {
		return
	}
	d.mu.Lock()
	if entry := d.executors[owner.ExecutorID()]; entry != nil && entry.owner == owner {
		delete(d.executors, owner.ExecutorID())
	}
	d.mu.Unlock()
}

// ============================================================
// ================ DEBUGLET STREAM MESSAGES ==================
// ============================================================

func (d *Dispatcher) OnDebugletState(ctx context.Context, mutation *rpc.Mutation, req *pb.DebugletStateRequest) (*pb.DebugletStateResponse, error) {
	if req.GetExecutorId() == "" {
		return nil, status.Error(codes.PermissionDenied, "executor identity does not match session")
	}
	owner, err := requireMutation(mutation, req.GetExecutorId())
	if err != nil {
		return nil, err
	}
	state, supported := models.GrpcToRunState(req.GetState())
	if !supported {
		return nil, status.Error(codes.InvalidArgument, "unsupported debuglet state")
	}
	debugletID := req.GetDebugletId()
	d.logger.Debug("Received debuglet state update", zap.String("debugletID", debugletID), zap.String("executorID", req.GetExecutorId()), zap.String("state", state.String()))

	id, err := parseRunID(debugletID)
	if err != nil {
		return nil, err
	}

	// Ordinary states only ever come from GrpcToRunState, never RunStateExited,
	// so the guard cannot be satisfied by an ordinary update itself: a terminal
	// row is never overwritten by a late state report.
	queries := database.New(d.db)
	if _, err := queries.UpdateDebugletState(ctx, database.UpdateDebugletStateParams{
		State:                 state,
		StateRank:             state.SemanticRank(),
		Uuid:                  id,
		ExitedState:           models.RunStateExited,
		ExecutorID:            owner.ExecutorID(),
		DispatcherIncarnation: owner.Binding().Incarnation,
		SessionID:             owner.Binding().SessionID,
	}); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			// A terminal, duplicate, reordered or missing row is acknowledged.
			_, classifyErr := d.ownedDebuglet(ctx, owner, id)
			if classifyErr != nil && status.Code(classifyErr) != codes.NotFound {
				return nil, classifyErr
			}
			return &pb.DebugletStateResponse{}, nil
		}
		d.logger.Error("Failed to update debuglet state in database", zap.String("debugletID", debugletID), zap.Error(err))
		return nil, fmt.Errorf("failed to update debuglet state in database: %w", err)
	}

	return &pb.DebugletStateResponse{}, nil
}

func (d *Dispatcher) OnDebugletAllocate(ctx context.Context, mutation *rpc.Mutation, req *pb.DebugletAllocateRequest) (*pb.DebugletAllocateResponse, error) {
	if req.GetExecutorId() == "" {
		return nil, status.Error(codes.PermissionDenied, "executor identity does not match session")
	}
	owner, err := requireMutation(mutation, req.GetExecutorId())
	if err != nil {
		return nil, err
	}
	policy := req.GetPolicy()
	if policy == nil {
		return nil, status.Error(codes.InvalidArgument, "missing debuglet policy")
	}
	executorID := owner.ExecutorID()
	debugletID := req.GetDebugletId()
	transactionID := req.GetTransactionId()
	id, err := parseRunID(debugletID)
	if err != nil {
		return nil, err
	}
	deb, err := d.ownedDebuglet(ctx, owner, id)
	if err != nil {
		return nil, err
	}
	if deb.TransactionID != transactionID {
		return nil, status.Error(codes.PermissionDenied, "run transaction does not match")
	}
	// A terminal run has already released everything it held. Charging it
	// again would leave capacity that no exit ever returns.
	if deb.State == models.RunStateExited {
		return nil, status.Error(codes.FailedPrecondition, "run is terminal")
	}
	// The stored policy of the run is the admitted one and never changes; the
	// request only repeats it. Allocating from the stored values keeps a
	// duplicate or altered request from charging limits that differ from the
	// ones the terminal release returns. A request that does not repeat the
	// admitted policy is rejected before anything is charged.
	floorBW := resource.Bitrate(deb.Usage)
	ceilBW := resource.Bitrate(deb.CeilBw)
	destinations := []string(deb.Addresses)
	if !repeatsPolicy(policy, floorBW, ceilBW, destinations) {
		return nil, status.Error(codes.FailedPrecondition, "request does not repeat the admitted policy of the run")
	}
	d.logger.Debug("Received debuglet allocation request", zap.String("debugletID", debugletID), zap.String("executorID", executorID), zap.Strings("destinations", destinations), zap.String("floorBW", floorBW.String()), zap.String("ceilBW", ceilBW.String()))

	// TODO: Allocate should never even be called if the debuglet hasn't been paid for and successfully submitted to the executor
	// Reject the Allocate RPC directly. A synchronous Abort here waits for
	// executor cleanup which itself must wait for this Allocate to return.
	// The executor owns the unwinding and its own terminal report.
	if paid, err := d.Payment.IsPaid(ctx, transactionID); err != nil {
		return nil, fmt.Errorf("check debuglet payment: %w", err)
	} else if !paid {
		return nil, fmt.Errorf("debuglet has not been paid for")
	}
	// One decision for the whole run: every destination is checked and
	// charged together, and a failure on any of them leaves the destination
	// accounting exactly as it was.
	d.mu.Lock()
	// Exit may have completed while payment was checked. Read terminal state
	// under the release lock so any accepted charge precedes its cleanup.
	current, err := d.ownedDebuglet(ctx, owner, id)
	if err != nil {
		d.mu.Unlock()
		return nil, err
	}
	if current.State == models.RunStateExited {
		d.mu.Unlock()
		return nil, status.Error(codes.FailedPrecondition, "run is terminal")
	}
	allocErr := d.destinations.Allocate(id, deb.ExecutorID, destinations, floorBW, ceilBW)
	d.mu.Unlock()
	if allocErr != nil {
		return nil, fmt.Errorf("allocate destinations: %w", allocErr)
	}
	if err := d.sendFairshare(ctx, mutation, destinations); err != nil {
		d.logger.Error("Failed to send fairshare update", zap.String("debugletID", debugletID), zap.Error(err))
	}
	return &pb.DebugletAllocateResponse{}, nil
}

// repeatsPolicy reports whether an allocation request carries exactly the
// policy the run was admitted with. Destinations are compared as a set:
// their order and repetition carry no meaning, a destination is either part
// of the run or it is not.
func repeatsPolicy(requested *pb.DebugletPolicy, floor, ceil resource.Bitrate, destinations []string) bool {
	if resource.Bitrate(requested.GetFloorBw()) != floor || resource.Bitrate(requested.GetCeilBw()) != ceil {
		return false
	}
	return maps.Equal(destinationSet(requested.GetAddresses()), destinationSet(destinations))
}

func destinationSet(addresses []string) map[string]struct{} {
	set := make(map[string]struct{}, len(addresses))
	for _, address := range addresses {
		set[address] = struct{}{}
	}
	return set
}

// terminalError normalizes an executor's exit report into the stored error
// column: a supplied nonempty message is preserved verbatim; otherwise a
// nonzero exit code becomes "debuglet exited with code N" and a zero exit
// stores SQL NULL. A zero exit with a nonempty message is therefore a failure.
func terminalError(exitCode int32, errMsg *string) sql.NullString {
	if errMsg != nil && *errMsg != "" {
		return sql.NullString{String: *errMsg, Valid: true}
	}
	if exitCode != 0 {
		return sql.NullString{String: fmt.Sprintf("debuglet exited with code %d", exitCode), Valid: true}
	}
	return sql.NullString{}
}

// OnDebugletExit handles the exit of a debuglet, cleaning up its state and notifying any connected log streams.
// It is safe to call multiple times: CompleteDebuglet is the sole terminal writer and its guard admits exactly
// one winner per debuglet. Only that winner runs the payment decision, destination removal, scheduler release
// and fairshare update; later callbacks for a terminal row acknowledge with no effects.
func (d *Dispatcher) OnDebugletExit(ctx context.Context, mutation *rpc.Mutation, req *pb.DebugletExitRequest) (*pb.DebugletExitResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "missing exit request")
	}
	owner, err := requireMutation(mutation, "")
	if err != nil {
		return nil, err
	}
	debugletID := req.GetDebugletId()
	exitCode := req.GetExitCode()
	errMsg := req.ErrorMessage
	d.logger.Debug("Received debuglet exit", zap.String("debugletID", debugletID), zap.Int32("exitCode", exitCode), zap.Stringp("errMsg", errMsg))

	id, err := parseRunID(debugletID)
	if err != nil {
		return nil, err
	}

	// Write the terminal result immediately; there is no read-before-write
	// decision. The returned row is the one this caller won.
	queries := database.New(d.db)
	deb, err := queries.CompleteDebuglet(ctx, database.CompleteDebugletParams{
		ExitedState:           models.RunStateExited,
		Error:                 terminalError(exitCode, errMsg),
		Uuid:                  id,
		ExecutorID:            owner.ExecutorID(),
		DispatcherIncarnation: owner.Binding().Incarnation,
		SessionID:             owner.Binding().SessionID,
	})
	if err != nil {
		if !errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("failed to mark debuglet exited: %w", err)
		}
		// The guard rejected the write: the row is terminal or missing.
		// Classify with a read; never retry the write.
		existing, err := d.ownedDebuglet(ctx, owner, id)
		if err != nil {
			if status.Code(err) == codes.NotFound || status.Code(err) == codes.PermissionDenied {
				return nil, err
			}
			return nil, fmt.Errorf("failed to classify rejected exit: %w", err)
		}
		if existing.State != models.RunStateExited {
			return nil, fmt.Errorf("exit of debuglet '%s' was rejected although it is in state %s", debugletID, existing.State.String())
		}
		d.logger.Debug("Duplicate debuglet exit ignored", zap.String("debugletID", debugletID))
		return &pb.DebugletExitResponse{}, nil
	}

	// Effects run exactly once, for the winner, using the returned row. The
	// payment decision stays exit-code based (also for zero exit with an
	// error); effect failures are logged and never retried by duplicates.
	switch exitCode {
	case 0:
		//credit executor
		d.logger.Debug("Debuglet Completed. Credit executor")
		if err := d.Payment.SetDebugletOrderComplete(&deb, ctx); err != nil {
			d.logger.Error(err.Error())
		}
	default:
		//refund
		d.logger.Debug("Debuglet Aborted. Refund Buyer")
		if err := d.Payment.RefundDebugletOrder(&deb, "", ctx); err != nil {
			d.logger.Error(err.Error())
		}
	}

	floor := resource.Bitrate(deb.Usage)

	d.mu.Lock()
	for _, dest := range deb.Addresses {
		// The release subtracts the recorded allocation of this run, so a
		// destination that was never allocated or already released is a no-op.
		d.destinations.Remove(id, dest)
	}

	d.releaseFloor(deb.ExecutorID, deb.Addresses, deb.StartTime.Time, deb.EndTime.Time, floor)

	d.mu.Unlock()
	// Reserve the origin continuation and every exact recipient before this
	// callback returns; the detached deadline releases no mutation of its own.
	notifyCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	work, captureErr := d.captureFairshare(notifyCtx, mutation, deb.Addresses)
	if captureErr != nil {
		cancel()
		d.logger.Error("Failed to reserve fairshare update", zap.Error(captureErr))
	} else {
		go func() {
			defer cancel()
			if err := work.send(notifyCtx); err != nil {
				d.logger.Error("Failed to send fairshare update", zap.Error(err))
			}
		}()
	}

	return &pb.DebugletExitResponse{}, nil
}

func (d *Dispatcher) OnDebugletStream(owner *rpc.SessionOwner, stream grpc.BidiStreamingServer[pb.DebugletStreamRequest, pb.DebugletStreamResponse]) error {
	if owner == nil {
		return status.Error(codes.FailedPrecondition, "stream session is unavailable")
	}
	ctx := stream.Context()
	var runID uuid.UUID
	identified := false
	for {
		// An idle receive holds no mutation; the transport joins this handler.
		in, err := stream.Recv()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			if identified && ctx.Err() == nil && status.Code(err) != codes.Canceled {
				// A receive failure on an identified stream reports the run as
				// failed, under a freshly admitted mutation. Frame errors do not.
				mutation, admitErr := owner.AdmitMutation(ctx)
				if admitErr == nil {
					message := "debuglet output stream failed"
					_, _ = d.OnDebugletExit(mutation.Context(), mutation, &pb.DebugletExitRequest{DebugletId: runID.String(), ExitCode: -1, ErrorMessage: &message})
					mutation.Finish()
				}
			}
			return err
		}
		mutation, err := owner.AdmitMutation(ctx)
		if err != nil {
			return status.Error(codes.FailedPrecondition, "stream session is unavailable")
		}
		frameErr := func() error {
			defer mutation.Finish()
			frameCtx := mutation.Context()
			switch msg := in.GetMsg().(type) {
			case *pb.DebugletStreamRequest_Ident:
				if identified || msg.Ident == nil {
					return status.Error(codes.InvalidArgument, "unexpected stream identity")
				}
				id, err := parseRunID(msg.Ident.GetDebugletId())
				if err != nil {
					return err
				}
				if _, err := d.ownedDebuglet(frameCtx, owner, id); err != nil {
					return err
				}
				runID, identified = id, true
				return nil
			case *pb.DebugletStreamRequest_Output:
				if !identified || msg.Output == nil || msg.Output.GetTimestamp() == nil || msg.Output.GetTimestamp().CheckValid() != nil {
					return status.Error(codes.InvalidArgument, "invalid stream output frame")
				}
				_, err := database.New(d.db).CreateDebugletLog(frameCtx, database.CreateDebugletLogParams{
					Uuid: runID, Timestamp: models.NewUTCTime(msg.Output.GetTimestamp().AsTime()), Output: msg.Output.GetOutput(),
					ExecutorID: owner.ExecutorID(), DispatcherIncarnation: owner.Binding().Incarnation, SessionID: owner.Binding().SessionID,
				})
				if errors.Is(err, sql.ErrNoRows) {
					_, err = d.ownedDebuglet(frameCtx, owner, runID)
				}
				if err != nil {
					return err
				}
				return nil
			default:
				return status.Error(codes.InvalidArgument, "unknown stream frame")
			}
		}()
		if frameErr != nil {
			return frameErr
		}
	}
}

// ============================================================
// =========================== UTIL ===========================
// ============================================================

// requireMutation validates the local authority a caller already holds;
// retirement does not invalidate work already admitted. Fresh network requests
// are admitted by transport, and a setup mutation never authorizes these
// ordinary callbacks.
func requireMutation(mutation *rpc.Mutation, claimedExecutor string) (*rpc.SessionOwner, error) {
	if mutation == nil || mutation.IsSetup() || !mutation.Live() {
		return nil, status.Error(codes.FailedPrecondition, "ordinary control mutation required")
	}
	owner := mutation.Owner()
	if claimedExecutor != "" && claimedExecutor != owner.ExecutorID() {
		return nil, status.Error(codes.PermissionDenied, "executor identity does not match session")
	}
	return owner, nil
}

func parseRunID(value string) (uuid.UUID, error) {
	id, err := uuid.Parse(value)
	if err != nil || id == uuid.Nil || id.String() != value {
		return uuid.Nil, status.Error(codes.InvalidArgument, "invalid debuglet ID")
	}
	return id, nil
}

func (d *Dispatcher) ownedDebuglet(ctx context.Context, owner *rpc.SessionOwner, id uuid.UUID) (database.Debuglet, error) {
	queries := database.New(d.db)
	row, err := queries.GetOwnedDebugletByUUID(ctx, database.GetOwnedDebugletByUUIDParams{Uuid: id, ExecutorID: owner.ExecutorID(), DispatcherIncarnation: owner.Binding().Incarnation, SessionID: owner.Binding().SessionID})
	if err == nil {
		return row, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return database.Debuglet{}, status.Error(codes.Internal, "stored debuglet data is invalid")
	}
	identity, err := queries.GetDebugletIdentityByUUID(ctx, id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return database.Debuglet{}, status.Error(codes.NotFound, "debuglet does not exist")
		}
		return database.Debuglet{}, status.Error(codes.Internal, "failed to classify debuglet ownership")
	}
	binding := owner.Binding()
	if identity.ExecutorID == owner.ExecutorID() && identity.DispatcherIncarnation == binding.Incarnation && identity.SessionID == binding.SessionID {
		// The full owned query and narrow identity query observed conflicting
		// results, or the row changed between them. Do not infer authorization.
		return database.Debuglet{}, status.Error(codes.Internal, "stored debuglet data is invalid")
	}
	return database.Debuglet{}, status.Error(codes.PermissionDenied, "run does not belong to session")
}

// mutationCallContext joins the two local cancellation sources and its own
// AfterFunc before releasing the surrounding ticket. Cleanup callers may
// deliberately pass a detached context instead of using this helper.
func mutationCallContext(ctx context.Context, mutation *rpc.Mutation) (context.Context, func()) {
	callCtx, cancel := context.WithCancel(ctx)
	joined := make(chan struct{})
	stop := context.AfterFunc(mutation.Context(), func() { defer close(joined); cancel() })
	return callCtx, func() {
		cancel()
		if !stop() {
			<-joined
		}
	}
}

type fairshareRecipient struct {
	owner    *rpc.SessionOwner
	mutation *rpc.Mutation
	client   rpc.BoundExecutorClient
	updates  []*pb.DestinationLimit
}
type fairshareWork struct {
	d          *Dispatcher
	origin     *rpc.Mutation
	recipients []fairshareRecipient
	err        error
}

func (d *Dispatcher) captureFairshare(ctx context.Context, origin *rpc.Mutation, dests []string) (*fairshareWork, error) {
	owner, err := requireMutation(origin, "")
	if err != nil {
		return nil, err
	}
	continuation, err := origin.Fork(ctx)
	if err != nil {
		return nil, err
	}
	work := &fairshareWork{d: d, origin: continuation}
	perExec := make(map[string][]*pb.DestinationLimit)
	// Fairshare reads the destination state as its iterator is consumed, so both
	// happen under one lock; updates are copied and recipients reserved first.
	d.mu.Lock()
	for _, dest := range dests {
		for id, limit := range d.destinations.Fairshare(dest) {
			perExec[id] = append(perExec[id], &pb.DestinationLimit{Address: dest, BitsLimit: int64(limit)})
		}
	}
	for id, updates := range perExec {
		var recipient *rpc.SessionOwner
		var ticket *rpc.Mutation
		var admitErr error
		if id == owner.ExecutorID() {
			recipient = owner
			ticket, admitErr = continuation.Fork(ctx)
		} else if entry := d.executors[id]; entry != nil && !d.closed {
			recipient = entry.owner
			ticket, admitErr = recipient.AdmitMutation(ctx)
		} else {
			admitErr = rpc.ErrSessionUnavailable
		}
		if admitErr != nil {
			work.err = errors.Join(work.err, admitErr)
			continue
		}
		work.recipients = append(work.recipients, fairshareRecipient{owner: recipient, mutation: ticket, updates: updates})
	}
	d.mu.Unlock()
	// No map-lock nesting and no later executor-ID lookup. A retired exact
	// recipient can fail delivery, but can never be replaced by its successor.
	for i := range work.recipients {
		r := &work.recipients[i]
		client, ok := d.Bidi.GetClientFor(r.owner)
		if !ok {
			work.err = errors.Join(work.err, status.Error(codes.FailedPrecondition, "fairshare recipient is unavailable"))
			continue
		}
		r.client = client
	}
	return work, nil
}

func (work *fairshareWork) send(ctx context.Context) error {
	defer work.origin.Finish()
	for _, r := range work.recipients {
		defer r.mutation.Finish()
	}
	g, subCtx := errgroup.WithContext(ctx)
	for _, r := range work.recipients {
		if r.client == nil {
			continue
		}
		for _, update := range r.updates {
			work.d.logger.Debug("New fairshared update", zap.String("executorID", r.owner.ExecutorID()), zap.String("newLimit", resource.Bitrate(update.BitsLimit).String()))
		}
		g.Go(func() error {
			callCtx, finish := mutationCallContext(subCtx, r.mutation)
			defer finish()
			_, err := r.client.Bandwidth(callCtx, &pb.BandwidthRequest{Limits: r.updates})
			return err
		})
	}
	return errors.Join(work.err, g.Wait())
}

func (d *Dispatcher) sendFairshare(ctx context.Context, origin *rpc.Mutation, dests []string) error {
	work, err := d.captureFairshare(ctx, origin, dests)
	if err != nil {
		return err
	}
	return work.send(ctx)
}

func (d *Dispatcher) releaseFloor(executor string, dest []string, from, to time.Time, use resource.Bitrate) {
	r := schedule.Request{
		Executor:    executor,
		Destination: dest,
		From:        from,
		To:          to,
		Use:         use,
	}
	d.scheduler.Remove(r)
}
