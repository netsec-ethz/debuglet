// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package dispatcher

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"github.com/netsec-ethz/debuglet/internal/bitrate"
	"github.com/netsec-ethz/debuglet/internal/daemonlog"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/database"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/models"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/tag"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/transport/rpc"
	"github.com/netsec-ethz/debuglet/internal/executor/debuglet/netpolicy"
	"github.com/netsec-ethz/debuglet/internal/ids"
	"github.com/netsec-ethz/debuglet/pkg/wire"
	pb "github.com/netsec-ethz/debuglet/protocol"
	"io"
	"maps"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"
	"go.uber.org/zap"
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
	d.logger.Debug("Heartbeat received", zap.String("executor_id", daemonlog.Identifier(execID)))
	seen := d.now()
	var connectivity *wire.Connectivity
	if req.GetVantagePoint().GetSchemaVersion() == 1 {
		connectivity = d.observeConnectivity(ctx, owner, req.GetVantagePoint().GetConnectivity(), seen)
	}
	// The anchor names the chain the disclosed key belongs to; a re-registered
	// executor announces a new one.
	var chain tag.Chain
	d.mu.Lock()
	if exec, exists := d.executors[execID]; !d.closed && exists && exec.owner == owner {
		// Concurrent requests may acquire the lock out of receipt order. A later
		// local observation must not be replaced by an earlier one.
		if seen.After(exec.LastSeen) {
			exec.LastSeen = seen
		}
		exec.Ready = true
		if connectivity != nil && !seen.Before(exec.connectivityObserved) {
			exec.connectivity, exec.connectivityObserved = connectivity, seen
		}
		if req.Capabilities != nil && !seen.Before(exec.capabilityObserved) {
			exec.Capabilities = capabilitiesFromReport(req.Capabilities, seen)
			exec.capabilityObserved = seen
		}
		if req.VantagePoint != nil && !seen.Before(exec.vantageObserved) {
			exec.vantage = vantageFromReport(req.VantagePoint)
			exec.vantageObserved = seen
			exec.connectivity = connectivitySCION(exec.connectivity, exec.vantage, seen)
		}
		chain = exec.teslaChain()
	} else {
		d.mu.Unlock()
		return nil, status.Error(codes.FailedPrecondition, "executor session is unavailable")
	}
	d.mu.Unlock()
	defer d.reconcileFairshare(ctx, mutation)

	if entry := d.logger.Check(zap.DebugLevel, "Earnings"); entry != nil {
		earnings, _ := database.New(d.db).GetEarningsIn(ctx, database.GetEarningsInParams{
			ExecutorID: execID,
			Currency:   "USDC",
		})
		entry.Write(zap.Int64("amount", earnings.TotalIncome), zap.Int64("next payout", earnings.CurrentBalance))
	}
	d.storeDisclosure(ctx, execID, chain, seen, req.GetTeslaKeyAnchor(), req.GetTeslaKeyEpoch(), req.GetTeslaKey())
	// Keys of earlier chains, such as the tail of the chain a restart retired,
	// follow the same path. The keystore keeps at most maxExtraDisclosures
	// chains per executor, so a longer list is refused whole.
	if extra := req.GetExtraDisclosures(); len(extra) > maxExtraDisclosures {
		d.logger.Warn("Refused a heartbeat's extra TESLA disclosures", zap.String("executor_id", daemonlog.Identifier(execID)), zap.Int("count", len(extra)))
	} else {
		for _, disclosure := range extra {
			d.storeDisclosure(ctx, execID, chain, seen, disclosure.GetAnchor(), disclosure.GetEpoch(), disclosure.GetKey())
		}
	}
	return &pb.HeartbeatResponse{}, nil
}

// maxExtraDisclosures bounds the extra disclosures one heartbeat may carry; it
// matches the chains the keystore keeps per executor.
const maxExtraDisclosures = 4

// storeDisclosure verifies one disclosed key and stores it. An empty anchor
// names chain, the session's own. A key for another chain of this executor is
// verified against that chain's recorded schedule, so the tail of a chain can
// be disclosed after the executor restarted onto a new one. An anchor not on
// record names no chain the dispatcher knows, and its key is dropped.
func (d *Dispatcher) storeDisclosure(ctx context.Context, execID string, chain tag.Chain, seen time.Time, anchor []byte, epoch int64, key []byte) {
	if len(anchor) > 0 && len(key) > 0 && !bytes.Equal(anchor, chain.Anchor) {
		recorded, ok, err := d.recordedChain(ctx, execID, anchor)
		if err != nil {
			d.logger.Warn("Failed to read the recorded TESLA chain of a disclosure", zap.String("executor_id", execID), zap.Error(err))
			return
		}
		if !ok {
			d.logger.Debug("Dropped a disclosed TESLA key for a chain not on record", zap.String("executor_id", execID), zap.String("chain", tag.ChainID(anchor)))
			return
		}
		chain = recorded
	}
	// A disclosure that does not verify against the chain is dropped; the
	// heartbeat still counts, and the chain is logged once rather than per beat.
	err := d.keystore.Store(execID, chain, seen, epoch, key)
	var rejected *tag.RejectedError
	if errors.As(err, &rejected) {
		switch {
		case rejected.First && rejected.Early:
			// A key published before its schedule allows lets anyone forge
			// tags that verifiers still attribute to this executor.
			d.logger.Error("Executor disclosed a TESLA key early; it is misbehaving", zap.String("executor_id", daemonlog.Identifier(execID)))
			d.logger.Debug("Private runtime diagnostic", zap.String("executor_id", daemonlog.Identifier(execID)), zap.String("operation", "Executor disclosed a TESLA key early; it is misbehaving"), zap.String("error", daemonlog.Diagnostic(err)))
		case rejected.First:
			d.logger.Warn("Rejected disclosed TESLA key", zap.String("executor_id", daemonlog.Identifier(execID)))
			d.logger.Debug("Private runtime diagnostic", zap.String("executor_id", daemonlog.Identifier(execID)), zap.String("operation", "Rejected disclosed TESLA key"), zap.String("error", daemonlog.Diagnostic(err)))
		}
	} else if err != nil {
		// The record could not be written; nothing was stored, and the
		// executor's next heartbeat discloses the key again.
		d.logger.Warn("Failed to record disclosed TESLA key", zap.String("executor_id", execID), zap.Error(err))
	}
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
	bw := bitrate.Bitrate(req.GetBandwidthCapacity())
	d.logger.Debug("Resource update received", zap.String("executor_id", daemonlog.Identifier(execID)), zap.String("capacity", bw.String()))
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
	entry := d.executors[owner.ExecutorID()]
	removed := entry != nil && entry.owner == owner
	if removed {
		delete(d.executors, owner.ExecutorID())
	}
	d.mu.Unlock()
	if removed {
		d.logger.Info("Executor control session ended", zap.String("executor_id", owner.ExecutorID()), zap.String("session_id", owner.Binding().SessionID), zap.String("reason", "transport closed"))
	}
	d.interruptUnresumableOutput(owner.Binding())
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
	if _, err := d.recordStateObservation(ctx, owner, id, state, req.GetTcpListener()); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			// A terminal, duplicate, reordered or missing row is acknowledged.
			_, classifyErr := d.ownedDebuglet(ctx, owner, id)
			if classifyErr != nil && status.Code(classifyErr) != codes.NotFound {
				return nil, classifyErr
			}
			return &pb.DebugletStateResponse{}, nil
		}
		d.logger.Error("Failed to update debuglet state in database", zap.String("debugletID", debugletID))
		d.logger.Debug("Private runtime diagnostic", zap.String("debugletID", debugletID), zap.String("operation", "Failed to update debuglet state in database"), zap.String("error", daemonlog.Diagnostic(err)))
		return nil, fmt.Errorf("failed to update debuglet state in database: %w", err)
	}

	return &pb.DebugletStateResponse{}, nil
}

// OnDebugletAllocate records the admitted run's idempotent allocation, then
// waits for delivery to every affected recipient. A failed delivery is returned
// to the executor and retried on the recipient's next heartbeat. The caller
// owns run failure/terminal reporting; a repeated allocation never charges twice.
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
	floorBW := bitrate.Bitrate(deb.Usage)
	ceilBW := bitrate.Bitrate(deb.CeilBw)
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
	if !current.EndTime.Time.After(d.now()) {
		d.mu.Unlock()
		return nil, status.Error(codes.FailedPrecondition, "run allocation window has ended")
	}
	_, reclaimed := database.New(d.db).GetAllocationReclamation(ctx, id)
	if reclaimed == nil || !errors.Is(reclaimed, sql.ErrNoRows) {
		d.mu.Unlock()
		if reclaimed != nil {
			return nil, status.Error(codes.Internal, "allocation reclamation could not be checked")
		}
		return nil, status.Error(codes.FailedPrecondition, "run allocation was reclaimed")
	}
	allocErr := d.destinations.Allocate(id, deb.ExecutorID, destinations, floorBW, ceilBW)
	d.mu.Unlock()
	if allocErr != nil {
		return nil, fmt.Errorf("allocate destinations: %w", allocErr)
	}
	if err := d.sendFairshare(ctx, mutation, destinations); err != nil {
		d.logger.Error("Failed to send fairshare update", zap.String("debugletID", debugletID))
		d.logger.Debug("Private runtime diagnostic", zap.String("debugletID", debugletID), zap.String("operation", "Failed to send fairshare update"), zap.String("error", daemonlog.Diagnostic(err)))
		return nil, status.Error(codes.Unavailable, "destination allocation delivery is pending")
	}
	return &pb.DebugletAllocateResponse{}, nil
}

// repeatsPolicy reports whether an allocation request carries exactly the
// policy the run was admitted with. Destinations are compared as a set:
// their order and repetition carry no meaning, a destination is either part
// of the run or it is not.
func repeatsPolicy(requested *pb.DebugletPolicy, floor, ceil bitrate.Bitrate, destinations []string) bool {
	if bitrate.Bitrate(requested.GetFloorBw()) != floor || bitrate.Bitrate(requested.GetCeilBw()) != ceil {
		return false
	}
	return maps.Equal(destinationSet(requested.GetAddresses()), destinationSet(destinations))
}

func destinationSet(addresses []string) map[string]struct{} {
	set := make(map[string]struct{}, len(addresses))
	for _, address := range addresses {
		set[netpolicy.DestinationKey(address)] = struct{}{}
	}
	return set
}

// maxTerminalError bounds a stored error message, before the "..." that marks
// a cut.
const maxTerminalError = 512

// terminalError normalizes an executor's exit report into the stored error
// column: a supplied nonempty message is stored as one bounded line (see
// terminalLine); otherwise a nonzero exit code becomes "debuglet exited with
// code N" and a zero exit stores SQL NULL. A zero exit with a nonempty message
// is therefore a failure.
func terminalError(exitCode int32, errMsg *string) sql.NullString {
	if errMsg != nil && *errMsg != "" {
		return sql.NullString{String: terminalLine(*errMsg), Valid: true}
	}
	if exitCode != 0 {
		return sql.NullString{String: fmt.Sprintf("debuglet exited with code %d", exitCode), Valid: true}
	}
	return sql.NullString{}
}

// terminalLine returns message as one line of valid UTF-8: an invalid byte
// becomes the replacement character, a control character a space, and a
// message longer than maxTerminalError bytes is cut on a rune boundary and
// marked with "...".
func terminalLine(message string) string {
	var line strings.Builder
	for _, r := range message { // An invalid byte ranges as utf8.RuneError.
		if unicode.IsControl(r) {
			r = ' '
		}
		if line.Len()+utf8.RuneLen(r) > maxTerminalError {
			line.WriteString("...")
			break
		}
		line.WriteRune(r)
	}
	return line.String()
}

// OnDebugletExit selects one immutable terminal result. Only its winner handles
// payment and fairshare notification. Winner and duplicates release the run's
// resources by run identity, so a duplicate completes a release an earlier
// delivery did not reach without repeating payment or subtracting another
// run's reservation.
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
	d.logger.Debug("Received debuglet exit", zap.String("debugletID", debugletID), zap.Int32("exitCode", exitCode), zap.Bool("has_error", errMsg != nil && *errMsg != ""))

	id, err := parseRunID(debugletID)
	if err != nil {
		return nil, err
	}

	// Write the terminal result immediately; there is no read-before-write
	// decision. The returned row is the one this caller won.
	deb, err := d.recordTerminalObservation(ctx, owner, id, exitCode, errMsg)
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
		// The winning write may have committed without its caller seeing
		// the result; release by run identity, a no-op if already done.
		d.releaseTerminal(existing)
		return &pb.DebugletExitResponse{}, nil
	}

	d.endRunActivity(ctx, id, d.now())
	d.settleTerminalPayment(ctx, &deb, exitCode)
	d.releaseTerminal(deb)
	// Reserve the origin continuation and every exact recipient before this
	// callback returns; the detached deadline releases no mutation of its own.
	notifyCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	work, captureErr := d.captureFairshare(notifyCtx, mutation, deb.Addresses)
	if captureErr != nil {
		cancel()
		d.logger.Error("Failed to reserve fairshare update")
		d.logger.Debug("Private runtime diagnostic", zap.String("operation", "Failed to reserve fairshare update"), zap.String("error", daemonlog.Diagnostic(captureErr)))
	} else {
		go func() {
			defer cancel()
			if err := work.send(notifyCtx); err != nil {
				d.logger.Error("Failed to send fairshare update")
				d.logger.Debug("Private runtime diagnostic", zap.String("operation", "Failed to send fairshare update"), zap.String("error", daemonlog.Diagnostic(err)))
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
	var writer outputWriter
	identified := false
	for {
		// An idle receive holds no mutation; the transport joins this handler.
		in, err := stream.Recv()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			if identified && ctx.Err() == nil && status.Code(err) != codes.Canceled {
				// Delivery failure does not establish a guest terminal outcome.
				d.logger.Warn("Debuglet output stream failed", zap.String("debugletID", runID.String()))
				d.logger.Debug("Private runtime diagnostic", zap.String("debugletID", runID.String()), zap.String("operation", "Debuglet output stream failed"), zap.String("error", daemonlog.Diagnostic(err)))
			}
			return err
		}
		mutation, err := owner.AdmitMutation(ctx)
		if err != nil {
			return status.Error(codes.FailedPrecondition, "stream session is unavailable")
		}
		receipt, frameErr := func() (*pb.DebugletStreamResponse, error) {
			defer mutation.Finish()
			switch msg := in.GetMsg().(type) {
			case *pb.DebugletStreamRequest_Ident:
				if identified || msg.Ident == nil {
					return nil, status.Error(codes.InvalidArgument, "unexpected stream identity")
				}
				if msg.Ident.GetExecutorId() != "" && msg.Ident.GetExecutorId() != owner.ExecutorID() {
					return nil, status.Error(codes.PermissionDenied, "executor identity does not match session")
				}
				id, err := parseRunID(msg.Ident.GetDebugletId())
				if err != nil {
					return nil, err
				}
				writer, err = outputWriterFor(owner, msg.Ident.GetOriginalBinding())
				if err != nil {
					return nil, err
				}
				receipt, err := d.storeOutput(mutation.Context(), writer, id, nil, nil)
				if err == nil {
					runID, identified = id, true
				}
				return receipt, err
			case *pb.DebugletStreamRequest_Output:
				if !identified || msg.Output == nil {
					return nil, status.Error(codes.InvalidArgument, "unexpected output frame")
				}
				return d.storeOutput(mutation.Context(), writer, runID, msg.Output, nil)
			case *pb.DebugletStreamRequest_End:
				if !identified || msg.End == nil {
					return nil, status.Error(codes.InvalidArgument, "unexpected output end")
				}
				return d.storeOutput(mutation.Context(), writer, runID, nil, msg.End)
			default:
				return nil, status.Error(codes.InvalidArgument, "unknown stream frame")
			}
		}()
		if frameErr != nil {
			if status.Code(frameErr) != codes.Unknown {
				return frameErr
			}
			d.logger.Warn("Debuglet output storage failed", zap.String("debugletID", runID.String()))
			d.logger.Debug("Private runtime diagnostic", zap.String("debugletID", runID.String()), zap.String("operation", "Debuglet output storage failed"), zap.String("error", daemonlog.Diagnostic(frameErr)))
			return status.Error(codes.Unavailable, "output storage unavailable")
		}
		if writer.version == pb.OutputVersion {
			if err := stream.Send(receipt); err != nil {
				return err
			}
		}
		if receipt.End != nil {
			if writer.version == 0 {
				return status.Error(codes.ResourceExhausted, "output storage limit reached")
			}
			return nil
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
	id, ok := ids.ParseCanonical(value)
	if !ok {
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
	revision uint64
	ordered  bool
	// wait and done order the deliveries to one executor; see
	// executorEntry.bandwidthTail. Both are nil without a registry entry.
	wait, done chan struct{}
}
type fairshareWork struct {
	d              *Dispatcher
	origin         *rpc.Mutation
	recipients     []fairshareRecipient
	err            error
	requireOrdered bool
}

func (d *Dispatcher) captureFairshare(ctx context.Context, origin *rpc.Mutation, dests []string) (*fairshareWork, error) {
	return d.captureFairshareAfter(ctx, origin, dests, nil)
}

// captureFairshareAfter runs change, when given, under the lock the share is
// then read with; a refused change captures nothing. A nil origin captures a
// change no executor made: there is no continuation and every recipient is
// admitted on its own session.
func (d *Dispatcher) captureFairshareAfter(ctx context.Context, origin *rpc.Mutation, dests []string, change func() error) (*fairshareWork, error) {
	work := &fairshareWork{d: d}
	var owner *rpc.SessionOwner
	if origin != nil {
		var err error
		if owner, err = requireMutation(origin, ""); err != nil {
			return nil, err
		}
		if work.origin, err = origin.Fork(ctx); err != nil {
			return nil, err
		}
	}
	perExec := make(map[string][]*pb.DestinationLimit)
	// Fairshare reads the destination state as its iterator is consumed, so both
	// happen under one lock; updates are copied and recipients reserved first.
	d.mu.Lock()
	if change != nil {
		if err := change(); err != nil {
			d.mu.Unlock()
			if work.origin != nil {
				work.origin.Finish()
			}
			return nil, err
		}
	}
	seen := make(map[string]struct{}, len(dests))
	for _, dest := range dests {
		dest = netpolicy.DestinationKey(dest)
		if _, duplicate := seen[dest]; duplicate {
			continue
		}
		seen[dest] = struct{}{}
		for id, limit := range d.destinations.Fairshare(dest) {
			perExec[id] = append(perExec[id], d.destinationLimitLocked(dest, limit))
		}
	}
	for id, updates := range perExec {
		var recipient *rpc.SessionOwner
		var ticket *rpc.Mutation
		var admitErr error
		entry := d.executors[id]
		var revision uint64
		ordered := entry != nil && entry.bandwidthVersion >= 1
		if entry != nil && (owner == nil || id != owner.ExecutorID() || entry.owner == owner) {
			entry.bandwidthPending = true
			entry.bandwidthRevision++
			revision = entry.bandwidthRevision
			if ordered {
				updates = d.allocationSnapshot(id)
			}
		}
		if owner != nil && id == owner.ExecutorID() {
			recipient = owner
			ticket, admitErr = work.origin.Fork(ctx)
		} else if entry != nil && !d.closed {
			recipient = entry.owner
			ticket, admitErr = recipient.AdmitMutation(ctx)
		} else {
			admitErr = rpc.ErrSessionUnavailable
		}
		if admitErr != nil {
			work.err = errors.Join(work.err, fmt.Errorf("executor %s: %w", id, admitErr))
			continue
		}
		r := fairshareRecipient{owner: recipient, mutation: ticket, updates: updates, revision: revision, ordered: ordered}
		if entry != nil && entry.owner == recipient {
			r.wait, r.done = entry.bandwidthTail, make(chan struct{})
			entry.bandwidthTail = r.done
		}
		work.recipients = append(work.recipients, r)
	}
	d.mu.Unlock()
	// No map-lock nesting and no later executor-ID lookup. A retired exact
	// recipient can fail delivery, but can never be replaced by its successor.
	for i := range work.recipients {
		r := &work.recipients[i]
		client, ok := d.Bidi.GetClientFor(r.owner)
		if !ok {
			work.err = errors.Join(work.err, fmt.Errorf("executor %s: %w", r.owner.ExecutorID(), status.Error(codes.FailedPrecondition, "fairshare recipient is unavailable")))
			continue
		}
		r.client = client
	}
	return work, nil
}

// send joins every recipient's delivery. Legacy peers are serialized; revised
// peers also reject a superseded snapshot when a timed-out RPC applies late.
// Only an acknowledgement of the current exact session's current snapshot
// clears pending reconciliation.
func (work *fairshareWork) send(ctx context.Context) error {
	if work.origin != nil {
		defer work.origin.Finish()
	}
	for _, r := range work.recipients {
		defer r.mutation.Finish()
	}
	var g sync.WaitGroup
	errs := make([]error, len(work.recipients))
	for i, r := range work.recipients {
		if r.client == nil && r.done == nil {
			continue
		}
		if r.client != nil {
			for _, update := range r.updates {
				work.d.logger.Debug("New fairshared update", zap.String("executorID", r.owner.ExecutorID()), zap.String("newLimit", bitrate.Bitrate(update.BitsLimit).String()))
			}
		}
		g.Go(func() {
			if r.done != nil {
				defer close(r.done)
			}
			callCtx, finish := mutationCallContext(ctx, r.mutation)
			defer finish()
			if r.wait != nil {
				select {
				case <-r.wait:
				case <-callCtx.Done():
					if r.client != nil {
						errs[i] = fmt.Errorf("executor %s: %w", r.owner.ExecutorID(), callCtx.Err())
					}
					return
				}
			}
			if r.client == nil {
				return // Reported at capture.
			}
			wireRevision := r.revision
			if !r.ordered {
				wireRevision = 0
			}
			response, err := r.client.Bandwidth(callCtx, &pb.BandwidthRequest{Limits: r.updates, Revision: wireRevision})
			if err == nil && r.ordered && response.GetRevision() < r.revision {
				err = status.Error(codes.FailedPrecondition, "executor did not acknowledge allocation revision")
			}
			if err == nil && work.requireOrdered && !r.ordered {
				err = ErrOrderedBandwidthUnsupported
			}
			if err != nil {
				errs[i] = fmt.Errorf("executor %s: %w", r.owner.ExecutorID(), err)
				return
			}
			work.d.mu.Lock()
			if entry := work.d.executors[r.owner.ExecutorID()]; entry != nil && entry.owner == r.owner && entry.bandwidthRevision == r.revision {
				entry.bandwidthPending = false
			}
			work.d.mu.Unlock()
		})
	}
	g.Wait()
	return errors.Join(work.err, errors.Join(errs...))
}

// allocationSnapshot reads the current shares under d.mu. An omitted address
// has no allocation on this executor; its old limiter cache is unused until a
// fresh allocation supplies another snapshot.
func (d *Dispatcher) allocationSnapshot(executorID string) []*pb.DestinationLimit {
	var updates []*pb.DestinationLimit
	for address, limit := range d.destinations.ForExecutor(executorID) {
		updates = append(updates, d.destinationLimitLocked(address, limit))
	}
	return updates
}

func (d *Dispatcher) reconcileFairshare(ctx context.Context, origin *rpc.Mutation) {
	owner, err := requireMutation(origin, "")
	if err != nil {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	d.mu.Lock()
	entry := d.executors[owner.ExecutorID()]
	if d.closed || entry == nil || entry.owner != owner || !entry.bandwidthPending {
		d.mu.Unlock()
		return
	}
	mutation, err := origin.Fork(ctx)
	if err != nil {
		d.mu.Unlock()
		return
	}
	entry.bandwidthRevision++
	r := fairshareRecipient{owner: owner, mutation: mutation, updates: d.allocationSnapshot(owner.ExecutorID()), ordered: entry.bandwidthVersion >= 1, wait: entry.bandwidthTail, done: make(chan struct{})}
	r.revision = entry.bandwidthRevision
	entry.bandwidthTail = r.done
	d.mu.Unlock()
	r.client, _ = d.Bidi.GetClientFor(owner)
	work := &fairshareWork{d: d, recipients: []fairshareRecipient{r}}
	if r.client == nil {
		work.err = rpc.ErrSessionUnavailable
	}
	if err := work.send(ctx); err != nil {
		d.logger.Warn("Destination allocation reconciliation remains pending", zap.String("executor_id", owner.ExecutorID()))
	}
}

func (d *Dispatcher) sendFairshare(ctx context.Context, origin *rpc.Mutation, dests []string) error {
	work, err := d.captureFairshare(ctx, origin, dests)
	if err != nil {
		return err
	}
	return work.send(ctx)
}

// settleTerminalPayment preserves the winner's exit-code-based payment decision.
// Resource release is separate and never retries payment effects. A failure is
// logged here; the settlement sweep delivers the decision later.
func (d *Dispatcher) settleTerminalPayment(ctx context.Context, deb *database.Debuglet, exitCode int32) {
	if err := d.Payment.SettleTerminalOrder(ctx, deb, exitCode); err != nil {
		operation := "Failed to credit executor for debuglet"
		if exitCode != 0 {
			operation = "Failed to refund debuglet order"
		}
		d.logger.Warn(operation, zap.String("debugletID", deb.Uuid.String()))
		d.logger.Debug("Private runtime diagnostic", zap.String("debugletID", deb.Uuid.String()), zap.String("operation", operation), zap.String("error", daemonlog.Diagnostic(err)))
	}
}
