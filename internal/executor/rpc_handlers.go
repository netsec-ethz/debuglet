// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package executor

import (
	"context"
	"errors"
	"fmt"
	"github.com/netsec-ethz/debuglet/internal/controlsession"
	"github.com/netsec-ethz/debuglet/internal/executor/debuglet/netpolicy"
	"github.com/netsec-ethz/debuglet/internal/executor/ratelimit/app"
	"github.com/netsec-ethz/debuglet/internal/executor/scheduler"
	"github.com/netsec-ethz/debuglet/internal/executor/transport/rpc"
	pb "github.com/netsec-ethz/debuglet/protocol"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"math"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

// Numeric bounds the executor admits on the values the control protocol
// carries. They repeat what the dispatcher's HTTP contract documents:
// bandwidth is bits per second and timeout_ms is milliseconds, and both are
// bounded on each side so that the duration and the aggregate limits derived
// from them stay exact. The executor enforces them itself: a control peer is
// not a reason to convert an unchecked number into a run budget or a rate.
const (
	maxPolicyBitrate   = int64(app.Petabit)
	maxPolicyTimeoutMS = int64(math.MaxInt64) / int64(time.Millisecond)
)

// validatePolicyNumbers rejects a policy whose numbers are outside those
// ranges. An absent policy carries no run budget and is rejected the same way.
func validatePolicyNumbers(policy *pb.DebugletPolicy) error {
	floor, ceil, timeout := policy.GetFloorBw(), policy.GetCeilBw(), policy.GetTimeoutMs()
	switch {
	case floor < 0 || floor > maxPolicyBitrate:
		return status.Errorf(codes.InvalidArgument, "floor_bw %d must be between 0 and %d bits per second", floor, maxPolicyBitrate)
	case ceil < 0 || ceil > maxPolicyBitrate:
		return status.Errorf(codes.InvalidArgument, "ceil_bw %d must be between 0 and %d bits per second", ceil, maxPolicyBitrate)
	case ceil < floor:
		return status.Error(codes.InvalidArgument, "ceil_bw must be at least floor_bw")
	case timeout <= 0 || timeout > maxPolicyTimeoutMS:
		return status.Errorf(codes.InvalidArgument, "timeout_ms %d must be positive and at most %d", timeout, maxPolicyTimeoutMS)
	}
	return nil
}

func (e *Executor) OnHello(ctx context.Context, req *pb.HelloRequest) (*pb.HelloResponse, error) {
	e.logger.Debug("Hello received")
	var publicHost *string
	if e.cfg.Network.PublicHost != "" {
		publicHost = &e.cfg.Network.PublicHost
	}
	resp := &pb.HelloResponse{
		ExecutorId: e.cfg.Identity.ExecutorID,
		Version:    e.cfg.Identity.Version,
		// The dispatcher records the address it observes on the control
		// connection, which is what probe recipients see. Reporting an
		// address here would only be a hint, so leave it empty.
		SourceIp:               "",
		PublicHost:             publicHost,
		TeslaDelaySec:          int64(e.teslaSchedule.Config().Delay.Seconds()),
		TeslaAnchorTimestampNs: e.teslaSchedule.Config().Epoch.UnixNano(),
		TeslaAnchorKey:         e.teslaSchedule.Anchor(),
		// ICMP is advertised only when the operator's network policy leaves it
		// enabled and this process can actually open the raw socket the
		// transport needs; the packet counter says nothing about either.
		IcmpEnabled: e.cfg.Network.Policy.Spec().ICMP && netpolicy.ICMPPermitted() == nil,
		PricePerBwS: e.cfg.Pricing.PricePerBwS,
		Currency:    e.cfg.Pricing.Currency,
		SuiWallet:   &e.cfg.Pricing.SuiWallet,
	}
	// Presented until the dispatcher has bound this node's certificate to the
	// executor ID; an already enrolled node sends nothing.
	if e.cfg.Credentials.EnrollmentToken != "" {
		resp.EnrollmentToken = &e.cfg.Credentials.EnrollmentToken
	}
	return resp, nil
}

func (e *Executor) OnUpload(ctx context.Context, binding controlsession.Binding, req *pb.UploadRequest) (*pb.UploadResponse, error) {
	if err := e.checkControlBinding(ctx, binding); err != nil {
		return nil, err
	}
	if err := rpc.CheckPayloadBinding(req.GetControlBinding(), binding); err != nil {
		return nil, err
	}
	e.logger.Debug("Upload received", zap.String("id", req.GetId()), zap.String("transaction_id", req.GetTransactionId()))

	id, err := uuid.Parse(req.GetId())
	if err != nil || id == uuid.Nil || id.String() != req.GetId() {
		return nil, status.Error(codes.InvalidArgument, "invalid debuglet ID")
	}

	policy := req.GetPolicy()
	if err := validatePolicyNumbers(policy); err != nil {
		return nil, err
	}

	var startTime *time.Time
	if st := req.GetStartTime(); st != nil {
		if !st.IsValid() {
			return nil, status.Error(codes.InvalidArgument, "invalid start time")
		}
		tmp := st.AsTime().UTC()
		startTime = &tmp
	}
	spec := scheduler.Spec{
		Binding:       binding,
		DebugletID:    id,
		TransactionID: req.GetTransactionId(),
		StartTime:     startTime,
		Args:          req.GetArgs(),
		Wasm:          req.GetWasm(),
		Policy: scheduler.Policy{
			FloorBW:     policy.GetFloorBw(),
			CeilBW:      policy.GetCeilBw(),
			Timeout:     time.Duration(policy.GetTimeoutMs()) * time.Millisecond,
			Addresses:   policy.GetAddresses(),
			RequireICMP: policy.GetRequireIcmp(),
			ListenUDP:   policy.GetListenUdp(),
			ListenTCP:   policy.GetListenTcp(),
			ListenSCION: policy.GetListenScion(),
		},
	}
	// Nothing a new run sends could be tagged, so it is not admitted. Runs
	// admitted earlier continue untagged.
	if e.teslaSchedule.Exhausted(time.Now()) {
		return nil, status.Error(codes.FailedPrecondition, "TESLA key chain exhausted: this executor admits no new runs until it is restarted")
	}
	if err := e.scheduler.Insert(ctx, spec); err != nil {
		return nil, err
	}

	return &pb.UploadResponse{}, nil
}

func (e *Executor) OnAbort(ctx context.Context, binding controlsession.Binding, req *pb.AbortRequest) (*pb.AbortResponse, error) {
	if err := e.checkExecutionLease(ctx, binding); err != nil {
		return nil, err
	}
	debugletID := req.GetDebugletId()
	e.logger.Debug("Abort received", zap.String("debugletID", debugletID))

	id, err := uuid.Parse(debugletID)
	if err != nil || id == uuid.Nil || id.String() != debugletID {
		return nil, status.Error(codes.InvalidArgument, "invalid debuglet ID")
	}

	cause := error(context.Canceled)
	if req.Reason != "" {
		cause = errors.New(req.Reason)
	}
	existed, err := e.scheduler.CancelBound(ctx, id, binding, cause)
	if err != nil {
		if errors.Is(err, scheduler.ErrBindingMismatch) {
			return nil, status.Error(codes.PermissionDenied, "run belongs to another control session")
		}
		return nil, fmt.Errorf("failed to cancel debuglet: %w", err)
	}
	if !existed {
		return nil, status.Error(codes.NotFound, "debuglet not found")
	}
	return &pb.AbortResponse{}, nil
}

func (e *Executor) OnBandwidth(ctx context.Context, binding controlsession.Binding, req *pb.BandwidthRequest) (*pb.BandwidthResponse, error) {
	if err := e.checkExecutionLease(ctx, binding); err != nil {
		return nil, err
	}
	return e.applyBandwidth(binding, req)
}

// Local Allocate-response limits carry the already selected run binding. The
// caller owns its execution context and has completed exact-bound allocation.
func (e *Executor) applyBandwidth(binding controlsession.Binding, req *pb.BandwidthRequest) (*pb.BandwidthResponse, error) {
	if !binding.Valid() {
		return nil, status.Error(codes.FailedPrecondition, "control session unavailable")
	}
	e.logger.Debug("Bandwidth received")
	// Every limit is checked before the first one is applied, so a message
	// carrying one value the executor cannot account for leaves no capacity
	// changed at all.
	for _, up := range req.GetLimits() {
		if bits := up.GetBitsLimit(); bits < 0 || bits > maxPolicyBitrate {
			return nil, status.Errorf(codes.InvalidArgument,
				"destination limit %d must be between 0 and %d bits per second", bits, maxPolicyBitrate)
		}
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	destinations := make([]string, 0, len(req.GetLimits()))
	for _, up := range req.GetLimits() {
		e.limiter.SetAddrCapacity(up.GetAddress(), app.Bitrate(up.GetBitsLimit()))
		destinations = append(destinations, up.GetAddress())
	}
	e.publishLimitsLocked(destinations)

	return &pb.BandwidthResponse{}, nil
}

// publishLimits applies every limit a capacity or membership change can move to
// the connections that are already running: the destinations named by the
// caller, plus the executor share, which every such change moves for all of
// them. A cached read reports no update when nothing actually moved, so this
// stays a bounded walk of the current runs.
func (e *Executor) publishLimits(destinations []string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.publishLimitsLocked(destinations)
}

func (e *Executor) publishLimitsLocked(destinations []string) {
	for _, running := range e.running {
		for _, addr := range destinations {
			limit, _, err := e.limiter.GetAddrLimit(running.id, addr)
			if err != nil {
				continue // The run does not use this destination.
			}
			if err := e.packetCount.SetLimit(addr, running.id, limit); err != nil {
				e.logger.Warn("Failed to apply destination limit", zap.String("debugletID", running.id.String()),
					zap.String("address", addr), zap.Error(err))
			}
		}
		execLimit, _, err := e.limiter.GetExecLimit(running.id)
		if err != nil {
			continue
		}
		if err := e.packetCount.SetExecLimit(running.id, execLimit); err != nil {
			e.logger.Warn("Failed to apply executor limit", zap.String("debugletID", running.id.String()), zap.Error(err))
		}
	}
}
