package executor

import (
	"context"
	"debuglet/internal/executor/debuglet/wasm/hostconn"
	"debuglet/internal/executor/ratelimit/app"
	"debuglet/internal/executor/scheduler"
	pb "debuglet/protocol"
	"errors"
	"net/netip"
	"slices"
	"time"

	"go.uber.org/zap"
)

func (e *Executor) OnHello(ctx context.Context, req *pb.HelloRequest) (*pb.HelloResponse, error) {
	e.logger.Debug("Hello received")
	resp := &pb.HelloResponse{
		ExecutorId:             e.cfg.ExecutorID,
		Version:                e.cfg.Version,
		SourceIp:               "127.0.0.1", // TODO: detect public IP
		TeslaDelaySec:          int64(e.teslaSchedule.Config().Delay.Seconds()),
		TeslaAnchorTimestampNs: e.teslaSchedule.Config().Epoch.UnixNano(),
		TeslaAnchorKey:         e.teslaSchedule.Anchor(),
	}
	return resp, nil
}

func (e *Executor) OnUpload(ctx context.Context, req *pb.UploadRequest) (*pb.UploadResponse, error) {
	// TODO: perform checks and throw error if can't submit
	e.logger.Debug("Upload received", zap.String("id", req.GetId()))

	var startTime *time.Time
	if st := req.GetStartTime(); st != nil {
		tmp := st.AsTime().UTC()
		startTime = &tmp
	}
	policy := req.GetPolicy()
	spec := scheduler.Spec{
		DebugletID: req.GetId(),
		StartTime:  startTime,
		Args:       req.GetArgs(),
		Wasm:       req.GetWasm(),
		Policy: scheduler.Policy{
			FloorBW:   policy.GetFloorBw(),
			CeilBW:    policy.GetCeilBw(),
			Timeout:   time.Duration(policy.GetTimeoutMs()) * time.Millisecond,
			Addresses: policy.GetAddresses(),
		},
	}
	if err := e.scheduler.Insert(spec); err != nil {
		return nil, err
	}

	return &pb.UploadResponse{}, nil
}

func (e *Executor) OnAbort(ctx context.Context, req *pb.AbortRequest) (*pb.AbortResponse, error) {
	debugletID := req.GetDebugletId()
	e.logger.Debug("Abort received", zap.String("debugletID", debugletID))

	existed := e.scheduler.Remove(debugletID)
	if existed {
		e.logger.Info("Removed debuglet from storage before it was started", zap.String("debugletID", debugletID))
		return &pb.AbortResponse{}, nil
	}

	e.mu.Lock()
	run, exists := e.running[debugletID]
	e.mu.Unlock()
	if !exists {
		return nil, errors.New("debuglet not found")
	}
	run.cancelCtx(errors.New(req.Reason))

	return &pb.AbortResponse{}, nil
}

func (e *Executor) OnBandwidth(ctx context.Context, req *pb.BandwidthRequest) (*pb.BandwidthResponse, error) {
	e.logger.Debug("Bandwidth received")

	// convert the bandwidth updates which are a mix of IPs and domains into a list of IPv6s to be inserted into ebpf
	var ipUpdates []Update
	for _, up := range req.GetLimits() {
		ips, err := hostconn.DomainsToIP6(ctx, []string{up.Address})
		if err != nil {
			e.logger.Error("Failed to resolve address", zap.String("address", up.Address), zap.Error(err))
			continue
		}
		for _, ip := range ips {
			ipUpdates = append(ipUpdates, Update{
				Address: ip,
				Limit:   app.Bitrate(up.GetBitsLimit()),
			})
		}
	}
	e.logger.Debug("Resolved update addresses", zap.Objects("destination", ipUpdates))

	e.mu.Lock()
	defer e.mu.Unlock()
	for _, up := range ipUpdates {
		e.limiter.SetAddrCapacity(up.Address, up.Limit)
	}

	if e.packetCount == nil {
		return nil, errors.New("packet count is not initialized")
	}

	for _, up := range ipUpdates {
		ip, err := netip.ParseAddr(up.Address)
		if err != nil {
			continue
		}
		for _, running := range e.running {
			if !slices.Contains(running.addresses, up.Address) {
				continue
			}
			limit, err := e.limiter.GetLimit(running.id.String(), up.Address)
			if err != nil {
				continue
			}
			e.packetCount.SetLimit(ip, running.id, min(limit.Executor, limit.Address))
			e.packetCount.SetExecLimit(running.id, limit.Executor)
		}
	}

	return &pb.BandwidthResponse{}, nil
}
