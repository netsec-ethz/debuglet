package executor

import (
	"context"
	"debuglet/internal/executor/ratelimit/app"
	"debuglet/internal/executor/scheduler"
	pb "debuglet/protocol"
	"errors"
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
		PricePerBw:             e.cfg.PricePerBw,
	}
	return resp, nil
}

func (e *Executor) OnUpload(ctx context.Context, req *pb.UploadRequest) (*pb.UploadResponse, error) {
	// TODO: perform checks and throw error if can't submit
	e.logger.Debug("Upload received", zap.String("id", req.GetId()), zap.String("tranasaction_id", req.GetTransactionId()))

	var startTime *time.Time
	if st := req.GetStartTime(); st != nil {
		tmp := st.AsTime().UTC()
		startTime = &tmp
	}
	policy := req.GetPolicy()
	spec := scheduler.Spec{
		DebugletID:    req.GetId(),
		TransactionID: req.GetTransactionId(),
		StartTime:     startTime,
		Args:          req.GetArgs(),
		Wasm:          req.GetWasm(),
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

	e.mu.Lock()
	defer e.mu.Unlock()
	for _, up := range req.GetLimits() {
		e.limiter.SetAddrCapacity(up.Address, app.Bitrate(up.GetBitsLimit()))

		for _, running := range e.running {
			limit, err := e.limiter.GetLimit(running.id.String(), up.Address)
			if err != nil {
				continue
			}
			e.packetCount.SetLimit(up.Address, running.id, limit.Address)
			e.packetCount.SetExecLimit(running.id, limit.Executor)
		}
	}

	return &pb.BandwidthResponse{}, nil
}
