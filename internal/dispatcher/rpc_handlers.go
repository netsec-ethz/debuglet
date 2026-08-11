package dispatcher

import (
	"context"
	"debuglet/internal/dispatcher/resource"
	"debuglet/internal/dispatcher/resource/schedule"
	pb "debuglet/protocol"
	"fmt"
	"io"
	"time"

	"go.uber.org/zap"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const maxDebugletLogSize = 100 * 1024 * 1024

// ============================================================
// ==================== CONTROL MESSAGES ======================
// ============================================================

func (d *Dispatcher) OnHeartbeat(ctx context.Context, req *pb.HeartbeatRequest) (*pb.HeartbeatResponse, error) {
	execID := req.GetExecutorId()
	d.logger.Debug("Heartbeat received", zap.String("executor_id", execID))
	d.mu.Lock()
	defer d.mu.Unlock()

	if exec, exists := d.executors[execID]; exists {
		exec.LastSeen = time.Unix(0, req.GetTimestampNs())
		exec.Ready = true
	} else {
		return nil, fmt.Errorf("executor '%s' not found", execID)
	}

	err := d.keystore.Store(execID, req.GetTeslaKeyEpoch(), req.GetTeslaKey())
	if err != nil {
		return nil, fmt.Errorf("failed to store Tesla key: %w", err)
	}
	return &pb.HeartbeatResponse{}, nil
}

func (d *Dispatcher) OnResources(ctx context.Context, req *pb.ResourcesRequest) (*pb.ResourcesResponse, error) {
	execID := req.GetExecutorId()
	bw := resource.Bitrate(req.GetBandwidthCapacity())
	d.logger.Debug("Resource update received", zap.String("executor_id", execID), zap.String("capacity", bw.String()))
	if exec, ok := d.executors[execID]; !ok {
		return nil, fmt.Errorf("executor '%s' not found", execID)
	} else {
		exec.capacity = bw
	}
	return &pb.ResourcesResponse{}, nil
}

func (d *Dispatcher) OnExecutorConnected(h *pb.HelloResponse) {
	execID := h.GetExecutorId()
	d.logger.Debug("Executor connected", zap.String("executor_id", execID))
	d.RegisterExecutor(
		execID,
		h.GetVersion(),
		h.GetSourceIp(),
		time.Duration(h.GetTeslaDelaySec())*time.Second,
		time.Unix(0, h.GetTeslaAnchorTimestampNs()),
		h.GetTeslaAnchorKey(),
		h.GetPricePerBw(),
	)

	go func() {
		ticker := time.NewTicker(d.execTimeout)
		defer ticker.Stop()
		for range ticker.C {
			d.mu.RLock()
			exec, ok := d.executors[execID]
			if !ok {
				d.mu.RUnlock()
				return
			}
			d.mu.RUnlock()
			since := time.Since(exec.LastSeen)
			if since > d.execTimeout {
				d.logger.Warn("Executor timed out", zap.String("executor_id", execID))
				d.RemoveExecutor(execID)
				return
			}
		}
	}()
}

func (d *Dispatcher) OnExecutorDisconnected(execID string) {
	d.logger.Debug("Executor disconnected", zap.String("executor_id", execID))
	d.RemoveExecutor(execID)
}

// ============================================================
// ================ DEBUGLET STREAM MESSAGES ==================
// ============================================================

func (d *Dispatcher) OnDebugletState(ctx context.Context, req *pb.DebugletStateRequest) (*pb.DebugletStateResponse, error) {
	state := grpcToRunState(req.GetState())
	debugletID := req.GetDebugletId()
	d.logger.Debug("Received debuglet state update", zap.String("debugletID", debugletID), zap.String("executorID", req.GetExecutorId()), zap.String("state", state.String()))

	d.mu.Lock()
	defer d.mu.Unlock()

	if store, ok := d.debugletStores[debugletID]; ok {
		store.State = state
		for _, conn := range d.connectedLogs[debugletID] {
			if conn.state != nil {
				select {
				case conn.state <- state:
				default:
				}
			}
		}
	}

	return &pb.DebugletStateResponse{}, nil
}

func (d *Dispatcher) OnDebugletAllocate(ctx context.Context, req *pb.DebugletAllocateRequest) (*pb.DebugletAllocateResponse, error) {
	policy := req.GetPolicy()
	executorID := req.GetExecutorId()
	debugletID := req.GetDebugletId()
	transactionID := req.GetTransactionId()
	floorBW := resource.Bitrate(policy.GetFloorBw())
	ceilBW := resource.Bitrate(policy.GetCeilBw())
	d.logger.Debug("Received debuglet allocation request", zap.String("debugletID", debugletID), zap.String("executorID", executorID), zap.Strings("destinations", policy.Addresses), zap.String("floorBW", floorBW.String()), zap.String("ceilBW", ceilBW.String()))

	d.logger.Debug("Checking debuglet capacity usage", zap.String("debugletID", debugletID), zap.Strings("destinations", policy.Addresses), zap.String("floorBW", floorBW.String()), zap.String("ceilBW", ceilBW.String()))

	if payed, err := d.Payment.IsPayed(transactionID); err != nil || !payed {
		d.logger.Error("Debuglet has not been payed yet", zap.Error(err))
		// TODO only aboart if the transaction expired, otherwise wait
		if errAbort := d.AbortDebuglet(ctx, executorID, debugletID, "Debuglet has not been payed for"); errAbort != nil {
			d.logger.Error("Failed to abort debuglet", zap.Error(errAbort))
		}
		return nil, err
	}
	for _, dest := range policy.Addresses {
		if err := d.destinations.CheckCapacity(dest, floorBW); err != nil {
			if errAbort := d.AbortDebuglet(ctx, executorID, debugletID, "not enough capacity"); errAbort != nil {
				d.logger.Error("Failed to abort debuglet", zap.Error(errAbort))
			}
			return nil, err
		}
	}
	for _, dest := range policy.Addresses {
		if err := d.destinations.Insert(debugletID, dest, executorID, floorBW, ceilBW); err != nil {
			if errAbort := d.AbortDebuglet(ctx, executorID, debugletID, "not enough capacity"); errAbort != nil {
				d.logger.Error("Failed to abort debuglet", zap.Error(errAbort))
			}
			return nil, err
		}
	}
	d.sendFairshare(ctx, policy.Addresses)
	return &pb.DebugletAllocateResponse{}, nil
}

// OnDebugletExit handles the exit of a debuglet, cleaning up its state and notifying any connected log streams.
// It is safe to call multiple times. Subsequent calls are no-ops if the debuglet has already been marked as exited.
func (d *Dispatcher) OnDebugletExit(ctx context.Context, req *pb.DebugletExitRequest) (*pb.DebugletExitResponse, error) {
	debugletID := req.GetDebugletId()
	exitCode := req.GetExitCode()
	errMsg := req.ErrorMessage
	d.logger.Debug("Received debuglet exit", zap.String("debugletID", debugletID), zap.Int32("exitCode", exitCode), zap.Stringp("errMsg", errMsg))

	d.mu.Lock()
	st, exists := d.debugletStores[debugletID]
	if !exists {
		d.mu.Unlock()
		return nil, fmt.Errorf("debuglet with id '%s' does not exist", debugletID)
	}
	if st.State == RunStateExited {
		d.mu.Unlock()
		return &pb.DebugletExitResponse{}, nil
	}

	st.State = RunStateExited
	if errMsg != nil {
		st.Err = *errMsg
	}

	for _, conn := range d.connectedLogs[debugletID] {
		if conn.state != nil {
			select {
			case conn.state <- RunStateExited:
			default:
			}
		}
	}

	for _, dest := range st.Policy.Addresses {
		d.destinations.Remove(debugletID, dest, st.ExecutorID, st.Policy.FloorBW, st.Policy.CeilBW)
	}

	d.releaseFloor(st)

	for _, conn := range d.connectedLogs[debugletID] {
		close(conn.done)
	}
	d.mu.Unlock()

	go func() {
		if err := d.sendFairshare(context.Background(), st.Policy.Addresses); err != nil {
			d.logger.Error("Failed to send fairshare update", zap.Error(err))
		}

		time.Sleep(10 * time.Minute)
		d.mu.Lock()
		delete(d.debugletStores, debugletID)
		delete(d.connectedLogs, debugletID)
		d.mu.Unlock()
	}()

	return &pb.DebugletExitResponse{}, nil
}

func (d *Dispatcher) OnDebugletStream(stream grpc.BidiStreamingServer[pb.DebugletStreamRequest, pb.DebugletStreamResponse]) error {
	d.logger.Debug("Debuglet stream started")
	var debugletID string
	ctx := stream.Context()

	err := func() error {
		for {
			in, err := stream.Recv()
			if err == io.EOF {
				return nil
			}
			if err != nil {
				st := status.Convert(err)
				if st.Code() == codes.Canceled || ctx.Err() != nil {
					d.logger.Info("Debuglet disconnected (context canceled)", zap.String("debugletID", debugletID))
				} else {
					d.logger.Error("Debuglet stream error", zap.Error(err))
				}
				return err
			}

			switch msg := in.GetMsg().(type) {
			case *pb.DebugletStreamRequest_Ident:
				debugletID = msg.Ident.GetDebugletId()
			case *pb.DebugletStreamRequest_Output:
				output := msg.Output.GetOutput()
				d.logger.Debug("Received debuglet output", zap.String("debugletID", debugletID), zap.Int("outputSize", len(output)))
				d.mu.Lock()
				store, exists := d.debugletStores[debugletID]
				if !exists {
					d.mu.Unlock()
					d.logger.Error("Debuglet output for unknown debuglet", zap.String("debugletID", debugletID))
					continue
				}
				if len(store.Logs) < maxDebugletLogSize {
					store.Logs = append(store.Logs, output...)
					if len(store.Logs) > maxDebugletLogSize {
						store.Logs = store.Logs[:maxDebugletLogSize]
					}
				}
				connections := d.connectedLogs[debugletID]
				d.mu.Unlock()

				for _, conn := range connections {
					conn.logs <- output
				}
			default:
				d.logger.Warn("Unknown debuglet message")
			}
		}
	}()

	if debugletID != "" {
		if err != nil && ctx.Err() == nil {
			d.logger.Error("Debuglet stream ended with error", zap.String("debugletID", debugletID), zap.Error(err))
			errMsg := err.Error()
			d.OnDebugletExit(ctx, &pb.DebugletExitRequest{DebugletId: debugletID, ExitCode: -1, ErrorMessage: &errMsg})
		}
	}

	return err
}

// ============================================================
// =========================== UTIL ===========================
// ============================================================

// sendFairshare sends fairshare updates to all executors that have debuglets running for the given destinations
// and blocks until all updates have been sent or an error occurs.
func (d *Dispatcher) sendFairshare(ctx context.Context, dests []string) error {
	var perExec map[string][]*pb.DestinationLimit = make(map[string][]*pb.DestinationLimit)
	for _, dest := range dests {
		for eID, limit := range d.destinations.Fairshare(dest) {
			d.logger.Debug("New fairshared update", zap.String("executorID", eID), zap.String("newLimit", limit.String()))
			perExec[eID] = append(perExec[eID], &pb.DestinationLimit{Address: dest, BitsLimit: int64(limit)})
		}
	}
	g, subCtx := errgroup.WithContext(ctx)
	for exec, updates := range perExec {
		g.Go(func() error {
			client, ok := d.Bidi.GetClient(exec)
			if !ok {
				return fmt.Errorf("executor '%s' not found", exec)
			}
			_, err := client.Bandwidth(subCtx, &pb.BandwidthRequest{Limits: updates})
			if err != nil {
				return fmt.Errorf("failed to send fairshare update to executor '%s': %w", exec, err)
			}
			return nil
		})
	}
	return g.Wait()
}

func (d *Dispatcher) releaseFloor(st *DebugletStore) {
	r := schedule.Request{
		Executor:    st.ExecutorID,
		Destination: st.Policy.Addresses,
		From:        st.From,
		To:          st.To,
		Use:         st.Policy.FloorBW,
	}
	d.scheduler.Remove(r)
}
