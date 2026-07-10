package dispatcher

import (
	"context"
	"debuglet/internal/dispatcher/resource"
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

// ============================================================
// ==================== CONTROL MESSAGES ======================
// ============================================================

func (d *Dispatcher) OnHeartbeat(ctx context.Context, req *pb.HeartbeatRequest) (*pb.HeartbeatResponse, error) {
	d.logger.Debug("Heartbeat received", zap.String("executor_id", req.GetExecutorId()))
	d.mu.Lock()
	defer d.mu.Unlock()

	if exec, exists := d.executors[req.GetExecutorId()]; exists {
		exec.LastSeen = time.Unix(0, req.GetTimestampNs())
		exec.Ready = true
	} else {
		return nil, fmt.Errorf("executor '%s' not found", req.GetExecutorId())
	}

	err := d.keystore.Store(req.GetExecutorId(), req.GetTeslaKeyEpoch(), req.GetTeslaKey())
	if err != nil {
		return nil, fmt.Errorf("failed to store Tesla key: %w", err)
	}
	return &pb.HeartbeatResponse{}, nil
}

func (d *Dispatcher) OnResources(ctx context.Context, req *pb.ResourcesRequest) (*pb.ResourcesResponse, error) {
	// TODO
	d.logger.Debug("Resource update received")
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
	)

	// goroutine to monitor the executor's heartbeat and remove it if it times out
	go func() {
		ticker := time.NewTicker(d.execTimeout)
		defer ticker.Stop()
		for range ticker.C {
			d.mu.RLock()
			exec, ok := d.executors[execID]
			if !ok {
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
	floorBW := resource.Bitrate(policy.GetFloorBw())
	ceilBW := resource.Bitrate(policy.GetCeilBw())
	d.logger.Debug("Received debuglet allocation request", zap.String("debugletID", debugletID), zap.String("executorID", executorID), zap.Strings("destinations", policy.Addresses), zap.String("floorBW", floorBW.String()), zap.String("ceilBW", ceilBW.String()))

	// check if any destination is overloaded (only accounts for the floor bandwidth)
	d.logger.Debug("Checking debuglet capacity usage", zap.String("debugletID", debugletID), zap.Strings("destinations", policy.Addresses), zap.String("floorBW", floorBW.String()), zap.String("ceilBW", ceilBW.String()))
	for _, dest := range policy.Addresses {
		if err := d.destinations.CheckCapacity(dest, floorBW); err != nil {
			d.sender.AbortDebuglet(ctx, executorID, debugletID, "not enough capacity")
			return nil, err
		}
	}
	for _, dest := range policy.Addresses {
		if err := d.destinations.Insert(debugletID, dest, executorID, floorBW, ceilBW); err != nil {
			d.sender.AbortDebuglet(ctx, executorID, debugletID, err.Error())
			return nil, err
		}
	}
	if err := d.sendFairshare(ctx, policy.Addresses); err != nil {
		d.logger.Error("Failed to send fairshare update", zap.Error(err))
		return nil, err
	}
	return &pb.DebugletAllocateResponse{}, nil
}

// OnDebugletExit handles the exit of a debuglet, cleaning up its state and notifying any connected log streams.
// It may be called multiple times if the stream is closed and the debuglet sends the exit call manually, so it should be idempotent.
func (d *Dispatcher) OnDebugletExit(ctx context.Context, req *pb.DebugletExitRequest) (*pb.DebugletExitResponse, error) {
	debugletID := req.GetDebugletId()
	exitCode := req.GetExitCode()
	errMsg := req.ErrorMessage
	d.logger.Debug("Received debuglet exit", zap.String("debugletID", debugletID), zap.Int32("exitCode", exitCode), zap.Stringp("errMsg", errMsg))

	d.mu.Lock()
	defer func() {
		for _, conn := range d.connectedLogs[debugletID] {
			close(conn.done)
		}
		d.mu.Unlock()
	}()

	st, exists := d.debugletStores[debugletID]
	if !exists {
		return nil, fmt.Errorf("debuglet with id '%s' does not exist", debugletID)
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

	go func() {
		// send fairshare updates in the background
		if err := d.sendFairshare(ctx, st.Policy.Addresses); err != nil {
			d.logger.Error("Failed to send fairshare update", zap.Error(err))
		}

		// remove debuglet store 10 minutes later
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
				store.Logs = append(store.Logs, output...)
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

	// send an exit if stream closes
	if debugletID != "" {
		if err == nil {
			d.OnDebugletExit(ctx, &pb.DebugletExitRequest{DebugletId: debugletID, ExitCode: 0})
		} else {
			errMsg := err.Error()
			d.logger.Error("Debuglet stream ended with error", zap.String("debugletID", debugletID), zap.Error(err))
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
	var perExec map[string][]LimitUpdate = make(map[string][]LimitUpdate)
	for _, dest := range dests {
		for eID, limit := range d.destinations.Fairshare(dest) {
			d.logger.Debug("New fairshared update", zap.String("executorID", eID), zap.String("newLimit", limit.String()))
			perExec[eID] = append(perExec[eID], LimitUpdate{Address: dest, Limit: limit})
		}
	}
	g, subCtx := errgroup.WithContext(ctx)
	for exec, updates := range perExec {
		g.Go(func() error { return d.sender.DestinationUpdates(subCtx, exec, updates) })
	}
	return g.Wait()
}

// -------------------

// HandleError handles an error reported by a debuglet
//
// Deprecated: This method might be removed.
func (d *Dispatcher) HandleError(ctx context.Context, debugletID *string, err error) {
	d.logger.Error("Got executor error", zap.Stringp("debugletID", debugletID), zap.Error(err))

	if debugletID == nil {
		return
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	st, exists := d.debugletStores[*debugletID]
	if !exists {
		return
	}

	st.State = RunStateExited
	st.Err = err.Error()

	for _, conn := range d.connectedLogs[*debugletID] {
		if conn.state != nil {
			select {
			case conn.state <- RunStateExited:
			default:
			}
		}
	}

	for _, dest := range st.Policy.Addresses {
		d.destinations.Remove(*debugletID, dest, st.ExecutorID, st.Policy.FloorBW, st.Policy.CeilBW)
	}
	ctxBg := context.Background()
	d.sendFairshare(ctxBg, st.Policy.Addresses)

	go func() {
		time.Sleep(10 * time.Minute)
		d.mu.Lock()
		delete(d.debugletStores, *debugletID)
		delete(d.connectedLogs, *debugletID)
		d.mu.Unlock()
	}()

	for _, conn := range d.connectedLogs[*debugletID] {
		close(conn.done)
	}
}
