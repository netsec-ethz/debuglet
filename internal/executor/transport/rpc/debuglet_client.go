package rpc

import (
	"context"
	pb "debuglet/protocol"
	"io"

	"go.uber.org/zap"
)

type DebugletClient struct {
	client      pb.DispatcherServiceClient
	stream      pb.DispatcherService_DebugletStreamClient
	logger      *zap.Logger
	debuglet    Spec
	executorID  string
	streamReady chan struct{}
}

func NewDebugletClient(l *zap.Logger, client pb.DispatcherServiceClient, debuglet Spec, executorID string) *DebugletClient {
	return &DebugletClient{
		client:      client,
		logger:      l,
		debuglet:    debuglet,
		executorID:  executorID,
		streamReady: make(chan struct{}),
	}
}
func (d *DebugletClient) Ready() <-chan struct{} {
	return d.streamReady
}

func (d *DebugletClient) Listen(ctx context.Context) error {
	stream, err := d.client.DebugletStream(ctx)
	if err != nil {
		return err
	}
	d.stream = stream
	close(d.streamReady)

	for {
		_, err := stream.Recv()
		if err == io.EOF {
			d.logger.Info("Debuglet stream closed", zap.Error(err), zap.String("debugletID", d.debuglet.DebugletID))
			return nil
		}
		if err != nil {
			if ctx.Err() != nil {
				return context.Cause(ctx)
			}
			d.logger.Error("Error receiving", zap.Error(err), zap.String("debugletID", d.debuglet.DebugletID))
			return err
		}
	}
}

func (d *DebugletClient) SendSetState(state pb.RunState) error {
	d.logger.Debug("Sending debuglet state", zap.String("debugletID", d.debuglet.DebugletID), zap.String("state", state.String()))
	return d.stream.Send(&pb.ExecutorDebugletMessage{
		Msg: &pb.ExecutorDebugletMessage_State{
			State: &pb.DebugletState{
				DebugletId: d.debuglet.DebugletID,
				ExecutorId: d.executorID,
				State:      state,
				Policy: &pb.DebugletPolicy{
					FloorBw:   d.debuglet.Policy.FloorBW,
					CeilBw:    d.debuglet.Policy.CeilBW,
					TimeoutMs: d.debuglet.Policy.Timeout.Milliseconds(),
					Addresses: d.debuglet.Policy.Addresses,
				},
			},
		},
	})
}

func (d *DebugletClient) SendOutput(output []byte) error {
	d.logger.Debug("Sending debuglet output", zap.String("debugletID", d.debuglet.DebugletID), zap.Int("outputSize", len(output)))
	return d.stream.Send(&pb.ExecutorDebugletMessage{
		Msg: &pb.ExecutorDebugletMessage_Output{
			Output: &pb.DebugletOutput{
				DebugletId: d.debuglet.DebugletID,
				Output:     output,
			},
		},
	})
}

func (d *DebugletClient) SendExit(exitCode int32, err error) error {
	d.logger.Debug("Sending debuglet exit", zap.String("debugletID", d.debuglet.DebugletID), zap.Int32("exitCode", exitCode), zap.Error(err))
	var errMsg *string
	if err != nil {
		tmp := err.Error()
		errMsg = &tmp
	}
	return d.stream.Send(&pb.ExecutorDebugletMessage{
		Msg: &pb.ExecutorDebugletMessage_Exit{
			Exit: &pb.DebugletExit{
				DebugletId:   d.debuglet.DebugletID,
				ExitCode:     exitCode,
				ErrorMessage: errMsg,
			},
		},
	})
}
