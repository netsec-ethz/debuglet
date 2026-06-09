package rpc

import (
	"context"
	pb "debuglet/protocol"
	"io"
	"sync"

	"go.uber.org/zap"
)

type DebugletClient struct {
	client      pb.DispatcherServiceClient
	stream      pb.DispatcherService_DebugletStreamClient
	logger      *zap.Logger
	debuglet    Spec
	executorID  string
	cancel      chan struct{}
	cancelOnce  sync.Once
	streamReady chan struct{}
}

func NewDebugletClient(l *zap.Logger, client pb.DispatcherServiceClient, debuglet Spec, executorID string) *DebugletClient {
	return &DebugletClient{
		client:     client,
		logger:     l,
		debuglet:   debuglet,
		executorID: executorID,
		cancel:     make(chan struct{}),
	}
}

func (d *DebugletClient) Cancel() {
	d.cancelOnce.Do(func() {
		close(d.cancel)
	})
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

func (d *DebugletClient) SetState(state pb.RunState) {
	d.stream.Send(&pb.ExecutorDebugletMessage{
		Msg: &pb.ExecutorDebugletMessage_State{
			State: &pb.DebugletState{
				DebugletId: d.debuglet.DebugletID,
				ExecutorId: d.executorID,
				State:      state,
			},
		},
	})
}
