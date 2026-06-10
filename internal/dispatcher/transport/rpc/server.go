package rpc

import (
	"errors"
	"io"
	"time"

	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"debuglet/internal/dispatcher"
	pb "debuglet/protocol"
)

type Server struct {
	pb.UnsafeDispatcherServiceServer
	logger    *zap.Logger
	registry  *StreamRegistry
	coHandler dispatcher.DispatcherControlHandler
	deHandler dispatcher.DispatcherDebugletHandler
}

var _ dispatcher.ExecutorSender = (*Server)(nil)

func NewServer(logger *zap.Logger, c dispatcher.DispatcherControlHandler, d dispatcher.DispatcherDebugletHandler) *Server {
	return &Server{
		logger:    logger,
		coHandler: c,
		deHandler: d,
		registry:  &StreamRegistry{streams: make(map[string]*ExecutorConn)},
	}
}

func (s *Server) ControlStream(stream pb.DispatcherService_ControlStreamServer) error {
	var executorID string
	ctx := stream.Context()
	var err error = nil

	for {
		var in *pb.ExecutorControlMessage
		in, err = stream.Recv()
		if err == io.EOF {
			err = nil
			break
		}
		if err != nil {
			st := status.Convert(err)
			if st.Code() == codes.Canceled || ctx.Err() != nil {
				s.coHandler.HandleDisconnect(ctx, executorID)
				s.logger.Info("Executor disconnected (context canceled)", zap.String("executor_id", executorID))
				break
			}
			s.logger.Error("ControlStream error", zap.Error(err))
			break
		}

		switch msg := in.GetMsg().(type) {
		case *pb.ExecutorControlMessage_Hello:
			h := dispatcher.Hello{
				ExecutorID:           msg.Hello.GetExecutorId(),
				Version:              msg.Hello.GetVersion(),
				SourceIP:             msg.Hello.GetSourceIp(),
				TeslaDelay:           time.Duration(msg.Hello.GetTeslaDelaySec()) * time.Second,
				TeslaAnchorTimestamp: time.Unix(0, msg.Hello.GetTeslaAnchorTimestampNs()),
				TeslaAnchorKey:       msg.Hello.GetTeslaAnchorKey(),
			}
			executorID = msg.Hello.GetExecutorId()
			s.registry.Register(executorID, stream)
			if err := s.coHandler.HandleHello(ctx, h); err != nil {
				s.logger.Error("Failed to handle hello", zap.Error(err))
			}
		case *pb.ExecutorControlMessage_Heartbeat:
			hh := dispatcher.Heartbeat{
				Timestamp:     time.Unix(0, msg.Heartbeat.GetTimestampNs()),
				TeslaKeyEpoch: msg.Heartbeat.GetTeslaKeyEpoch(),
				TeslaKey:      msg.Heartbeat.GetTeslaKey(),
			}
			if err := s.coHandler.HandleHeartbeat(ctx, hh); err != nil {
				s.logger.Error("Failed to handle heartbeat", zap.Error(err))
			}
		case *pb.ExecutorControlMessage_Error:
			var debugletID *string
			if s := msg.Error.GetDebugletId(); s != "" {
				debugletID = &s
			}
			s.coHandler.HandleError(ctx, debugletID, errors.New(msg.Error.GetError()))
		case *pb.ExecutorControlMessage_Resources:
			s.coHandler.HandleResources(ctx, executorID, msg.Resources.GetBandwidthCapacity())
		default:
			s.logger.Warn("Unknown control message")
		}
	}

	if executorID != "" {
		s.registry.Unregister(executorID)
	}
	return err
}

func grpcToRunState(r pb.RunState) dispatcher.DebugletRunState {
	switch r {
	case pb.RunState_RUN_STATE_INITIALIZING:
		return dispatcher.RunStateInitializing
	case pb.RunState_RUN_STATE_STARTED:
		return dispatcher.RunStateStarted
	default:
		return dispatcher.RunStateUnspecified
	}
}

func (s *Server) DebugletStream(stream pb.DispatcherService_DebugletStreamServer) error {
	var executorID string
	ctx := stream.Context()
	var err error = nil

	for {
		var in *pb.ExecutorDebugletMessage
		in, err = stream.Recv()
		if err == io.EOF {
			err = nil
			break
		}
		if err != nil {
			st := status.Convert(err)
			if st.Code() == codes.Canceled || ctx.Err() != nil {
				s.coHandler.HandleDisconnect(ctx, executorID)
				s.logger.Info("Executor disconnected (context canceled)", zap.String("executor_id", executorID))
				break
			}
			s.logger.Error("ControlStream error", zap.Error(err))
			break
		}

		switch msg := in.GetMsg().(type) {
		case *pb.ExecutorDebugletMessage_State:
			s.deHandler.HandleState(ctx, msg.State.GetDebugletId(), msg.State.GetExecutorId(), grpcToRunState(msg.State.GetState()))
		case *pb.ExecutorDebugletMessage_Output:
			s.deHandler.HandleOutput(ctx, msg.Output.GetDebugletId(), msg.Output.GetOutput())
		case *pb.ExecutorDebugletMessage_Exit:
			var errMsg error
			if e := msg.Exit.GetErrorMessage(); e != "" {
				errMsg = errors.New(e)
			}
			s.deHandler.HandleExit(ctx, msg.Exit.GetDebugletId(), msg.Exit.GetExitCode(), errMsg)
		default:
			s.logger.Warn("Unknown debuglet message")
		}
	}

	return err
}
