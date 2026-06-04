package rpc

import (
	"io"
	"time"

	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"debuglet/internal/dispatcher"
	pb "debuglet/protocol"
)

type Server struct {
	pb.UnimplementedDispatcherServiceServer
	logger   *zap.Logger
	handler  dispatcher.ControlHandler
	registry *StreamRegistry
}

func NewServer(logger *zap.Logger, h dispatcher.ControlHandler) *Server {
	return &Server{
		logger:   logger,
		handler:  h,
		registry: &StreamRegistry{streams: make(map[string]*ExecutorConn)},
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
				s.handler.HandleDisconnect(ctx, executorID)
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
			if err := s.handler.HandleHello(ctx, h); err != nil {
				s.logger.Error("Failed to handle hello", zap.Error(err))
			}
		case *pb.ExecutorControlMessage_Heartbeat:
			hh := dispatcher.Heartbeat{
				Timestamp:     time.Unix(0, msg.Heartbeat.GetTimestampNs()),
				TeslaKeyEpoch: msg.Heartbeat.GetTeslaKeyEpoch(),
				TeslaKey:      msg.Heartbeat.GetTeslaKey(),
			}
			if err := s.handler.HandleHeartbeat(ctx, hh); err != nil {
				s.logger.Error("Failed to handle heartbeat", zap.Error(err))
			}
		default:
			s.logger.Warn("Unknown control message")
		}
	}

	if executorID != "" {
		s.registry.Unregister(executorID)
	}
	return err
}
