package rpc

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"go.uber.org/zap"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"debuglet/internal/dispatcher"
	pb "debuglet/protocol"
)

type ServerOptions struct {
	// ExecutorTimeout is the maximum time allowed between heartbeats
	ExecutorTimeout time.Duration
}

type Server struct {
	pb.UnsafeDispatcherServiceServer
	logger    *zap.Logger
	registry  *StreamRegistry
	coHandler dispatcher.DispatcherControlHandler
	deHandler dispatcher.DispatcherDebugletHandler
	opts      ServerOptions
}

var _ dispatcher.ExecutorServer = (*Server)(nil)

func NewServer(logger *zap.Logger, c dispatcher.DispatcherControlHandler, d dispatcher.DispatcherDebugletHandler, opts ServerOptions) *Server {
	if opts.ExecutorTimeout <= 0 {
		panic("non-positive executor timeout")
	}

	return &Server{
		logger:    logger,
		coHandler: c,
		deHandler: d,
		registry:  &StreamRegistry{streams: make(map[string]*ExecutorConn)},
		opts:      opts,
	}
}

type controlRecv struct {
	in  *pb.ExecutorControlMessage
	err error
}

func (s *Server) ControlStream(stream pb.DispatcherService_ControlStreamServer) error {
	ctx := stream.Context()
	g, ctx := errgroup.WithContext(ctx)

	var executorID string
	var hbMu sync.RWMutex
	var lastHeartbeat time.Time

	// ======== LISTEN ========
	g.Go(func() error {
		recvChan := make(chan controlRecv, 1)
		for {
			go func() {
				in, err := stream.Recv()
				recvChan <- controlRecv{in, err}
			}()

			select {
			case <-ctx.Done():
				return ctx.Err()
			case res := <-recvChan:
				in, err := res.in, res.err
				if err == io.EOF {
					return nil
				}
				if err != nil {
					s.logger.Error("ControlStream error", zap.Error(err))
					return err
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
						ExecutorID:    executorID,
						Timestamp:     time.Unix(0, msg.Heartbeat.GetTimestampNs()),
						TeslaKeyEpoch: msg.Heartbeat.GetTeslaKeyEpoch(),
						TeslaKey:      msg.Heartbeat.GetTeslaKey(),
					}
					hbMu.Lock()
					lastHeartbeat = hh.Timestamp
					hbMu.Unlock()

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
		}
	})

	// ======== HEARTBEAT TIMEOUT ========
	g.Go(func() error {
		ticker := time.NewTicker(s.opts.ExecutorTimeout)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				hbMu.RLock()
				since := time.Since(lastHeartbeat)
				hbMu.RUnlock()
				if since > s.opts.ExecutorTimeout {
					return fmt.Errorf("executor '%s' timed out", executorID)
				}
			case <-ctx.Done():
				return context.Cause(ctx)
			}
		}
	})

	err := g.Wait()
	if executorID != "" {
		s.logger.Info("Executor disconnected", zap.String("executorID", executorID))
		s.registry.Unregister(executorID)
		s.coHandler.HandleDisconnect(executorID)
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
	var debugletID string
	ctx := stream.Context()

	for {
		in, err := stream.Recv()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			st := status.Convert(err)
			if st.Code() == codes.Canceled || ctx.Err() != nil {
				s.logger.Info("Debuglet disconnected (context canceled)", zap.String("debugletID", debugletID))
			} else {
				s.logger.Error("ControlStream error", zap.Error(err))
			}
			return err
		}

		switch msg := in.GetMsg().(type) {
		case *pb.ExecutorDebugletMessage_State:
			debugletID = msg.State.GetDebugletId()
			s.deHandler.HandleState(ctx, msg.State.GetDebugletId(), msg.State.GetExecutorId(), grpcToRunState(msg.State.GetState()))
		case *pb.ExecutorDebugletMessage_Output:
			s.deHandler.HandleOutput(ctx, msg.Output.GetDebugletId(), msg.Output.GetOutput())
		case *pb.ExecutorDebugletMessage_Exit:
			var errMsg error
			if e := msg.Exit.GetErrorMessage(); e != "" {
				errMsg = errors.New(e)
			}
			s.deHandler.HandleExit(msg.Exit.GetDebugletId(), msg.Exit.GetExitCode(), errMsg)
		default:
			s.logger.Warn("Unknown debuglet message")
		}
	}
}
