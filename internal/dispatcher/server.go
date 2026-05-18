// Copyright 2025 ETH Zurich
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package dispatcher

import (
	"io"

	pb "debuglet/protocol"

	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type DispatcherServer struct {
	pb.UnimplementedDebugletDispatcherServer
	dispatcher *Dispatcher
	logger     *zap.Logger
}

func NewDispatcherServer(m *Dispatcher, logger *zap.Logger) *DispatcherServer {
	return &DispatcherServer{dispatcher: m, logger: logger}
}

// ControlStream handles executor registration, heartbeat, and task assignment
func (s *DispatcherServer) ControlStream(stream pb.DebugletDispatcher_ControlStreamServer) error {
	var executorID string
	ctx := stream.Context()

	go func() {
		<-ctx.Done()
		if executorID != "" {
			s.dispatcher.RemoveExecutor(executorID)
			s.logger.Info("Executor disconnected", zap.String("executor_id", executorID))
		}
	}()

	for {
		in, err := stream.Recv()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			st := status.Convert(err)
			if st.Code() == codes.Canceled {
				s.logger.Info("Executor disconnected (context canceled)", zap.String("executor_id", executorID))
				return nil
			}
			s.logger.Error("ControlStream error", zap.Error(err))
			return err
		}

		switch msg := in.Msg.(type) {
		case *pb.ControlMessage_Hello:
			executorID = msg.Hello.ExecutorId
			s.dispatcher.RegisterExecutor(executorID, msg.Hello.SourceIp, msg.Hello.TeslaDelaySec, msg.Hello.TeslaAnchorTimestampNs)
			s.logger.Info("Executor connected", zap.String("executor_id", executorID), zap.String("source_ip", msg.Hello.SourceIp))

			// Optional acknowledgment
			stream.Send(&pb.ControlMessage{
				Msg: &pb.ControlMessage_Noop{Noop: &pb.NoOp{Message: "Hello received"}},
			})

			// Start assignment push loop
			go func(id string) {
				exec := s.dispatcher.executors[id]
				for {
					select {
					case assign := <-exec.Assignments:
						stream.Send(&pb.ControlMessage{
							Msg: &pb.ControlMessage_Assignment{Assignment: assign},
						})
					case updates := <-exec.Updates:
						stream.Send(&pb.ControlMessage{
							Msg: &pb.ControlMessage_Updates{Updates: updates},
						})
					case <-ctx.Done():
						return
					}
				}
			}(executorID)

		case *pb.ControlMessage_Heartbeat:
			s.logger.Debug("Heartbeat received", zap.String("executor_id", executorID), zap.Int64("timestamp", msg.Heartbeat.Timestamp), zap.Int64("epoch", msg.Heartbeat.TeslaKeyEpoch), zap.Binary("key", msg.Heartbeat.TeslaKey))
			s.dispatcher.SetExecutor(executorID, msg.Heartbeat.Timestamp)
			if msg.Heartbeat.TeslaKey != nil {
				err := s.dispatcher.KeyStore.Store(executorID, msg.Heartbeat.TeslaKeyEpoch, msg.Heartbeat.TeslaKey)
				if err != nil {
					s.logger.Error("Failed to store TESLA key from heartbeat", zap.Error(err), zap.String("executor_id", executorID), zap.Int64("epoch", msg.Heartbeat.TeslaKeyEpoch))
				}
			}

		case *pb.ControlMessage_Resources:
			if bw := msg.Resources.GetBandwidthCapacity(); bw > 0 {
				s.logger.Debug("Updating executor bandwidth capacity", zap.String("executor_id", executorID), zap.Int64("new_bandwidth", bw))
				s.dispatcher.SetExecutorCapacity(executorID, bw)
			}

		default:
			s.logger.Warn("Unknown control message")
		}
	}
}

// SessionStream handles per-session bidirectional communication
func (s *DispatcherServer) SessionStream(stream pb.DebugletDispatcher_SessionStreamServer) error {
	var measurement *Measurement
	var session *DebugletSession
	for {
		in, err := stream.Recv()
		if err == io.EOF {
			s.logger.Info("Stream closed", zap.Error(err))
			return nil
		}
		if err != nil {
			s.logger.Error("Stream error", zap.Error(err))
			return err
		}

		switch msg := in.Msg.(type) {
		case *pb.SessionMessage_Ready:
			sessionId := msg.Ready.SessionId
			measurementId := msg.Ready.MeasurementId
			measurement = s.dispatcher.GetMeasurement(measurementId)
			if measurement == nil {
				s.logger.Warn("Measurement not found", zap.String("measurement_id", measurementId), zap.String("session_id", sessionId))
				return status.Errorf(codes.NotFound, "measurement %s not found", measurementId)
			}
			session = measurement.GetSession(sessionId)
			if session == nil {
				s.logger.Warn("Session not found in measurement", zap.String("session_id", sessionId), zap.String("measurement_id", measurementId))
				return status.Errorf(codes.NotFound, "session %s not found", sessionId)
			}
			session.Register(stream)
			measurement.SessionReady()
			measurement.EventChan <- ReadyEvent{
				Event:         "ready",
				SessionId:     sessionId,
				MeasurementId: measurementId,
				ExecutorId:    msg.Ready.ExecutorId,
				ScionAddr:     msg.Ready.ScionAddr,
			}
			s.logger.Info("Executor ready for session", zap.String("executor_id", msg.Ready.ExecutorId), zap.String("session_id", msg.Ready.SessionId))

		case *pb.SessionMessage_Stdout:
			stdout := string(msg.Stdout.Stdout)
			s.logger.Debug("STDOUT from session", zap.String("session_id", msg.Stdout.SessionId))
			measurement.EventChan <- StdoutEvent{
				Event:     "stdout",
				SessionId: msg.Stdout.SessionId,
				Stdout:    stdout,
			}

		case *pb.SessionMessage_Exit:
			s.logger.Info("Session finished", zap.String("session_id", msg.Exit.GetSessionId()), zap.Int32("exit_code", msg.Exit.GetExitCode()))
			measurement.EventChan <- ExitEvent{}
			return nil

		default:
			s.logger.Warn("Unknown session message type")
		}
	}
}
