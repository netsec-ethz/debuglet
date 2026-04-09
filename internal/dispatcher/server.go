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
	"log"

	pb "debuglet/protocol"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type DispatcherServer struct {
	pb.UnimplementedDebugletDispatcherServer
	manager *Dispatcher
}

func NewDispatcherServer(m *Dispatcher) *DispatcherServer {
	return &DispatcherServer{manager: m}
}

// ControlStream handles executor registration, heartbeat, and task assignment
func (s *DispatcherServer) ControlStream(stream pb.DebugletDispatcher_ControlStreamServer) error {
	var executorID string
	ctx := stream.Context()

	go func() {
		<-ctx.Done()
		if executorID != "" {
			s.manager.RemoveExecutor(executorID)
			log.Printf("[DISPATCHER] Executor %s disconnected", executorID)
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
				log.Printf("[DISPATCHER] Executor %s disconnected (context canceled)", executorID)
				return nil
			}
			log.Printf("[DISPATCHER] ControlStream error: %v", err)
			return err
		}

		switch msg := in.Msg.(type) {
		case *pb.ControlMessage_Hello:
			executorID = msg.Hello.ExecutorId
			s.manager.RegisterExecutor(executorID)
			log.Printf("[DISPATCHER] Executor %s connected", executorID)

			// Optional acknowledgment
			stream.Send(&pb.ControlMessage{
				Msg: &pb.ControlMessage_Noop{Noop: &pb.NoOp{Message: "Hello received"}},
			})

			// Start assignment push loop
			go func(id string) {
				exec := s.manager.executors[id]
				for {
					select {
					case assign := <-exec.Assignments:
						stream.Send(&pb.ControlMessage{
							Msg: &pb.ControlMessage_Assignment{Assignment: assign},
						})
					case <-ctx.Done():
						return
					}
				}
			}(executorID)

		case *pb.ControlMessage_Heartbeat:
			log.Printf("[DISPATCHER] Heartbeat from %s at %d", msg.Heartbeat.ExecutorId, msg.Heartbeat.Timestamp)
			s.manager.SetExecutor(msg.Heartbeat.ExecutorId, msg.Heartbeat.Timestamp)

		default:
			log.Printf("[DISPATCHER] Unknown control message")
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
			log.Printf("[SESSION] Stream closed: %v", err)
			return nil
		}
		if err != nil {
			log.Printf("[SESSION] Error: %v", err)
			return err
		}

		switch msg := in.Msg.(type) {
		case *pb.SessionMessage_Ready:
			sessionId := msg.Ready.SessionId
			measurementId := msg.Ready.MeasurementId
			measurement = s.manager.GetMeasurement(measurementId)
			if measurement == nil {
				log.Printf("[SESSION] Measurement %s not found for session %s", measurementId, sessionId)
				return status.Errorf(codes.NotFound, "measurement %s not found", measurementId)
			}
			session = measurement.GetSession(sessionId)
			if session == nil {
				log.Printf("[SESSION] Session %s not found in measurement %s", sessionId, measurementId)
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
			log.Printf("[SESSION] Executor %s ready for session %s", msg.Ready.ExecutorId, msg.Ready.SessionId)

		case *pb.SessionMessage_Stdout:
			stdout := string(msg.Stdout.Stdout)
			log.Printf("[SESSION] STDOUT from %s: %s", msg.Stdout.SessionId, stdout)
			measurement.EventChan <- StdoutEvent{
				Event:     "stdout",
				SessionId: msg.Stdout.SessionId,
				Stdout:    stdout,
			}

		case *pb.SessionMessage_Exit:
			log.Printf("[SESSION] Session %s finished with code %d", msg.Exit.SessionId, msg.Exit.ExitCode)
			return nil

		default:
			log.Printf("[SESSION] Unknown message type")
		}
	}
}
