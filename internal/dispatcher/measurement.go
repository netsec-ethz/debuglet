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
	"fmt"
	"sync"

	pb "debuglet/protocol"
)

type DebugletSession struct {
	sessionStream pb.DebugletDispatcher_SessionStreamServer
	Assignment    *pb.DebugletAssignment
	MeasurementId string
	ExecutorID    string
}

func (s *DebugletSession) Register(stream pb.DebugletDispatcher_SessionStreamServer) {
	s.sessionStream = stream
}

func (s *DebugletSession) Start() error {
	err := s.sessionStream.Send(&pb.SessionMessage{
		Msg: &pb.SessionMessage_DispatcherCmd{
			DispatcherCmd: &pb.DispatcherCommand{
				SessionId: s.Assignment.SessionId,
				Type:      pb.DispatcherCommandType_START_EXECUTION,
			},
		},
	})
	if err != nil {
		return fmt.Errorf("failed to start session %s: %w", s.Assignment.SessionId, err)
	}
	return nil
}

func (s *DebugletSession) Close() {
	// TODO: clean up if necessary
}

type Measurement struct {
	mu        sync.RWMutex
	sessions  map[string]*DebugletSession
	EventChan chan interface{}
	wg        *sync.WaitGroup
}

func NewMeasurement(numDebuglets int) *Measurement {
	wg := sync.WaitGroup{}
	wg.Add(numDebuglets)
	return &Measurement{
		sessions:  make(map[string]*DebugletSession),
		EventChan: make(chan interface{}, 100),
		wg:        &wg,
	}
}

func (m *Measurement) SessionReady() {
	m.wg.Done()
}

func (m *Measurement) Start() error {
	m.wg.Wait()
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, s := range m.sessions {
		err := s.Start()
		if err != nil {
			return fmt.Errorf("failed to start session %s: %w", s.Assignment.SessionId, err)
		}
	}
	return nil
}

func (m *Measurement) Assign(executorID string, assignment *pb.DebugletAssignment) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sessions[assignment.SessionId] = &DebugletSession{
		MeasurementId: assignment.MeasurementId,
		Assignment:    assignment,
		ExecutorID:    executorID,
	}
}

func (m *Measurement) GetSession(sessionId string) *DebugletSession {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.sessions[sessionId]
}

func (m *Measurement) Close() {
	m.mu.Lock()
	defer m.mu.Unlock()
	for sessionId, s := range m.sessions {
		// TODO: session cleanup
		s.Close()
		delete(m.sessions, sessionId)
	}
	close(m.EventChan)
}
