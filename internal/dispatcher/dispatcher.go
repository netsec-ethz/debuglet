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

	"debuglet/internal/dispatcher/resource"
	pb "debuglet/protocol"

	"github.com/google/uuid"
)

type Executor struct {
	ID          string                      `json:"id"`
	Ready       bool                        `json:"ready"`
	LastSeen    int64                       `json:"last_seen"`
	Assignments chan *pb.DebugletAssignment `json:"-"`
	Updates     chan *pb.DestinationUpdates `json:"-"`
}

type Dispatcher struct {
	mu           sync.RWMutex
	executors    map[string]*Executor
	measurements map[string]*Measurement
	assignments  map[string]*pb.DebugletAssignment
	resource     *resource.DispatcherManager

	KeyStore     *KeyStore
	ipToExecutor map[string]string // source_ip -> executor_id
}

func NewDispatcher() *Dispatcher {
	return &Dispatcher{
		executors:    make(map[string]*Executor),
		measurements: make(map[string]*Measurement),
		assignments:  make(map[string]*pb.DebugletAssignment),
		resource:     resource.New(),
		KeyStore:     NewKeyStore(),
		ipToExecutor: make(map[string]string),
	}
}

func (d *Dispatcher) CreateMeasurement(numDebuglets int) (string, *Measurement) {
	d.mu.Lock()
	defer d.mu.Unlock()
	measurementId := uuid.New().String()
	measurement := NewMeasurement(numDebuglets)
	d.measurements[measurementId] = measurement
	return measurementId, measurement
}

func (d *Dispatcher) StartMeasurement(measurement *Measurement) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	for _, session := range measurement.sessions {
		assignment := session.Assignment
		policy := assignment.GetPolicy()
		executorID := session.ExecutorID

		err := d.resource.CheckPolicy(executorID, policy.GetFloorBw(), policy.GetCeilBw(), assignment.GetAddresses())
		if err != nil {
			return err
		}
		destinationUpdates, err := d.resource.RegisterPolicy(executorID, assignment)
		if err != nil {
			return err
		}
		for executorID, updates := range destinationUpdates {
			d.UpdateDestinations(executorID, updates)
		}
	}

	return measurement.Start()
}

func (d *Dispatcher) GetMeasurement(id string) *Measurement {
	d.mu.RLock()
	defer d.mu.RUnlock()
	measurement, exists := d.measurements[id]
	if !exists {
		return nil
	}
	return measurement
}

func (d *Dispatcher) RemoveMeasurement(id string) {
	m := d.GetMeasurement(id)
	if m == nil {
		return
	}

	for _, session := range m.sessions {
		destinationUpdates := d.resource.RemovePolicy(session.Assignment.SessionId)
		if destinationUpdates == nil {
			continue
		}
		for executorID, updates := range destinationUpdates {
			d.UpdateDestinations(executorID, updates)
		}
	}

	m.Close()

	delete(d.measurements, id)
}

func (d *Dispatcher) RegisterExecutor(id string, ip string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if _, exists := d.executors[id]; !exists {
		d.executors[id] = &Executor{
			ID:          id,
			Assignments: make(chan *pb.DebugletAssignment, 1),
			Updates:     make(chan *pb.DestinationUpdates, 1),
		}
	}
	if ip != "" {
		d.ipToExecutor[ip] = id
	}
}

func (d *Dispatcher) GetExecutorByIP(ip string) string {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.ipToExecutor[ip]
}

func (d *Dispatcher) RemoveExecutor(id string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	delete(d.executors, id)
}

func (d *Dispatcher) SetExecutor(id string, lastSeen int64) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	exec, exists := d.executors[id]
	if !exists {
		return fmt.Errorf("executor %s not found", id)
	}
	exec.Ready = true
	exec.LastSeen = lastSeen
	return nil
}

func (d *Dispatcher) SetExecutorCapacity(id string, capacity int64) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	_, exists := d.executors[id]
	if !exists {
		return fmt.Errorf("executor %s not found", id)
	}
	d.resource.SetExecutorCapacity(id, capacity)
	return nil
}

func (d *Dispatcher) GetExecutor(id string) *Executor {
	d.mu.RLock()
	defer d.mu.RUnlock()
	exec, exists := d.executors[id]
	if !exists {
		return nil
	}
	return exec
}

func (d *Dispatcher) ListExecutors() []Executor {
	d.mu.RLock()
	defer d.mu.RUnlock()
	execs := []Executor{}
	for _, exec := range d.executors {
		execs = append(execs, *exec)
	}
	return execs
}

func (d *Dispatcher) DispatchTask(executorID string, measurement *Measurement, assignment *pb.DebugletAssignment) error {
	d.mu.RLock()
	exec, ok := d.executors[executorID]
	d.mu.RUnlock()
	if !ok {
		return fmt.Errorf("executor %s not found", executorID)
	}
	measurement.Assign(executorID, assignment)
	select {
	case exec.Assignments <- assignment:
		return nil
	default:
		return fmt.Errorf("executor %s assignment queue full", executorID)
	}
}

func (d *Dispatcher) UpdateDestinations(executorID string, updates *pb.DestinationUpdates) error {
	exec, ok := d.executors[executorID]
	if !ok {
		return fmt.Errorf("executor %s not found", executorID)
	}
	select {
	case exec.Updates <- updates:
		return nil
	default:
		return fmt.Errorf("executor %s updates queue full", executorID)
	}
}
