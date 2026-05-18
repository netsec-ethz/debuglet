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

// maxMeasurementHistory is the default number of recent measurement IDs to
// retain per executor. The caller can override it via HTTP query parameters.
const maxMeasurementHistory = 10

// Executor represents a registered executor and its metadata.
type Executor struct {
	ID          string                      `json:"id"`
	Ready       bool                        `json:"ready"`
	LastSeen    int64                       `json:"last_seen"`
	Assignments chan *pb.DebugletAssignment `json:"-"`
	Updates     chan *pb.DestinationUpdates `json:"-"`

	TeslaDelaySec          int64  `json:"tesla_delay_sec"`
	TeslaAnchorTimestampNs int64  `json:"tesla_anchor_timestamp_ns"`
	TeslaAnchorKey         []byte `json:"tesla_anchor_key"` // k_0, the public chain anchor

	// measurementIDs is a ring buffer of the last maxMeasurementHistory
	// measurement IDs that were dispatched to this executor.
	measurementIDs []string
}

// RecentMeasurementIDs returns up to n recent measurement IDs for this
// executor, newest first. If n ≤ 0 the default (maxMeasurementHistory) is
// used.
func (e *Executor) RecentMeasurementIDs(n int) []string {
	if n <= 0 {
		n = maxMeasurementHistory
	}
	if len(e.measurementIDs) == 0 {
		return []string{}
	}
	start := 0
	if len(e.measurementIDs) > n {
		start = len(e.measurementIDs) - n
	}
	// Return a copy, newest first.
	slice := e.measurementIDs[start:]
	out := make([]string, len(slice))
	for i, v := range slice {
		out[len(slice)-1-i] = v
	}
	return out
}

// appendMeasurementID adds id to the executor's history, trimming old entries
// so the total length stays within 2× the maximum to bound memory usage.
func (e *Executor) appendMeasurementID(id string) {
	e.measurementIDs = append(e.measurementIDs, id)
	// Keep at most 2× the default to avoid unbounded growth.
	if trim := 2 * maxMeasurementHistory; len(e.measurementIDs) > trim {
		e.measurementIDs = e.measurementIDs[len(e.measurementIDs)-trim:]
	}
}

type Dispatcher struct {
	mu           sync.RWMutex
	executors    map[string]*Executor
	measurements map[string]*Measurement
	assignments  map[string]*pb.DebugletAssignment
	resource     *resource.DispatcherManager

	KeyStore     *KeyStore
	ipToExecutor map[string]string // source_ip → executor_id
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

	measurement.mu.RLock()
	sessions := make([]*DebugletSession, 0, len(measurement.sessions))
	for _, session := range measurement.sessions {
		sessions = append(sessions, session)
	}
	measurement.mu.RUnlock()

	for _, session := range sessions {
		assignment := session.Assignment
		policy := assignment.GetPolicy()
		executorID := session.ExecutorID

		err := d.resource.CheckPolicy(executorID, policy.GetFloorBw(), policy.GetCeilBw(), assignment.GetAddresses())
		if err != nil {
			d.mu.Unlock()
			return err
		}
		destinationUpdates, err := d.resource.RegisterPolicy(executorID, assignment)
		if err != nil {
			d.mu.Unlock()
			return err
		}
		for executorID, updates := range destinationUpdates {
			go d.UpdateDestinations(executorID, updates)
		}
	}

	d.mu.Unlock()

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

	d.mu.Lock()
	defer d.mu.Unlock()

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

// RegisterExecutor creates or updates the executor record for id. anchorKey is
// k_0, the public TESLA chain anchor published by the executor at startup.
func (d *Dispatcher) RegisterExecutor(id string, ip string, teslaDelay int64, teslaAnchor int64, anchorKey []byte) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if _, exists := d.executors[id]; !exists {
		d.executors[id] = &Executor{
			ID:          id,
			Assignments: make(chan *pb.DebugletAssignment),
			Updates:     make(chan *pb.DestinationUpdates),
		}
	}
	exec := d.executors[id]
	exec.TeslaDelaySec = teslaDelay
	exec.TeslaAnchorTimestampNs = teslaAnchor
	if len(anchorKey) > 0 {
		exec.TeslaAnchorKey = anchorKey
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

// GetExecutorByIPFull returns the full Executor record for the given source IP,
// or nil if no executor is registered with that IP.
func (d *Dispatcher) GetExecutorByIPFull(ip string) *Executor {
	d.mu.RLock()
	defer d.mu.RUnlock()
	id, ok := d.ipToExecutor[ip]
	if !ok {
		return nil
	}
	return d.executors[id]
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
	_, exists := d.executors[id]
	d.mu.Unlock()

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

	// Record this measurement ID in the executor's history.
	d.mu.Lock()
	exec.appendMeasurementID(assignment.MeasurementId)
	d.mu.Unlock()

	exec.Assignments <- assignment
	return nil
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
