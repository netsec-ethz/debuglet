package dispatcher

import (
	"context"
	"io"
	"strconv"
	"testing"

	pb "debuglet/protocol"

	"google.golang.org/grpc/metadata"
)

const (
	benchExecutorID          = "bench-exec"
	benchCapacity      int64 = 10_000_000_000
	benchFloor         int64 = 1
	benchCeil          int64 = 1_000
	benchChannelBuffer       = 1024
)

type destMode int

const (
	destShared destMode = iota
	destUnique
)

type benchJobCase struct {
	name string
	jobs int
	mode destMode
}

var benchJobCases = []benchJobCase{
	{name: "shared/N=0", jobs: 0, mode: destShared},
	{name: "shared/N=10", jobs: 10, mode: destShared},
	{name: "shared/N=100", jobs: 100, mode: destShared},
	{name: "shared/N=1000", jobs: 1000, mode: destShared},
	{name: "shared/N=10000", jobs: 10000, mode: destShared},
	{name: "unique/N=0", jobs: 0, mode: destUnique},
	{name: "unique/N=10", jobs: 10, mode: destUnique},
	{name: "unique/N=100", jobs: 100, mode: destUnique},
	{name: "unique/N=1000", jobs: 1000, mode: destUnique},
	{name: "unique/N=10000", jobs: 10000, mode: destUnique},
	{name: "unique/N=100000", jobs: 100000, mode: destUnique},
	{name: "unique/N=1000000", jobs: 1000000, mode: destUnique},
}

var noopStream = &noopSessionStream{}

type noopSessionStream struct{}

func (s *noopSessionStream) Send(*pb.SessionMessage) error     { return nil }
func (s *noopSessionStream) Recv() (*pb.SessionMessage, error) { return nil, io.EOF }
func (s *noopSessionStream) SetHeader(metadata.MD) error       { return nil }
func (s *noopSessionStream) SendHeader(metadata.MD) error      { return nil }
func (s *noopSessionStream) SetTrailer(metadata.MD)            {}
func (s *noopSessionStream) Context() context.Context          { return context.Background() }
func (s *noopSessionStream) SendMsg(any) error                 { return nil }
func (s *noopSessionStream) RecvMsg(any) error                 { return io.EOF }

type noopMeasurement struct {
	sessions []*DebugletSession
}

func (m *noopMeasurement) Sessions() []*DebugletSession {
	return m.sessions
}

func (m *noopMeasurement) Start() error {
	return nil
}

func destinationsFor(mode destMode, idx int) []string {
	if mode == destUnique {
		return []string{"dest-" + strconv.Itoa(idx)}
	}
	return []string{"dest-1"}
}

func newAssignment(sessionID, measurementID string, dests []string) *pb.DebugletAssignment {
	return &pb.DebugletAssignment{
		SessionId:     sessionID,
		MeasurementId: measurementID,
		Addresses:     dests,
		Policy: &pb.DebugletAssignment_Policy{
			FloorBw: benchFloor,
			CeilBw:  benchCeil,
		},
	}
}

func makeMeasurement(numJobs int, measurementID, executorID string, mode destMode, ready bool, withStream bool) *Measurement {
	m := NewMeasurement(numJobs)
	for i := range numJobs {
		sessionID := measurementID + "-s-" + strconv.Itoa(i)
		assignment := newAssignment(sessionID, measurementID, destinationsFor(mode, i))
		m.Assign(executorID, assignment)
		if withStream {
			session := m.GetSession(sessionID)
			if session != nil {
				session.Register(noopStream)
			}
		}
		if ready {
			m.SessionReady()
		}
	}
	return m
}

func seedPoliciesForMeasurement(d *Dispatcher, m *Measurement) error {
	for _, session := range m.sessions {
		if err := d.resource.RegisterPolicy(session.ExecutorID, session.Assignment); err != nil {
			return err
		}
	}
	return nil
}

func removePoliciesForMeasurement(d *Dispatcher, m *Measurement) {
	for _, session := range m.sessions {
		d.resource.RemovePolicy(session.Assignment.SessionId)
	}
}

func startMeasurementBaseline(d *Dispatcher, m *Measurement) error {
	d.mu.Lock()
	m.mu.RLock()
	sessions := make([]*DebugletSession, 0, len(m.sessions))
	for _, session := range m.sessions {
		sessions = append(sessions, session)
	}
	m.mu.RUnlock()
	for range sessions {
	}
	d.mu.Unlock()

	return m.Start()
}

func removeMeasurementBaseline(d *Dispatcher, id string) {
	m := d.GetMeasurement(id)
	if m == nil {
		return
	}

	d.mu.Lock()
	for range m.sessions {
	}
	m.Close()
	delete(d.measurements, id)
	d.mu.Unlock()
}

func startExecutorDrain(exec *Executor) func() {
	done := make(chan struct{})
	go func() {
		for {
			select {
			case <-exec.Assignments:
			case <-exec.Updates:
			case <-done:
				return
			}
		}
	}()
	return func() { close(done) }
}

func newBenchDispatcher(b *testing.B) (*Dispatcher, func()) {
	d := NewDispatcher()
	d.RegisterExecutor(benchExecutorID)
	exec := d.GetExecutor(benchExecutorID)
	if exec == nil {
		b.Fatalf("executor %s not found", benchExecutorID)
	}
	exec.Assignments = make(chan *pb.DebugletAssignment, benchChannelBuffer)
	exec.Updates = make(chan *pb.DestinationUpdates, benchChannelBuffer)
	if err := d.SetExecutorCapacity(benchExecutorID, benchCapacity); err != nil {
		b.Fatalf("SetExecutorCapacity failed: %v", err)
	}
	stopDrain := startExecutorDrain(exec)
	return d, stopDrain
}

func skipLongBench(b *testing.B, jobs int) {
	if testing.Short() && jobs > 100000 {
		b.Skip("skipping large benchmark case in short mode")
	}
}

func BenchmarkNewDispatcher(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		_ = NewDispatcher()
	}
}

func BenchmarkCreateMeasurement(b *testing.B) {
	d := NewDispatcher()
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		d.CreateMeasurement(1)
	}
}

func BenchmarkGetMeasurement(b *testing.B) {
	d := NewDispatcher()
	id, _ := d.CreateMeasurement(1)
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		_ = d.GetMeasurement(id)
	}
}

func BenchmarkRegisterExecutor(b *testing.B) {
	d := NewDispatcher()
	b.ReportAllocs()
	b.ResetTimer()
	for i := range b.N {
		d.RegisterExecutor("exec-" + strconv.Itoa(i))
	}
}

func BenchmarkRemoveExecutor(b *testing.B) {
	d := NewDispatcher()
	ids := make([]string, b.N)
	for i := range b.N {
		id := "exec-" + strconv.Itoa(i)
		ids[i] = id
		d.RegisterExecutor(id)
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := range b.N {
		d.RemoveExecutor(ids[i])
	}
}

func BenchmarkSetExecutor(b *testing.B) {
	d := NewDispatcher()
	d.RegisterExecutor(benchExecutorID)
	b.ReportAllocs()
	b.ResetTimer()
	for i := range b.N {
		if err := d.SetExecutor(benchExecutorID, int64(i)); err != nil {
			b.Fatalf("SetExecutor failed: %v", err)
		}
	}
}

func BenchmarkSetExecutorCapacity(b *testing.B) {
	d := NewDispatcher()
	d.RegisterExecutor(benchExecutorID)
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		if err := d.SetExecutorCapacity(benchExecutorID, benchCapacity); err != nil {
			b.Fatalf("SetExecutorCapacity failed: %v", err)
		}
	}
}

func BenchmarkGetExecutor(b *testing.B) {
	d := NewDispatcher()
	d.RegisterExecutor(benchExecutorID)
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		_ = d.GetExecutor(benchExecutorID)
	}
}

func BenchmarkListExecutors(b *testing.B) {
	cases := []int{1, 10, 100, 1000, 10000, 100000}
	for _, n := range cases {
		b.Run("N="+strconv.Itoa(n), func(b *testing.B) {
			d := NewDispatcher()
			for i := 0; i < n; i++ {
				d.RegisterExecutor("exec-" + strconv.Itoa(i))
			}
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				_ = d.ListExecutors()
			}
		})
	}
}

func BenchmarkDispatchTask(b *testing.B) {
	d, stopDrain := newBenchDispatcher(b)
	defer stopDrain()

	measurement := NewMeasurement(0)
	assignment := newAssignment("session-1", "measurement-1", []string{"dest-1"})

	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		if err := d.DispatchTask(benchExecutorID, measurement, assignment); err != nil {
			b.Fatalf("DispatchTask failed: %v", err)
		}
	}
}

func BenchmarkUpdateDestinations(b *testing.B) {
	d, stopDrain := newBenchDispatcher(b)
	defer stopDrain()

	updates := &pb.DestinationUpdates{Updates: []*pb.DestinationUpdates_Update{
		{AssignmentId: "assignment-1", Destination: "dest-1", NewCeilBw: benchCeil},
	}}

	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		if err := d.UpdateDestinations(benchExecutorID, updates); err != nil {
			b.Fatalf("UpdateDestinations failed: %v", err)
		}
	}
}

func BenchmarkStartMeasurement(b *testing.B) {
	for _, tc := range benchJobCases {
		b.Run(tc.name, func(b *testing.B) {
			skipLongBench(b, tc.jobs)
			d, stopDrain := newBenchDispatcher(b)
			defer stopDrain()

			b.ReportAllocs()
			b.ResetTimer()
			for i := range b.N {
				b.StopTimer()
				measurementID := "bench-measurement-" + strconv.Itoa(i)
				m := makeMeasurement(tc.jobs, measurementID, benchExecutorID, tc.mode, true, false)
				mockMeasurement := &noopMeasurement{sessions: m.Sessions()}
				b.StartTimer()

				if err := d.StartMeasurement(mockMeasurement); err != nil {
					b.Fatalf("StartMeasurement failed: %v", err)
				}

				b.StopTimer()
				removePoliciesForMeasurement(d, m)
				m.Close()
				b.StartTimer()
			}
		})
	}
}

func BenchmarkStartMeasurementBaseline(b *testing.B) {
	for _, tc := range benchJobCases {
		b.Run(tc.name, func(b *testing.B) {
			skipLongBench(b, tc.jobs)
			d, stopDrain := newBenchDispatcher(b)
			defer stopDrain()

			b.ReportAllocs()
			b.ResetTimer()
			for i := range b.N {
				b.StopTimer()
				measurementID := "bench-measurement-" + strconv.Itoa(i)
				m := makeMeasurement(tc.jobs, measurementID, benchExecutorID, tc.mode, true, true)
				b.StartTimer()

				if err := startMeasurementBaseline(d, m); err != nil {
					b.Fatalf("startMeasurementBaseline failed: %v", err)
				}

				b.StopTimer()
				m.Close()
				b.StartTimer()
			}
		})
	}
}

func BenchmarkRemoveMeasurement(b *testing.B) {
	for _, tc := range benchJobCases {
		b.Run(tc.name, func(b *testing.B) {
			skipLongBench(b, tc.jobs)
			d, stopDrain := newBenchDispatcher(b)
			defer stopDrain()

			b.ReportAllocs()
			b.ResetTimer()
			for i := range b.N {
				b.StopTimer()
				measurementID := "bench-measurement-" + strconv.Itoa(i)
				m := makeMeasurement(tc.jobs, measurementID, benchExecutorID, tc.mode, false, false)
				d.mu.Lock()
				d.measurements[measurementID] = m
				d.mu.Unlock()
				if err := seedPoliciesForMeasurement(d, m); err != nil {
					b.Fatalf("seedPoliciesForMeasurement failed: %v", err)
				}
				b.StartTimer()

				d.RemoveMeasurement(measurementID)

				b.StopTimer()
				b.StartTimer()
			}
		})
	}
}

func BenchmarkRemoveMeasurementBaseline(b *testing.B) {
	for _, tc := range benchJobCases {
		b.Run(tc.name, func(b *testing.B) {
			skipLongBench(b, tc.jobs)
			d, stopDrain := newBenchDispatcher(b)
			defer stopDrain()

			b.ReportAllocs()
			b.ResetTimer()
			for i := range b.N {
				b.StopTimer()
				measurementID := "bench-measurement-" + strconv.Itoa(i)
				m := makeMeasurement(tc.jobs, measurementID, benchExecutorID, tc.mode, false, false)
				d.mu.Lock()
				d.measurements[measurementID] = m
				d.mu.Unlock()
				b.StartTimer()

				removeMeasurementBaseline(d, measurementID)

				b.StopTimer()
				b.StartTimer()
			}
		})
	}
}
