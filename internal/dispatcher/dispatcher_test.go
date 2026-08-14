package dispatcher_test

import (
	"debuglet/internal/dispatcher"
	"debuglet/internal/dispatcher/models"
	"debuglet/internal/dispatcher/resource"
	"debuglet/internal/executor"
	"debuglet/internal/executor/config"
	"debuglet/internal/executor/scheduler/memory"
	"debuglet/protocol"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

// TestRestart tests if the dispatcher can correctly restore the scheduler state after a restart.
func TestRestart(t *testing.T) {
	start := time.Now().Add(time.Hour)

	logger := zap.NewNop()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create sqlmock: %v", err)
	}
	defer db.Close()

	d := dispatcher.New(logger, db, "test", time.Hour, time.Minute, nil)

	// RESTORE
	mock.ExpectQuery("SELECT id, start_time, end_time, usage, executor_id, addresses, state FROM debuglets").
		WillReturnRows(mockDebugletRow(start))
	if err := d.RestoreScheduler(t.Context()); err != nil {
		t.Fatalf("failed to restore scheduler: %v", err)
	}

	lis, err := net.Listen("tcp", ":9000")
	if err != nil {
		t.Fatalf("failed to listen on port 9000: %v", err)
	}
	go d.Bidi.ServeYamux(t.Context(), lis)
	go d.Bidi.ServeGRPC(t.Context(), ":9001")

	e, err := executor.New(&config.ExecutorConfig{
		Identity:   config.IdentityConfig{ExecutorID: "test"},
		Dispatcher: config.DispatcherConfig{Addr: "127.0.0.1:9001", YamuxAddr: "127.0.0.1:9000"},
		Resources:  config.ResourcesConfig{Capacity: int64(resource.Gigabit)},
		TLS:        config.TLSConfig{Disable: true},
	}, logger, memory.NewStorage())
	if err != nil {
		t.Fatalf("failed to create executor: %v", err)
	}
	go e.Listen(t.Context())

	for {
		time.Sleep(100 * time.Millisecond)
		_, exists := d.GetExecutor("test")
		if exists {
			break
		}
	}

	d.OnResources(t.Context(), &protocol.ResourcesRequest{ExecutorId: "test", BandwidthCapacity: int64(resource.Gigabit)})

	// INSERT DEBUGLET
	mock.ExpectBegin()
	mock.ExpectQuery("INSERT INTO debuglets").WillReturnRows(mockDebugletRow(start))
	mock.ExpectCommit()

	// UPDATE DEBUGLET STATE
	mock.ExpectQuery("UPDATE debuglets").WillReturnRows(mockDebugletRow(start))

	_, err = d.SubmitDebuglets(t.Context(), []models.DebugletSpec{{
		StartTime:     &start,
		ExecutorID:    "test",
		TransactionID: "test",
		Policy: models.DebugletPolicy{
			FloorBW: resource.Gigabit,
			CeilBW:  resource.Gigabit,
			Timeout: 10 * time.Second,
		},
	}})

	if err == nil {
		t.Fatalf("expected error when submitting debuglet while executor has no capacity from startup")
	}
	if !errors.Is(err, resource.ErrCapacityFull) {
		t.Fatalf("expected ErrCapacityFull, got: %v", err)
	}
}

func mockDebugletRow(start time.Time) *sqlmock.Rows {
	return sqlmock.NewRows([]string{"id", "start_time", "end_time", "usage", "executor_id", "addresses", "state"}).AddRow(
		uuid.New().String(),
		start,
		start.Add(10*time.Second),
		int64(resource.Gigabit),
		"test",
		nil,
		models.RunStateUploading,
	)
}
