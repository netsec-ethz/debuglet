package dispatcher

import (
	"context"
	"database/sql"
	"debuglet/internal/dispatcher/database/ddb"
	"debuglet/internal/dispatcher/models"
	"debuglet/internal/dispatcher/payments"
	"debuglet/internal/dispatcher/resource"
	"debuglet/internal/dispatcher/resource/schedule"
	"debuglet/internal/dispatcher/tag"
	"debuglet/internal/dispatcher/transport/rpc"
	"fmt"
	"slices"
	"sync"
	"time"

	"go.uber.org/zap"
)

type logConn struct {
	seq   int
	logs  chan<- []byte
	state chan<- models.DebugletRunState
	done  chan struct{}
}

type DebugletStore struct {
	Logs       []byte
	Policy     models.DebugletPolicy
	ExecutorID string
	State      models.DebugletRunState
	Err        string
	From, To   time.Time
}

type Dispatcher struct {
	version string

	executors    map[string]*RegisteredExecutor
	execTimeout  time.Duration
	ipToExecutor map[string]string
	keystore     *tag.KeyStore
	logger       *zap.Logger
	Bidi         *rpc.BidiServer
	mu           sync.RWMutex
	db           *sql.DB

	// Naive storage of the full output of debuglets.
	// debugletStores allows for a user to get the full logs at a later point in time.
	debugletStores map[string]*DebugletStore
	// connectedLogs stores the users connected via websockets
	connectedLogs map[string][]logConn
	seq           int // counter for log connection IDs

	destinations *resource.DestinationsUsage
	Payment      *payments.PaymentHandler
	scheduler    *schedule.JobScheduler
}

func New(l *zap.Logger, db *sql.DB, version string, execTimeout, granularity time.Duration, paymentHandler *payments.PaymentHandler) *Dispatcher {
	if granularity <= 0 {
		granularity = 30 * time.Second
	}
	d := &Dispatcher{
		version:        version,
		executors:      make(map[string]*RegisteredExecutor),
		execTimeout:    execTimeout,
		ipToExecutor:   make(map[string]string),
		keystore:       tag.NewKeyStore(),
		logger:         l,
		db:             db,
		debugletStores: make(map[string]*DebugletStore),
		connectedLogs:  make(map[string][]logConn),
		destinations:   resource.NewDestinations(resource.Gigabit),
		Payment:        paymentHandler,
		scheduler:      schedule.New(granularity),
	}

	d.Bidi = rpc.NewBidiServer(l, d)
	return d
}

func (d *Dispatcher) RestoreScheduler(ctx context.Context) error {
	queries := ddb.New(d.db)
	debuglets, err := queries.ListDebugletsEndAfter(ctx, time.Now().Add(-1*time.Minute))
	if err != nil {
		return fmt.Errorf("failed to list debuglets from database: %w", err)
	}
	for _, deb := range debuglets {
		d.scheduler.Submit(schedule.Request{
			Executor:    deb.ExecutorID,
			From:        deb.StartTime,
			To:          deb.EndTime,
			Destination: deb.Addresses,
			Use:         resource.Bitrate(deb.Usage),
		})
	}
	return nil
}

func (d *Dispatcher) Close()                     { d.Bidi.Close() }
func (d *Dispatcher) GetVersion() string         { return d.version }
func (d *Dispatcher) GetKeyStore() *tag.KeyStore { return d.keystore }

func (d *Dispatcher) GetStore(debugletID string) (DebugletStore, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if st, ok := d.debugletStores[debugletID]; ok {
		return *st, nil
	} else {
		return DebugletStore{}, fmt.Errorf("debuglet with '%s' does not exist", debugletID)
	}
}

func (d *Dispatcher) RegisterLogConnection(debugletID string, logs chan<- []byte, state chan<- models.DebugletRunState) (int, <-chan struct{}, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if _, exists := d.debugletStores[debugletID]; !exists {
		return 0, nil, fmt.Errorf("debuglet with id '%s' does not exist", debugletID)
	}

	d.seq++
	lc := logConn{logs: logs, state: state, seq: d.seq, done: make(chan struct{})}
	d.connectedLogs[debugletID] = append(d.connectedLogs[debugletID], lc)
	return lc.seq, lc.done, nil
}

func (d *Dispatcher) RemoveLogConnection(debugletID string, seq int) {
	d.mu.Lock()
	defer d.mu.Unlock()
	index := slices.IndexFunc(d.connectedLogs[debugletID], func(lc logConn) bool {
		return seq == lc.seq
	})
	if index == -1 {
		return
	}
	conn := d.connectedLogs[debugletID][index]
	close(conn.logs)
	if conn.state != nil {
		close(conn.state)
	}
	d.connectedLogs[debugletID] = slices.Delete(d.connectedLogs[debugletID], index, index+1)
}

func (d *Dispatcher) SetDestinationLimit(destination string, limit resource.Bitrate) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.destinations.SetLimit(destination, limit)
	// TODO: Notify executors of the new limit if needed
}
