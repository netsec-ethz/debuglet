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
	"sync"
	"time"

	"go.uber.org/zap"
)

type DebugletStore struct {
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

	// debugletStores tracks in-memory state for active debuglets.
	debugletStores map[string]*DebugletStore

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
func (d *Dispatcher) DB() *sql.DB                { return d.db }

func (d *Dispatcher) GetStore(debugletID string) (DebugletStore, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if st, ok := d.debugletStores[debugletID]; ok {
		return *st, nil
	} else {
		return DebugletStore{}, fmt.Errorf("debuglet with '%s' does not exist", debugletID)
	}
}

func (d *Dispatcher) SetDestinationLimit(destination string, limit resource.Bitrate) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.destinations.SetLimit(destination, limit)
	// TODO: Notify executors of the new limit if needed
}
