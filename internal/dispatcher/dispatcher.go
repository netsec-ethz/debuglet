package dispatcher

import (
	"debuglet/internal/dispatcher/resource"
	"debuglet/internal/dispatcher/tag"
	"fmt"
	"slices"
	"sync"

	"go.uber.org/zap"
)

type logConn struct {
	seq   int
	logs  chan<- []byte
	state chan<- DebugletRunState
	done  chan struct{}
}

type DebugletStore struct {
	Logs       []byte
	Policy     DebugletPolicy
	ExecutorID string
	State      DebugletRunState
	Err        string
}

type Dispatcher struct {
	executors    map[string]*RegisteredExecutor
	ipToExecutor map[string]string
	mu           sync.RWMutex
	keystore     *tag.KeyStore
	sender       ExecutorServer
	logger       *zap.Logger

	// Naive storage of the full output of debuglets.
	// debugletStores allows for a user to get the full logs at a later point in time.
	debugletStores map[string]*DebugletStore
	// connectedLogs stores the users connected via websockets
	connectedLogs map[string][]logConn
	seq           int // counter for log connection IDs

	destinations *resource.DestinationsUsage
}

var _ DispatcherControlHandler = (*Dispatcher)(nil)
var _ DispatcherDebugletHandler = (*Dispatcher)(nil)

func New(l *zap.Logger) *Dispatcher {
	return &Dispatcher{
		executors:      make(map[string]*RegisteredExecutor),
		ipToExecutor:   make(map[string]string),
		keystore:       tag.NewKeyStore(),
		logger:         l,
		debugletStores: make(map[string]*DebugletStore),
		connectedLogs:  make(map[string][]logConn),
		destinations:   resource.NewDestinations(resource.Gigabit),
	}
}

func (d *Dispatcher) SetExecutorSender(s ExecutorServer) {
	d.sender = s
}

func (d *Dispatcher) GetKeyStore() *tag.KeyStore {
	return d.keystore
}

func (d *Dispatcher) GetStore(debugletID string) (*DebugletStore, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if st, ok := d.debugletStores[debugletID]; ok {
		return st, nil
	} else {
		return nil, fmt.Errorf("debuglet with '%s' does not exist", debugletID)
	}
}

func (d *Dispatcher) RegisterLogConnection(debugletID string, logs chan<- []byte, state chan<- DebugletRunState) (int, <-chan struct{}, error) {
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
}
