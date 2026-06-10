package dispatcher

import (
	"debuglet/internal/dispatcher/tag"
	"fmt"
	"slices"
	"sync"

	"go.uber.org/zap"
)

type logConn struct {
	seq  int
	logs chan<- []byte
	done chan struct{}
}

type Dispatcher struct {
	executors    map[string]*RegisteredExecutor
	ipToExecutor map[string]string
	mu           sync.RWMutex
	keystore     *tag.KeyStore
	sender       ExecutorSender
	logger       *zap.Logger

	// Naive storage of the full output of debuglets.
	// debugletLogs allows for a user to get the full logs at a later point in time.
	debugletLogs map[string][]byte
	// connectedLogs stores the users connected via websockets
	connectedLogs map[string][]logConn
	seq           int
}

var _ DispatcherControlHandler = (*Dispatcher)(nil)
var _ DispatcherDebugletHandler = (*Dispatcher)(nil)

func New(l *zap.Logger) *Dispatcher {
	return &Dispatcher{
		executors:     make(map[string]*RegisteredExecutor),
		ipToExecutor:  make(map[string]string),
		keystore:      tag.NewKeyStore(),
		logger:        l,
		debugletLogs:  make(map[string][]byte),
		connectedLogs: make(map[string][]logConn),
	}
}

func (d *Dispatcher) SetExecutorSender(s ExecutorSender) {
	d.sender = s
}

func (d *Dispatcher) GetKeyStore() *tag.KeyStore {
	return d.keystore
}

func (d *Dispatcher) RegisterLogConnection(debugletID string, channel chan<- []byte) (int, <-chan struct{}, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if _, exists := d.debugletLogs[debugletID]; !exists {
		return 0, nil, fmt.Errorf("debuglet with id '%s' does not exist", debugletID)
	}

	d.seq++
	lc := logConn{logs: channel, seq: d.seq, done: make(chan struct{})}
	d.connectedLogs[debugletID] = append(d.connectedLogs[debugletID], lc)
	return lc.seq, lc.done, nil
}

func (d *Dispatcher) RemoveLogConnection(debugletID string, seq int) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.connectedLogs[debugletID] = slices.DeleteFunc(d.connectedLogs[debugletID], func(lc logConn) bool {
		close(lc.logs)
		return seq == lc.seq
	})
}
