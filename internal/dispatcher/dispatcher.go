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

type debugletStore struct {
	logs []byte
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
	debugletStores map[string]*debugletStore
	// connectedLogs stores the users connected via websockets
	connectedLogs map[string][]logConn
	seq           int
}

var _ DispatcherControlHandler = (*Dispatcher)(nil)
var _ DispatcherDebugletHandler = (*Dispatcher)(nil)

func New(l *zap.Logger) *Dispatcher {
	return &Dispatcher{
		executors:      make(map[string]*RegisteredExecutor),
		ipToExecutor:   make(map[string]string),
		keystore:       tag.NewKeyStore(),
		logger:         l,
		debugletStores: make(map[string]*debugletStore),
		connectedLogs:  make(map[string][]logConn),
	}
}

func (d *Dispatcher) SetExecutorSender(s ExecutorServer) {
	d.sender = s
}

func (d *Dispatcher) GetKeyStore() *tag.KeyStore {
	return d.keystore
}

func (d *Dispatcher) RegisterLogConnection(debugletID string, channel chan<- []byte) (int, <-chan struct{}, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if _, exists := d.debugletStores[debugletID]; !exists {
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
	index := slices.IndexFunc(d.connectedLogs[debugletID], func(lc logConn) bool {
		return seq == lc.seq
	})
	if index == -1 {
		return
	}
	conn := d.connectedLogs[debugletID][index]
	close(conn.logs)
	d.connectedLogs[debugletID] = slices.Delete(d.connectedLogs[debugletID], index, index+1)
}
