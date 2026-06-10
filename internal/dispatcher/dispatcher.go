package dispatcher

import (
	"debuglet/internal/dispatcher/tag"
	"sync"

	"go.uber.org/zap"
)

type Dispatcher struct {
	executors    map[string]*RegisteredExecutor
	ipToExecutor map[string]string
	mu           sync.RWMutex
	keystore     *tag.KeyStore
	sender       ExecutorSender
	logger       *zap.Logger
}

var _ DispatcherControlHandler = (*Dispatcher)(nil)
var _ DispatcherDebugletHandler = (*Dispatcher)(nil)

func New(l *zap.Logger) *Dispatcher {
	return &Dispatcher{
		executors:    make(map[string]*RegisteredExecutor),
		ipToExecutor: make(map[string]string),
		keystore:     tag.NewKeyStore(),
		logger:       l,
	}
}

func (d *Dispatcher) SetExecutorSender(s ExecutorSender) {
	d.sender = s
}

func (d *Dispatcher) GetKeyStore() *tag.KeyStore {
	return d.keystore
}
