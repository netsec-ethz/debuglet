package dispatcher

import (
	"debuglet/internal/dispatcher/tag"
	"sync"

	"go.uber.org/zap"
)

type Dispatcher struct {
	executors    map[string]*Executor
	mu           sync.RWMutex
	keystore     *tag.KeyStore
	sender       ExecutorSender
	ipToExecutor map[string]string
	logger       *zap.Logger
}

func New(l *zap.Logger) *Dispatcher {
	return &Dispatcher{
		executors:    make(map[string]*Executor),
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
