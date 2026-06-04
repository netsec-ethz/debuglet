package dispatcher

import (
	"debuglet/internal/dispatcher/tag"
	"sync"
)

type Dispatcher struct {
	executors    map[string]*Executor
	mu           sync.RWMutex
	keystore     *tag.KeyStore
	sender       ExecutorSender
	ipToExecutor map[string]string
}

func New() *Dispatcher {
	return &Dispatcher{
		executors: make(map[string]*Executor),
		keystore:  tag.NewKeyStore(),
	}
}

func (d *Dispatcher) SetExecutorSender(s ExecutorSender) {
	d.sender = s
}

func (d *Dispatcher) GetKeyStore() *tag.KeyStore {
	return d.keystore
}
