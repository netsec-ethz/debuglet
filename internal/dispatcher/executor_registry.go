package dispatcher

import (
	"fmt"
	"sync"
	"time"

	"go.uber.org/zap"
)

type debugletHistory struct {
	mu  sync.RWMutex
	ids []string
}

// RegisteredExecutor represents a registered executor and its metadata.
type RegisteredExecutor struct {
	ID       string
	Ready    bool
	LastSeen time.Time

	TeslaDelay           time.Duration
	TeslaAnchorTimestamp time.Time
	TeslaAnchorKey       []byte // k_0, the public chain anchor

	// debugletIDs is a ring buffer of the last lastDebugletHistory
	// debuglet IDs that were dispatched to this executor.
	history *debugletHistory
	PricePerBw float64
}

// lastDebugletHistory is the default number of recent debuglet IDs to
// retain per executor. The caller can override it via HTTP query parameters.
const lastDebugletHistory = 10

// RecentDebugletIDs returns up to n recent debuglet IDs for this
// executor, newest first. If n ≤ 0 the default (lastDebugletHistory) is
// used.
func (e *RegisteredExecutor) RecentDebugletIDs(n int) []string {
	if n <= 0 {
		n = lastDebugletHistory
	}
	if e.history == nil {
		panic("history not initialized")
	}
	e.history.mu.RLock()
	defer e.history.mu.RUnlock()

	if len(e.history.ids) == 0 {
		return []string{}
	}
	start := 0
	if len(e.history.ids) > n {
		start = len(e.history.ids) - n
	}
	// Return a copy, newest first.
	slice := e.history.ids[start:]
	out := make([]string, len(slice))
	for i, v := range slice {
		out[len(slice)-1-i] = v
	}
	return out
}

// AppendDebugletID adds id to the executor's history, trimming old entries
// so the total length stays within 2× the maximum to bound memory usage.
func (e *RegisteredExecutor) AppendDebugletID(id string) {
	if e.history == nil {
		panic("history not initialized")
	}
	e.history.mu.Lock()
	defer e.history.mu.Unlock()

	e.history.ids = append(e.history.ids, id)
	// Keep at most 2× the default to avoid unbounded growth.
	if trim := 2 * lastDebugletHistory; len(e.history.ids) > trim {
		e.history.ids = e.history.ids[len(e.history.ids)-trim:]
	}
}

// RegisterExecutor creates or updates the executor record for id. anchorKey is
// k_0, the public TESLA chain anchor published by the executor at startup.
func (d *Dispatcher) RegisterExecutor(id string, ip string, teslaDelay time.Duration, teslaAnchor time.Time, anchorKey []byte, price float64) {
	d.logger.Info("Registering executor", zap.String("id", id), zap.String("ip", ip))
	d.mu.Lock()
	defer d.mu.Unlock()
	if _, exists := d.executors[id]; !exists {
		d.executors[id] = &RegisteredExecutor{
			ID:                   id,
			TeslaDelay:           teslaDelay,
			TeslaAnchorTimestamp: teslaAnchor,
			TeslaAnchorKey:       anchorKey,
			history:              &debugletHistory{},
			PricePerBw:		  price,
		}
	} else {
		d.logger.Debug("Executor is already registered", zap.String("id", id))
	}
	exec := d.executors[id]
	exec.TeslaDelay = teslaDelay
	exec.TeslaAnchorTimestamp = teslaAnchor
	if len(anchorKey) > 0 {
		exec.TeslaAnchorKey = anchorKey
	}
	if ip != "" {
		d.ipToExecutor[ip] = id
	}
}

// GetExecutorByIPFull returns the full Executor record for the given source IP,
// or nil if no executor is registered with that IP.
func (d *Dispatcher) GetExecutorByIPFull(ip string) (RegisteredExecutor, bool) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	id, ok := d.ipToExecutor[ip]
	if !ok {
		return RegisteredExecutor{}, false
	}
	return *d.executors[id], true
}

func (d *Dispatcher) RemoveExecutor(id string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	delete(d.executors, id)
}

func (d *Dispatcher) SetExecutor(id string, lastSeenNs int64) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	exec, exists := d.executors[id]
	if !exists {
		return fmt.Errorf("executor %s not found", id)
	}
	exec.Ready = true
	exec.LastSeen = time.Unix(0, lastSeenNs)
	return nil
}

func (d *Dispatcher) ListExecutors() []RegisteredExecutor {
	d.mu.RLock()
	defer d.mu.RUnlock()
	var executors []RegisteredExecutor
	for _, e := range d.executors {
		executors = append(executors, *e)
	}
	return executors
}

func (d *Dispatcher) GetExecutor(ID string) (RegisteredExecutor, bool) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	e, exists := d.executors[ID]
	return *e, exists
}
