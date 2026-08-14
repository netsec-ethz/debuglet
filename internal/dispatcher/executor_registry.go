package dispatcher

import (
	"debuglet/internal/dispatcher/resource"
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
	Version  string
	Ready    bool
	LastSeen time.Time

	TeslaDelay           time.Duration
	TeslaAnchorTimestamp time.Time
	TeslaAnchorKey       []byte // k_0, the public chain anchor

	ICMPEnabled bool

	// history is a ring buffer of the last lastDebugletHistory
	// debuglet IDs that were dispatched to this executor.
	history *debugletHistory

	PricePerBwS int64
	Currency    string
	capacity    resource.Bitrate

	sourceIp   string
	publicHost *string
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
func (d *Dispatcher) RegisterExecutor(id, version, sourceIp, publicHost string, teslaDelay time.Duration, teslaAnchor time.Time, anchorKey []byte, icmpEnabled bool, price int64, currency string) {
	d.logger.Info("Registering executor", zap.String("id", id), zap.String("source_ip", sourceIp), zap.Int64("price", price), zap.String("currency", currency))
	d.mu.Lock()
	defer d.mu.Unlock()
	exec, exists := d.executors[id]
	if !exists {
		d.executors[id] = &RegisteredExecutor{
			ID:      id,
			history: &debugletHistory{},
		}
		exec = d.executors[id]
	} else {
		d.logger.Debug("Executor is already registered", zap.String("id", id))
	}

	exec.Version = version
	exec.TeslaDelay = teslaDelay
	exec.TeslaAnchorTimestamp = teslaAnchor
	if len(anchorKey) > 0 {
		exec.TeslaAnchorKey = anchorKey
	}
	exec.LastSeen = time.Now()
	exec.ICMPEnabled = icmpEnabled
	exec.PricePerBwS = price
	exec.Currency = currency
	exec.sourceIp = sourceIp
	if publicHost != "" {
		exec.publicHost = &publicHost
	} else {
		exec.publicHost = nil
	}
}

// GetExecutorByIPFull returns the full Executor record for the given source IP,
// or nil if no executor is registered with that IP.
func (d *Dispatcher) GetExecutorByIPFull(ip string) (RegisteredExecutor, bool) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	for _, exec := range d.executors {
		if exec.sourceIp == ip {
			return *exec, true
		}
	}
	return RegisteredExecutor{}, false
}

func (d *Dispatcher) RemoveExecutor(id string) {
	d.mu.Lock()
	delete(d.executors, id)
	d.mu.Unlock()
	d.Bidi.RemoveClient(id)
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

func (d *Dispatcher) GetExecutor(ID string) (*RegisteredExecutor, bool) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	e, exists := d.executors[ID]
	return e, exists
}
