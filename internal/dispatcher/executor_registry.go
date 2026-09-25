// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package dispatcher

import (
	"context"
	"errors"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/resource"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/transport/rpc"
	pb "github.com/netsec-ethz/debuglet/protocol"
	"sync"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

type debugletHistory struct {
	mu  sync.RWMutex
	ids []uuid.UUID
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
	SuiWallet   string
	capacity    resource.Bitrate

	sourceIp   string
	publicHost *string
}

// PublicHost returns the executor's public host (IP or domain) at which
// debuglet listeners can be contacted, or "" if none is configured.
func (e *RegisteredExecutor) PublicHost() string {
	if e.publicHost == nil {
		return ""
	}
	return *e.publicHost
}

// lastDebugletHistory is the default number of recent debuglet IDs to
// retain per executor. The caller can override it via HTTP query parameters.
const lastDebugletHistory = 10

// RecentDebugletIDs returns up to n recent debuglet IDs for this
// executor, newest first. If n ≤ 0 the default (lastDebugletHistory) is
// used.
func (e *RegisteredExecutor) RecentDebugletIDs(n int) []uuid.UUID {
	if n <= 0 {
		n = lastDebugletHistory
	}
	if e.history == nil {
		panic("history not initialized")
	}
	e.history.mu.RLock()
	defer e.history.mu.RUnlock()

	if len(e.history.ids) == 0 {
		return []uuid.UUID{}
	}
	start := 0
	if len(e.history.ids) > n {
		start = len(e.history.ids) - n
	}
	// Return a copy, newest first.
	slice := e.history.ids[start:]
	out := make([]uuid.UUID, len(slice))
	for i, v := range slice {
		out[len(slice)-1-i] = v
	}
	return out
}

// AppendDebugletID adds id to the executor's history, trimming old entries
// so the total length stays within 2× the maximum to bound memory usage.
func (e *RegisteredExecutor) AppendDebugletID(id uuid.UUID) {
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

// executorEntry is never returned to readers. The embedded record preserves
// internal history updates; every public getter returns a detached snapshot.
type executorEntry struct {
	*RegisteredExecutor
	owner *rpc.SessionOwner
}

type registrationOperation struct{ cancel context.CancelFunc }

var (
	ErrSessionRetired   = errors.New("executor session retired")
	ErrDispatcherClosed = errors.New("dispatcher closed")
)

// RegisterExecutor stages metadata for an already-published transport owner.
// ctx belongs to the setup mutation the transport admitted on that owner, so
// retirement cancels it and a replacement session waits for this call to return.
// Registration admits no mutation of its own.
func (d *Dispatcher) RegisterExecutor(ctx context.Context, owner *rpc.SessionOwner, hello *pb.HelloResponse, sourceIP string) error {
	if owner == nil || hello == nil || owner.ExecutorID() != hello.GetExecutorId() {
		return errors.New("executor registration identity mismatch")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	callCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	op := &registrationOperation{cancel: cancel}
	d.mu.Lock()
	if d.closed {
		d.mu.Unlock()
		cancel()
		return ErrDispatcherClosed
	}
	if err := callCtx.Err(); err != nil {
		d.mu.Unlock()
		cancel()
		return err
	}
	if !owner.Active() {
		d.mu.Unlock()
		cancel()
		return ErrSessionRetired
	}
	d.registrations[op] = struct{}{}
	d.registrationWG.Add(1)
	d.mu.Unlock()

	// Close cancels outside the owner/map locks, and joins this registration
	// through registrationWG once every effect below has returned.
	defer func() {
		cancel()
		d.mu.Lock()
		delete(d.registrations, op)
		d.mu.Unlock()
		d.registrationWG.Done()
	}()
	if err := callCtx.Err(); err != nil {
		return err
	}
	if sourceIP == "" {
		sourceIP = hello.GetSourceIp()
	}
	record := &RegisteredExecutor{
		ID: owner.ExecutorID(), Version: hello.GetVersion(),
		TeslaDelay:           time.Duration(hello.GetTeslaDelaySec()) * time.Second,
		TeslaAnchorTimestamp: time.Unix(0, hello.GetTeslaAnchorTimestampNs()),
		TeslaAnchorKey:       append([]byte(nil), hello.GetTeslaAnchorKey()...),
		ICMPEnabled:          hello.GetIcmpEnabled(), PricePerBwS: hello.GetPricePerBwS(),
		Currency: hello.GetCurrency(), SuiWallet: hello.GetSuiWallet(),
		sourceIp: sourceIP, history: &debugletHistory{},
	}
	if host := hello.GetPublicHost(); host != "" {
		record.publicHost = &host
	}
	d.initializeEarnings(callCtx, record)
	record.LastSeen = d.now()
	d.mu.Lock()
	if d.closed {
		d.mu.Unlock()
		return ErrDispatcherClosed
	}
	old := d.executors[record.ID]
	if old != nil {
		record.history = cloneHistory(old.history)
	}
	var commitErr error
	var startExpiry chan struct{}
	committed := owner.CommitActive(func() {
		if err := callCtx.Err(); err != nil {
			commitErr = err
			return
		}
		d.executors[record.ID] = &executorEntry{RegisteredExecutor: record, owner: owner}
		if d.expiryDone == nil {
			d.expiryDone = make(chan struct{})
			startExpiry = d.expiryDone
		}
	})
	d.mu.Unlock()
	if !committed {
		return ErrSessionRetired
	}
	if commitErr != nil {
		return commitErr
	}
	if old != nil && old.owner != owner {
		d.logger.Info("Executor control session ended", zap.String("executor_id", record.ID), zap.String("session_id", old.owner.Binding().SessionID), zap.String("reason", "replaced"))
	}
	if startExpiry != nil {
		go d.runExpiry(startExpiry)
	}
	return nil
}

func cloneHistory(history *debugletHistory) *debugletHistory {
	out := &debugletHistory{}
	if history != nil {
		history.mu.RLock()
		out.ids = append([]uuid.UUID(nil), history.ids...)
		history.mu.RUnlock()
	}
	return out
}

// snapshotLocked copies data only; no used mutex or live history is copied.
func snapshotLocked(entry *executorEntry) RegisteredExecutor {
	out := *entry.RegisteredExecutor
	out.TeslaAnchorKey = append([]byte(nil), out.TeslaAnchorKey...)
	out.history = cloneHistory(entry.history)
	if entry.publicHost != nil {
		host := *entry.publicHost
		out.publicHost = &host
	}
	return out
}

// GetExecutorByIPFull selects the latest local observation, with a stable ID
// tie-break, and returns metadata independent of subsequent registry changes.
func (d *Dispatcher) GetExecutorByIPFull(ip string) (RegisteredExecutor, bool) {
	if ip == "" {
		return RegisteredExecutor{}, false
	}
	d.mu.RLock()
	defer d.mu.RUnlock()
	if d.closed {
		return RegisteredExecutor{}, false
	}
	var best *executorEntry
	for _, entry := range d.executors {
		if entry.sourceIp != ip || !entry.owner.Available() {
			continue
		}
		if best == nil || entry.LastSeen.After(best.LastSeen) || (entry.LastSeen.Equal(best.LastSeen) && entry.ID < best.ID) {
			best = entry
		}
	}
	if best == nil {
		return RegisteredExecutor{}, false
	}
	return snapshotLocked(best), true
}

func (d *Dispatcher) ListExecutors() []RegisteredExecutor {
	d.mu.RLock()
	defer d.mu.RUnlock()
	var out []RegisteredExecutor
	if d.closed {
		return out
	}
	for _, entry := range d.executors {
		if entry.owner.Available() {
			out = append(out, snapshotLocked(entry))
		}
	}
	return out
}

// ExecutorEligibility counts the registry and the subset of it that may be
// given work now, which is the entries whose owner is available. It copies no
// record and reads no database.
func (d *Dispatcher) ExecutorEligibility() (eligible, registered int) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	if d.closed {
		return 0, 0
	}
	for _, entry := range d.executors {
		registered++
		if entry.owner.Available() {
			eligible++
		}
	}
	return eligible, registered
}

func (d *Dispatcher) GetExecutor(id string) (*RegisteredExecutor, bool) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	entry, exists := d.executors[id]
	if d.closed || !exists || !entry.owner.Available() {
		return nil, false
	}
	out := snapshotLocked(entry)
	return &out, true
}

type expiryTicker interface {
	C() <-chan time.Time
	Stop()
}
type realExpiryTicker struct{ *time.Ticker }

func (t realExpiryTicker) C() <-chan time.Time { return t.Ticker.C }

func (d *Dispatcher) runExpiry(done chan struct{}) {
	defer close(done)
	ticker := d.newExpiryTicker(d.leaseTiming.WatchdogInterval)
	defer ticker.Stop()
	for {
		select {
		case <-d.expiryStop:
			return
		case <-ticker.C():
			for _, owner := range d.expiryCandidates() {
				d.expireOwner(owner)
			}
		}
	}
}

func (d *Dispatcher) expiryCandidates() []*rpc.SessionOwner {
	d.mu.RLock()
	defer d.mu.RUnlock()
	if d.closed {
		return nil
	}
	owners := make([]*rpc.SessionOwner, 0, len(d.executors))
	for _, entry := range d.executors {
		owners = append(owners, entry.owner)
	}
	return owners
}

// expireOwner retires an owner whose lease has run out, and only while it is
// still the registry's entry for its ID; a heartbeat never renews a lease. The
// transport removal that follows runs outside the registry lock.
func (d *Dispatcher) expireOwner(owner *rpc.SessionOwner) bool {
	if owner == nil {
		return false
	}
	d.mu.Lock()
	entry := d.executors[owner.ExecutorID()]
	if d.closed || entry == nil || entry.owner != owner || !owner.ExpireLease() {
		d.mu.Unlock()
		return false
	}
	delete(d.executors, owner.ExecutorID())
	d.mu.Unlock()
	d.logger.Info("Executor control session ended", zap.String("executor_id", owner.ExecutorID()), zap.String("session_id", owner.Binding().SessionID), zap.String("reason", "lease expired"))
	d.Bidi.RemoveClient(owner)
	return true
}
