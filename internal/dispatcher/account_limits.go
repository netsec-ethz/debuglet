// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package dispatcher

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/config"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/database"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/models"
	"github.com/netsec-ethz/debuglet/internal/uploadsize"
	"golang.org/x/time/rate"
)

var ErrAccountQuota = errors.New("account admission quota exceeded")

// AccountQuotaError identifies a finite admission limit. RetryAfter is supplied
// only for the replenishing request budget; work capacity requires retirement,
// so a clock-based promise would be misleading.
type AccountQuotaError struct {
	Resource   string
	RetryAfter time.Duration
}

func (e *AccountQuotaError) Error() string        { return "account " + e.Resource + " quota exceeded" }
func (e *AccountQuotaError) Is(target error) bool { return target == ErrAccountQuota }

type accountRate struct {
	limiter *rate.Limiter
	last    time.Time
}

type accountAdmission struct {
	config config.AdmissionConfig
	mu     sync.Mutex
	rates  map[int64]*accountRate
}

func newAccountAdmission() *accountAdmission {
	return &accountAdmission{config: config.DefaultAdmissionConfig(), rates: make(map[int64]*accountRate)}
}

// ConfigureDataLimits is called before startup, as ConfigureOutputLimits is.
func (d *Dispatcher) ConfigureDataLimits(admission config.AdmissionConfig, retention config.RetentionConfig) error {
	if err := admission.Validate(); err != nil {
		return err
	}
	if err := retention.Validate(); err != nil {
		return err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed || d.restored || len(d.executors) != 0 || len(d.registrations) != 0 {
		return errors.New("data limits must be configured before dispatcher startup")
	}
	d.admission.config = admission
	d.retention = retention
	return nil
}

func (d *Dispatcher) accountLimits(ctx context.Context, q *database.Queries, owner *uuid.UUID) (int64, config.AccountLimits, error) {
	if owner == nil {
		return 0, d.admission.config.Operator, nil
	}
	user, err := q.GetUserByUUID(ctx, *owner)
	if err != nil {
		return 0, config.AccountLimits{}, err
	}
	limits := d.admission.config.Account
	if user.Role == "operator" {
		limits = d.admission.config.Operator
	}
	return user.ID, limits, nil
}

// AllowAdmissionRequest uses the authenticated account, never a request body or
// address. Only intent/submission routes call it; cancellation, reads, logout and
// executor control remain available at exhaustion. Restart replenishes this
// short-lived token bucket, but never the durable accepted-work reservations.
func (d *Dispatcher) AllowAdmissionRequest(ctx context.Context, owner *uuid.UUID) error {
	accountID, limits, err := d.accountLimits(ctx, database.New(d.db), owner)
	if err != nil {
		return err
	}
	now := d.now()
	d.admission.mu.Lock()
	defer d.admission.mu.Unlock()
	r := d.admission.rates[accountID]
	if r == nil {
		// Idle entries have fully replenished before removal. A bounded map
		// cannot be enlarged by creating an unlimited number of accounts.
		if len(d.admission.rates) >= 4096 {
			for id, old := range d.admission.rates {
				if now.Sub(old.last) >= 2*time.Minute {
					delete(d.admission.rates, id)
				}
			}
			if len(d.admission.rates) >= 4096 {
				return &AccountQuotaError{Resource: "request", RetryAfter: time.Minute}
			}
		}
		r = &accountRate{limiter: rate.NewLimiter(rate.Limit(limits.RequestsPerMinute)/60, limits.RequestsPerMinute)}
		d.admission.rates[accountID] = r
	}
	r.last = now
	r.limiter.SetLimitAt(now, rate.Limit(limits.RequestsPerMinute)/60)
	r.limiter.SetBurstAt(now, limits.RequestsPerMinute)
	if !r.limiter.AllowN(now, 1) {
		return &AccountQuotaError{Resource: "request", RetryAfter: time.Duration(float64(time.Second)*60/float64(limits.RequestsPerMinute)) + time.Second}
	}
	return nil
}

// validateSubmissionSize precedes SQL writes, even for direct application
// callers. HTTP checks the encoded module and batch before decoding it too.
func validateSubmissionSize(specs []models.DebugletSpec) (int64, error) {
	if len(specs) > uploadsize.MaxBatchRuns {
		return 0, fmt.Errorf("%w: batch exceeds %d runs", uploadsize.ErrLimit, uploadsize.MaxBatchRuns)
	}
	var bytes int64
	for _, spec := range specs {
		charge, err := uploadsize.StoredBytes(spec.Wasm, spec.Args, spec.Policy.Addresses, spec.TransactionID)
		if err != nil {
			return 0, err
		}
		bytes += charge + 256 // Per-run output metadata; module bytes make this conservative for dispatcher provenance.
	}
	return bytes, nil
}

// reserveAccountRuns runs in the existing admission transaction, after all run
// rows exist and before commit. Any refusal rolls back those rows and their
// order claims together. The earlier admitted-order lookup handles retries.
func (d *Dispatcher) reserveAccountRuns(ctx context.Context, q *database.Queries, ids uuid.UUIDs, specs []models.DebugletSpec, owner *uuid.UUID) error {
	accountID, limits, err := d.accountLimits(ctx, q, owner)
	if err != nil {
		return err
	}
	existing, err := q.ListAccountReservations(ctx, accountID)
	if err != nil {
		return err
	}
	if int64(len(existing)) > limits.QueuedJobs-int64(len(ids)) {
		return &AccountQuotaError{Resource: "queued jobs"}
	}
	type window struct{ from, to time.Time }
	windows := make([]window, 0, len(existing)+len(ids))
	var bytes int64
	for _, row := range existing {
		if row.QueuedBytes > limits.QueuedBytes-bytes {
			return &AccountQuotaError{Resource: "queued bytes"}
		}
		bytes += row.QueuedBytes
		windows = append(windows, window{row.StartTime.Time, row.EndTime.Time})
	}
	charges := make([]int64, len(ids))
	rows := make([]database.Debuglet, len(ids))
	for i, id := range ids {
		rows[i], err = q.GetDebugletByUUID(ctx, id)
		if err != nil {
			return err
		}
		spec := specs[i]
		charges[i], err = uploadsize.StoredBytes(spec.Wasm, spec.Args, spec.Policy.Addresses, spec.TransactionID, rows[i].DispatcherIncarnation, rows[i].SessionID)
		if err != nil {
			return err
		}
		if charges[i] > limits.QueuedBytes-bytes {
			return &AccountQuotaError{Resource: "queued bytes"}
		}
		bytes += charges[i]
		windows = append(windows, window{rows[i].StartTime.Time, rows[i].EndTime.Time})
	}
	// Use the windows already admitted by the scheduler. An ended window
	// without confirmed retirement consumes one slot at every later time.
	// A timer therefore cannot reclaim work of uncertain remote disposition.
	type event struct {
		at     time.Time
		change int64
	}
	events := make([]event, 0, len(windows)*2)
	now, active := d.now(), int64(0)
	for _, w := range windows {
		if !w.to.After(now) {
			active++
			continue
		}
		if w.from.Before(now) {
			w.from = now
		}
		events = append(events, event{w.from, 1}, event{w.to, -1})
	}
	sort.Slice(events, func(i, j int) bool {
		if events[i].at.Equal(events[j].at) {
			return events[i].change > events[j].change
		}
		return events[i].at.Before(events[j].at)
	})
	if active > limits.ActiveJobs {
		return &AccountQuotaError{Resource: "reserved active jobs"}
	}
	for _, e := range events {
		active += e.change
		if active > limits.ActiveJobs {
			return &AccountQuotaError{Resource: "reserved active jobs"}
		}
	}
	for i, row := range rows {
		if err := q.ReserveAccountRun(ctx, database.ReserveAccountRunParams{DebugletID: row.ID, AccountID: accountID, QueuedBytes: charges[i]}); err != nil {
			return err
		}
	}
	return nil
}
