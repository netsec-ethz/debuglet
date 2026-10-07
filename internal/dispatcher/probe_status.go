// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package dispatcher

import (
	"context"
	"database/sql"
	"errors"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/netsec-ethz/debuglet/internal/dispatcher/database"
	"github.com/netsec-ethz/debuglet/internal/ipmetadata"
	"github.com/netsec-ethz/debuglet/pkg/wire"
	pb "github.com/netsec-ethz/debuglet/protocol"
	"go.uber.org/zap"
)

const (
	// probeFlushInterval spaces the maintenance pass that advances the
	// connected executors' last_connected, uptime and address history, and
	// closes the records of executors that are gone.
	probeFlushInterval = time.Minute
	probeFlushTimeout  = 5 * time.Second
	// probeStreakGrace is how close to its last record a registration must be
	// to continue a connected streak: a replacement session or a dispatcher
	// restart. It is the 120 seconds of RecordProbeConnected.
	probeStreakGrace = 2 * probeFlushInterval
	// probePruneInterval and probeAddressRetention bound the address history;
	// every family's latest run is kept whatever its age.
	probePruneInterval    = time.Hour
	probeAddressRetention = 91 * 24 * time.Hour
	// probeObservationFresh is how recent a reflection must be to count as
	// working: two missed 10-minute observation rounds and some slack.
	probeObservationFresh = 25 * time.Minute
)

// probeFromHello reads the registration-time settings of the vantage report:
// the address opt-out and the host tags. A malformed tag list is dropped.
func probeFromHello(report *pb.VantagePointReport, at time.Time) probeAddresses {
	out := probeAddresses{optOut: report.GetAddressOptOut(), hostTags: []string{}, registeredAt: at}
	if tags, err := wire.CanonicalHostTags(report.GetHostTags()); err == nil {
		out.hostTags = tags
	}
	return out
}

// addressCheck is a validated AddressSelfCheck. It is part of the vantage
// report, so it expires with it.
type addressCheck struct {
	ipv4LocalPrivate *bool
	resolvesA        bool
	resolvesAAAA     bool
}

func addressCheckFromReport(report *pb.AddressSelfCheck) *addressCheck {
	if report == nil {
		return nil
	}
	out := &addressCheck{resolvesA: report.GetResolvesA(), resolvesAAAA: report.GetResolvesAaaa()}
	if report.Ipv4LocalPrivate != nil {
		private := report.GetIpv4LocalPrivate()
		out.ipv4LocalPrivate = &private
	}
	return out
}

// recordProbeConnected records a registration. A failure is logged and does
// not refuse the executor: status history is listing metadata.
func (d *Dispatcher) recordProbeConnected(executorID string) {
	if d.db == nil {
		return
	}
	d.mu.RLock()
	entry := d.executors[executorID]
	if d.closed || entry == nil {
		d.mu.RUnlock()
		return
	}
	snapshot := snapshotLocked(entry, d.now())
	d.mu.RUnlock()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err := sqlTx(ctx, d.db, func(q *database.Queries) error {
		if err := recordConnected(ctx, q, &snapshot); err != nil {
			return err
		}
		return recordSightings(ctx, q, executorID, snapshot.sightings())
	})
	if err != nil {
		d.logger.Warn("Failed to record executor status", zap.String("executor_id", executorID), zap.Error(err))
	}
}

func recordConnected(ctx context.Context, q *database.Queries, e *RegisteredExecutor) error {
	public := int64(1)
	if e.probe.optOut {
		public = 0
	}
	return q.RecordProbeConnected(ctx, database.RecordProbeConnectedParams{ExecutorID: e.ID, Now: e.LastSeen.Unix(),
		IsPublic: public, HostTags: strings.Join(e.probe.hostTags, ","), Version: e.Version})
}

func recordSightings(ctx context.Context, q *database.Queries, executorID string, sightings [2]addressSighting) error {
	for i, sighting := range sightings {
		if sighting.address == "" {
			continue
		}
		family := int64(4)
		if i == 1 {
			family = 6
		}
		extended, err := q.ExtendProbeAddress(ctx, database.ExtendProbeAddressParams{At: sighting.at.Unix(), ExecutorID: executorID, Family: family, Address: sighting.address})
		if err != nil {
			return err
		}
		if extended == 0 {
			if _, err := q.StartProbeAddress(ctx, database.StartProbeAddressParams{ExecutorID: executorID, Family: family, Address: sighting.address, Via: sighting.via, At: sighting.at.Unix()}); err != nil {
				return err
			}
		}
	}
	return nil
}

// flushProbeStatusDue runs on the maintenance goroutine. Every
// probeFlushInterval it advances the connected executors' records and closes
// those of executors no longer registered at their last record, which also
// closes the records a stopped dispatcher left connected.
func (d *Dispatcher) flushProbeStatusDue() {
	now := d.now()
	if d.db == nil || !d.probeFlushedAt.IsZero() && now.Sub(d.probeFlushedAt) < probeFlushInterval {
		return
	}
	d.probeFlushedAt = now
	d.mu.RLock()
	live := map[string]RegisteredExecutor{}
	for id, entry := range d.executors {
		if !d.closed && entry.owner.Available() {
			live[id] = snapshotLocked(entry, now)
		}
	}
	d.mu.RUnlock()
	// The pass shares the loop that expires leases, so it is kept short.
	ctx, cancel := context.WithTimeout(context.Background(), probeFlushTimeout)
	defer cancel()
	err := sqlTx(ctx, d.db, func(q *database.Queries) error {
		connected, err := q.ListConnectedProbeIDs(ctx)
		if err != nil {
			return err
		}
		for _, id := range connected {
			if _, ok := live[id]; !ok {
				if _, err := q.RecordProbeDisconnected(ctx, id); err != nil {
					return err
				}
			}
		}
		for id, e := range live {
			touched, err := q.TouchProbeConnected(ctx, database.TouchProbeConnectedParams{Now: e.LastSeen.Unix(), ExecutorID: id})
			if err != nil {
				return err
			}
			// Missing, or closed while the executor stayed registered, as
			// when its registration record failed: record it now.
			if touched == 0 {
				if err := recordConnected(ctx, q, &e); err != nil {
					return err
				}
			}
			if err := recordSightings(ctx, q, id, e.sightings()); err != nil {
				return err
			}
		}
		if d.probePrunedAt.IsZero() || now.Sub(d.probePrunedAt) >= probePruneInterval {
			if _, err := q.PruneProbeAddresses(ctx, now.Add(-probeAddressRetention).Unix()); err != nil {
				return err
			}
			d.probePrunedAt = now
		}
		return nil
	})
	if err != nil {
		d.logger.Warn("Failed to record executor status", zap.Error(err))
	}
}

func sqlTx(ctx context.Context, db *sql.DB, fn func(*database.Queries) error) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	if err := fn(database.New(tx)); err != nil {
		return errors.Join(err, tx.Rollback())
	}
	return tx.Commit()
}

// ProbeBook is one read of the durable status history, for one listing.
type ProbeBook struct {
	now       time.Time
	status    map[string]database.ProbeStatus
	addresses map[string][2]*database.ProbeAddress
	enrolled  []string
	databases *ipmetadata.Databases
}

// LiveProbeBook is a book without the history: every listed executor is
// connected since its registration and nothing else is known.
func (d *Dispatcher) LiveProbeBook() *ProbeBook {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return &ProbeBook{now: d.now(), status: map[string]database.ProbeStatus{}, addresses: map[string][2]*database.ProbeAddress{}, databases: d.ipMetadata}
}

// ProbeBook reads the status history. Without a database every listed
// executor is connected since its registration and nothing else is known.
func (d *Dispatcher) ProbeBook(ctx context.Context) (*ProbeBook, error) {
	book := d.LiveProbeBook()
	if d.db == nil {
		return book, nil
	}
	q := database.New(d.db)
	rows, err := q.ListProbeStatus(ctx)
	if err != nil {
		return nil, err
	}
	for _, row := range rows {
		book.status[row.ExecutorID] = row
	}
	runs, err := q.ListLatestProbeAddresses(ctx)
	if err != nil {
		return nil, err
	}
	for i := range runs {
		run := &runs[i]
		latest := book.addresses[run.ExecutorID]
		latest[familyOf(run.Family)] = run
		book.addresses[run.ExecutorID] = latest
	}
	if book.enrolled, err = q.ListEnrolledExecutorIDs(ctx); err != nil {
		return nil, err
	}
	return book, nil
}

func familyOf(family int64) int {
	if family == 6 {
		return 1
	}
	return 0
}

func unix(t time.Time) *int64 {
	value := t.Unix()
	return &value
}

// Live is the status and tags of a registered executor.
func (b *ProbeBook) Live(e *RegisteredExecutor) wire.ProbeStatus {
	since, first, uptime := e.probe.registeredAt, e.probe.registeredAt, int64(0)
	if row, ok := b.status[e.ID]; ok {
		first = time.Unix(row.FirstConnected, 0)
		if row.Connected == 1 {
			since = time.Unix(row.StatusSince, 0)
			uptime = row.TotalUptime + max(0, e.LastSeen.Unix()-row.LastConnected)
		} else {
			uptime = row.TotalUptime
		}
	}
	if since.After(e.LastSeen) || since.IsZero() {
		since = e.LastSeen
	}
	if first.After(since) || first.IsZero() {
		first = since
	}
	tags := append(append([]string{}, e.probe.hostTags...), b.systemTags(e)...)
	return wire.ProbeStatus{Status: &wire.ProbeStatusName{Name: wire.ProbeConnected, Since: unix(since)}, StatusSince: unix(since),
		FirstConnected: unix(first), LastConnected: unix(e.LastSeen), TotalUptime: &uptime, Tags: tags}
}

// systemTags derives the system tags of a registered executor from its live
// observations and its address history.
func (b *ProbeBook) systemTags(e *RegisteredExecutor) []string {
	tags := []string{}
	sightings := e.sightings()
	connectivity := e.Connectivity(true)
	for i, family := range []struct {
		works, capable string
		stable         [3]string
		measured       func(*wire.Connectivity) wire.Reachability
	}{
		{wire.TagIPv4Works, wire.TagIPv4Capable, [3]string{wire.TagIPv4Stable1d, wire.TagIPv4Stable30d, wire.TagIPv4Stable90d}, func(c *wire.Connectivity) wire.Reachability { return c.IPv4 }},
		{wire.TagIPv6Works, wire.TagIPv6Capable, [3]string{wire.TagIPv6Stable1d, wire.TagIPv6Stable30d, wire.TagIPv6Stable90d}, func(c *wire.Connectivity) wire.Reachability { return c.IPv6 }},
	} {
		sighting := sightings[i]
		measured := connectivity != nil && family.measured(connectivity).FreshReachable(b.now)
		fresh := sighting.address != "" && (sighting.via == wire.AddressViaControl || b.now.Sub(sighting.at) <= probeObservationFresh)
		if measured || fresh {
			tags = append(tags, family.works)
		}
		if measured || sighting.address != "" {
			tags = append(tags, family.capable)
		}
		if run := b.addresses[e.ID][i]; run != nil && sighting.address != "" && run.Address == sighting.address {
			for n, days := range []int{1, 30, 90} {
				if b.now.Sub(time.Unix(run.FirstObserved, 0)) >= time.Duration(days)*24*time.Hour {
					tags = append(tags, family.stable[n])
				}
			}
		}
	}
	if check := e.addressCheckValue(); check != nil {
		if v4, err := netip.ParseAddr(sightings[0].address); err == nil && check.ipv4LocalPrivate != nil && *check.ipv4LocalPrivate && ipmetadata.Global(v4) {
			tags = append(tags, wire.TagIPv4RFC1918)
		}
		if check.resolvesA {
			tags = append(tags, wire.TagResolvesA)
		}
		if check.resolvesAAAA {
			tags = append(tags, wire.TagResolvesAAAA)
		}
	}
	return tags
}

func (e *RegisteredExecutor) addressCheckValue() *addressCheck {
	if e.vantage == nil {
		return nil
	}
	return e.vantage.addressCheck
}

// Offline lists the known executors that are not registered and whose status
// is in statuses, sorted by ID. live names the registered ones; display is the
// operator's metadata; private reveals a private executor's addresses.
func (b *ProbeBook) Offline(live map[string]bool, statuses []string, display func(string) wire.ExecutorDisplay, private bool) []wire.Executor {
	out := []wire.Executor{}
	seen := map[string]bool{}
	ids := []string{}
	for id := range b.status {
		ids = append(ids, id)
	}
	ids = append(ids, b.enrolled...)
	slices.Sort(ids)
	for _, id := range ids {
		if live[id] || seen[id] {
			continue
		}
		seen[id] = true
		entry := wire.Executor{ID: id, Admission: wire.AdmissionOffline, Display: display(id)}
		row, known := b.status[id]
		if !known {
			if !slices.Contains(statuses, wire.ProbeNeverConnected) {
				continue
			}
			public := true
			entry.ProbeAddressing = wire.ProbeAddressing{IsPublic: &public, AddressObservations: &wire.AddressObservations{}}
			entry.ProbeStatus = wire.ProbeStatus{Status: &wire.ProbeStatusName{Name: wire.ProbeNeverConnected}, Tags: []string{}}
			out = append(out, entry)
			continue
		}
		last := time.Unix(row.LastConnected, 0)
		name, since := wire.ProbeDisconnected, last
		if b.now.Sub(last) > wire.AbandonedAfter {
			name, since = wire.ProbeAbandoned, last.Add(wire.AbandonedAfter)
		}
		if !slices.Contains(statuses, name) {
			continue
		}
		entry.Version, entry.LastSeen = row.Version, row.LastConnected
		tags := []string{}
		if row.HostTags != "" {
			if canonical, err := wire.CanonicalHostTags(strings.Split(row.HostTags, ",")); err == nil {
				tags = canonical
			}
		}
		first, uptime := row.FirstConnected, row.TotalUptime
		entry.ProbeStatus = wire.ProbeStatus{Status: &wire.ProbeStatusName{Name: name, Since: unix(since)}, StatusSince: unix(since),
			FirstConnected: &first, LastConnected: &row.LastConnected, TotalUptime: &uptime, Tags: tags}
		entry.ProbeAddressing = b.lastAddressing(id, row.IsPublic == 1, private)
		out = append(out, entry)
	}
	return out
}

// lastAddressing is the addressing of an unregistered executor: the latest
// address run of each family, looked up again in the current database.
func (b *ProbeBook) lastAddressing(id string, public, private bool) wire.ProbeAddressing {
	var sightings [2]addressSighting
	for i, run := range b.addresses[id] {
		if run == nil {
			continue
		}
		at := time.Unix(run.LastObserved, 0)
		lookup := b.databases.Lookup(run.Address, wire.SourceDispatcherObserved, at.Unix(), true)
		sightings[i] = addressSighting{address: run.Address, via: run.Via, at: at, asn: lookup.ASN}
	}
	return addressing(sightings, public, private)
}
