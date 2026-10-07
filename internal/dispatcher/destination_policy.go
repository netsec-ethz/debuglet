// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package dispatcher

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/netsec-ethz/debuglet/internal/bitrate"
	"github.com/netsec-ethz/debuglet/internal/daemonlog"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/database"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/resource"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/transport/rpc"
	"github.com/netsec-ethz/debuglet/internal/executor/debuglet/netpolicy"
	pb "github.com/netsec-ethz/debuglet/protocol"
	"go.uber.org/zap"
)

// Kinds of destination policy events.
const (
	DestinationPolicyLimit = "limit"
	DestinationPolicyDeny  = "deny"
	DestinationPolicyAllow = "allow"
)

const (
	// SystemActor is recorded for changes the dispatcher makes itself, such
	// as restoring the default when a policy expires.
	SystemActor = "system"
	// MaxDestinationPolicyReason bounds the recorded reason, in bytes.
	MaxDestinationPolicyReason = 500
	// MaxDestinationLength bounds a destination a policy is recorded for.
	MaxDestinationLength = 255

	destinationPolicyBound = 5 * time.Second
	// bandwidthVersionDenial is the first executor bandwidth version that
	// applies DestinationLimit.denied, refusing new work and closing active
	// sockets, before it acknowledges a revision.
	bandwidthVersionDenial = 2
	expiredPolicyReason    = "expired"
)

var (
	// ErrInvalidDestinationPolicy refuses a change before anything is
	// recorded or applied.
	ErrInvalidDestinationPolicy = errors.New("invalid destination policy")
	errPolicySuperseded         = errors.New("destination policy was superseded")

	// ErrDestinationPolicyNotRecorded is a change whose event was not
	// committed; nothing of it was applied or sent, and the previous
	// policy stays authoritative.
	ErrDestinationPolicyNotRecorded = errors.New("destination policy was not recorded")
	// ErrDenialUnsupported is a recorded deny that an executor holding an
	// allocation acknowledged without being able to revoke its traffic.
	ErrDenialUnsupported = errors.New("executor upgrade required to revoke denied destinations")
)

// DestinationPolicyChange is the complete policy an operator sets for a
// destination. A denied destination admits nothing, so its limit is not
// recorded; lifting the deny sets the limit of that change. A zero ExpiresAt
// never expires.
type DestinationPolicyChange struct {
	Limit     bitrate.Bitrate
	Denied    bool
	Reason    string
	ExpiresAt time.Time
}

// DestinationPolicy is the current policy of a destination: its latest
// recorded event, and how far the latest application of it was delivered.
type DestinationPolicy struct {
	Destination string
	Kind        string
	// Limit is nil when the destination has the default capacity.
	Limit     *bitrate.Bitrate
	Reason    string
	Actor     string
	SetAt     time.Time
	ExpiresAt *time.Time
	Revision  int64
	// Recipients is the number of executors that held an allocation on the
	// destination when the policy was applied in this dispatcher lifetime,
	// and Unconfirmed the number of them that did not acknowledge it.
	Recipients  int
	Unconfirmed int
}

// destinationPolicies is the in-memory side of the recorded policies. It is
// guarded by Dispatcher.mu.
type destinationPolicies struct {
	expiry   map[string]policyExpiry
	delivery map[string]policyDelivery
}

type policyExpiry struct {
	at       time.Time
	revision int64
}

type policyDelivery struct {
	revision                int64
	recipients, unconfirmed int
}

// pendingPolicyEvent is an event that is about to be recorded.
type pendingPolicyEvent struct {
	kind      string
	limit     sql.NullInt64
	reason    string
	actor     string
	expiresAt time.Time
}

// SetDestinationLimit sets the limit of a destination, lifting a deny, as a
// change of the dispatcher itself. See SetDestinationPolicy.
func (d *Dispatcher) SetDestinationLimit(destination string, limit bitrate.Bitrate) error {
	return d.SetDestinationPolicy(context.Background(), SystemActor, destination, DestinationPolicyChange{Limit: limit})
}

// SetDestinationPolicy records change as the policy of destination, applies
// it to admission and sends the recomputed shares to every executor holding an
// allocation there, waiting up to five seconds for those deliveries.
//
// The event is recorded before anything is applied: a refused or failed write
// changes nothing. A limit below the floors already charged or reserved on the
// destination is refused with resource.ErrCapacityFull; a deny is never
// refused for floors, since it admits nothing new and the admitted runs keep
// their allocations until they end. Once recorded, the policy governs
// admission whether or not every executor acknowledged; the error joins the
// failed deliveries, and the delivery outcome is kept for
// ListDestinationPolicies.
func (d *Dispatcher) SetDestinationPolicy(ctx context.Context, actor, destination string, change DestinationPolicyChange) error {
	if strings.ContainsAny(destination, "\x00\r\n\t") {
		return ErrInvalidDestinationPolicy
	}
	destination = netpolicy.DestinationKey(destination)
	if destination == "" || strings.Contains(destination, "/") || len(destination) > MaxDestinationLength || actor == "" ||
		len(change.Reason) > MaxDestinationPolicyReason || !bitrate.InPolicyRange(int64(change.Limit)) {
		return ErrInvalidDestinationPolicy
	}
	if _, err := netpolicy.Parse(netpolicy.Spec{DeniedDestinations: destination}); err != nil {
		return ErrInvalidDestinationPolicy
	}
	if !change.ExpiresAt.IsZero() && !change.ExpiresAt.After(d.now()) {
		return fmt.Errorf("expiry is not in the future: %w", ErrInvalidDestinationPolicy)
	}
	event := pendingPolicyEvent{kind: DestinationPolicyLimit, limit: sql.NullInt64{Int64: int64(change.Limit), Valid: true},
		reason: change.Reason, actor: actor, expiresAt: change.ExpiresAt}
	if change.Denied {
		event.kind, event.limit = DestinationPolicyDeny, sql.NullInt64{}
	}
	return d.changeDestinationPolicy(ctx, destination, event, 0)
}

// changeDestinationPolicy records, applies and propagates one event. A
// nonzero expect records the event only while it is the revision after expect.
func (d *Dispatcher) changeDestinationPolicy(ctx context.Context, destination string, event pendingPolicyEvent, expect int64) error {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), destinationPolicyBound)
	defer cancel()
	var recorded database.DestinationPolicyEvent
	var holders int
	work, err := d.captureFairshareAfter(ctx, nil, []string{destination}, func() error {
		if event.kind == DestinationPolicyLimit {
			limit := bitrate.Bitrate(event.limit.Int64)
			// Runs admitted for a window still ahead hold their floors only in
			// the scheduler; a lower limit would fail them at their allocation.
			if reserved := d.scheduler.QueryMaxDest(destination, d.now(), maxReservableTime); limit < reserved {
				return fmt.Errorf("%s destination limit below its reserved floors (want %s, reserved %s): %w", destination, limit, reserved, resource.ErrCapacityFull)
			}
			if err := d.destinations.CheckLimit(destination, limit); err != nil {
				return err
			}
		}
		var err error
		if recorded, err = d.recordDestinationPolicy(ctx, destination, event, expect); err != nil {
			return err
		}
		d.applyDestinationPolicyLocked(recorded)
		for range d.destinations.Fairshare(destination) {
			holders++
		}
		d.policies.delivery[destination] = policyDelivery{revision: recorded.Revision, recipients: holders, unconfirmed: holders}
		return nil
	})
	if err != nil {
		return err
	}
	work.requireOrdered = true
	sendErr := work.send(ctx)

	d.mu.Lock()
	confirmed, cannotRevoke := 0, 0
	var stale []*rpc.SessionOwner
	for _, r := range work.recipients {
		entry := d.executors[r.owner.ExecutorID()]
		if entry == nil || entry.owner != r.owner {
			continue
		}
		if r.revision == 0 || entry.bandwidthPending || entry.bandwidthRevision < r.revision {
			if event.kind == DestinationPolicyDeny {
				stale = append(stale, r.owner)
			}
			continue
		}
		// An executor that predates denials applies the zero limit and
		// acknowledges, but keeps its runs' floors and connections.
		if event.kind == DestinationPolicyDeny && entry.bandwidthVersion < bandwidthVersionDenial {
			cannotRevoke++
			stale = append(stale, r.owner)
			continue
		}
		confirmed++
	}
	if current := d.policies.delivery[destination]; current.revision == recorded.Revision {
		d.policies.delivery[destination] = policyDelivery{revision: recorded.Revision, recipients: holders, unconfirmed: max(holders-confirmed, 0)}
	}
	d.mu.Unlock()
	// Retire only the captured sessions: a successor must never inherit an
	// old delivery failure. Retirement prevents healthy session probes from
	// renewing a lease while its destination policy remains unconfirmed.
	// Remote cleanup can still take the remainder of that existing lease.
	for _, owner := range stale {
		d.Bidi.RemoveClient(owner)
	}
	if cannotRevoke > 0 {
		sendErr = errors.Join(sendErr, ErrDenialUnsupported)
	}
	return sendErr
}

// recordDestinationPolicy appends the event with the next revision of the
// destination in a transaction of its own.
func (d *Dispatcher) recordDestinationPolicy(ctx context.Context, destination string, event pendingPolicyEvent, expect int64) (database.DestinationPolicyEvent, error) {
	var recorded database.DestinationPolicyEvent
	tx, err := d.db.BeginTx(ctx, nil)
	if err != nil {
		return recorded, fmt.Errorf("%w: %w", ErrDestinationPolicyNotRecorded, err)
	}
	defer tx.Rollback()
	queries := database.New(d.db).WithTx(tx)
	latest, err := queries.LatestDestinationPolicyRevision(ctx, destination)
	if err != nil {
		return recorded, fmt.Errorf("%w: %w", ErrDestinationPolicyNotRecorded, err)
	}
	if expect != 0 && latest != expect {
		return recorded, errPolicySuperseded
	}
	params := database.RecordDestinationPolicyParams{
		Destination: destination, Kind: event.kind, LimitBps: event.limit, Reason: event.reason,
		Actor: event.actor, RequestedAtNs: d.now().UnixNano(), Revision: latest + 1,
	}
	if !event.expiresAt.IsZero() {
		params.ExpiresAtNs = sql.NullInt64{Int64: event.expiresAt.UnixNano(), Valid: true}
	}
	if recorded, err = queries.RecordDestinationPolicy(ctx, params); err != nil {
		return recorded, fmt.Errorf("%w: %w", ErrDestinationPolicyNotRecorded, err)
	}
	if err := tx.Commit(); err != nil {
		return recorded, fmt.Errorf("%w: %w", ErrDestinationPolicyNotRecorded, err)
	}
	return recorded, nil
}

// applyDestinationPolicyLocked makes a recorded event the in-memory policy of
// its destination. The caller holds d.mu and has checked a limit against the
// charged floors, or is restoring with nothing charged yet.
func (d *Dispatcher) applyDestinationPolicyLocked(event database.DestinationPolicyEvent) {
	if d.policies.expiry == nil {
		d.policies.expiry = make(map[string]policyExpiry)
		d.policies.delivery = make(map[string]policyDelivery)
	}
	destination := event.Destination
	switch {
	case event.Kind == DestinationPolicyDeny:
		d.destinations.Deny(destination)
		d.destinations.ResetLimit(destination)
	case event.LimitBps.Valid:
		d.destinations.Allow(destination)
		if err := d.destinations.SetLimit(destination, bitrate.Bitrate(event.LimitBps.Int64)); err != nil {
			d.logger.Warn("Recorded destination limit is below the floors charged there; the previous limit stays until they end",
				zap.String("destination", destination), zap.Int64("revision", event.Revision))
		}
	default:
		d.destinations.Allow(destination)
		d.destinations.ResetLimit(destination)
	}
	if event.ExpiresAtNs.Valid {
		d.policies.expiry[destination] = policyExpiry{at: time.Unix(0, event.ExpiresAtNs.Int64), revision: event.Revision}
	} else {
		delete(d.policies.expiry, destination)
	}
}

// restoreDestinationPoliciesLocked applies the current policy of every
// destination when the dispatcher starts, before any executor can allocate.
// A policy whose expiry has passed is left to the expiry sweep, which records
// the return to the default.
func (d *Dispatcher) restoreDestinationPoliciesLocked(ctx context.Context) error {
	events, err := database.New(d.db).ListCurrentDestinationPolicies(ctx)
	if err != nil {
		return fmt.Errorf("failed to list destination policies: %w", err)
	}
	now := d.now()
	for _, event := range events {
		if event.ExpiresAtNs.Valid && !time.Unix(0, event.ExpiresAtNs.Int64).After(now) {
			d.applyDestinationPolicyLocked(database.DestinationPolicyEvent{Destination: event.Destination, Kind: DestinationPolicyAllow, Revision: event.Revision, ExpiresAtNs: event.ExpiresAtNs})
		} else {
			d.applyDestinationPolicyLocked(event)
		}
		d.policies.delivery[event.Destination] = policyDelivery{revision: event.Revision}
		if event.Kind != DestinationPolicyAllow {
			d.logger.Info("Restored destination policy", zap.String("destination", event.Destination), zap.String("kind", event.Kind), zap.Int64("revision", event.Revision))
		}
	}
	return nil
}

// expireDestinationPolicies restores the default of every destination whose
// current policy has expired, recording that as an event of the dispatcher.
// It runs on the expiry loop and reads only memory unless a policy is due.
func (d *Dispatcher) expireDestinationPolicies() {
	now := d.now()
	d.mu.RLock()
	due := map[string]int64{}
	if !d.closed {
		for destination, expiry := range d.policies.expiry {
			if !expiry.at.After(now) {
				due[destination] = expiry.revision
			}
		}
	}
	d.mu.RUnlock()
	for destination, revision := range due {
		event := pendingPolicyEvent{kind: DestinationPolicyAllow, reason: expiredPolicyReason, actor: SystemActor}
		err := d.changeDestinationPolicy(context.Background(), destination, event, revision)
		if errors.Is(err, errPolicySuperseded) {
			continue
		}
		if err != nil {
			d.logger.Warn("Expired destination policy was not restored to the default everywhere", zap.String("destination", destination))
			d.logger.Debug("Private runtime diagnostic", zap.String("destination", destination), zap.String("error", daemonlog.Diagnostic(err)))
			continue
		}
		d.logger.Info("Destination policy expired; default restored", zap.String("destination", destination))
	}
}

// ListDestinationPolicies returns the current policy of every destination
// that has one recorded, ordered by destination.
func (d *Dispatcher) ListDestinationPolicies(ctx context.Context) ([]DestinationPolicy, error) {
	events, err := database.New(d.db).ListCurrentDestinationPolicies(ctx)
	if err != nil {
		return nil, fmt.Errorf("list destination policies: %w", err)
	}
	d.mu.RLock()
	defer d.mu.RUnlock()
	policies := make([]DestinationPolicy, 0, len(events))
	for _, event := range events {
		policy := DestinationPolicy{
			Destination: event.Destination, Kind: event.Kind, Reason: event.Reason, Actor: event.Actor,
			SetAt: time.Unix(0, event.RequestedAtNs).UTC(), Revision: event.Revision,
		}
		if event.LimitBps.Valid {
			limit := bitrate.Bitrate(event.LimitBps.Int64)
			policy.Limit = &limit
		}
		if event.ExpiresAtNs.Valid {
			at := time.Unix(0, event.ExpiresAtNs.Int64).UTC()
			policy.ExpiresAt = &at
		}
		if delivery, ok := d.policies.delivery[event.Destination]; ok && delivery.revision == event.Revision {
			policy.Recipients, policy.Unconfirmed = delivery.recipients, delivery.unconfirmed
		}
		policies = append(policies, policy)
	}
	return policies, nil
}

// DestinationLimit is the capacity admission currently uses for a destination.
func (d *Dispatcher) DestinationLimit(destination string) bitrate.Bitrate {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.destinations.Cap(destination)
}

// destinationLimitLocked is the wire form of the share of one destination.
// Every snapshot an executor receives is its complete set, so each builder
// marks a denied destination: with the flag, and with a zero limit that an
// executor which does not know the flag still applies. The caller holds d.mu.
func (d *Dispatcher) destinationLimitLocked(address string, limit bitrate.Bitrate) *pb.DestinationLimit {
	if d.destinations.Denied(address) {
		return &pb.DestinationLimit{Address: address, Denied: true}
	}
	return &pb.DestinationLimit{Address: address, BitsLimit: int64(limit)}
}
