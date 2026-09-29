// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package dispatcher

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/netsec-ethz/debuglet/internal/dispatcher/config"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/database"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/resource/schedule"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/tag"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

// The attribution history (docs/verification.md, delivery step 2) answers
// which runs were active from a source address at a time, with the TESLA
// schedule and disclosed keys a verifier checks their tags against. It is
// recorded in three places: a chain when an executor registers it, a verified
// disclosure when the key store accepts it, and a run's interval when it is
// admitted, narrowed when it exits. It is pruned after the configured
// retention.

// attributionTimeout bounds one history write made outside a request, such as
// a disclosure recorded from a heartbeat.
const attributionTimeout = 5 * time.Second

// attributionPruneInterval is how often the expiry loop prunes the history.
const attributionPruneInterval = time.Hour

// ConfigureAttribution fixes the attribution history retention before startup.
func (d *Dispatcher) ConfigureAttribution(cfg config.AttributionConfig) error {
	if err := cfg.Validate(); err != nil {
		return err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed || d.restored || len(d.executors) != 0 || len(d.registrations) != 0 {
		return errors.New("attribution retention must be configured before dispatcher startup")
	}
	d.attribution = cfg
	return nil
}

// teslaChain is the chain this executor's session announced.
func (e *RegisteredExecutor) teslaChain() tag.Chain {
	return tag.Chain{Anchor: bytes.Clone(e.TeslaAnchorKey), Start: e.TeslaAnchorTimestamp, Interval: e.TeslaDelay,
		DisclosureDelay: e.TeslaDisclosureDelay, Length: e.TeslaChainLength}
}

// attributionBackend is the durable record behind the key store.
type attributionBackend struct{ db *sql.DB }

func chainParams(executorID string, chain tag.Chain, seen time.Time) database.RecordAttributionChainParams {
	return database.RecordAttributionChainParams{
		ExecutorID: executorID, ChainID: tag.ChainID(chain.Anchor), Anchor: chain.Anchor,
		T0Ns: chain.Start.UnixNano(), IntervalNs: int64(chain.Interval), DelayEpochs: max(chain.DisclosureDelay, 0),
		ChainLength: max(chain.Length, 0), TagSpec: tag.TagSpec, SeenNs: seen.UnixNano(),
	}
}

// Save records the chain, if it is not yet on record, and the key once.
func (b attributionBackend) Save(executorID string, chain tag.Chain, epoch int64, key []byte, at time.Time) error {
	ctx, cancel := context.WithTimeout(context.Background(), attributionTimeout)
	defer cancel()
	tx, err := b.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	q := database.New(tx)
	if err := q.RecordAttributionChain(ctx, chainParams(executorID, chain, at)); err != nil {
		return err
	}
	if err := q.InsertAttributionKey(ctx, database.InsertAttributionKeyParams{
		ExecutorID: executorID, ChainID: tag.ChainID(chain.Anchor), Epoch: epoch, Key: key, DisclosedAtNs: at.UnixNano(),
	}); err != nil {
		return err
	}
	return tx.Commit()
}

func (b attributionBackend) Latest(executorID string, anchor []byte) (int64, []byte, bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), attributionTimeout)
	defer cancel()
	row, err := database.New(b.db).LatestAttributionKey(ctx, database.LatestAttributionKeyParams{ExecutorID: executorID, ChainID: tag.ChainID(anchor)})
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil, false, nil
	}
	if err != nil {
		return 0, nil, false, err
	}
	return row.Epoch, row.Key, true, nil
}

func (b attributionBackend) Get(executorID string, anchor []byte, epoch int64) ([]byte, bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), attributionTimeout)
	defer cancel()
	key, err := database.New(b.db).GetAttributionKey(ctx, database.GetAttributionKeyParams{ExecutorID: executorID, ChainID: tag.ChainID(anchor), Epoch: epoch})
	if errors.Is(err, sql.ErrNoRows) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	return key, true, nil
}

// recordChain puts the chain an executor announced on record. An executor
// without an anchor has nothing to record.
func (d *Dispatcher) recordChain(ctx context.Context, executorID string, chain tag.Chain, seen time.Time) error {
	if d.db == nil || len(chain.Anchor) == 0 {
		return nil
	}
	return database.New(d.db).RecordAttributionChain(ctx, chainParams(executorID, chain, seen))
}

// recordedChain returns a chain of executorID with the given anchor from the
// record, so a disclosure for a chain other than the session's own can be
// verified. ok is false when it is not on record.
func (d *Dispatcher) recordedChain(ctx context.Context, executorID string, anchor []byte) (tag.Chain, bool, error) {
	if d.db == nil || len(anchor) == 0 {
		return tag.Chain{}, false, nil
	}
	row, err := database.New(d.db).GetAttributionChain(ctx, database.GetAttributionChainParams{ExecutorID: executorID, ChainID: tag.ChainID(anchor)})
	if errors.Is(err, sql.ErrNoRows) {
		return tag.Chain{}, false, nil
	}
	if err != nil {
		return tag.Chain{}, false, err
	}
	return tag.Chain{Anchor: row.Anchor, Start: time.Unix(0, row.T0Ns), Interval: time.Duration(row.IntervalNs),
		DisclosureDelay: row.DelayEpochs, Length: row.ChainLength}, true, nil
}

// normalizeIP returns the canonical text of an address, or the input when it
// is no IP literal.
func normalizeIP(ip string) string {
	if addr, err := netip.ParseAddr(ip); err == nil {
		return addr.WithZone("").Unmap().String()
	}
	return ip
}

// recordRunActivity records, in the admission transaction, the interval in
// which a run may send tagged packets: its reserved window, from the source
// address the dispatcher knows for the executor, tagged with the executor's
// current chain. The caller holds d.mu, which guards entry. An executor
// without a chain anchor or a known address tags nothing attributable, so its
// runs are not recorded.
func recordRunActivity(ctx context.Context, q *database.Queries, runID int64, entry *executorEntry, window schedule.Request) error {
	if len(entry.TeslaAnchorKey) == 0 || entry.sourceIp == "" {
		return nil
	}
	observed := int64(0)
	if entry.sourceIPObserved {
		observed = 1
	}
	return q.RecordAttributionRun(ctx, database.RecordAttributionRunParams{
		DebugletID: runID, ChainID: tag.ChainID(entry.TeslaAnchorKey), SourceIp: normalizeIP(entry.sourceIp),
		SourceIpObserved: observed, ActiveFromNs: window.From.UnixNano(), ActiveToNs: window.To.UnixNano(),
	})
}

// endRunActivity narrows a run's recorded interval to its exit.
func (d *Dispatcher) endRunActivity(ctx context.Context, id uuid.UUID, ended time.Time) {
	if err := database.New(d.db).EndAttributionRun(ctx, database.EndAttributionRunParams{EndedNs: ended.UnixNano(), Uuid: id}); err != nil {
		d.logger.Warn("Failed to record the end of a run's attribution interval; it keeps its window end", zap.String("debugletID", id.String()), zap.Error(err))
	}
}

// PruneAttribution deletes the attribution history older than the configured
// retention before now and advances retained_from to the cutoff: runs whose
// interval ended before it, keys whose epoch ended before it and chains with
// neither left that were last seen before it.
func (d *Dispatcher) PruneAttribution(ctx context.Context, now time.Time) error {
	if d.db == nil {
		return nil
	}
	cutoff := now.Add(-d.attribution.Retention()).UnixNano()
	tx, err := d.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	q := database.New(tx)
	runs, err := q.PruneAttributionRuns(ctx, cutoff)
	if err != nil {
		return fmt.Errorf("prune attribution runs: %w", err)
	}
	keys, err := q.PruneAttributionKeys(ctx, cutoff)
	if err != nil {
		return fmt.Errorf("prune attribution keys: %w", err)
	}
	chains, err := q.PruneAttributionChains(ctx, cutoff)
	if err != nil {
		return fmt.Errorf("prune attribution chains: %w", err)
	}
	if err := q.AdvanceAttributionRetention(ctx, cutoff); err != nil {
		return fmt.Errorf("advance attribution retention: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	if runs+keys+chains > 0 {
		d.logger.Info("Pruned attribution history", zap.Time("retained_from", time.Unix(0, cutoff)),
			zap.Int64("runs", runs), zap.Int64("keys", keys), zap.Int64("chains", chains))
	}
	return nil
}

// pruneAttributionDue prunes when the last prune is attributionPruneInterval
// old, and returns the time of the last prune.
func (d *Dispatcher) pruneAttributionDue(last time.Time) time.Time {
	now := d.now()
	if !last.IsZero() && now.Sub(last) < attributionPruneInterval {
		return last
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if err := d.PruneAttribution(ctx, now); err != nil {
		d.logger.Warn("Failed to prune attribution history", zap.Error(err))
	}
	return now
}
