// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package dispatcher

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"time"

	"github.com/google/uuid"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/config"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/models"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/resource"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/resource/schedule"
	"github.com/netsec-ethz/debuglet/internal/executor/debuglet/netpolicy"
	pb "github.com/netsec-ethz/debuglet/protocol"
	"google.golang.org/protobuf/encoding/protojson"
)

var ErrEgressBudget = fmt.Errorf("aggregate egress budget unavailable: %w", resource.ErrCapacityFull)

func egressPolicyHash(cfg config.EgressConfig) string {
	data, _ := json.Marshal(cfg)
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}

// ConfigureEgress refuses policy changes while previously issued grants remain
// usable. Restarting cannot advertise a lower bound than outstanding authority.
func (d *Dispatcher) ConfigureEgress(ctx context.Context, cfg config.EgressConfig) error {
	if err := cfg.Validate(); err != nil {
		return err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	var committed int
	if err := d.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM egress_grants WHERE policy_hash != ? AND (window_end > ? OR NOT EXISTS (SELECT 1 FROM debuglets d JOIN account_run_reservations r ON r.debuglet_id = d.id WHERE d.uuid = egress_grants.run_uuid AND r.retired_at IS NOT NULL))`, egressPolicyHash(cfg), d.now().Unix()).Scan(&committed); err != nil {
		return err
	}
	if committed != 0 {
		return fmt.Errorf("%w: %d grants remain committed; retain the configuration until their windows end and retirement is confirmed", ErrEgressBudget, committed)
	}
	if cfg.Enabled {
		if err := d.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM account_run_reservations r JOIN debuglets d ON d.id = r.debuglet_id WHERE r.retired_at IS NULL AND COALESCE(d.addresses, '') != '' AND NOT EXISTS (SELECT 1 FROM egress_grants g WHERE g.run_uuid = d.uuid)`).Scan(&committed); err != nil {
			return err
		}
		if committed != 0 {
			return fmt.Errorf("%w: %d earlier runs lack grants; confirm their retirement before enabling egress budgets", ErrEgressBudget, committed)
		}
	}
	cfg.Groups = slices.Clone(cfg.Groups)
	for i := range cfg.Groups {
		cfg.Groups[i].Prefixes = slices.Clone(cfg.Groups[i].Prefixes)
		cfg.Groups[i].Names = slices.Clone(cfg.Groups[i].Names)
	}
	d.egress = cfg
	return nil
}

type egressReservation struct {
	grant   *pb.EgressGrant
	buckets map[string]config.EgressLimits
}

// prepareEgress keeps one grant for the whole run, even when its addresses fall
// into multiple groups. Every matching group reserves the entire grant.
func prepareEgress(ctx context.Context, cfg config.EgressConfig, spec models.DebugletSpec, owner *uuid.UUID) (egressReservation, error) {
	if !cfg.Enabled {
		return egressReservation{}, nil
	}
	if spec.Policy.ListenSCION {
		return egressReservation{}, fmt.Errorf("%w: SCION is not supported by pinned-address grants", ErrEgressBudget)
	}
	// The run policy already denies every peer when no target is declared.
	if len(spec.Policy.Addresses) == 0 {
		return egressReservation{}, nil
	}
	answers := make(map[string][]netip.Addr)
	resolve := func(text string) ([]netip.Addr, error) {
		text = netpolicy.DestinationKey(text)
		if addresses, ok := answers[text]; ok {
			return addresses, nil
		}
		if address, err := netip.ParseAddr(text); err == nil {
			return []netip.Addr{netpolicy.Normalize(address)}, nil
		}
		addresses, err := net.DefaultResolver.LookupNetIP(ctx, "ip", text)
		if err != nil {
			return nil, fmt.Errorf("%w: resolve a budget destination: %v", ErrEgressBudget, err)
		}
		for i := range addresses {
			addresses[i] = netpolicy.Normalize(addresses[i])
		}
		answers[text] = addresses
		return addresses, nil
	}
	addresses := make(map[netip.Addr]bool)
	for _, declared := range spec.Policy.Addresses {
		resolved, err := resolve(declared)
		if err != nil {
			return egressReservation{}, err
		}
		for _, address := range resolved {
			addresses[address] = true
		}
	}
	if len(addresses) == 0 || int64(len(addresses)) > cfg.Run.Targets {
		return egressReservation{}, fmt.Errorf("%w: too many or no resolved targets", ErrEgressBudget)
	}
	account := "local"
	if owner != nil {
		account = owner.String()
	}
	r := egressReservation{buckets: map[string]config.EgressLimits{"account:" + account: cfg.Account, "node:" + spec.ExecutorID: cfg.Node}}
	for _, group := range cfg.Groups {
		matched := false
		for _, text := range group.Prefixes {
			prefix := netip.MustParsePrefix(text)
			for address := range addresses {
				matched = matched || netpolicy.MatchesPrefix(prefix, address)
			}
		}
		for _, name := range group.Names {
			resolved, err := resolve(name)
			if err != nil {
				return egressReservation{}, err
			}
			for _, address := range resolved {
				matched = matched || addresses[address]
			}
		}
		if matched {
			r.buckets["group:"+group.Name] = group.Limits
		}
	}
	r.grant = &pb.EgressGrant{}
	for address := range addresses {
		r.grant.Addresses = append(r.grant.Addresses, address.String())
	}
	slices.Sort(r.grant.Addresses)
	return r, nil
}

func (d *Dispatcher) completeEgress(spec models.DebugletSpec, window schedule.Request, r *egressReservation) error {
	if r.grant == nil {
		return nil
	}
	entry := d.executors[spec.ExecutorID]
	if entry == nil || entry.egressBudgetVersion < 1 {
		return fmt.Errorf("%w: executor must support aggregate egress grants", ErrEgressBudget)
	}
	from := window.From.Unix() / d.egress.WindowSeconds * d.egress.WindowSeconds
	until := from + d.egress.WindowSeconds
	if window.To.After(time.Unix(until, 0)) {
		return fmt.Errorf("%w: execution must fit within one %d-second UTC budget window", ErrEgressBudget, d.egress.WindowSeconds)
	}
	limit := d.egress.Run
	rate := min(int64(spec.Policy.CeilBW), limit.BitsPerSecond)
	if rate < int64(spec.Policy.FloorBW) {
		return fmt.Errorf("%w: requested floor exceeds the per-run rate", ErrEgressBudget)
	}
	addresses := r.grant.Addresses
	r.grant = &pb.EgressGrant{Addresses: addresses, Version: 1, BitsPerSecond: rate, BurstBytes: limit.BurstBytes, Bytes: limit.Bytes,
		AttemptsPerSecond: limit.AttemptsPerSecond, AttemptBurst: limit.AttemptBurst, Attempts: limit.Attempts, NotBeforeUnix: from, ExpiresUnix: until}
	return netpolicy.ValidateEgressGrant(r.grant)
}

func (d *Dispatcher) reserveEgress(ctx context.Context, tx *sql.Tx, id uuid.UUID, r egressReservation) error {
	if r.grant == nil {
		return nil
	}
	now := d.now().Unix()
	updated, err := tx.ExecContext(ctx, `UPDATE egress_clock SET observed_at = ? WHERE id = 1 AND observed_at <= ?`, now, now)
	if err != nil {
		return err
	}
	if rows, err := updated.RowsAffected(); err != nil || rows != 1 {
		return fmt.Errorf("%w: dispatcher clock moved backwards", ErrEgressBudget)
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM egress_grants WHERE window_end <= ? AND EXISTS (SELECT 1 FROM debuglets d JOIN account_run_reservations r ON r.debuglet_id = d.id WHERE d.uuid = egress_grants.run_uuid AND r.retired_at IS NOT NULL)`, now); err != nil {
		return err
	}
	encoded, err := protojson.Marshal(r.grant)
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO egress_grants(run_uuid,policy_hash,window_start,window_end,grant_json) VALUES(?,?,?,?,?)`, id.String(), egressPolicyHash(d.egress), r.grant.NotBeforeUnix, r.grant.ExpiresUnix, encoded); err != nil {
		return err
	}
	g := r.grant
	charge := [7]int64{g.BitsPerSecond, g.BurstBytes, g.Bytes, g.AttemptsPerSecond, g.AttemptBurst, g.Attempts, int64(len(g.Addresses))}
	for bucket, limit := range r.buckets {
		var used [7]int64
		err := tx.QueryRowContext(ctx, `SELECT COALESCE(SUM(r.bits_per_second),0),COALESCE(SUM(r.burst_bytes),0),COALESCE(SUM(r.bytes),0),COALESCE(SUM(r.attempts_per_second),0),COALESCE(SUM(r.attempt_burst),0),COALESCE(SUM(r.attempts),0),COALESCE(SUM(r.targets),0) FROM egress_reservations r JOIN egress_grants g ON g.run_uuid = r.run_uuid WHERE r.bucket = ? AND ((g.window_start < ? AND g.window_end > ?) OR NOT EXISTS (SELECT 1 FROM debuglets d JOIN account_run_reservations a ON a.debuglet_id = d.id WHERE d.uuid = g.run_uuid AND a.retired_at IS NOT NULL))`, bucket, g.ExpiresUnix, g.NotBeforeUnix).Scan(&used[0], &used[1], &used[2], &used[3], &used[4], &used[5], &used[6])
		if err != nil {
			return err
		}
		for i, capacity := range limit.Values() {
			if used[i] > capacity || charge[i] > capacity-used[i] {
				dimension := [...]string{"bits_per_second", "burst_bytes", "bytes", "attempts_per_second", "attempt_burst", "attempts", "targets"}[i]
				return fmt.Errorf("%w: %s %s has outstanding commitments", ErrEgressBudget, bucket, dimension)
			}
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO egress_reservations(run_uuid,bucket,bits_per_second,burst_bytes,bytes,attempts_per_second,attempt_burst,attempts,targets) VALUES(?,?,?,?,?,?,?,?,?)`, id.String(), bucket, charge[0], charge[1], charge[2], charge[3], charge[4], charge[5], charge[6]); err != nil {
			return err
		}
	}
	return nil
}
