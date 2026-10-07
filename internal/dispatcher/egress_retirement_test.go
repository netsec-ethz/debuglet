// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package dispatcher

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/config"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/database"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/models"
	pb "github.com/netsec-ethz/debuglet/protocol"
)

func TestAggregateEgressReplenishesOnlyAfterAuthenticatedAbsence(t *testing.T) {
	d := newTerminalPeerDispatcher(t)
	cfg := egressConfig()
	if err := d.ConfigureEgress(t.Context(), cfg); err != nil {
		t.Fatal(err)
	}
	var absent atomic.Bool
	peer := &recoveryPeer{respond: func(context.Context, *pb.InspectRetainedRunRequest) (*pb.InspectRetainedRunResponse, error) {
		if absent.Load() {
			return &pb.InspectRetainedRunResponse{Status: pb.RetainedRunStatus_RETAINED_RUN_STATUS_ABSENT}, nil
		}
		return &pb.InspectRetainedRunResponse{Status: pb.RetainedRunStatus_RETAINED_RUN_STATUS_FOUND}, nil
	}}
	stop, err := startTerminalPeer(t.Context(), d, tgCapacity, peer)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := stop(ctx); err != nil {
			t.Error(err)
		}
	})
	d.mu.RLock()
	binding := d.executors["recovery-executor"].owner.Binding()
	d.mu.RUnlock()
	q := database.New(d.db)
	now := time.Now().Truncate(time.Second)
	row, err := q.CreateDebuglet(t.Context(), database.CreateDebugletParams{Uuid: uuid.New(), ExecutorID: "recovery-executor", State: models.RunStateExited, StartTime: models.NewUTCTime(now), EndTime: models.NewUTCTime(now.Add(time.Second)), DispatcherIncarnation: binding.Incarnation, SessionID: binding.SessionID})
	if err != nil {
		t.Fatal(err)
	}
	if err := q.ReserveAccountRun(t.Context(), database.ReserveAccountRunParams{DebugletID: row.ID, QueuedBytes: 1024}); err != nil {
		t.Fatal(err)
	}
	reservation := egressReservation{buckets: map[string]config.EgressLimits{"group:owned-targets": cfg.Run}, grant: &pb.EgressGrant{Version: 1, BitsPerSecond: cfg.Run.BitsPerSecond, BurstBytes: cfg.Run.BurstBytes, Bytes: cfg.Run.Bytes, AttemptsPerSecond: 1, AttemptBurst: 4, Attempts: 4, Addresses: []string{"127.0.0.1"}, NotBeforeUnix: now.Unix() - 120, ExpiresUnix: now.Unix() - 60}}
	reserve := func(id uuid.UUID) error {
		tx, err := d.db.BeginTx(t.Context(), nil)
		if err != nil {
			return err
		}
		defer tx.Rollback()
		if err := d.reserveEgress(t.Context(), tx, id, reservation); err != nil {
			return err
		}
		return tx.Commit()
	}
	if err := reserve(row.Uuid); err != nil {
		t.Fatal(err)
	}
	reservation.grant.NotBeforeUnix, reservation.grant.ExpiresUnix = now.Unix(), now.Unix()+60
	if err := d.confirmRunRetirement(t.Context(), row.Uuid); !errors.Is(err, ErrPayloadNotDeletable) {
		t.Fatalf("retained authority: %v", err)
	}
	if err := reserve(uuid.New()); !errors.Is(err, ErrEgressBudget) {
		t.Fatalf("unknown authority replenished: %v", err)
	}
	absent.Store(true)
	if err := d.confirmRunRetirement(t.Context(), row.Uuid); err != nil {
		t.Fatal(err)
	}
	if err := reserve(uuid.New()); err != nil {
		t.Fatalf("authenticated retirement did not replenish: %v", err)
	}
	if peer.calls.Load() != 2 {
		t.Fatalf("retirement inspections=%d", peer.calls.Load())
	}
}
