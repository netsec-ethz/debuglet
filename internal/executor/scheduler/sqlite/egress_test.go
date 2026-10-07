// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package sqlite

import (
	"testing"
	"time"

	"github.com/netsec-ethz/debuglet/internal/executor/scheduler"
	pb "github.com/netsec-ethz/debuglet/protocol"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

func TestSQLiteEgressGrantSurvivesRestoreAndChargesStorage(t *testing.T) {
	db := newSchedulerTestDB(t)
	storage := newTestStorage(t, db, storageTestEligibility)
	spec := insertTestSpec()
	before, err := scheduler.StoredRunBytes(spec)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().Unix()
	spec.Policy.EgressGrant = &pb.EgressGrant{Version: 1, BitsPerSecond: 8, BurstBytes: 64, Bytes: 64, AttemptsPerSecond: 1, AttemptBurst: 4, Attempts: 4, Addresses: []string{"127.0.0.1"}, NotBeforeUnix: now - 60, ExpiresUnix: now + 3600}
	encoded, err := protojson.Marshal(spec.Policy.EgressGrant)
	if err != nil {
		t.Fatal(err)
	}
	after, err := scheduler.StoredRunBytes(spec)
	if err != nil || after-before != int64(len(encoded)) {
		t.Fatalf("grant storage charge %d: %v", after-before, err)
	}
	if _, err := storage.persist(t.Context(), spec); err != nil {
		t.Fatal(err)
	}
	restored := newTestStorage(t, db, storageTestEligibility)
	count := 0
	if err := restored.restore(t.Context(), func(got scheduler.Spec) error {
		count++
		if got.Binding != spec.Binding || !proto.Equal(got.Policy.EgressGrant, spec.Policy.EgressGrant) {
			t.Errorf("grant or ownership changed across restore: %+v", got)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("restored %d", count)
	}
	if _, err := db.Exec("UPDATE debuglets SET egress_grant = X'FF'"); err != nil {
		t.Fatal(err)
	}
	if err := restored.restore(t.Context(), func(scheduler.Spec) error { t.Error("corrupt grant escaped restore"); return nil }); err == nil {
		t.Fatal("corrupt grant was accepted")
	}
}
