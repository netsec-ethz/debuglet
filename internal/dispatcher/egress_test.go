// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package dispatcher

import (
	"context"
	"database/sql"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/config"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/database"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/models"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/payments"
	"github.com/netsec-ethz/debuglet/internal/sqlitedb"
	"go.uber.org/zap"
)

func egressConfig() config.EgressConfig {
	run := config.EgressLimits{BitsPerSecond: 2000, BurstBytes: 64, Bytes: 64, AttemptsPerSecond: 1, AttemptBurst: 4, Attempts: 4, Targets: 1}
	large := config.EgressLimits{BitsPerSecond: 20000, BurstBytes: 640, Bytes: 640, AttemptsPerSecond: 10, AttemptBurst: 40, Attempts: 40, Targets: 10}
	return config.EgressConfig{Enabled: true, WindowSeconds: 3600, Run: run, Account: large, Node: large,
		Groups: []config.EgressGroup{{Name: "owned-targets", Prefixes: []string{"127.0.0.0/8"}, Limits: run}}}
}

func egressFixture(t *testing.T) *tgFixture {
	t.Helper()
	f := newTGFixture(t, nil)
	f.start = time.Now().Add(time.Hour).Truncate(time.Hour).Add(time.Minute)
	f.d.executors[tgExecutorID].egressBudgetVersion = 1
	if err := f.d.ConfigureEgress(t.Context(), egressConfig()); err != nil {
		t.Fatal(err)
	}
	return f
}

func egressSpec(t *testing.T, f *tgFixture, address string) models.DebugletSpec {
	t.Helper()
	spec := f.spec(t, tgFloorA)
	spec.Policy.Addresses = []string{address}
	return spec
}

func TestAggregateEgressConcurrentGroupAcrossAccountsAndExecutors(t *testing.T) {
	f := egressFixture(t)
	quotaRegister(t, f.d, "second-egress-executor")
	f.d.executors["second-egress-executor"].egressBudgetVersion = 1
	owners := []database.User{quotaUser(t, f), quotaUser(t, f)}
	specs := []models.DebugletSpec{egressSpec(t, f, "127.0.0.1"), egressSpec(t, f, "127.0.0.2")}
	specs[1].ExecutorID = "second-egress-executor"
	type result struct {
		ids   uuid.UUIDs
		err   error
		index int
	}
	results := make(chan result, 2)
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := range specs {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			ids, err := f.d.SubmitDebuglets(f.ctx, []models.DebugletSpec{specs[i]}, &owners[i].Uuid)
			results <- result{ids, err, i}
		}(i)
	}
	close(start)
	wg.Wait()
	close(results)
	accepted, denied := 0, 0
	for r := range results {
		if len(r.ids) == 1 {
			accepted++
			// Lost upload acknowledgement must retain the same grant on retries.
			ids, err := f.d.SubmitDebuglets(f.ctx, []models.DebugletSpec{specs[r.index]}, &owners[r.index].Uuid)
			if err != nil || len(ids) != 1 || ids[0] != r.ids[0] {
				t.Fatalf("retry: %v %v", ids, err)
			}
		} else if errors.Is(r.err, ErrEgressBudget) {
			denied++
		} else {
			t.Fatalf("unexpected admission: %+v", r)
		}
	}
	if accepted != 1 || denied != 1 {
		t.Fatalf("accepted=%d denied=%d", accepted, denied)
	}
	var count int
	if err := f.db.QueryRow("SELECT COUNT(*) FROM egress_grants").Scan(&count); err != nil || count != 1 {
		t.Fatalf("grants=%d: %v", count, err)
	}
}

func TestAggregateEgressAtomicBudgetsRemainSeparate(t *testing.T) {
	for _, limit := range []string{"group", "account storage"} {
		t.Run(limit, func(t *testing.T) {
			f := egressFixture(t)
			owner := quotaUser(t, f)
			if limit == "account storage" {
				f.d.admission.config.Account.QueuedBytes = 1
			}
			specs := []models.DebugletSpec{egressSpec(t, f, "127.0.0.1")}
			if limit == "group" {
				specs = append(specs, egressSpec(t, f, "127.0.0.2"))
			}
			ids, err := f.d.SubmitDebuglets(f.ctx, specs, &owner.Uuid)
			if len(ids) != 0 || err == nil {
				t.Fatalf("refusal: %v %v", ids, err)
			}
			for _, table := range []string{"egress_grants", "egress_reservations", "account_run_reservations"} {
				var count int
				if err := f.db.QueryRow("SELECT COUNT(*) FROM " + table).Scan(&count); err != nil || count != 0 {
					t.Fatalf("%s retained %d after rollback: %v", table, count, err)
				}
			}
			if limit == "account storage" {
				f.d.admission.config.Account.QueuedBytes = 4096
			}
			ids, _ = f.d.SubmitDebuglets(f.ctx, specs[:1], &owner.Uuid)
			if len(ids) != 1 {
				t.Fatal("failed admission consumed another budget")
			}
		})
	}
}

func TestAggregateEgressRetainsAuthorityAcrossWindowsAndRestart(t *testing.T) {
	f := egressFixture(t)
	owner := quotaUser(t, f)
	ids, _ := f.d.SubmitDebuglets(f.ctx, []models.DebugletSpec{egressSpec(t, f, "127.0.0.1")}, &owner.Uuid)
	if len(ids) != 1 {
		t.Fatal("first run not accepted")
	}
	cfg := egressConfig()
	cfg.Groups[0].Limits.Bytes--
	if err := f.d.ConfigureEgress(f.ctx, cfg); !errors.Is(err, ErrEgressBudget) {
		t.Fatalf("live reduction: %v", err)
	}
	if err := f.d.ConfigureEgress(f.ctx, config.EgressConfig{}); !errors.Is(err, ErrEgressBudget) {
		t.Fatalf("live disable: %v", err)
	}
	var sequence int
	var name, path string
	if err := f.db.QueryRow("PRAGMA database_list").Scan(&sequence, &name, &path); err != nil {
		t.Fatal(err)
	}
	f.d.Close()
	if err := f.db.Close(); err != nil {
		t.Fatal(err)
	}
	db, err := sqlitedb.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	ph, _ := payments.NewPaymentHandler(db, &config.DispatcherConfig{Sui: config.SuiConfig{Disabled: true}}, zap.NewNop())
	d, err := New(zap.NewNop(), db, "egress-restart", time.Minute, time.Minute, ph)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(d.Close)
	quotaRegister(t, d, tgExecutorID)
	d.executors[tgExecutorID].egressBudgetVersion = 1
	if err := d.ConfigureEgress(t.Context(), egressConfig()); err != nil {
		t.Fatal(err)
	}
	// The dispatcher has crossed the boundary while an old executor could lag.
	// Neither the new window nor a restart proves that old authority stopped.
	now := f.start.Add(2 * time.Hour)
	d.now = func() time.Time { return now }
	restarted := &tgFixture{ctx: t.Context(), db: db, q: database.New(db), ph: ph, d: d, start: now.Add(time.Minute)}
	later := egressSpec(t, restarted, "127.0.0.2")
	if got, err := d.SubmitDebuglets(t.Context(), []models.DebugletSpec{later}, &owner.Uuid); len(got) != 0 || !errors.Is(err, ErrEgressBudget) {
		t.Fatalf("unknown old grant freed: %v %v", got, err)
	}
	if err := d.ConfigureEgress(t.Context(), config.EgressConfig{}); !errors.Is(err, ErrEgressBudget) {
		t.Fatalf("clock alone disabled enforcement: %v", err)
	}
	// This is the durable observation written only by authenticated ABSENT.
	row, err := database.New(db).GetDebugletByUUID(t.Context(), ids[0])
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.New(db).RetireAccountRun(t.Context(), database.RetireAccountRunParams{DebugletID: row.ID, RetiredAt: sql.NullInt64{Int64: now.Unix(), Valid: true}}); err != nil {
		t.Fatal(err)
	}
	got, _ := d.SubmitDebuglets(t.Context(), []models.DebugletSpec{later}, &owner.Uuid)
	if len(got) != 1 {
		t.Fatal("proved retirement did not permit replenishment")
	}
	// A backwards dispatcher clock cannot open an earlier window again.
	now = now.Add(-time.Hour)
	older := egressSpec(t, restarted, "127.0.0.3")
	if got, err := d.SubmitDebuglets(context.Background(), []models.DebugletSpec{older}, &owner.Uuid); len(got) != 0 || !errors.Is(err, ErrEgressBudget) {
		t.Fatalf("backwards clock admitted: %v %v", got, err)
	}
}

func TestAggregateEgressEveryMatchingGroupAndExecutorVersion(t *testing.T) {
	f := egressFixture(t)
	cfg := egressConfig()
	second := cfg.Groups[0]
	second.Name = "second"
	second.Prefixes = []string{"::ffff:127.0.0.0/104"}
	cfg.Groups = append(cfg.Groups, second)
	if err := f.d.ConfigureEgress(t.Context(), cfg); err != nil {
		t.Fatal(err)
	}
	f.d.executors[tgExecutorID].egressBudgetVersion = 0
	spec := egressSpec(t, f, "127.0.0.1")
	if ids, err := f.d.SubmitDebuglets(f.ctx, []models.DebugletSpec{spec}, nil); len(ids) != 0 || !errors.Is(err, ErrEgressBudget) {
		t.Fatalf("legacy executor admitted: %v %v", ids, err)
	}
	f.d.executors[tgExecutorID].egressBudgetVersion = 1
	ids, _ := f.d.SubmitDebuglets(f.ctx, []models.DebugletSpec{spec}, nil)
	if len(ids) != 1 {
		t.Fatal("capable executor refused")
	}
	var groups int
	if err := f.db.QueryRow("SELECT COUNT(*) FROM egress_reservations WHERE bucket LIKE 'group:%'").Scan(&groups); err != nil || groups != 2 {
		t.Fatalf("groups=%d: %v", groups, err)
	}
}

func TestAggregateEgressEnablingRequiresExistingRunRetirement(t *testing.T) {
	f := newTGFixture(t, nil)
	ids, _ := f.d.SubmitDebuglets(f.ctx, []models.DebugletSpec{egressSpec(t, f, "127.0.0.1")}, nil)
	if len(ids) != 1 {
		t.Fatal("existing run not admitted")
	}
	if err := f.d.ConfigureEgress(f.ctx, egressConfig()); !errors.Is(err, ErrEgressBudget) {
		t.Fatalf("enabled over unknown unbudgeted authority: %v", err)
	}
}
