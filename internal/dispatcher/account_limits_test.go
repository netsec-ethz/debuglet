// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package dispatcher

import (
	"context"
	"errors"
	"github.com/netsec-ethz/debuglet/internal/testtls"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"path/filepath"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/config"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/database"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/models"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/payments"
	"github.com/netsec-ethz/debuglet/internal/sqlitedb"
	pb "github.com/netsec-ethz/debuglet/protocol"
	"go.uber.org/zap"
)

func quotaUser(t *testing.T, f *tgFixture) database.User {
	t.Helper()
	u, err := f.q.CreateUser(f.ctx, database.CreateUserParams{Uuid: uuid.New(), Name: "quota fixture"})
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func quotaRegister(t *testing.T, d *Dispatcher, id string) {
	t.Helper()
	registryRegister(t, d, id)
	mutation := effectTestMutation(t, d, id)
	defer mutation.Finish()
	if _, err := d.OnResources(t.Context(), mutation, &pb.ResourcesRequest{ExecutorId: id, BandwidthCapacity: int64(tgCapacity)}); err != nil {
		t.Fatal(err)
	}
}

func TestAccountAdmissionIsAtomicAcrossExecutorsAndRestart(t *testing.T) {
	f := newTGFixture(t, nil)
	quotaRegister(t, f.d, "second-quota-executor")
	f.d.admission.config.Account = config.AccountLimits{RequestsPerMinute: 60, QueuedJobs: 1, ActiveJobs: 1, QueuedBytes: 4096}
	owner, other := quotaUser(t, f), quotaUser(t, f)
	specs := []models.DebugletSpec{f.spec(t, tgFloorA), f.spec(t, tgFloorA)}
	specs[1].ExecutorID = "second-quota-executor"
	type result struct {
		ids   uuid.UUIDs
		err   error
		index int
	}
	results := make(chan result, 2)
	start := make(chan struct{})
	var joined sync.WaitGroup
	for i := range specs {
		joined.Add(1)
		go func(i int) {
			defer joined.Done()
			<-start
			ids, err := f.d.SubmitDebuglets(f.ctx, []models.DebugletSpec{specs[i]}, &owner.Uuid)
			results <- result{ids, err, i}
		}(i)
	}
	close(start)
	joined.Wait()
	close(results)
	var accepted result
	winners, refused := 0, 0
	for result := range results {
		if len(result.ids) == 1 {
			winners++
			accepted = result
		} else if errors.Is(result.err, ErrAccountQuota) {
			refused++
		} else {
			t.Fatalf("unexpected admission: %+v", result)
		}
	}
	if winners != 1 || refused != 1 {
		t.Fatalf("accepted=%d refused=%d", winners, refused)
	}
	// These direct fixture registrations intentionally lack an upload transport.
	// Accepted identities must stay charged through that uncertain outcome.
	if accepted.err == nil {
		t.Fatal("fixture unexpectedly uploaded")
	}
	rows, err := f.q.ListAccountReservations(f.ctx, owner.ID)
	if err != nil || len(rows) != 1 {
		t.Fatalf("owner reservations: %+v, %v", rows, err)
	}
	retried, err := f.d.SubmitDebuglets(f.ctx, []models.DebugletSpec{specs[accepted.index]}, &owner.Uuid)
	if err != nil || !reflect.DeepEqual(retried, accepted.ids) {
		t.Fatalf("retry: %v, %v", retried, err)
	}
	otherIDs, _ := f.d.SubmitDebuglets(f.ctx, []models.DebugletSpec{f.spec(t, tgFloorA)}, &other.Uuid)
	if len(otherIDs) != 1 {
		t.Fatal("one account exhausted another account's capacity")
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
	ph := payments.NewPaymentHandler(db, &config.DispatcherConfig{Sui: config.SuiConfig{Disabled: true}}, zap.NewNop())
	d, err := New(zap.NewNop(), db, "restarted", time.Minute, time.Minute, ph)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(d.Close)
	d.admission.config.Account = config.AccountLimits{RequestsPerMinute: 60, QueuedJobs: 1, ActiveJobs: 1, QueuedBytes: 4096}
	quotaRegister(t, d, tgExecutorID)
	restarted := &tgFixture{ctx: t.Context(), db: db, q: database.New(db), ph: ph, d: d, start: f.start}
	ids, err := d.SubmitDebuglets(t.Context(), []models.DebugletSpec{restarted.spec(t, tgFloorA)}, &owner.Uuid)
	if len(ids) != 0 || !errors.Is(err, ErrAccountQuota) {
		t.Fatalf("restart reclaimed unknown work: %v, %v", ids, err)
	}
}

func TestAccountReservedConcurrencyAndBytes(t *testing.T) {
	for _, resource := range []string{"reserved active jobs", "queued bytes"} {
		t.Run(resource, func(t *testing.T) {
			f := newTGFixture(t, &tgPeer{})
			owner := quotaUser(t, f)
			limits := config.AccountLimits{RequestsPerMinute: 60, QueuedJobs: 4, ActiveJobs: 1, QueuedBytes: 4096}
			if resource == "queued bytes" {
				limits.ActiveJobs = 4
				limits.QueuedBytes = 700
			}
			f.d.admission.config.Account = limits
			first := f.spec(t, tgFloorA)
			ids, err := f.d.SubmitDebuglets(f.ctx, []models.DebugletSpec{first}, &owner.Uuid)
			if err != nil || len(ids) != 1 {
				t.Fatalf("first: %v, %v", ids, err)
			}
			second := f.spec(t, tgFloorA)
			_, err = f.d.SubmitDebuglets(f.ctx, []models.DebugletSpec{second}, &owner.Uuid)
			var quota *AccountQuotaError
			if !errors.As(err, &quota) || quota.Resource != resource {
				t.Fatalf("second: %v", err)
			}
			if resource == "reserved active jobs" {
				later := f.start.Add(time.Hour)
				second.StartTime = &later
				ids, err = f.d.SubmitDebuglets(f.ctx, []models.DebugletSpec{second}, &owner.Uuid)
				if err != nil || len(ids) != 1 {
					t.Fatalf("non-overlapping work: %v, %v", ids, err)
				}
			}
		})
	}
}

func TestAccountRetirementRequiresAuthoritativeAbsence(t *testing.T) {
	for _, replyKind := range []string{"absent", "absent with pending output", "absent without output metadata", "filtered", "found", "failed", "malformed", "offline", "different credential"} {
		t.Run(replyKind, func(t *testing.T) {
			d := newTerminalPeerDispatcher(t)
			peer := &recoveryPeer{respond: func(context.Context, *pb.InspectRetainedRunRequest) (*pb.InspectRetainedRunResponse, error) {
				switch replyKind {
				case "failed":
					return nil, errors.New("owned fixture read failure")
				case "filtered":
					return &pb.InspectRetainedRunResponse{Status: pb.RetainedRunStatus_RETAINED_RUN_STATUS_FILTERED}, nil
				case "found":
					return &pb.InspectRetainedRunResponse{Status: pb.RetainedRunStatus_RETAINED_RUN_STATUS_FOUND, Run: &pb.RetainedRun{}}, nil
				case "malformed":
					return &pb.InspectRetainedRunResponse{Status: pb.RetainedRunStatus_RETAINED_RUN_STATUS_ABSENT, Run: &pb.RetainedRun{}}, nil
				default:
					return &pb.InspectRetainedRunResponse{Status: pb.RetainedRunStatus_RETAINED_RUN_STATUS_ABSENT}, nil
				}
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
			owner := d.executors["recovery-executor"].owner
			d.mu.RUnlock()
			binding := owner.Binding()
			if replyKind == "different credential" {
				binding.SessionID = uuid.NewString()
			}
			q := database.New(d.db)
			row, err := q.CreateDebuglet(t.Context(), database.CreateDebugletParams{Uuid: uuid.New(), StartTime: models.NewUTCTime(time.Now()), EndTime: models.NewUTCTime(time.Now().Add(time.Second)), ExecutorID: "recovery-executor", State: models.RunStateExited, DispatcherIncarnation: binding.Incarnation, SessionID: binding.SessionID})
			if err != nil {
				t.Fatal(err)
			}
			if err := q.ReserveAccountRun(t.Context(), database.ReserveAccountRunParams{DebugletID: row.ID, QueuedBytes: 1024}); err != nil {
				t.Fatal(err)
			}
			if replyKind != "absent without output metadata" {
				if err := d.createOutputMetadata(t.Context(), q, row.Uuid, 0, ""); err != nil {
					t.Fatal(err)
				}
				if replyKind != "absent with pending output" {
					if _, err := q.FinishDebugletOutput(t.Context(), database.FinishDebugletOutputParams{DebugletID: row.ID, Status: "complete"}); err != nil {
						t.Fatal(err)
					}
				}
			}
			if replyKind == "offline" {
				owner.Retire()
			}
			err = d.confirmRunRetirement(t.Context(), row.Uuid)
			reservation, readErr := q.GetAccountRunReservation(t.Context(), row.ID)
			if readErr != nil {
				t.Fatal(readErr)
			}
			wantRetired := replyKind == "absent" || replyKind == "absent with pending output" || replyKind == "absent without output metadata"
			if (err == nil) != wantRetired || reservation.RetiredAt.Valid != wantRetired {
				t.Fatalf("retirement: %+v, %v", reservation, err)
			}
		})
	}
}

func TestRequestQuotaLeavesSeparateAccountsUsable(t *testing.T) {
	f := newTGFixture(t, nil)
	u, other := quotaUser(t, f), quotaUser(t, f)
	f.d.admission.config.Account.RequestsPerMinute = 1
	if err := f.d.AllowAdmissionRequest(f.ctx, &u.Uuid); err != nil {
		t.Fatal(err)
	}
	var quota *AccountQuotaError
	if err := f.d.AllowAdmissionRequest(f.ctx, &u.Uuid); !errors.As(err, &quota) || quota.RetryAfter <= 0 {
		t.Fatalf("rate error: %v", err)
	}
	if err := f.d.AllowAdmissionRequest(f.ctx, &other.Uuid); err != nil {
		t.Fatalf("other account: %v", err)
	}
}

func TestAccountQuotaRetainsPartialUploadAndCancellation(t *testing.T) {
	peer := &tgPeer{}
	f := newTGFixture(t, peer)
	u := quotaUser(t, f)
	f.d.admission.config.Account.QueuedJobs = 2
	f.d.admission.config.Account.ActiveJobs = 2
	var calls atomic.Int32
	peer.scriptUpload(func(context.Context, *pb.UploadRequest) error {
		if calls.Add(1) == 2 {
			return status.Error(codes.Unavailable, "owned upload response lost")
		}
		return nil
	})
	specs := f.batch(t, tgFloorA, tgFloorA)
	ids, err := f.d.SubmitDebuglets(f.ctx, specs, &u.Uuid)
	if err == nil || len(ids) != 2 {
		t.Fatalf("partial admission: %v %v", ids, err)
	}
	rows, err := f.q.ListAccountReservations(f.ctx, u.ID)
	if err != nil || len(rows) != 2 {
		t.Fatalf("partial reservations: %+v %v", rows, err)
	}
	if err = f.d.AbortDebuglet(f.ctx, tgExecutorID, ids[0], "cancelled via API"); err != nil {
		t.Fatal(err)
	}
	rows, err = f.q.ListAccountReservations(f.ctx, u.ID)
	if err != nil || len(rows) != 2 {
		t.Fatalf("cancellation freed uncertainty: %+v %v", rows, err)
	}
	retry, err := f.d.SubmitDebuglets(f.ctx, specs, &u.Uuid)
	if err != nil || !reflect.DeepEqual(retry, ids) || calls.Load() != 2 {
		t.Fatalf("retry: %v %v", retry, err)
	}
	if more, err := f.d.SubmitDebuglets(f.ctx, []models.DebugletSpec{f.spec(t, tgFloorA)}, &u.Uuid); len(more) != 0 || !errors.Is(err, ErrAccountQuota) {
		t.Fatalf("unknown work uncharged: %v %v", more, err)
	}
}

func TestPopulatedUpgradePreservesUnknownWorkAndFiniteAllowance(t *testing.T) {
	db, err := sqlitedb.Open(filepath.Join(t.TempDir(), "upgrade.sqlite"), sqlitedb.Create(), sqlitedb.WithoutSync())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := sqlitedb.Migrate(t.Context(), db, database.MigrationFS(), 15); err != nil {
		t.Fatal(err)
	}
	f := &tgFixture{ctx: t.Context(), db: db, q: database.New(db), start: time.Now().Add(time.Hour).Truncate(time.Second)}
	owner, other := quotaUser(t, f), quotaUser(t, f)
	var history []database.Debuglet
	for range 9 {
		row, err := f.q.CreateDebuglet(f.ctx, database.CreateDebugletParams{Uuid: uuid.New(), ExecutorID: "offline-historical", State: models.RunStateExited, StartTime: models.NewUTCTime(time.Now().Add(-2 * time.Hour)), EndTime: models.NewUTCTime(time.Now().Add(-time.Hour))})
		if err != nil {
			t.Fatal(err)
		}
		if err = f.q.InsertDebugletUser(f.ctx, database.InsertDebugletUserParams{DebUuid: row.Uuid, UserUuid: owner.Uuid}); err != nil {
			t.Fatal(err)
		}
		history = append(history, row)
	}
	if _, err := sqlitedb.Migrate(f.ctx, f.db, database.MigrationFS(), 16); err != nil {
		t.Fatal(err)
	}
	f.ph = payments.NewPaymentHandler(db, &config.DispatcherConfig{Sui: config.SuiConfig{Disabled: true}}, zap.NewNop())
	f.d, err = New(zap.NewNop(), db, "upgraded", time.Minute, time.Minute, f.ph)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(f.d.Close)
	quotaRegister(t, f.d, tgExecutorID)
	spec := f.spec(t, tgFloorA)
	if ids, err := f.d.SubmitDebuglets(f.ctx, []models.DebugletSpec{spec}, &owner.Uuid); len(ids) != 0 || !errors.Is(err, ErrAccountQuota) {
		t.Fatalf("upgrade guessed retirement: %v %v", ids, err)
	}
	if row, err := f.q.GetDebugletByUUID(f.ctx, history[0].Uuid); err != nil || row.State != models.RunStateExited {
		t.Fatalf("historical read: %+v %v", row, err)
	}
	if err := f.d.AbortDebuglet(f.ctx, "offline-historical", history[0].Uuid, "cancelled via API"); err != nil {
		t.Fatalf("terminal control unavailable: %v", err)
	}
	if ids, _ := f.d.SubmitDebuglets(f.ctx, []models.DebugletSpec{f.spec(t, tgFloorA)}, &other.Uuid); len(ids) != 1 {
		t.Fatal("historical account blocked another owner")
	}
	f.d.admission.config.Account.QueuedBytes = 512 << 20 // Explicit finite operator configuration.
	if ids, _ := f.d.SubmitDebuglets(f.ctx, []models.DebugletSpec{spec}, &owner.Uuid); len(ids) != 1 {
		t.Fatal("finite allowance did not restore admission")
	}
	rows, err := f.q.ListAccountReservations(f.ctx, owner.ID)
	if err != nil || len(rows) != 10 {
		t.Fatalf("historical reservations lost: %d %v", len(rows), err)
	}
}

func TestAccountRetirementUsesEnrolledCredentialAfterReconnect(t *testing.T) {
	f := newOutputTLS(t)
	client, owner := f.connect(f.identity, true)
	writer, err := outputWriterFor(owner, &pb.ControlBinding{DispatcherIncarnation: owner.Binding().Incarnation, SessionId: owner.Binding().SessionID})
	if err != nil {
		t.Fatal(err)
	}
	q := database.New(f.d.db)
	ids := []uuid.UUID{outputTestRun(t, f.d, writer, nil), outputTestRun(t, f.d, writer, nil)}
	for _, id := range ids {
		row, err := q.GetDebugletByUUID(f.ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = f.d.db.Exec("UPDATE debuglets SET state=? WHERE id=?", models.RunStateExited, row.ID); err != nil {
			t.Fatal(err)
		}
		if err = q.ReserveAccountRun(f.ctx, database.ReserveAccountRunParams{DebugletID: row.ID, QueuedBytes: 1024}); err != nil {
			t.Fatal(err)
		}
	}
	client.Close()
	client, replacement := f.connect(f.identity, false)
	if replacement.Binding() == owner.Binding() {
		t.Fatal("reconnect reused session")
	}
	if err = f.d.confirmRunRetirement(f.ctx, ids[0]); err != nil {
		t.Fatalf("same enrolled node: %v", err)
	}
	if _, err = f.store.Revoke(f.ctx, writer.executorID); err != nil {
		t.Fatal(err)
	}
	if err = f.d.confirmRunRetirement(f.ctx, ids[1]); !errors.Is(err, ErrPayloadNotDeletable) {
		t.Fatalf("revoked node freed reservation: %v", err)
	}
	client.Close()
	rotated, err := f.ca.Issue("rotated-retirement", testtls.Options{Client: true})
	if err != nil {
		t.Fatal(err)
	}
	f.connect(rotated, true)
	if err = f.d.confirmRunRetirement(f.ctx, ids[1]); !errors.Is(err, ErrPayloadNotDeletable) {
		t.Fatalf("rotated node freed reservation: %v", err)
	}
}
