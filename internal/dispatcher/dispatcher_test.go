// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package dispatcher_test

import (
	"database/sql"
	"errors"
	"github.com/netsec-ethz/debuglet/internal/controlsession"
	"regexp"
	"testing"
	"time"

	"github.com/netsec-ethz/debuglet/internal/dispatcher"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/models"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/resource"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/transport/rpc"
	"github.com/netsec-ethz/debuglet/protocol"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

const (
	testExecutorID = "test"
	testCurrency   = "USDC"
	testWallet     = "0xwallet"
	testCapacity   = resource.Gigabit
	// testTimeout is the debuglet policy timeout. validateDebugletSpec adds a
	// further 10s slack, so an admission window is [start, start+20s].
	testTimeout = 10 * time.Second
)

// Column list of the generated ListDebugletsEndAfter / CreateDebuglet queries
// (internal/dispatcher/database/debuglet.sql.go). The restore query must select
// exactly these 12 columns; the mock rows must provide a value for each one.
var debugletColumns = []string{
	"id", "uuid", "start_time", "end_time", "usage", "ceil_bw",
	"executor_id", "addresses", "state", "error", "transaction_id", "order_id", "dispatcher_incarnation", "session_id",
}

var listDebugletsEndAfterQuery = regexp.QuoteMeta(
	"SELECT id, uuid, start_time, end_time, usage, ceil_bw, executor_id, addresses, state, error, transaction_id, order_id, dispatcher_incarnation, session_id FROM debuglets WHERE end_time > ?",
)

// RegisterExecutor calls PaymentHandler.CreateEarningsIfNotExists, which looks
// up the executor's earnings row (GetEarningsIn) and inserts one when the lookup
// returns sql.ErrNoRows (CreateEarnings). Both queries are part of the exact
// fixture so that no database access goes unnoticed by ExpectationsWereMet.
var (
	earningsColumns    = []string{"executor_id", "currency", "total_income", "current_balance", "sui_wallet_address"}
	getEarningsInQuery = regexp.QuoteMeta(
		"SELECT executor_id, currency, total_income, current_balance, sui_wallet_address FROM earnings WHERE executor_id = ? AND currency = ?",
	)
	createEarningsQuery = regexp.QuoteMeta(
		"INSERT INTO earnings (executor_id, currency, sui_wallet_address, total_income, current_balance) VALUES (?,?,?,0,0) RETURNING executor_id, currency, total_income, current_balance, sui_wallet_address",
	)
)

// errSentinelInsert is returned by the mocked INSERT. Reaching the INSERT proves
// that admission (validateDebugletSpec) accepted the request, without needing a
// connected executor transport for the subsequent upload.
var errSentinelInsert = errors.New("sentinel: insert reached")

// restoredRow describes one debuglets row returned by the restore query.
type restoredRow struct {
	start time.Time
	end   time.Time
	usage resource.Bitrate
}

// TestRestoreSchedulerAdmission verifies that reservations restored from the
// database on dispatcher start are applied to resource admission: overlapping
// requests that exceed the executor capacity are rejected before any database
// write, while requests that fit (non-overlapping, or within the remaining
// capacity) are admitted. A control case without restored rows admits the
// request that the restored case rejects.
func TestRestoreSchedulerAdmission(t *testing.T) {
	// Fixed reference time well in the future so validateDebugletSpec keeps the
	// requested start time (it resets past start times to "now").
	start := time.Now().Add(time.Hour).Truncate(time.Second)
	restoredEnd := start.Add(10 * time.Second)

	cases := []struct {
		name     string
		restored []restoredRow
		reqStart time.Time
		reqFloor resource.Bitrate
		admitted bool
	}{
		{
			name:     "restored full reservation rejects overlapping request",
			restored: []restoredRow{{start, restoredEnd, testCapacity}},
			reqStart: start,
			reqFloor: testCapacity,
			admitted: false,
		},
		{
			name:     "restored full reservation admits non-overlapping request",
			restored: []restoredRow{{start, restoredEnd, testCapacity}},
			reqStart: start.Add(2 * time.Hour),
			reqFloor: testCapacity,
			admitted: true,
		},
		{
			name:     "restored partial reservation admits request within remaining capacity",
			restored: []restoredRow{{start, restoredEnd, 400 * resource.Megabit}},
			reqStart: start,
			reqFloor: 600 * resource.Megabit,
			admitted: true,
		},
		{
			name:     "restored partial reservation rejects request exceeding remaining capacity",
			restored: []restoredRow{{start, restoredEnd, 400 * resource.Megabit}},
			reqStart: start,
			reqFloor: 600*resource.Megabit + resource.Bit,
			admitted: false,
		},
		{
			name: "multiple restored reservations are aggregated",
			restored: []restoredRow{
				{start, restoredEnd, 300 * resource.Megabit},
				{start, restoredEnd, 300 * resource.Megabit},
			},
			reqStart: start,
			reqFloor: 500 * resource.Megabit,
			admitted: false,
		},
		{
			name:     "control: no restored reservations admit overlapping full request",
			restored: nil,
			reqStart: start,
			reqFloor: testCapacity,
			admitted: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := t.Context()
			d, mock := newRestoredDispatcher(t, tc.restored)

			if tc.admitted {
				// Admission passed: the dispatcher opens a transaction and
				// inserts the debuglet. The sentinel error aborts the flow
				// before any upload; the deferred tx.Rollback follows.
				mock.ExpectBegin()
				mock.ExpectQuery(regexp.QuoteMeta("INSERT INTO debuglets")).WillReturnError(errSentinelInsert)
				mock.ExpectRollback()
			}

			reqStart := tc.reqStart
			ids, err := d.SubmitDebuglets(ctx, []models.DebugletSpec{{
				StartTime:     &reqStart,
				ExecutorID:    testExecutorID,
				TransactionID: "tx",
				Policy: models.DebugletPolicy{
					FloorBW: tc.reqFloor,
					CeilBW:  tc.reqFloor,
					Timeout: testTimeout,
				},
			}}, nil)
			if err == nil {
				t.Fatalf("SubmitDebuglets returned no error (ids=%v); expected a rejection or the sentinel insert error", ids)
			}
			if ids != nil {
				t.Fatalf("SubmitDebuglets returned ids %v alongside error %v", ids, err)
			}

			if tc.admitted {
				if errors.Is(err, resource.ErrCapacityFull) {
					t.Fatalf("request was rejected for capacity but should have been admitted: %v", err)
				}
				if !errors.Is(err, errSentinelInsert) {
					t.Fatalf("expected sentinel insert error proving admission, got: %v", err)
				}
			} else {
				if !errors.Is(err, resource.ErrCapacityFull) {
					t.Fatalf("expected ErrCapacityFull, got: %v", err)
				}
				if errors.Is(err, errSentinelInsert) {
					t.Fatalf("rejected request must not reach the database insert: %v", err)
				}
			}

			// Rejections must not touch the database beyond the fixture issued
			// during setup (restore SELECT, earnings lookup and insert);
			// admissions must have performed exactly Begin/INSERT/Rollback.
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatalf("unmet sqlmock expectations: %v", err)
			}
		})
	}
}

// newRestoredDispatcher builds a dispatcher backed by sqlmock, restores the
// given rows through RestoreScheduler and registers executor testExecutorID
// with capacity testCapacity via the direct registry callbacks (no transport).
func newRestoredDispatcher(t *testing.T, restored []restoredRow) (*dispatcher.Dispatcher, sqlmock.Sqlmock) {
	t.Helper()
	ctx := t.Context()

	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create sqlmock: %v", err)
	}
	t.Cleanup(func() {
		mock.ExpectClose()
		if err := db.Close(); err != nil {
			t.Errorf("failed to close mock db: %v", err)
		}
	})

	d, err := dispatcher.New(zap.NewNop(), db, "test", time.Minute, time.Minute, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(d.Close)

	rows := sqlmock.NewRows(debugletColumns)
	for i, r := range restored {
		rows.AddRow(
			int64(i+1),                      // id
			uuid.New(),                      // uuid (driver.Valuer -> string)
			r.start,                         // start_time (UTCTime.Scan accepts time.Time)
			r.end,                           // end_time
			int64(r.usage),                  // usage
			int64(testCapacity),             // ceil_bw
			testExecutorID,                  // executor_id
			nil,                             // addresses (CommaSeparatedList.Scan accepts nil)
			int64(models.RunStateUploading), // state
			nil,                             // error (sql.NullString)
			"tx",                            // transaction_id
			int64(0),                        // order_id
			"", "",                          // historical rows remain reserved in the dispatcher
		)
	}
	mock.ExpectQuery(listDebugletsEndAfterQuery).WillReturnRows(rows)

	if err := d.RestoreScheduler(ctx); err != nil {
		t.Fatalf("failed to restore scheduler: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("restore did not issue the expected query: %v", err)
	}

	// First registration of this executor: the earnings lookup finds no row
	// and the earnings record is created.
	mock.ExpectQuery(getEarningsInQuery).
		WithArgs(testExecutorID, testCurrency).
		WillReturnError(sql.ErrNoRows)
	mock.ExpectQuery(createEarningsQuery).
		WithArgs(testExecutorID, testCurrency, testWallet).
		WillReturnRows(sqlmock.NewRows(earningsColumns).AddRow(testExecutorID, testCurrency, int64(0), int64(0), testWallet))

	binding, err := controlsession.NewBinding(d.ControlIncarnation())
	if err != nil {
		t.Fatal(err)
	}
	owner, err := rpc.NewSessionOwner(testExecutorID, binding, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	wallet := testWallet
	// Registration runs under the setup operation the transport admits for it.
	setup, err := owner.AdmitSetup(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := d.RegisterExecutor(setup.Context(), owner, &protocol.HelloResponse{
		ExecutorId: testExecutorID, Version: "test", Currency: testCurrency, SuiWallet: &wallet,
	}, "127.0.0.1"); err != nil {
		t.Fatalf("register executor: %v", err)
	}
	setup.Finish()
	// This isolated registry fixture has no callback transport to mark completion.
	if !owner.MarkRegistered() {
		t.Fatal("executor owner retired before registration completed")
	}
	if _, ok := d.GetExecutor(testExecutorID); !ok {
		t.Fatalf("executor %q not registered", testExecutorID)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("registration did not issue the expected earnings queries: %v", err)
	}
	mutation, err := owner.AdmitMutation(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer mutation.Finish()
	if _, err := d.OnResources(ctx, mutation, &protocol.ResourcesRequest{
		ExecutorId:        testExecutorID,
		BandwidthCapacity: int64(testCapacity),
	}); err != nil {
		t.Fatalf("failed to set executor capacity: %v", err)
	}

	return d, mock
}
