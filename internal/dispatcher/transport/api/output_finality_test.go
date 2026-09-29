// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package api

import (
	"database/sql"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
	"github.com/netsec-ethz/debuglet/internal/dispatcher"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/config"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/database"
	"github.com/netsec-ethz/debuglet/pkg/client"
	"go.uber.org/zap"
)

func TestLogOutputFinalityWithSQLite(t *testing.T) {
	f := ccNewFixture(t)
	c := f.client(f.root.URL, false)
	f.peer.setUploadHook(f.exitHook(0, nil))
	for _, tc := range []struct {
		name, status, reason, want string
		version                    int64
		chunks                     [][]byte
	}{
		{name: "historical without metadata", want: "unknown"},
		{name: "legacy pending", status: "pending", want: "unknown"},
		{name: "terminal with pending output", version: 1, status: "pending", want: "pending", chunks: [][]byte{[]byte("prefix")}},
		{name: "empty complete", version: 1, status: "complete", want: "complete"},
		{name: "full final page", version: 1, status: "complete", want: "complete", chunks: [][]byte{{0, 255}, []byte("tail")}},
		{name: "truncated", version: 1, status: "truncated", reason: "executor_interrupted", want: "truncated", chunks: [][]byte{[]byte("prefix")}},
		{name: "legacy quota truncation", status: "truncated", reason: "storage_limit", want: "truncated", chunks: [][]byte{[]byte("legacy")}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sub := f.submit(c, nil)
			id := uuid.MustParse(sub.IDs[0])
			ids := f.seedLogs(sub.IDs[0], tc.chunks)
			// Establish each persisted compatibility shape without a stream or
			// terminal callback manufacturing output completeness.
			if _, err := f.db.ExecContext(f.ctx, "DELETE FROM debuglet_output WHERE debuglet_id = (SELECT id FROM debuglets WHERE uuid = ?)", id); err != nil {
				t.Fatal(err)
			}
			var final int64
			if len(ids) > 0 {
				final = ids[len(ids)-1]
			}
			if tc.status != "" {
				if err := f.queries.CreateDebugletOutput(f.ctx, database.CreateDebugletOutputParams{Uuid: id, OutputVersion: tc.version}); err != nil {
					t.Fatal(err)
				}
				if tc.status != "pending" {
					_, err := f.db.ExecContext(f.ctx, "UPDATE debuglet_output SET status = ?, reason = ?, final_sequence = committed_sequence, final_cursor = last_log_id WHERE debuglet_id = (SELECT id FROM debuglets WHERE uuid = ?)", tc.status, tc.reason, id)
					if err != nil {
						t.Fatal(err)
					}
				}
			}
			var cursor int64
			for i := 0; i <= len(ids); i++ {
				page, err := c.Logs(f.ctx, sub.IDs[0], client.LogOptions{After: cursor, Limit: 1})
				if err != nil {
					t.Fatal(err)
				}
				if page.State != client.StateExited || page.Output.State != tc.want || page.Output.LossReason != tc.reason {
					t.Fatalf("page: %+v", page)
				}
				if tc.want == "complete" || tc.want == "truncated" {
					if page.Output.FinalCursor == nil || *page.Output.FinalCursor != final {
						t.Fatalf("finality: %+v, want cursor %d", page.Output, final)
					}
				} else if page.Output.FinalCursor != nil {
					t.Fatalf("nonfinal cursor: %+v", page.Output)
				}
				if i < len(ids) && (len(page.Logs) != 1 || page.Logs[0].ID != ids[i] || !page.HasMore) {
					t.Fatalf("page %d: %+v", i, page)
				}
				cursor = page.After
			}
		})
	}
}

func TestLogSnapshotFailuresDoNotReturnOutput(t *testing.T) {
	id := uuid.MustParse(logsPaginationID)
	for _, phase := range []string{"begin", "metadata", "commit"} {
		t.Run(phase, func(t *testing.T) {
			e, mock := newLogsPaginationServer(t)
			failure := errors.New("private database detail")
			begin := mock.ExpectBegin()
			if phase == "begin" {
				begin.WillReturnError(failure)
			} else {
				mock.ExpectQuery(logsPaginationListQuery).WithArgs(id, int64(0), int64(100)).WillReturnRows(sqlmock.NewRows([]string{"id", "debuglet_id", "timestamp", "output", "source_sequence"}))
				mock.ExpectQuery(logsPaginationGetQuery).WithArgs(id).WillReturnRows(debugletPaginationRow(id))
				metadata := mock.ExpectQuery(logsPaginationOutputQuery).WithArgs(id)
				if phase == "metadata" {
					metadata.WillReturnError(failure)
					mock.ExpectRollback()
				} else {
					metadata.WillReturnError(sql.ErrNoRows)
					mock.ExpectCommit().WillReturnError(failure)
				}
			}
			rec := serveLogsPaginationRequest(e, "")
			if rec.Code != http.StatusInternalServerError || strings.Contains(rec.Body.String(), "private database") || strings.Contains(rec.Body.String(), `"output":`) {
				t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestOutputCapacityRefusalReachesHTTPClients(t *testing.T) {
	// Node and account caps are opt-in; this operator set a node cap.
	peer := &cpPeer{id: ccExecutorID, price: ccPricePerBwS, currency: "TEST"}
	f := ccNewFixtureConfigured(t, zap.NewNop(), peer, func(d *dispatcher.Dispatcher) error {
		limits := config.DefaultOutputConfig()
		limits.NodeBytes = 1 << 30
		return d.ConfigureOutputLimits(limits)
	}, LocalDevelopment(true))
	c := f.client(f.root.URL, false)
	if _, err := f.db.ExecContext(f.ctx, "UPDATE output_node_usage SET charged_bytes = ? WHERE singleton = 1", int64(1)<<40); err != nil {
		t.Fatal(err)
	}
	batch, err := client.Prepare([]client.Request{ccRequest(nil)})
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.SubmitTEST(f.ctx, batch)
	var httpErr *client.HTTPError
	if !errors.As(err, &httpErr) || httpErr.StatusCode != http.StatusServiceUnavailable || httpErr.Code != CodeUnavailable || httpErr.Message != "output storage capacity exhausted" {
		t.Fatalf("capacity refusal: %v", err)
	}
	if f.peer.uploadCount() != 0 {
		t.Fatal("refused output capacity uploaded a workload")
	}
	var count int
	if err := f.db.QueryRowContext(f.ctx, "SELECT COUNT(*) FROM debuglets").Scan(&count); err != nil || count != 0 {
		t.Fatalf("refused runs=%d, err=%v", count, err)
	}
}
