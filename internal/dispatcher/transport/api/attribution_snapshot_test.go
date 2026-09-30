// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package api

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/labstack/echo/v4"
	"go.uber.org/zap"
	"modernc.org/sqlite"
)

func TestAttributionCandidatesKeepRetentionSnapshotDuringPrune(t *testing.T) {
	f := atFixture(t)
	_, _, owner := authAccount(t, f, "snapshot owner")
	f.peer.setUploadHook(nil)
	submission := f.submit(owner, []string{"snapshot"})
	ctx, cancel := f.requestCtx()
	defer cancel()
	retainedBefore, err := f.queries.GetAttributionRetention(ctx)
	if err != nil {
		t.Fatal(err)
	}
	// A separate WAL connection lets the ordinary retention writer commit
	// while the reader holds its snapshot, without scheduling sleeps.
	var mode, name, path string
	var sequence int
	if err := f.db.QueryRowContext(ctx, `PRAGMA journal_mode=WAL`).Scan(&mode); err != nil || mode != "wal" {
		t.Fatalf("enable WAL: %q, %v", mode, err)
	}
	if err := f.db.QueryRowContext(ctx, `PRAGMA database_list`).Scan(&sequence, &name, &path); err != nil {
		t.Fatal(err)
	}
	at := time.Now().UTC()
	future := at.Add(100 * 24 * time.Hour)
	pruned := false
	reader := sql.OpenDB(&attributionSnapshotConnector{
		path: path,
		afterRetention: func() error {
			if pruned {
				return nil
			}
			pruned = true
			return f.d.PruneAttribution(ctx, future)
		},
	})
	t.Cleanup(func() { _ = reader.Close() })
	reader.SetMaxOpenConns(1)
	h := NewHandler(f.d, reader, zap.NewNop())
	e := echo.New()
	lookup := func() AttributionCandidatesResponse {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, "/attribution/candidates?ip=127.0.0.1&at="+at.Format(time.RFC3339Nano), nil).WithContext(ctx)
		rec := httptest.NewRecorder()
		if err := h.GetAttributionCandidates(e.NewContext(req, rec)); err != nil {
			t.Fatal(err)
		}
		var doc AttributionCandidatesResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil || rec.Code != http.StatusOK {
			t.Fatalf("lookup: status=%d, decode=%v", rec.Code, err)
		}
		return doc
	}
	before := lookup()
	if !pruned || !before.RetainedFrom.Equal(time.Unix(0, retainedBefore)) || len(before.Candidates) != 1 || before.Candidates[0].RunID != submission.IDs[0] {
		t.Fatalf("lookup mixed snapshots: pruned=%v, response=%+v", pruned, before)
	}
	// The following request sees the completed prune, with the coverage
	// marker that explains why the previously retained run is absent.
	after := lookup()
	if len(after.Candidates) != 0 || !after.RetainedFrom.Equal(future.Add(-90*24*time.Hour)) {
		t.Fatalf("lookup after prune=%+v", after)
	}
}

// The connector closes the retention cursor before running the writer. A
// transaction keeps the SQLite snapshot alive across the next query; two
// independent queries would instead see the pruned rows with the old marker.
type attributionSnapshotConnector struct {
	path           string
	afterRetention func() error
}

func (c *attributionSnapshotConnector) Driver() driver.Driver { return &sqlite.Driver{} }

func (c *attributionSnapshotConnector) Connect(context.Context) (driver.Conn, error) {
	conn, err := c.Driver().Open(c.path)
	if err != nil {
		return nil, err
	}
	return &attributionSnapshotConn{Conn: conn, afterRetention: c.afterRetention}, nil
}

type attributionSnapshotConn struct {
	driver.Conn
	afterRetention func() error
}

func (c *attributionSnapshotConn) BeginTx(ctx context.Context, opts driver.TxOptions) (driver.Tx, error) {
	return c.Conn.(driver.ConnBeginTx).BeginTx(ctx, opts)
}

func (c *attributionSnapshotConn) QueryContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	rows, err := c.Conn.(driver.QueryerContext).QueryContext(ctx, query, args)
	if err != nil || !strings.HasPrefix(query, "-- name: GetAttributionRetention ") {
		return rows, err
	}
	return &attributionSnapshotRows{Rows: rows, afterClose: c.afterRetention}, nil
}

type attributionSnapshotRows struct {
	driver.Rows
	afterClose func() error
}

func (r *attributionSnapshotRows) Close() error {
	if err := r.Rows.Close(); err != nil {
		return err
	}
	return r.afterClose()
}
