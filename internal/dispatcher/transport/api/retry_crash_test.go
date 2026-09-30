// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package api

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/netsec-ethz/debuglet/internal/dispatcher"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/config"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/database"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/payments"
	"github.com/netsec-ethz/debuglet/internal/sqlitedb"
	"github.com/netsec-ethz/debuglet/protocol"
	"go.uber.org/zap"
	"modernc.org/sqlite"
)

// The owned subprocess exits after SQLite's real admission Commit succeeds,
// before database/sql can return to SubmitDebuglets and begin its upload phase.
// Only the test driver is wrapped; production construction is unchanged.
type retryCommitConnector struct {
	path  string
	armed *atomic.Bool
}

func (c retryCommitConnector) Driver() driver.Driver { return &sqlite.Driver{} }
func (c retryCommitConnector) Connect(ctx context.Context) (driver.Conn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	conn, err := c.Driver().Open(c.path)
	if err != nil {
		return nil, err
	}
	return &retryCommitConn{Conn: conn, armed: c.armed}, nil
}

type retryCommitConn struct {
	driver.Conn
	armed     *atomic.Bool
	admission bool
}

func (c *retryCommitConn) Begin() (driver.Tx, error) {
	tx, err := c.Conn.Begin()
	if err != nil {
		return nil, err
	}
	c.admission = false
	return &retryCommitTx{Tx: tx, conn: c}, nil
}
func (c *retryCommitConn) ExecContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Result, error) {
	result, err := c.Conn.(driver.ExecerContext).ExecContext(ctx, query, args)
	if err == nil && strings.HasPrefix(query, "-- name: CreateDebugletProvenance ") {
		c.admission = true
	}
	return result, err
}
func (c *retryCommitConn) QueryContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	return c.Conn.(driver.QueryerContext).QueryContext(ctx, query, args)
}

type retryCommitTx struct {
	driver.Tx
	conn *retryCommitConn
}

func (t *retryCommitTx) Commit() error {
	err := t.Tx.Commit()
	if err == nil && t.conn.admission && t.conn.armed.Load() {
		os.Exit(73)
	}
	return err
}

func retryProcessFixture(t *testing.T, db *sql.DB) *ccFixture {
	t.Helper()
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	logger := zap.NewNop()
	ph := payments.NewPaymentHandler(db, &config.DispatcherConfig{Sui: config.SuiConfig{Disabled: true}}, logger)
	d, err := dispatcher.New(logger, db, "retry-crash", time.Minute, time.Minute, ph)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(d.Close)
	peer := &cpPeer{id: ccExecutorID, price: ccPricePerBwS, currency: "TEST"}
	stop, err := startClientPeer(ctx, d, ccCapacity, peer)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cancel()
		cleanup, done := context.WithTimeout(context.Background(), ccCleanupBound)
		defer done()
		if err := stop(cleanup); err != nil {
			t.Error(err)
		}
	})
	e := echo.New()
	NewHandler(d, db, logger).RegisterRoutes(e)
	server := httptest.NewServer(e)
	t.Cleanup(server.Close)
	return &ccFixture{t: t, ctx: ctx, db: db, queries: database.New(db), d: d, peer: peer, root: server}
}

type retryCrashRequest struct {
	Parent, Key, Token string
	Original           database.Debuglet
}

func TestRetryCommitProcessLoss(t *testing.T) {
	const marker = "DEBUGLET_RETRY_CRASH_PATH"
	if path := os.Getenv(marker); path != "" {
		var armed atomic.Bool
		db := sql.OpenDB(retryCommitConnector{path: path, armed: &armed})
		db.SetMaxOpenConns(1)
		t.Cleanup(func() { _ = db.Close() })
		if _, err := db.Exec("PRAGMA foreign_keys=ON"); err != nil {
			t.Fatal(err)
		}
		if _, err := sqlitedb.Migrate(t.Context(), db, database.MigrationFS(), sqlitedb.Latest); err != nil {
			t.Fatal(err)
		}
		f := retryProcessFixture(t, db)
		_, token, owner := authAccount(t, f, "crash owner")
		parent := f.submit(owner, []string{"original"}).IDs[0]
		original, err := f.queries.GetDebugletByUUID(f.ctx, uuid.MustParse(parent))
		if err != nil {
			t.Fatal(err)
		}
		saved := retryCrashRequest{Parent: parent, Key: uuid.NewString(), Token: token, Original: original}
		encoded, err := json.Marshal(saved)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path+".request", encoded, 0600); err != nil {
			t.Fatal(err)
		}
		// Any child upload means the precise commit boundary was missed.
		f.peer.setUploadHook(func(context.Context, *protocol.UploadRequest) error { os.Exit(74); return nil })
		armed.Store(true)
		_, _ = owner.RetryTEST(f.ctx, parent, saved.Key, retryBatch(t))
		t.Fatal("admission did not stop after Commit")
	}
	path := filepath.Join(t.TempDir(), "dispatcher.sqlite")
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestRetryCommitProcessLoss$")
	command.Env = append(os.Environ(), marker+"="+path)
	output, err := command.CombinedOutput()
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 73 || ctx.Err() != nil {
		t.Fatalf("commit-boundary child: %v; %s", err, output)
	}
	encoded, err := os.ReadFile(path + ".request")
	if err != nil {
		t.Fatal(err)
	}
	var saved retryCrashRequest
	if err := json.Unmarshal(encoded, &saved); err != nil {
		t.Fatal(err)
	}
	db, err := sqlitedb.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	f := retryProcessFixture(t, db)
	owner, err := f.client(f.root.URL, false).WithCredential(saved.Token)
	if err != nil {
		t.Fatal(err)
	}
	var admitted string
	if err := db.QueryRow("SELECT d.uuid FROM retry_requests r JOIN debuglet_order o ON o.transaction_id=r.transaction_id JOIN debuglets d ON d.id=o.debuglet_id WHERE r.request_id=?", saved.Key).Scan(&admitted); err != nil || admitted == saved.Parent {
		t.Fatalf("committed child missing: %v", err)
	}
	result, err := owner.RetryTEST(f.ctx, saved.Parent, saved.Key, retryBatch(t))
	if err != nil || len(result.IDs) != 1 || result.IDs[0] != admitted {
		t.Fatalf("committed receipt not recovered: %v", err)
	}
	after, err := f.queries.GetDebugletByUUID(f.ctx, uuid.MustParse(saved.Parent))
	if err != nil || !reflect.DeepEqual(after, saved.Original) {
		t.Fatal("parent changed during crash or recovery")
	}
	if f.peer.uploadCount() != 0 || iaCount(t, db, "debuglets") != 2 || iaCount(t, db, "transactions") != 2 || iaCount(t, db, "retry_requests") != 1 {
		t.Fatal("crash recovery uploaded or admitted another attempt")
	}
}
