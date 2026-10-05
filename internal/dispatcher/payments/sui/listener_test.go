// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package sui_test

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/netsec-ethz/debuglet/internal/dispatcher/config"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/database"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/models"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/payments"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/payments/sui"
	"github.com/netsec-ethz/debuglet/internal/sqlitedb"

	suiModels "github.com/block-vision/sui-go-sdk/models"
	"github.com/block-vision/sui-go-sdk/mystenbcs"
	v2 "github.com/block-vision/sui-go-sdk/pb/sui/rpc/v2"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
	"google.golang.org/protobuf/proto"
	_ "modernc.org/sqlite"
)

const (
	testPackage = "0x5ca1ab1e"
	eventType   = testPackage + "::payment_kit::PaymentReceipt"
	cursorKey   = "sui_event_cursor:" + testPackage
	price       = 7
)

var (
	ourAddress   = strings.Repeat("ab", 32)
	otherAddress = strings.Repeat("cd", 32)
	// The chain reports coin types without the 0x prefix.
	usdcType = strings.TrimPrefix(sui.GetCoinType("USDC", "testnet"), "0x")
)

// registryPayment and receiptEvent mirror the payment kit's PaymentReceipt
// event layout, so fixtures are encoded the way the chain encodes them.
type registryPayment struct {
	Ephemeral any
	Registry  *suiModels.SuiAddressBytes
}

func (*registryPayment) IsBcsEnum() {}

type receiptEvent struct {
	PaymentType   *registryPayment
	Nonce         string
	PaymentAmount uint64
	Receiver      suiModels.SuiAddressBytes
	CoinType      string
	TimestampMs   uint64
}

func receipt(nonce string, edit ...func(*receiptEvent)) receiptEvent {
	ev := receiptEvent{
		PaymentType:   &registryPayment{Registry: &suiModels.SuiAddressBytes{1}},
		Nonce:         nonce,
		PaymentAmount: price,
		Receiver:      address(ourAddress),
		CoinType:      usdcType,
		TimestampMs:   uint64(time.Now().UnixMilli()),
	}
	for _, e := range edit {
		e(&ev)
	}
	return ev
}

func address(h string) suiModels.SuiAddressBytes {
	var a suiModels.SuiAddressBytes
	b, err := hex.DecodeString(h)
	if err != nil || len(b) != len(a) {
		panic("bad fixture address " + h)
	}
	copy(a[:], b)
	return a
}

func encode(t *testing.T, ev receiptEvent) []byte {
	t.Helper()
	b, err := mystenbcs.Marshal(ev)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// event is one GraphQL event node.
type event struct {
	digest string
	bcs    []byte
}

func node(t *testing.T, digest string, ev receiptEvent) event {
	t.Helper()
	return event{digest: digest, bcs: encode(t, ev)}
}

// graphQL serves PaymentReceipt events in pages, linked by endCursor.
type graphQL struct {
	mu      sync.Mutex
	pages   [][]event
	queries []map[string]any
}

func (g *graphQL) setPages(pages ...[]event) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.pages = pages
}

func (g *graphQL) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Variables map[string]any `json:"variables"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	g.queries = append(g.queries, req.Variables)
	index := 0
	if after, ok := req.Variables["after"].(string); ok {
		fmt.Sscanf(after, "page-%d", &index)
	}
	type nodeJSON struct {
		Transaction struct {
			Digest string `json:"digest"`
		} `json:"transaction"`
		Contents struct {
			Bcs string `json:"bcs"`
		} `json:"contents"`
	}
	nodes := []nodeJSON{}
	if index < len(g.pages) {
		for _, ev := range g.pages[index] {
			var n nodeJSON
			n.Transaction.Digest = ev.digest
			n.Contents.Bcs = base64.StdEncoding.EncodeToString(ev.bcs)
			nodes = append(nodes, n)
		}
	}
	resp := map[string]any{"data": map[string]any{"events": map[string]any{
		"pageInfo": map[string]any{"hasNextPage": index+1 < len(g.pages), "endCursor": fmt.Sprintf("page-%d", index+1)},
		"nodes":    nodes,
	}}}
	_ = json.NewEncoder(w).Encode(resp)
}

type fixture struct {
	db     *sql.DB
	cfg    *config.DispatcherConfig
	server *graphQL
	core   zapcore.Core
	logs   *observer.ObservedLogs
	ph     *payments.PaymentHandler
}

// newFixture is a real dispatcher database, an enabled payment handler as the
// listener's fulfiller and a local GraphQL server. No chain endpoint is
// contacted: the gRPC client is never used and the keystore does not exist.
func newFixture(t *testing.T) *fixture {
	t.Helper()
	db, err := sqlitedb.Open(filepath.Join(t.TempDir(), "dispatcher.sqlite"), sqlitedb.Create())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := sqlitedb.Migrate(t.Context(), db, database.MigrationFS(), sqlitedb.Latest); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	server := &graphQL{}
	httpServer := httptest.NewServer(server)
	t.Cleanup(httpServer.Close)
	cfg := &config.DispatcherConfig{Sui: config.SuiConfig{
		Network:           "testnet",
		GRPCEndpoint:      "fullnode.invalid:443",
		GraphQLURL:        httpServer.URL,
		Address:           "0x" + strings.ToUpper(ourAddress),
		PaymentKitPackage: testPackage,
		KeystorePath:      filepath.Join(t.TempDir(), "missing.keystore"),
	}}
	core, logs := observer.New(zapcore.InfoLevel)
	return &fixture{db: db, cfg: cfg, server: server, core: core, logs: logs, ph: payments.NewPaymentHandler(db, cfg, zap.New(core))}
}

// listener is a fresh listener, as after a dispatcher restart.
func (f *fixture) listener() *sui.Listener {
	return sui.NewListener(f.cfg, f.db, zap.New(f.core), f.ph)
}

func (f *fixture) transaction(t *testing.T, id string, expires time.Time) {
	t.Helper()
	if _, err := database.New(f.db).CreateTransaction(t.Context(), database.CreateTransactionParams{
		ID: id, AuthKey: "key", Price: price, Currency: "USDC", Method: "USDC",
		ExpiresAt: models.NewUTCTime(expires), Status: int64(models.Outstanding), Hash: "hash",
	}); err != nil {
		t.Fatal(err)
	}
}

func (f *fixture) status(t *testing.T, id string) models.TransactionState {
	t.Helper()
	transaction, err := database.New(f.db).GetTransactionByID(t.Context(), id)
	if err != nil {
		t.Fatal(err)
	}
	return models.TransactionState(transaction.Status)
}

func (f *fixture) setCursor(t *testing.T, value string) {
	t.Helper()
	if _, err := database.New(f.db).UpdateTransactionState(t.Context(), database.UpdateTransactionStateParams{Key: cursorKey, Value: value}); err != nil {
		t.Fatal(err)
	}
}

func (f *fixture) cursor(t *testing.T) string {
	t.Helper()
	state, err := database.New(f.db).GetTransactionState(t.Context(), cursorKey)
	if err != nil {
		t.Fatal(err)
	}
	return state.Value
}

// receipts returns "digest/nonce=disposition:detail:amount" for every row.
func (f *fixture) receipts(t *testing.T) []string {
	t.Helper()
	rows, err := f.db.QueryContext(t.Context(), "SELECT tx_digest, nonce, disposition, detail, amount FROM payment_receipts ORDER BY tx_digest, nonce")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var digest, nonce, disposition, detail, amount string
		if err := rows.Scan(&digest, &nonce, &disposition, &detail, &amount); err != nil {
			t.Fatal(err)
		}
		out = append(out, fmt.Sprintf("%s/%s=%s:%s:%s", digest, nonce, disposition, detail, amount))
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

// dispositions returns the dispositions the listener logged since the last
// call, in order.
func (f *fixture) dispositions() []string {
	var out []string
	for _, entry := range f.logs.TakeAll() {
		if entry.Message == "payment receipt recorded" {
			out = append(out, entry.ContextMap()["tx"].(string)+"="+entry.ContextMap()["disposition"].(string))
		}
	}
	return out
}

func equal(t *testing.T, what string, got, want []string) {
	t.Helper()
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("%s:\n got %q\nwant %q", what, got, want)
	}
}

func TestCatchUpAppliesEachReceiptOnce(t *testing.T) {
	f := newFixture(t)
	f.transaction(t, "tx-a", time.Now().Add(time.Hour))
	f.transaction(t, "tx-b", time.Now().Add(time.Hour))
	pageOne := []event{node(t, "d1", receipt("tx-a")), node(t, "d2", receipt("tx-b"))}
	pageTwo := []event{node(t, "d1", receipt("tx-a")), node(t, "d3", receipt("tx-a"))}
	f.server.setPages(pageOne, pageTwo)

	if err := f.listener().CatchUpRange(t.Context(), 10, 20); err != nil {
		t.Fatal(err)
	}
	equal(t, "first pass", f.dispositions(), []string{"d1=applied", "d2=applied", "d1=duplicate", "d3=mismatch"})
	if f.status(t, "tx-a") != models.Paid || f.status(t, "tx-b") != models.Paid || f.cursor(t) != "20" {
		t.Fatalf("after first pass: a=%v b=%v cursor=%s", f.status(t, "tx-a"), f.status(t, "tx-b"), f.cursor(t))
	}
	want := []string{"d1/tx-a=applied::7", "d2/tx-b=applied::7", "d3/tx-a=mismatch:already paid by d1:7"}
	equal(t, "rows", f.receipts(t), want)
	f.server.mu.Lock()
	after := f.server.queries[0]["afterCheckpoint"]
	f.server.mu.Unlock()
	if after != float64(10) {
		t.Fatalf("queried after checkpoint %v", after)
	}

	// A restart reads the same events again, in another order.
	f.server.setPages(pageTwo, pageOne)
	if err := f.listener().CatchUpRange(t.Context(), 20, 30); err != nil {
		t.Fatal(err)
	}
	equal(t, "after restart", f.dispositions(), []string{"d1=duplicate", "d3=mismatch", "d1=duplicate", "d2=duplicate"})
	equal(t, "rows after restart", f.receipts(t), want)
	if f.cursor(t) != "30" {
		t.Fatalf("cursor %s", f.cursor(t))
	}
}

func TestCatchUpRecordsRejectedReceipts(t *testing.T) {
	f := newFixture(t)
	for _, id := range []string{"amount", "huge", "coin", "receiver"} {
		f.transaction(t, id, time.Now().Add(time.Hour))
	}
	f.transaction(t, "late", time.Now().Add(-time.Minute))
	f.server.setPages([]event{
		node(t, "d1", receipt("amount", func(ev *receiptEvent) { ev.PaymentAmount = price + 1 })),
		node(t, "d2", receipt("huge", func(ev *receiptEvent) { ev.PaymentAmount = math.MaxUint64 })),
		node(t, "d3", receipt("coin", func(ev *receiptEvent) {
			ev.CoinType = "0000000000000000000000000000000000000000000000000000000000000002::sui::SUI"
		})),
		node(t, "d4", receipt("receiver", func(ev *receiptEvent) { ev.Receiver = address(otherAddress) })),
		node(t, "d5", receipt("late")),
		node(t, "d6", receipt("nobody")),
		node(t, "d7", receipt("nobody", func(ev *receiptEvent) { ev.Receiver = address(otherAddress) })),
	})

	if err := f.listener().CatchUpRange(t.Context(), 0, 5); err != nil {
		t.Fatal(err)
	}
	equal(t, "rows", f.receipts(t), []string{
		"d1/amount=mismatch:amount:8",
		"d2/huge=mismatch:amount:18446744073709551615",
		"d3/coin=mismatch:coin type:7",
		"d4/receiver=mismatch:receiver:7",
		"d5/late=expired::7",
		"d6/nobody=unknown_intent::7",
	})
	for _, id := range []string{"amount", "huge", "coin", "receiver", "late"} {
		if f.status(t, id) != models.Outstanding {
			t.Fatalf("%s was paid by a rejected receipt", id)
		}
	}
	if f.cursor(t) != "5" {
		t.Fatalf("cursor %s", f.cursor(t))
	}
}

// A receipt that cannot be recorded stops the pass and keeps the cursor, so
// the same range is read again and nothing is lost or applied twice.
func TestCatchUpFailureKeepsCursor(t *testing.T) {
	f := newFixture(t)
	f.transaction(t, "tx-a", time.Now().Add(time.Hour))
	f.transaction(t, "tx-b", time.Now().Add(time.Hour))
	f.setCursor(t, "10")
	f.server.setPages([]event{node(t, "d1", receipt("tx-a"))}, []event{node(t, "d2", receipt("tx-b"))})
	if _, err := f.db.Exec(`CREATE TRIGGER fail_receipt BEFORE INSERT ON payment_receipts WHEN NEW.nonce = 'tx-b'
BEGIN SELECT RAISE(ABORT, 'scripted receipt failure'); END`); err != nil {
		t.Fatal(err)
	}

	err := f.listener().CatchUpRange(t.Context(), 10, 20)
	if err == nil || !strings.Contains(err.Error(), "scripted receipt failure") {
		t.Fatalf("catch-up with a failing write: %v", err)
	}
	if f.cursor(t) != "10" || f.status(t, "tx-b") != models.Outstanding {
		t.Fatalf("failed pass: cursor %s, tx-b %v", f.cursor(t), f.status(t, "tx-b"))
	}
	equal(t, "rows after failure", f.receipts(t), []string{"d1/tx-a=applied::7"})

	if _, err := f.db.Exec(`DROP TRIGGER fail_receipt`); err != nil {
		t.Fatal(err)
	}
	f.dispositions()
	if err := f.listener().CatchUpRange(t.Context(), 10, 20); err != nil {
		t.Fatal(err)
	}
	equal(t, "retry", f.dispositions(), []string{"d1=duplicate", "d2=applied"})
	if f.cursor(t) != "20" || f.status(t, "tx-b") != models.Paid {
		t.Fatalf("retried pass: cursor %s, tx-b %v", f.cursor(t), f.status(t, "tx-b"))
	}
}

func TestCatchUpUndecodableEventKeepsCursor(t *testing.T) {
	for name, bcs := range map[string][]byte{
		"truncated":      encode(t, receipt("tx-a"))[:20],
		"trailing bytes": append(encode(t, receipt("tx-a")), 0),
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			f.transaction(t, "tx-a", time.Now().Add(time.Hour))
			f.setCursor(t, "10")
			f.server.setPages([]event{{digest: "d1", bcs: bcs}})
			if err := f.listener().CatchUpRange(t.Context(), 10, 20); err == nil || !strings.Contains(err.Error(), "decode") {
				t.Fatalf("undecodable event: %v", err)
			}
			if f.cursor(t) != "10" || len(f.receipts(t)) != 0 {
				t.Fatalf("cursor %s, rows %v", f.cursor(t), f.receipts(t))
			}
		})
	}
}

// checkpoint is a streamed checkpoint with one receipt for nonce among
// another package's event.
func checkpoint(t *testing.T, seq uint64, digest string, nonce string) *v2.Checkpoint {
	t.Helper()
	return &v2.Checkpoint{
		SequenceNumber: proto.Uint64(seq),
		Transactions: []*v2.ExecutedTransaction{{
			Digest: proto.String(digest),
			Events: &v2.TransactionEvents{Events: []*v2.Event{
				{EventType: proto.String("0x2::coin::Other"), Contents: &v2.Bcs{Value: []byte{0xff}}},
				{EventType: proto.String(eventType), Contents: &v2.Bcs{Value: encode(t, receipt(nonce))}},
			}},
		}},
	}
}

func TestProcessCheckpoint(t *testing.T) {
	f := newFixture(t)
	f.transaction(t, "tx-a", time.Now().Add(time.Hour))
	f.transaction(t, "tx-b", time.Now().Add(time.Hour))
	f.setCursor(t, "41")
	if err := f.listener().ProcessCheckpoint(t.Context(), checkpoint(t, 42, "d1", "tx-a")); err != nil {
		t.Fatal(err)
	}
	row, err := database.New(f.db).GetPaymentReceipt(t.Context(), database.GetPaymentReceiptParams{TxDigest: "d1", Nonce: "tx-a"})
	if err != nil || row.Disposition != "applied" || row.Checkpoint != (sql.NullInt64{Int64: 42, Valid: true}) {
		t.Fatalf("streamed receipt %+v, %v", row, err)
	}
	if f.cursor(t) != "42" || f.status(t, "tx-a") != models.Paid {
		t.Fatalf("cursor %s, tx-a %v", f.cursor(t), f.status(t, "tx-a"))
	}

	if _, err := f.db.Exec(`CREATE TRIGGER fail_receipt BEFORE INSERT ON payment_receipts
BEGIN SELECT RAISE(ABORT, 'scripted receipt failure'); END`); err != nil {
		t.Fatal(err)
	}
	if err := f.listener().ProcessCheckpoint(t.Context(), checkpoint(t, 43, "d2", "tx-b")); err == nil {
		t.Fatal("checkpoint with a failing write succeeded")
	}
	if f.cursor(t) != "42" || f.status(t, "tx-b") != models.Outstanding {
		t.Fatalf("failed checkpoint: cursor %s, tx-b %v", f.cursor(t), f.status(t, "tx-b"))
	}
}

func TestStartRefusesInvalidCursor(t *testing.T) {
	f := newFixture(t)
	f.setCursor(t, "not-a-checkpoint")
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	err := f.listener().Start(ctx)
	if err == nil || !strings.Contains(err.Error(), cursorKey) {
		t.Fatalf("Start with an invalid cursor: %v", err)
	}
	if ctx.Err() != nil {
		t.Fatal("Start did not fail before running")
	}
}

// The stream starts at the live checkpoint. Checkpoints between the stored
// cursor and it are caught up before the cursor moves past them.
func TestStreamCatchesUpGapBeforeCheckpoint(t *testing.T) {
	f := newFixture(t)
	f.transaction(t, "tx-gap", time.Now().Add(time.Hour))
	f.transaction(t, "tx-live", time.Now().Add(time.Hour))
	f.setCursor(t, "10")
	f.server.setPages([]event{node(t, "d-gap", receipt("tx-gap"))})
	l := f.listener()
	cursor := uint64(10)

	seq, err := l.StreamCheckpoint(t.Context(), &cursor, checkpoint(t, 15, "d-live", "tx-live"))
	if err != nil || seq != 15 {
		t.Fatalf("StreamCheckpoint = %d, %v", seq, err)
	}
	equal(t, "order", f.dispositions(), []string{"d-gap=applied", "d-live=applied"})
	f.server.mu.Lock()
	queries := len(f.server.queries)
	after := f.server.queries[0]["afterCheckpoint"]
	f.server.mu.Unlock()
	if queries != 1 || after != float64(10) {
		t.Fatalf("gap queries %d after %v", queries, after)
	}
	if f.cursor(t) != "15" {
		t.Fatalf("cursor %s", f.cursor(t))
	}

	// The next checkpoint follows directly: no catch-up query.
	cursor = 15
	if _, err := l.StreamCheckpoint(t.Context(), &cursor, checkpoint(t, 16, "d-next", "tx-live")); err != nil {
		t.Fatal(err)
	}
	f.server.mu.Lock()
	queries = len(f.server.queries)
	f.server.mu.Unlock()
	if queries != 1 || f.cursor(t) != "16" {
		t.Fatalf("contiguous checkpoint: queries %d, cursor %s", queries, f.cursor(t))
	}
}

// A failed gap catch-up leaves the cursor before the gap.
func TestStreamGapFailureKeepsCursor(t *testing.T) {
	f := newFixture(t)
	f.transaction(t, "tx-gap", time.Now().Add(time.Hour))
	f.setCursor(t, "10")
	f.server.setPages([]event{{digest: "d-gap", bcs: []byte{1}}})
	cursor := uint64(10)
	if _, err := f.listener().StreamCheckpoint(t.Context(), &cursor, checkpoint(t, 15, "d-live", "tx-gap")); err == nil {
		t.Fatal("gap with an undecodable event succeeded")
	}
	if f.cursor(t) != "10" || len(f.receipts(t)) != 0 {
		t.Fatalf("cursor %s, rows %v", f.cursor(t), f.receipts(t))
	}
}

// Without a stored cursor the listener starts at the tip and stores it, so a
// restart before the first streamed checkpoint keeps that starting point.
func TestFirstStartStoresTip(t *testing.T) {
	f := newFixture(t)
	cursor, err := f.listener().CatchUpTo(t.Context(), nil, 77)
	if err != nil || cursor == nil || *cursor != 77 {
		t.Fatalf("CatchUpTo = %v, %v", cursor, err)
	}
	if f.cursor(t) != "77" {
		t.Fatalf("stored cursor %s", f.cursor(t))
	}
	f.server.mu.Lock()
	queries := len(f.server.queries)
	f.server.mu.Unlock()
	if queries != 0 {
		t.Fatalf("first start queried %d pages", queries)
	}
}
