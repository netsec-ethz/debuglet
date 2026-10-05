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
	"strconv"
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

// event is one GraphQL event node. A zero checkpoint passes every
// checkpoint filter.
type event struct {
	digest     string
	seq        uint64
	checkpoint uint64
	bcs        []byte
}

func node(t *testing.T, digest string, ev receiptEvent) event {
	t.Helper()
	return event{digest: digest, bcs: encode(t, ev)}
}

// graphQL serves PaymentReceipt events in pages, linked by endCursor, and
// the indexer's last ingested checkpoint. Events of later checkpoints are not
// served, like an indexer that has not ingested them yet.
type graphQL struct {
	mu         sync.Mutex
	pages      [][]event
	indexed    uint64
	queries    []map[string]any // events queries
	watermarks int              // indexed checkpoint queries
}

func (g *graphQL) setIndexed(cp uint64) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.indexed = cp
}

func (g *graphQL) indexerQueries() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.watermarks
}

func (g *graphQL) eventQueries() []map[string]any {
	g.mu.Lock()
	defer g.mu.Unlock()
	return append([]map[string]any(nil), g.queries...)
}

func (g *graphQL) setPages(pages ...[]event) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.pages = pages
}

func (g *graphQL) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Query     string         `json:"query"`
		Variables map[string]any `json:"variables"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if strings.Contains(req.Query, "serviceConfig") {
		g.watermarks++
		_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"serviceConfig": map[string]any{
			"availableRange": map[string]any{"last": map[string]any{"sequenceNumber": g.indexed}},
		}}})
		return
	}
	g.queries = append(g.queries, req.Variables)
	visible := func(ev event) bool {
		if ev.checkpoint == 0 {
			return true
		}
		after, hasAfter := req.Variables["afterCheckpoint"].(float64)
		before, hasBefore := req.Variables["beforeCheckpoint"].(float64)
		return ev.checkpoint <= g.indexed && (!hasAfter || float64(ev.checkpoint) > after) &&
			(!hasBefore || float64(ev.checkpoint) < before)
	}
	index := 0
	if after, ok := req.Variables["after"].(string); ok {
		fmt.Sscanf(after, "page-%d", &index)
	}
	type nodeJSON struct {
		Transaction struct {
			Digest string `json:"digest"`
		} `json:"transaction"`
		SequenceNumber uint64 `json:"sequenceNumber"`
		Contents       struct {
			Bcs string `json:"bcs"`
		} `json:"contents"`
	}
	nodes := []nodeJSON{}
	if index < len(g.pages) {
		for _, ev := range g.pages[index] {
			if !visible(ev) {
				continue
			}
			var n nodeJSON
			n.Transaction.Digest = ev.digest
			n.SequenceNumber = ev.seq
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
	server := &graphQL{indexed: math.MaxInt32}
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
	want := []string{"d1/tx-a=applied::7", "d2/tx-b=applied::7", "d3/tx-a=mismatch:already paid by d1 event 0:7"}
	equal(t, "rows", f.receipts(t), want)
	if after := f.server.eventQueries()[0]["afterCheckpoint"]; after != float64(10) {
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

func TestStreamRecordsCheckpoint(t *testing.T) {
	f := newFixture(t)
	f.transaction(t, "tx-a", time.Now().Add(time.Hour))
	f.transaction(t, "tx-b", time.Now().Add(time.Hour))
	f.setCursor(t, "41")
	cursor := uint64(41)
	stream := f.listener().NewStream(&cursor)
	if err := stream.Checkpoint(t.Context(), checkpoint(t, 42, "d1", "tx-a")); err != nil {
		t.Fatal(err)
	}
	row, err := database.New(f.db).GetPaymentReceipt(t.Context(), database.GetPaymentReceiptParams{TxDigest: "d1", EventSeq: 1})
	if err != nil || row.Disposition != "applied" || row.Checkpoint != (sql.NullInt64{Int64: 42, Valid: true}) {
		t.Fatalf("streamed receipt %+v, %v", row, err)
	}
	if f.cursor(t) != "42" || f.status(t, "tx-a") != models.Paid || f.server.indexerQueries() != 0 {
		t.Fatalf("cursor %s, tx-a %v, indexer queries %d", f.cursor(t), f.status(t, "tx-a"), f.server.indexerQueries())
	}

	if _, err := f.db.Exec(`CREATE TRIGGER fail_receipt BEFORE INSERT ON payment_receipts
BEGIN SELECT RAISE(ABORT, 'scripted receipt failure'); END`); err != nil {
		t.Fatal(err)
	}
	if err := stream.Checkpoint(t.Context(), checkpoint(t, 43, "d2", "tx-b")); err == nil {
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
	f.server.setPages([]event{{digest: "d-gap", checkpoint: 12, bcs: encode(t, receipt("tx-gap"))}})
	cursor := uint64(10)
	stream := f.listener().NewStream(&cursor)

	if err := stream.Checkpoint(t.Context(), checkpoint(t, 15, "d-live", "tx-live")); err != nil {
		t.Fatal(err)
	}
	equal(t, "order", f.dispositions(), []string{"d-gap=applied", "d-live=applied"})
	queries := f.server.eventQueries()
	if len(queries) != 1 || queries[0]["afterCheckpoint"] != float64(10) || queries[0]["beforeCheckpoint"] != float64(15) {
		t.Fatalf("gap queries %v", queries)
	}
	if f.cursor(t) != "15" {
		t.Fatalf("cursor %s", f.cursor(t))
	}

	// The next checkpoint follows directly: no catch-up query.
	if err := stream.Checkpoint(t.Context(), checkpoint(t, 16, "d-next", "tx-live")); err != nil {
		t.Fatal(err)
	}
	if n := len(f.server.eventQueries()); n != 1 || f.cursor(t) != "16" {
		t.Fatalf("contiguous checkpoint: queries %d, cursor %s", n, f.cursor(t))
	}
}

// A failed gap catch-up leaves the cursor before the gap.
func TestStreamGapFailureKeepsCursor(t *testing.T) {
	f := newFixture(t)
	f.transaction(t, "tx-gap", time.Now().Add(time.Hour))
	f.setCursor(t, "10")
	f.server.setPages([]event{{digest: "d-gap", bcs: []byte{1}}})
	cursor := uint64(10)
	if err := f.listener().NewStream(&cursor).Checkpoint(t.Context(), checkpoint(t, 15, "d-live", "tx-gap")); err == nil {
		t.Fatal("gap with an undecodable event succeeded")
	}
	if f.cursor(t) != "10" || len(f.receipts(t)) != 0 {
		t.Fatalf("cursor %s, rows %v", f.cursor(t), f.receipts(t))
	}
}

// Without a stored cursor the listener starts at the tip the indexer has
// reached and stores it, so a restart before the first streamed checkpoint
// keeps that starting point.
func TestFirstStartStoresTip(t *testing.T) {
	for _, tc := range []struct {
		indexed uint64
		want    string
	}{{100, "77"}, {70, "70"}} {
		f := newFixture(t)
		f.server.setIndexed(tc.indexed)
		cursor, err := f.listener().CatchUpTo(t.Context(), nil, 77)
		if err != nil || cursor == nil || strconv.FormatUint(*cursor, 10) != tc.want {
			t.Fatalf("indexer at %d: CatchUpTo = %v, %v", tc.indexed, cursor, err)
		}
		if f.cursor(t) != tc.want || len(f.server.eventQueries()) != 0 {
			t.Fatalf("indexer at %d: stored cursor %s, %d event queries", tc.indexed, f.cursor(t), len(f.server.eventQueries()))
		}
	}
}

// The cursor never passes what the indexer has ingested. Node at 110,
// indexer at 105, a payment at 108 the indexer exposes only later: it is
// applied once, when the indexer has it.
func TestCatchUpStopsAtIndexedCheckpoint(t *testing.T) {
	f := newFixture(t)
	f.transaction(t, "tx-108", time.Now().Add(time.Hour))
	f.setCursor(t, "100")
	f.server.setPages([]event{{digest: "d108", checkpoint: 108, bcs: encode(t, receipt("tx-108"))}})
	f.server.setIndexed(105)
	l := f.listener()
	cursor := uint64(100)

	next, err := l.CatchUpTo(t.Context(), &cursor, 110)
	if err != nil || f.cursor(t) != "105" || *next != 105 {
		t.Fatalf("indexer behind the node: cursor %s, %v", f.cursor(t), err)
	}
	if f.status(t, "tx-108") != models.Outstanding || len(f.receipts(t)) != 0 {
		t.Fatal("receipt of an unindexed checkpoint was applied")
	}
	// The indexer behind the stored cursor: nothing is stored.
	f.server.setIndexed(103)
	if again, err := l.CatchUpTo(t.Context(), next, 110); err != nil || *again != 105 || f.cursor(t) != "105" {
		t.Fatalf("indexer behind the cursor: %v, cursor %s", err, f.cursor(t))
	}

	f.server.setIndexed(110)
	if next, err = l.CatchUpTo(t.Context(), next, 110); err != nil || *next != 110 || f.cursor(t) != "110" {
		t.Fatalf("indexer caught up: cursor %s, %v", f.cursor(t), err)
	}
	equal(t, "rows", f.receipts(t), []string{"d108/tx-108=applied::7"})
	if f.status(t, "tx-108") != models.Paid {
		t.Fatal("receipt at 108 not applied")
	}
}

// A streamed checkpoint far ahead of a lagging indexer records its own
// receipts but leaves the cursor at what the indexer has proven; the gap is
// read when the indexer has it.
func TestStreamWaitsForIndexer(t *testing.T) {
	f := newFixture(t)
	for _, id := range []string{"tx-108", "tx-115", "tx-116"} {
		f.transaction(t, id, time.Now().Add(time.Hour))
	}
	f.setCursor(t, "100")
	f.server.setPages([]event{{digest: "d108", checkpoint: 108, bcs: encode(t, receipt("tx-108"))}})
	f.server.setIndexed(105)
	cursor := uint64(100)
	stream := f.listener().NewStream(&cursor)

	if err := stream.Checkpoint(t.Context(), checkpoint(t, 115, "d115", "tx-115")); err != nil {
		t.Fatal(err)
	}
	if f.cursor(t) != "105" || *stream.Cursor() != 105 || f.status(t, "tx-115") != models.Paid || f.status(t, "tx-108") != models.Outstanding {
		t.Fatalf("lagging indexer: cursor %s, tx-115 %v, tx-108 %v", f.cursor(t), f.status(t, "tx-115"), f.status(t, "tx-108"))
	}

	f.server.setIndexed(115)
	if err := stream.Checkpoint(t.Context(), checkpoint(t, 116, "d116", "tx-116")); err != nil {
		t.Fatal(err)
	}
	if f.cursor(t) != "116" || f.status(t, "tx-108") != models.Paid || f.status(t, "tx-116") != models.Paid {
		t.Fatalf("indexer caught up: cursor %s, tx-108 %v", f.cursor(t), f.status(t, "tx-108"))
	}
	equal(t, "rows", f.receipts(t), []string{"d108/tx-108=applied::7", "d115/tx-115=applied::7", "d116/tx-116=applied::7"})
	queries := f.server.eventQueries()
	if len(queries) != 2 || queries[1]["afterCheckpoint"] != float64(105) || queries[1]["beforeCheckpoint"] != float64(115) {
		t.Fatalf("catch-up queries %v", queries)
	}

	// The same range read again on a restart applies nothing twice.
	if _, err := f.listener().CatchUpTo(t.Context(), &cursor, 116); err != nil {
		t.Fatal(err)
	}
	equal(t, "rows after restart", f.receipts(t), []string{"d108/tx-108=applied::7", "d115/tx-115=applied::7", "d116/tx-116=applied::7"})
}

// Several receipt events of one transaction are separate receipts.
func TestReceiptsOfOneTransaction(t *testing.T) {
	f := newFixture(t)
	f.transaction(t, "tx-a", time.Now().Add(time.Hour))
	wrong := encode(t, receipt("tx-a", func(ev *receiptEvent) { ev.PaymentAmount = price + 1 }))
	valid := encode(t, receipt("tx-a"))
	f.server.setPages([]event{{digest: "d1", seq: 0, bcs: wrong}, {digest: "d1", seq: 3, bcs: valid}})

	if err := f.listener().CatchUpRange(t.Context(), 0, 5); err != nil {
		t.Fatal(err)
	}
	if f.status(t, "tx-a") != models.Paid {
		t.Fatal("valid event after a rejected one in the same transaction did not pay")
	}
	var dispositions []string
	rows, err := f.db.QueryContext(t.Context(), "SELECT disposition || ':' || detail FROM payment_receipts WHERE tx_digest = 'd1' ORDER BY disposition")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var d string
		if err := rows.Scan(&d); err != nil {
			t.Fatal(err)
		}
		dispositions = append(dispositions, d)
	}
	equal(t, "events of d1", dispositions, []string{"applied:", "mismatch:amount"})
}
