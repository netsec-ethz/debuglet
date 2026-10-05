// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package sui

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"net"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/netsec-ethz/debuglet/internal/dispatcher/config"

	"github.com/block-vision/sui-go-sdk/common/grpcconn"
	sdkmodels "github.com/block-vision/sui-go-sdk/models"
	"github.com/block-vision/sui-go-sdk/mystenbcs"
	v2 "github.com/block-vision/sui-go-sdk/pb/sui/rpc/v2"
	"github.com/block-vision/sui-go-sdk/signer"
	"github.com/block-vision/sui-go-sdk/sui/v2/grpc_client"
	"github.com/block-vision/sui-go-sdk/sui/v2/types"
	"github.com/block-vision/sui-go-sdk/transaction"
	"github.com/block-vision/sui-go-sdk/utils"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/proto"
)

const testUSDC = "0xa1ec7fc00a6f40db9693ad1415d0c193ad3906494428cf252621037bd7117e29::usdc::USDC"

var testReceiver = testObjectID(0xaa)

func testObjectID(i int) string { return fmt.Sprintf("0x%064x", i) }

func testObjectDigest(i int) string {
	return string(transaction.ConvertObjectDigestBytesToString(bytes.Repeat([]byte{byte(i)}, 32)))
}

func testSigner() *signer.Signer { return signer.NewSigner(bytes.Repeat([]byte{7}, 32)) }

func testCoin(i int, balance string) types.Coin {
	return types.Coin{ObjectId: testObjectID(i), Version: strconv.Itoa(i), Digest: testObjectDigest(i), Balance: balance}
}

// ---- coin selection over scripted pages ----

// scriptedPages is a coinLister over fixed pages; page i's cursor is "i+1".
type scriptedPages struct {
	pages   [][]types.Coin
	cursors []string // overrides the cursor returned after page i
	calls   int
	onCall  func(call int)
}

func (s *scriptedPages) list(ctx context.Context, options types.ListCoinsOptions) (*types.ListCoinsResponse, error) {
	s.calls++
	if s.onCall != nil {
		s.onCall(s.calls)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	idx := 0
	if options.Cursor != nil {
		idx, _ = strconv.Atoi(*options.Cursor)
	}
	if options.Limit == nil || *options.Limit != coinPageSize {
		return nil, fmt.Errorf("unbounded page request")
	}
	resp := &types.ListCoinsResponse{}
	if idx < len(s.pages) {
		resp.Objects = s.pages[idx]
	}
	if idx+1 < len(s.pages) {
		next := strconv.Itoa(idx + 1)
		if idx < len(s.cursors) && s.cursors[idx] != "" {
			next = s.cursors[idx]
		}
		resp.Cursor, resp.HasNextPage = &next, true
	}
	return resp, nil
}

func TestSelectCoinsAcrossPages(t *testing.T) {
	pages := &scriptedPages{pages: [][]types.Coin{
		{testCoin(1, "10")}, {testCoin(2, "0"), testCoin(3, "20")}, {testCoin(4, "30")}, {testCoin(5, "40")},
	}}
	coins, total, err := selectCoins(context.Background(), pages.list, "0x1", testUSDC, 55, 100, nil)
	if err != nil {
		t.Fatalf("selectCoins: %v", err)
	}
	if total != 60 || len(coins) != 3 || coins[0].ObjectId != testObjectID(1) || coins[2].ObjectId != testObjectID(4) {
		t.Fatalf("selected %v total %d, want coins 1, 3, 4 totalling 60", coins, total)
	}
	if pages.calls != 3 {
		t.Fatalf("read %d pages, want to stop after the covering page 3", pages.calls)
	}
}

func TestSelectCoinsFailures(t *testing.T) {
	cases := []struct {
		name   string
		pages  *scriptedPages
		amount uint64
		max    int
		want   string
	}{
		{"malformed first balance", &scriptedPages{pages: [][]types.Coin{{testCoin(1, "x1"), testCoin(2, "100")}}}, 50, 100, "invalid balance"},
		{"malformed later balance", &scriptedPages{pages: [][]types.Coin{{testCoin(1, "10")}, {testCoin(2, "-5")}}}, 50, 100, "invalid balance"},
		{"overflow", &scriptedPages{pages: [][]types.Coin{{testCoin(1, strconv.FormatUint(math.MaxUint64-1, 10)), testCoin(2, "5")}}}, math.MaxUint64, 100, "overflows"},
		{"insufficient", &scriptedPages{pages: [][]types.Coin{{testCoin(1, "10")}, {testCoin(2, "20")}}}, 100, 100, "insufficient " + testUSDC + " balance: 30 of 100"},
		{"no coins", &scriptedPages{}, 1, 100, "insufficient " + testUSDC + " balance: 0 of 1"},
		{"coin limit", &scriptedPages{pages: [][]types.Coin{{testCoin(1, "10"), testCoin(2, "10"), testCoin(3, "10")}}}, 100, 2, "in 2 coins: 20 of 100"},
		{"empty page", &scriptedPages{pages: [][]types.Coin{{testCoin(1, "10")}, {}, {testCoin(2, "90")}}}, 50, 100, "empty page 2"},
		{"repeated cursor", &scriptedPages{pages: [][]types.Coin{{testCoin(1, "10")}, {testCoin(2, "10")}, {testCoin(3, "90")}}, cursors: []string{"1", "1"}}, 50, 100, "repeated a cursor"},
		{"zero amount", &scriptedPages{pages: [][]types.Coin{{testCoin(1, "10")}}}, 0, 100, "amount must be positive"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			coins, total, err := selectCoins(context.Background(), tc.pages.list, "0x1", testUSDC, tc.amount, tc.max, nil)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("selectCoins = (%v, %d, %v), want error containing %q", coins, total, err, tc.want)
			}
		})
	}
}

func TestSelectCoinsRefusesMalformedPagination(t *testing.T) {
	cases := []struct {
		name  string
		pages *scriptedPages
		max   int
		want  string
	}{
		// Coin 1 is listed again on the next page; counted twice it would cover 50.
		{"object repeated across pages", &scriptedPages{pages: [][]types.Coin{{testCoin(1, "30")}, {testCoin(1, "30")}}}, 100, "listed coin " + testObjectID(1) + " twice"},
		{"object repeated within a page", &scriptedPages{pages: [][]types.Coin{{testCoin(1, "30"), testCoin(1, "30")}}}, 100, "twice"},
		// Page 2 answers with the cursor that requested it; its coin would cover 50.
		{"page repeats its cursor", &scriptedPages{pages: [][]types.Coin{{testCoin(1, "10")}, {testCoin(2, "90")}, {testCoin(3, "1")}}, cursors: []string{"1", "1"}}, 100, "repeated a cursor"},
		{"cursor seen earlier", &scriptedPages{pages: [][]types.Coin{{testCoin(1, "10")}, {testCoin(2, "10")}, {testCoin(3, "90")}, {testCoin(4, "1")}}, cursors: []string{"1", "2", "1"}}, 100, "repeated a cursor"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			coins, total, err := selectCoins(context.Background(), tc.pages.list, "0x1", testUSDC, 50, tc.max, nil)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("selectCoins = (%v, %d, %v), want error containing %q", coins, total, err, tc.want)
			}
		})
	}
}

func TestSelectCoinsPageBound(t *testing.T) {
	endless := make([][]types.Coin, 3*maxCoinPages)
	for i := range endless {
		endless[i] = []types.Coin{testCoin(i+1, "1")}
	}
	pages := &scriptedPages{pages: endless}
	_, _, err := selectCoins(context.Background(), pages.list, "0x1", testUSDC, 1000, 1000, nil)
	if err == nil || !strings.Contains(err.Error(), fmt.Sprintf("more than %d pages", maxCoinPages)) {
		t.Fatalf("selectCoins = %v, want the page bound", err)
	}
	if pages.calls != maxCoinPages {
		t.Fatalf("read %d pages, want %d", pages.calls, maxCoinPages)
	}
}

func TestSelectCoinsContextCancelledMidPagination(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	pages := &scriptedPages{
		pages: [][]types.Coin{{testCoin(1, "10")}, {testCoin(2, "10")}, {testCoin(3, "90")}},
		onCall: func(call int) {
			if call == 2 {
				cancel()
			}
		},
	}
	_, _, err := selectCoins(ctx, pages.list, "0x1", testUSDC, 50, 100, nil)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("selectCoins = %v, want context.Canceled", err)
	}
	if pages.calls != 2 {
		t.Fatalf("read %d pages after cancellation, want 2", pages.calls)
	}
}

func TestSelectCoinsExcludesTransferInputs(t *testing.T) {
	pages := &scriptedPages{pages: [][]types.Coin{{testCoin(1, "100"), testCoin(2, "40")}, {testCoin(3, "70")}}}
	coins, total, err := selectCoins(context.Background(), pages.list, "0x1", types.SUI_TYPE_ARG, 100, 100, map[string]bool{testObjectID(1): true})
	if err != nil {
		t.Fatalf("selectCoins: %v", err)
	}
	if total != 110 || len(coins) != 2 || coins[0].ObjectId != testObjectID(2) || coins[1].ObjectId != testObjectID(3) {
		t.Fatalf("selected %v total %d, want coins 2 and 3", coins, total)
	}
}

// ---- transaction shape ----

func TestBuildTransferMergesAndSplitsExactly(t *testing.T) {
	gas := []types.Coin{testCoin(9, "50000000")}
	tx, err := buildTransfer(testSigner(), []types.Coin{testCoin(1, "10"), testCoin(2, "90")}, 100, 50, testReceiver, gas, 1000, 50_000_000)
	if err != nil {
		t.Fatalf("buildTransfer: %v", err)
	}
	pt := tx.Data.V1.Kind.ProgrammableTransaction
	if len(pt.Inputs) != 4 || pt.Inputs[0].Object == nil || pt.Inputs[1].Object == nil {
		t.Fatalf("inputs %d, want two coins, the amount and the receiver", len(pt.Inputs))
	}
	if got := binary.LittleEndian.Uint64(pt.Inputs[2].Pure.Bytes); len(pt.Inputs[2].Pure.Bytes) != 8 || got != 50 {
		t.Fatalf("split amount %v, want u64 50", pt.Inputs[2].Pure.Bytes)
	}
	want, err := transaction.ConvertSuiAddressStringToBytes(sdkmodels.SuiAddress(testReceiver))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pt.Inputs[3].Pure.Bytes, want[:]) {
		t.Fatalf("receiver input %x, want %x", pt.Inputs[3].Pure.Bytes, want[:])
	}
	if len(pt.Commands) != 3 || pt.Commands[0].MergeCoins == nil || pt.Commands[1].SplitCoins == nil || pt.Commands[2].TransferObjects == nil {
		t.Fatalf("commands %+v, want merge, split, transfer", pt.Commands)
	}
	if m := pt.Commands[0].MergeCoins; *m.Destination.Input != 0 || len(m.Sources) != 1 || *m.Sources[0].Input != 1 {
		t.Fatalf("merge %+v, want coin 1 into coin 0", m)
	}
	if s := pt.Commands[1].SplitCoins; *s.Coin.Input != 0 || len(s.Amount) != 1 || *s.Amount[0].Input != 2 {
		t.Fatalf("split %+v, want the amount from the merged coin", s)
	}
	// Only the split coin leaves; the merged coin keeps the change at the sender.
	if to := pt.Commands[2].TransferObjects; len(to.Objects) != 1 || to.Objects[0].Result == nil || *to.Objects[0].Result != 1 || *to.Address.Input != 3 {
		t.Fatalf("transfer %+v, want the split result to the receiver", to)
	}
	gd := tx.Data.V1.GasData
	if gd.Payment == nil || len(*gd.Payment) != 1 || *gd.Price != 1000 || *gd.Budget != 50_000_000 {
		t.Fatalf("gas data %+v", gd)
	}
}

func TestBuildTransferExactAmountSendsTheCoin(t *testing.T) {
	tx, err := buildTransfer(testSigner(), []types.Coin{testCoin(1, "50")}, 50, 50, testReceiver, []types.Coin{testCoin(9, "1")}, 1, 1)
	if err != nil {
		t.Fatalf("buildTransfer: %v", err)
	}
	pt := tx.Data.V1.Kind.ProgrammableTransaction
	if len(pt.Commands) != 1 || pt.Commands[0].TransferObjects == nil || *pt.Commands[0].TransferObjects.Objects[0].Input != 0 {
		t.Fatalf("commands %+v, want one transfer of the input coin", pt.Commands)
	}
}

// ---- adapter over a local gRPC fixture ----

func coinObject(i int, balance uint64) *v2.Object {
	return &v2.Object{
		ObjectId: proto.String(testObjectID(i)),
		Version:  proto.Uint64(uint64(i)),
		Digest:   proto.String(testObjectDigest(i)),
		Balance:  proto.Uint64(balance),
	}
}

// chainFixture serves the gRPC methods the adapter calls from local state.
type chainFixture struct {
	mu        sync.Mutex
	pages     map[string][][]*v2.Object // coin type -> pages
	gasPrice  uint64
	executed  [][]byte
	execErr   error
	execFails bool
	// statuses maps a digest to its executed status; absent means not found.
	statuses map[string]bool
	// changes maps a digest to the balance changes the node reports.
	changes map[string][]*v2.BalanceChange
	// respDigest, when set, replaces the digest in execution and lookup
	// responses, as a node answering for another transaction would.
	respDigest *string
}

type stateFixture struct {
	v2.UnimplementedStateServiceServer
	f *chainFixture
}

func (s stateFixture) ListOwnedObjects(_ context.Context, req *v2.ListOwnedObjectsRequest) (*v2.ListOwnedObjectsResponse, error) {
	s.f.mu.Lock()
	defer s.f.mu.Unlock()
	coinType := strings.TrimSuffix(strings.TrimPrefix(req.GetObjectType(), "0x2::coin::Coin<"), ">")
	pages := s.f.pages[coinType]
	idx := 0
	if tok := req.GetPageToken(); len(tok) > 0 {
		idx, _ = strconv.Atoi(string(tok))
	}
	resp := &v2.ListOwnedObjectsResponse{}
	if idx < len(pages) {
		resp.Objects = pages[idx]
	}
	if idx+1 < len(pages) {
		resp.NextPageToken = []byte(strconv.Itoa(idx + 1))
	}
	return resp, nil
}

type ledgerFixture struct {
	v2.UnimplementedLedgerServiceServer
	f *chainFixture
}

func (l ledgerFixture) GetEpoch(context.Context, *v2.GetEpochRequest) (*v2.GetEpochResponse, error) {
	l.f.mu.Lock()
	defer l.f.mu.Unlock()
	return &v2.GetEpochResponse{Epoch: &v2.Epoch{ReferenceGasPrice: proto.Uint64(l.f.gasPrice)}}, nil
}

func executed(digest string, success bool) *v2.ExecutedTransaction {
	st := &v2.ExecutionStatus{Success: proto.Bool(success)}
	if !success {
		st.Error = &v2.ExecutionError{Description: proto.String("insufficient coin balance")}
	}
	return &v2.ExecutedTransaction{Digest: proto.String(digest), Effects: &v2.TransactionEffects{Status: st}}
}

func (l ledgerFixture) GetTransaction(_ context.Context, req *v2.GetTransactionRequest) (*v2.GetTransactionResponse, error) {
	l.f.mu.Lock()
	defer l.f.mu.Unlock()
	success, ok := l.f.statuses[req.GetDigest()]
	if !ok {
		return nil, status.Error(codes.NotFound, "transaction not found")
	}
	tx := executed(req.GetDigest(), success)
	if l.f.respDigest != nil {
		tx.Digest = proto.String(*l.f.respDigest)
	}
	if slices.Contains(req.GetReadMask().GetPaths(), "balance_changes") {
		tx.BalanceChanges = l.f.changes[req.GetDigest()]
	}
	return &v2.GetTransactionResponse{Transaction: tx}, nil
}

type execFixture struct {
	v2.UnimplementedTransactionExecutionServiceServer
	f *chainFixture
}

func (e execFixture) ExecuteTransaction(_ context.Context, req *v2.ExecuteTransactionRequest) (*v2.ExecuteTransactionResponse, error) {
	e.f.mu.Lock()
	defer e.f.mu.Unlock()
	if e.f.execErr != nil {
		return nil, e.f.execErr
	}
	txBytes := req.GetTransaction().GetBcs().GetValue()
	e.f.executed = append(e.f.executed, txBytes)
	digest, err := utils.GetTxDigestFromBytes(txBytes)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	if e.f.respDigest != nil {
		digest = *e.f.respDigest
	}
	return &v2.ExecuteTransactionResponse{Transaction: executed(digest, !e.f.execFails)}, nil
}

// txDigest is the Sui digest of BCS transaction bytes.
func txDigest(t *testing.T, txBytes []byte) string {
	t.Helper()
	d, err := utils.GetTxDigestFromBytes(txBytes)
	if err != nil {
		t.Errorf("digest: %v", err)
	}
	return d
}

// startFixture serves f on an in-memory listener and returns an adapter whose
// SDK client dials it; nothing leaves the process.
func startFixture(t *testing.T, f *chainFixture) *SuiPaymentHandler {
	t.Helper()
	lis := bufconn.Listen(1 << 20)
	srv := grpc.NewServer()
	v2.RegisterStateServiceServer(srv, stateFixture{f: f})
	v2.RegisterLedgerServiceServer(srv, ledgerFixture{f: f})
	v2.RegisterTransactionExecutionServiceServer(srv, execFixture{f: f})
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)
	conn := grpcconn.NewSuiGrpcClient("passthrough:///fixture", grpcconn.WithDialOptions(
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return lis.DialContext(ctx) }),
	))
	t.Cleanup(func() { _ = conn.Close() })
	client, err := grpc_client.NewClient(grpc_client.ClientOptions{GrpcClient: conn})
	if err != nil {
		t.Fatal(err)
	}
	return &SuiPaymentHandler{client: client, signer: testSigner(), logger: zap.NewNop()}
}

// fundedFixture holds 10 + 90 USDC on two pages and two SUI gas coins that
// together cover the budget at a reference price of 1000.
func fundedFixture() *chainFixture {
	return &chainFixture{
		pages: map[string][][]*v2.Object{
			testUSDC:           {{coinObject(1, 10)}, {coinObject(2, 90)}},
			types.SUI_TYPE_ARG: {{coinObject(11, 30_000_000)}, {coinObject(12, 30_000_000)}},
		},
		gasPrice: 1000,
		statuses: map[string]bool{},
		changes:  map[string][]*v2.BalanceChange{},
	}
}

func TestTransferCoinsSelectsAcrossPagesAndReturnsDigest(t *testing.T) {
	f := fundedFixture()
	h := startFixture(t, f)
	prepared, err := h.PrepareTransfer(context.Background(), 50, testUSDC, testReceiver)
	if err != nil {
		t.Fatalf("PrepareTransfer: %v", err)
	}
	if prepared.Digest == "" || prepared.Digest != txDigest(t, prepared.txBytes) {
		t.Fatalf("prepared digest %q does not match its bytes", prepared.Digest)
	}
	if len(f.executed) != 0 {
		t.Fatalf("PrepareTransfer submitted a transaction")
	}

	digest, err := h.TransferCoins(50, testUSDC, testReceiver, context.Background())
	if err != nil {
		t.Fatalf("TransferCoins: %v", err)
	}
	if len(f.executed) != 1 || txDigest(t, f.executed[0]) != digest {
		t.Fatalf("returned digest %q is not the digest of the submitted bytes", digest)
	}
}

func TestPrepareTransferFailuresAreNotBroadcast(t *testing.T) {
	cases := []struct {
		name     string
		mutate   func(f *chainFixture)
		amount   uint64
		coinType string
		receiver string
		want     string
	}{
		{"insufficient balance", nil, 101, testUSDC, testReceiver, "insufficient " + testUSDC + " balance: 100 of 101"},
		{"insufficient gas", func(f *chainFixture) { f.pages[types.SUI_TYPE_ARG] = [][]*v2.Object{{coinObject(11, 1)}} }, 50, testUSDC, testReceiver, "gas: insufficient"},
		{"zero gas price", func(f *chainFixture) { f.gasPrice = 0 }, 50, testUSDC, testReceiver, "invalid reference gas price"},
		{"gas budget overflow", func(f *chainFixture) { f.gasPrice = math.MaxUint64 / 1000 }, 50, testUSDC, testReceiver, "overflows the gas budget"},
		{"malformed receiver", nil, 50, testUSDC, "0xreceiver", "receiver"},
		{"no coin type", nil, 50, "", testReceiver, "no coin type"},
		// A SUI transfer may not pay gas with the coin it sends.
		{"SUI input reused as gas", func(f *chainFixture) { f.pages[types.SUI_TYPE_ARG] = [][]*v2.Object{{coinObject(11, 60_000_000)}} }, 60_000_000, types.SUI_TYPE_ARG, testReceiver, "gas: insufficient"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := fundedFixture()
			if tc.mutate != nil {
				tc.mutate(f)
			}
			h := startFixture(t, f)
			digest, err := h.TransferCoins(tc.amount, tc.coinType, tc.receiver, context.Background())
			if !errors.Is(err, ErrNotBroadcast) || !strings.Contains(err.Error(), tc.want) || digest != "" {
				t.Fatalf("TransferCoins = (%q, %v), want ErrNotBroadcast containing %q", digest, err, tc.want)
			}
			if len(f.executed) != 0 {
				t.Fatalf("a failed preparation submitted a transaction")
			}
		})
	}
}

func TestPrepareTransferRefusesRepeatedCoins(t *testing.T) {
	for name, mutate := range map[string]func(f *chainFixture){
		"transfer coin repeated": func(f *chainFixture) { f.pages[testUSDC] = [][]*v2.Object{{coinObject(1, 30)}, {coinObject(1, 30)}} },
		"gas coin repeated": func(f *chainFixture) {
			f.pages[types.SUI_TYPE_ARG] = [][]*v2.Object{{coinObject(11, 30_000_000)}, {coinObject(11, 30_000_000)}}
		},
	} {
		t.Run(name, func(t *testing.T) {
			f := fundedFixture()
			mutate(f)
			h := startFixture(t, f)
			digest, err := h.TransferCoins(50, testUSDC, testReceiver, context.Background())
			if !errors.Is(err, ErrNotBroadcast) || !strings.Contains(err.Error(), "twice") || digest != "" {
				t.Fatalf("TransferCoins = (%q, %v), want ErrNotBroadcast for a repeated coin", digest, err)
			}
			if len(f.executed) != 0 {
				t.Fatalf("a transfer with a repeated coin was submitted")
			}
		})
	}
}

// TestPreparedTransferReferencesEachCoinOnce decodes the signed bytes and
// checks that no coin object appears twice among the inputs and the gas
// payment.
func TestPreparedTransferReferencesEachCoinOnce(t *testing.T) {
	f := fundedFixture()
	f.pages[testUSDC] = [][]*v2.Object{{coinObject(1, 10), coinObject(2, 10)}, {coinObject(3, 40)}}
	f.pages[types.SUI_TYPE_ARG] = [][]*v2.Object{{coinObject(11, 20_000_000)}, {coinObject(12, 20_000_000), coinObject(13, 20_000_000)}}
	h := startFixture(t, f)
	prepared, err := h.PrepareTransfer(context.Background(), 50, testUSDC, testReceiver)
	if err != nil {
		t.Fatalf("PrepareTransfer: %v", err)
	}
	var data transaction.TransactionData
	if _, err := mystenbcs.Unmarshal(prepared.Bytes(), &data); err != nil {
		t.Fatalf("decode prepared transaction: %v", err)
	}
	seen := map[sdkmodels.SuiAddressBytes]bool{}
	var inputs, gas int
	for _, in := range data.V1.Kind.ProgrammableTransaction.Inputs {
		if in.Object == nil {
			continue
		}
		id := in.Object.ImmOrOwnedObject.ObjectId
		if seen[id] {
			t.Fatalf("coin %x is referenced twice", id)
		}
		seen[id] = true
		inputs++
	}
	for _, ref := range *data.V1.GasData.Payment {
		if seen[ref.ObjectId] {
			t.Fatalf("gas coin %x is referenced twice", ref.ObjectId)
		}
		seen[ref.ObjectId] = true
		gas++
	}
	if inputs != 3 || gas != 3 {
		t.Fatalf("%d coin inputs and %d gas coins, want 3 and 3", inputs, gas)
	}
}

// TestPrepareTransferRefusesOverlongListedIDs feeds coin listings carrying
// an object id of 65 hex digits, which the SDK's address normalisation cannot
// handle; selection must refuse it as an ordinary preparation error.
func TestPrepareTransferRefusesOverlongListedIDs(t *testing.T) {
	overlong := func(balance uint64) *v2.Object {
		o := coinObject(1, balance)
		o.ObjectId = proto.String("0x" + strings.Repeat("a", 65))
		return o
	}
	for name, mutate := range map[string]func(f *chainFixture){
		"transfer coin": func(f *chainFixture) { f.pages[testUSDC] = [][]*v2.Object{{overlong(100)}} },
		"gas coin":      func(f *chainFixture) { f.pages[types.SUI_TYPE_ARG] = [][]*v2.Object{{overlong(60_000_000)}} },
		"zero-balance transfer coin": func(f *chainFixture) {
			f.pages[testUSDC] = [][]*v2.Object{{overlong(0), coinObject(2, 100)}}
		},
	} {
		t.Run(name, func(t *testing.T) {
			f := fundedFixture()
			mutate(f)
			h := startFixture(t, f)
			prepared, err := h.PrepareTransfer(context.Background(), 50, testUSDC, testReceiver)
			if !errors.Is(err, ErrNotBroadcast) || prepared != nil {
				t.Fatalf("PrepareTransfer = (%v, %v), want nil and ErrNotBroadcast", prepared, err)
			}
			if len(f.executed) != 0 {
				t.Fatalf("an execution request was made")
			}
		})
	}
}

func TestSUITransferPaysGasFromOtherCoins(t *testing.T) {
	f := fundedFixture()
	f.pages[types.SUI_TYPE_ARG] = [][]*v2.Object{{coinObject(11, 60_000_000)}, {coinObject(12, 50_000_000)}}
	h := startFixture(t, f)
	if _, err := h.TransferCoins(60_000_000, types.SUI_TYPE_ARG, testReceiver, context.Background()); err != nil {
		t.Fatalf("TransferCoins: %v", err)
	}
}

func TestExecuteTransferOutcomes(t *testing.T) {
	t.Run("failure status", func(t *testing.T) {
		f := fundedFixture()
		f.execFails = true
		h := startFixture(t, f)
		digest, err := h.TransferCoins(50, testUSDC, testReceiver, context.Background())
		if !errors.Is(err, ErrTransferFailed) || errors.Is(err, ErrNotBroadcast) || digest == "" {
			t.Fatalf("TransferCoins = (%q, %v), want ErrTransferFailed with a digest", digest, err)
		}
	})
	t.Run("submission error leaves the outcome unknown", func(t *testing.T) {
		f := fundedFixture()
		f.execErr = status.Error(codes.Unavailable, "connection reset")
		h := startFixture(t, f)
		digest, err := h.TransferCoins(50, testUSDC, testReceiver, context.Background())
		if err == nil || errors.Is(err, ErrTransferFailed) || errors.Is(err, ErrNotBroadcast) {
			t.Fatalf("TransferCoins = %v, want an error wrapping neither sentinel", err)
		}
		if digest == "" {
			t.Fatalf("an unknown outcome returned no digest to look up")
		}
	})
	t.Run("nothing prepared", func(t *testing.T) {
		h := startFixture(t, fundedFixture())
		if err := h.ExecuteTransfer(context.Background(), &PreparedTransfer{}); !errors.Is(err, ErrNotBroadcast) {
			t.Fatalf("ExecuteTransfer(empty) = %v, want ErrNotBroadcast", err)
		}
	})
}

func TestExecuteTransferResponseForAnotherDigestIsUnknown(t *testing.T) {
	for _, tc := range []struct {
		name       string
		respDigest string
		fails      bool
	}{
		{"other digest, success", testObjectDigest(0x42), false},
		{"other digest, failure", testObjectDigest(0x42), true},
		{"empty digest, success", "", false},
		{"empty digest, failure", "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := fundedFixture()
			h := startFixture(t, f)
			prepared, err := h.PrepareTransfer(context.Background(), 50, testUSDC, testReceiver)
			if err != nil {
				t.Fatalf("PrepareTransfer: %v", err)
			}
			digest, txBytes, signature := prepared.Digest, bytes.Clone(prepared.Bytes()), prepared.Signature()
			f.respDigest, f.execFails = &tc.respDigest, tc.fails

			err = h.ExecuteTransfer(context.Background(), prepared)
			if err == nil || errors.Is(err, ErrNotBroadcast) || errors.Is(err, ErrTransferFailed) {
				t.Fatalf("ExecuteTransfer = %v, want an unknown outcome wrapping neither sentinel", err)
			}
			if prepared.Digest != digest {
				t.Fatalf("prepared digest changed from %s to %s", digest, prepared.Digest)
			}
			if _, err := RestorePreparedTransfer(digest, txBytes, signature); err != nil {
				t.Fatalf("RestorePreparedTransfer after the mismatch: %v", err)
			}
		})
	}
}

func TestLookupTransferResponseForAnotherDigestIsAnError(t *testing.T) {
	for _, tc := range []struct {
		name       string
		respDigest string
		success    bool
	}{
		{"other digest, success", "other-digest", true},
		{"other digest, failure", "other-digest", false},
		{"empty digest, success", "", true},
		{"empty digest, failure", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := fundedFixture()
			f.statuses["digest"] = tc.success
			f.respDigest = &tc.respDigest
			h := startFixture(t, f)
			got, verified, err := h.LookupTransfer(context.Background(), "digest", nil)
			if err == nil || got == TransferConfirmed || got == TransferFailed || verified {
				t.Fatalf("LookupTransfer = (%q, %v, %v), want an error", got, verified, err)
			}
		})
	}
}

func TestLookupTransfer(t *testing.T) {
	f := fundedFixture()
	f.statuses["confirmed-digest"] = true
	f.statuses["failed-digest"] = false
	h := startFixture(t, f)
	for digest, want := range map[string]TransferOutcome{
		"confirmed-digest": TransferConfirmed,
		"failed-digest":    TransferFailed,
		"unknown-digest":   TransferNotFound,
	} {
		got, verified, err := h.LookupTransfer(context.Background(), digest, nil)
		if err != nil || got != want || verified {
			t.Fatalf("LookupTransfer(%q) = (%q, %v, %v), want %q unverified", digest, got, verified, err, want)
		}
	}
	if _, _, err := h.LookupTransfer(context.Background(), "", nil); err == nil {
		t.Fatalf("LookupTransfer(empty) succeeded")
	}
}

func balanceChange(address string, coinType string, amount string) *v2.BalanceChange {
	return &v2.BalanceChange{Address: proto.String(address), CoinType: proto.String(coinType), Amount: proto.String(amount)}
}

func TestLookupTransferChecksTheCredit(t *testing.T) {
	sender := testSigner().Address
	short := "0x" + strings.TrimLeft(testReceiver[2:], "0")
	expect := &TransferExpectation{Receiver: testReceiver, Amount: 50, CoinType: testUSDC}
	cases := []struct {
		name    string
		changes []*v2.BalanceChange
		want    TransferOutcome
		checked bool
		err     string
	}{
		{"matching credit", []*v2.BalanceChange{
			balanceChange(sender, testUSDC, "-50"),
			balanceChange(short, testUSDC, "50"), // short address form
			balanceChange(sender, "0x2::sui::SUI", "-1000"),
		}, TransferConfirmed, true, ""},
		{"no balance changes", nil, TransferConfirmed, false, ""},
		{"wrong amount", []*v2.BalanceChange{balanceChange(testReceiver, testUSDC, "49")}, "", false, "credited 49"},
		{"wrong receiver", []*v2.BalanceChange{balanceChange(testObjectID(0xbb), testUSDC, "50")}, "", false, "credited 0"},
		{"wrong coin type", []*v2.BalanceChange{balanceChange(testReceiver, "0x2::sui::SUI", "50")}, "", false, "credited 0"},
		{"malformed amount", []*v2.BalanceChange{balanceChange(testReceiver, testUSDC, "5x")}, "", false, "invalid amount"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := fundedFixture()
			f.statuses["digest"] = true
			f.changes["digest"] = tc.changes
			h := startFixture(t, f)
			got, checked, err := h.LookupTransfer(context.Background(), "digest", expect)
			if tc.err == "" {
				if err != nil || got != tc.want || checked != tc.checked {
					t.Fatalf("LookupTransfer = (%q, %v, %v), want (%q, %v)", got, checked, err, tc.want, tc.checked)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.err) || got == TransferFailed || got == TransferConfirmed {
				t.Fatalf("LookupTransfer = (%q, %v, %v), want an error containing %q", got, checked, err, tc.err)
			}
		})
	}
	t.Run("failure status is failed whatever the changes", func(t *testing.T) {
		f := fundedFixture()
		f.statuses["digest"] = false
		f.changes["digest"] = []*v2.BalanceChange{balanceChange(sender, "0x2::sui::SUI", "-1000")}
		h := startFixture(t, f)
		if got, _, err := h.LookupTransfer(context.Background(), "digest", expect); err != nil || got != TransferFailed {
			t.Fatalf("LookupTransfer = (%q, %v), want failed", got, err)
		}
	})
}

func TestRestorePreparedTransfer(t *testing.T) {
	f := fundedFixture()
	h := startFixture(t, f)
	prepared, err := h.PrepareTransfer(context.Background(), 50, testUSDC, testReceiver)
	if err != nil {
		t.Fatalf("PrepareTransfer: %v", err)
	}
	// What a caller persists before submission.
	digest, txBytes, signature := prepared.Digest, bytes.Clone(prepared.Bytes()), prepared.Signature()

	restored, err := RestorePreparedTransfer(digest, txBytes, signature)
	if err != nil {
		t.Fatalf("RestorePreparedTransfer: %v", err)
	}
	if err := h.ExecuteTransfer(context.Background(), restored); err != nil {
		t.Fatalf("ExecuteTransfer(restored): %v", err)
	}
	if len(f.executed) != 1 || !bytes.Equal(f.executed[0], txBytes) || restored.Digest != digest {
		t.Fatalf("the restored transfer did not submit the persisted bytes")
	}

	other, err := h.PrepareTransfer(context.Background(), 40, testUSDC, testReceiver)
	if err != nil {
		t.Fatalf("PrepareTransfer: %v", err)
	}
	for name, args := range map[string]struct {
		digest    string
		txBytes   []byte
		signature string
	}{
		"digest of other bytes": {other.Digest, txBytes, signature},
		"altered bytes":         {digest, append(bytes.Clone(txBytes), 0), signature},
		"no bytes":              {digest, nil, signature},
		"no signature":          {digest, txBytes, ""},
	} {
		if _, err := RestorePreparedTransfer(args.digest, args.txBytes, args.signature); !errors.Is(err, ErrNotBroadcast) {
			t.Fatalf("%s: RestorePreparedTransfer = %v, want ErrNotBroadcast", name, err)
		}
	}
	if len(f.executed) != 1 {
		t.Fatalf("a refused restore submitted a transaction")
	}
}

// ---- construction ----

func TestValidAddress(t *testing.T) {
	for _, ok := range []string{"0x2", testReceiver, "0x" + strings.Repeat("A", 64)} {
		if err := ValidAddress(ok); err != nil {
			t.Fatalf("ValidAddress(%q) = %v", ok, err)
		}
	}
	for _, bad := range []string{"", "0x", "2", "0xreceiver", "0x" + strings.Repeat("a", 65), "0X2", " 0x2"} {
		if err := ValidAddress(bad); err == nil {
			t.Fatalf("ValidAddress(%q) accepted", bad)
		}
	}
}

// suiConfig returns an enabled configuration that passes validation, with a
// keystore holding the key of its address. Endpoints are unresolvable
// placeholders; construction never dials.
func suiConfig(t *testing.T) *config.DispatcherConfig {
	t.Helper()
	path := writeKeystore(t, keystoreEntry(0, bytes.Repeat([]byte{7}, 32)))
	return &config.DispatcherConfig{Sui: config.SuiConfig{
		Network:           "testnet",
		GRPCEndpoint:      "fullnode.invalid:443",
		GraphQLURL:        "https://graphql.invalid/graphql",
		Address:           testSigner().Address,
		PaymentRegistryId: testObjectID(2),
		PaymentKitPackage: testObjectID(3),
		KeystorePath:      path,
	}}
}

func TestNewSuiPaymentHandler(t *testing.T) {
	h, err := NewSuiPaymentHandler(suiConfig(t), nil, zap.NewNop(), nil)
	if err != nil {
		t.Fatalf("NewSuiPaymentHandler: %v", err)
	}
	if h.signer == nil || h.signer.Address != testSigner().Address || h.client == nil || h.lis == nil {
		t.Fatalf("handler is incomplete")
	}
}

func TestNewSuiPaymentHandlerRejectsUnusableConfig(t *testing.T) {
	other := signer.NewSigner(bytes.Repeat([]byte{8}, 32))
	cases := []struct {
		name   string
		mutate func(t *testing.T, c *config.SuiConfig)
		want   string
	}{
		{"invalid network", func(_ *testing.T, c *config.SuiConfig) { c.Network = "devnet" }, "sui.network"},
		{"empty network", func(_ *testing.T, c *config.SuiConfig) { c.Network = "" }, "sui.network"},
		{"empty endpoint", func(_ *testing.T, c *config.SuiConfig) { c.GRPCEndpoint = "" }, "sui.grpc_endpoint"},
		{"endpoint without port", func(_ *testing.T, c *config.SuiConfig) { c.GRPCEndpoint = "fullnode.invalid" }, "sui.grpc_endpoint"},
		{"endpoint with bad port", func(_ *testing.T, c *config.SuiConfig) { c.GRPCEndpoint = "fullnode.invalid:0" }, "sui.grpc_endpoint"},
		{"relative graphql url", func(_ *testing.T, c *config.SuiConfig) { c.GraphQLURL = "/graphql" }, "sui.graphql_url"},
		{"malformed address", func(_ *testing.T, c *config.SuiConfig) { c.Address = "0xdead-beef" }, "sui.address"},
		{"malformed registry id", func(_ *testing.T, c *config.SuiConfig) { c.PaymentRegistryId = "registry" }, "sui.payment_registry_id"},
		{"malformed package id", func(_ *testing.T, c *config.SuiConfig) { c.PaymentKitPackage = "" }, "sui.payment_kit_package"},
		{"empty keystore path", func(_ *testing.T, c *config.SuiConfig) { c.KeystorePath = "" }, "sui.keystore_path is empty"},
		{"missing keystore", func(t *testing.T, c *config.SuiConfig) { c.KeystorePath = filepath.Join(t.TempDir(), "missing") }, "read keystore"},
		{"keystore without the address", func(_ *testing.T, c *config.SuiConfig) { c.Address = other.Address }, "no Ed25519 key for address"},
		{"keystore not JSON", func(t *testing.T, c *config.SuiConfig) { c.KeystorePath = writeFile(t, "not json") }, "not a JSON array"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := suiConfig(t)
			tc.mutate(t, &cfg.Sui)
			h, err := NewSuiPaymentHandler(cfg, nil, zap.NewNop(), nil)
			if err == nil || h != nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("NewSuiPaymentHandler = (%v, %v), want an error containing %q", h, err, tc.want)
			}
			if strings.Contains(err.Error(), keystoreEntry(0, bytes.Repeat([]byte{7}, 32))) {
				t.Fatalf("construction error contains keystore content")
			}
		})
	}
}

func TestNewSuiPaymentHandlerRedactsInvalidEndpoints(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(c *config.SuiConfig)
		want   string
	}{
		{"grpc credentials", func(c *config.SuiConfig) {
			c.GRPCEndpoint = "https://endpoint-user:endpoint-password@fullnode.invalid:443"
		}, "sui.grpc_endpoint must be host:port"},
		{"grpc port query token", func(c *config.SuiConfig) {
			c.GRPCEndpoint = "fullnode.invalid:443?token=query-secret"
		}, "sui.grpc_endpoint has an invalid port"},
		{"graphql parse credentials and query token", func(c *config.SuiConfig) {
			c.GraphQLURL = "https://endpoint-user:endpoint-password@graphql.invalid/%zz?token=query-secret"
		}, "sui.graphql_url must be an absolute http(s) URL"},
		{"graphql scheme credentials and query token", func(c *config.SuiConfig) {
			c.GraphQLURL = "ftp://endpoint-user:endpoint-password@graphql.invalid/graphql?token=query-secret"
		}, "sui.graphql_url must be an absolute http(s) URL"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := suiConfig(t)
			tc.mutate(&cfg.Sui)
			h, err := NewSuiPaymentHandler(cfg, nil, zap.NewNop(), nil)
			if h != nil || err == nil || err.Error() != tc.want {
				t.Fatalf("NewSuiPaymentHandler = (%v, %v), want only %q", h, err, tc.want)
			}
		})
	}
}
