// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package api

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/netsec-ethz/debuglet/internal/dispatcher"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/config"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/database"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/payments"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/tag"
	"github.com/netsec-ethz/debuglet/internal/sqlitedb"
	"github.com/netsec-ethz/debuglet/pkg/client"
	"github.com/netsec-ethz/debuglet/pkg/tagspec"
	"github.com/netsec-ethz/debuglet/pkg/wire"
	pb "github.com/netsec-ethz/debuglet/protocol"

	"github.com/labstack/echo/v4"
	"go.uber.org/zap"
	"golang.org/x/time/rate"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// vtChain is a real TESLA chain k_0 … k_L, so packets carry tags the
// dispatcher can check against a disclosed key.
type vtChain struct {
	seed   []byte
	length int64
	t0     time.Time
	delay  int64
}

func (c vtChain) key(e int64) []byte {
	k := bytes.Clone(c.seed)
	for i := c.length; i > e; i-- {
		sum := sha256.Sum256(k)
		k = sum[:]
	}
	return k
}

func (c vtChain) anchor() []byte { return c.key(0) }

func (c vtChain) epochOf(at time.Time) int64 { return int64(at.Sub(c.t0) / time.Minute) }

func (c vtChain) due(e int64) time.Time { return c.t0.Add(time.Duration(e+c.delay) * time.Minute) }

// vtPacket is a 64-byte UDP probe from src, tagged for run at epoch e when
// run is not empty.
func vtPacket(c vtChain, src string, e int64, run string, fill byte) []byte {
	p := make([]byte, 64)
	p[0], p[8], p[9] = 0x45, 64, 17
	binary.BigEndian.PutUint16(p[2:], 64)
	p[6] = 0x40
	copy(p[12:16], netip.MustParseAddr(src).AsSlice())
	copy(p[16:20], []byte{192, 0, 2, 1})
	binary.BigEndian.PutUint16(p[20:], 40000)
	binary.BigEndian.PutUint16(p[22:], 33434)
	binary.BigEndian.PutUint16(p[24:], 44)
	for i := 28; i < 64; i++ {
		p[i] = fill
	}
	if run != "" {
		ak, err := tagspec.DeriveAK(c.key(e), []byte(run))
		if err != nil {
			panic(err)
		}
		tag, err := tagspec.PacketTag(ak, p)
		if err != nil {
			panic(err)
		}
		binary.BigEndian.PutUint16(p[4:], tag)
	}
	return p
}

// vtPeer is the scripted executor with a VerifyTags answer.
type vtPeer struct {
	*cpPeer
	mu     sync.Mutex
	answer func(*pb.VerifyTagsRequest) (*pb.VerifyTagsResponse, error)
	calls  int
}

func (p *vtPeer) VerifyTags(_ context.Context, req *pb.VerifyTagsRequest) (*pb.VerifyTagsResponse, error) {
	p.mu.Lock()
	p.calls++
	answer := p.answer
	p.mu.Unlock()
	if answer == nil {
		return nil, status.Error(codes.Unimplemented, "no answer scripted")
	}
	return answer(req)
}

func (p *vtPeer) script(answer func(*pb.VerifyTagsRequest) (*pb.VerifyTagsResponse, error)) {
	p.mu.Lock()
	p.answer = answer
	p.mu.Unlock()
}

func (p *vtPeer) callCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.calls
}

// vtFixture is a dispatcher whose executor announces a real chain with one
// minute epochs, d = 15, started ten minutes ago, and answers VerifyTags as
// scripted. The handler keeps its receipt key in a temporary directory.
func vtFixture(t *testing.T, options ...Option) (*ccFixture, *vtPeer, vtChain) {
	t.Helper()
	chain := vtChain{seed: bytes.Repeat([]byte{0x5A}, 32), length: 10080, t0: time.Now().Truncate(time.Minute).Add(-10 * time.Minute), delay: 15}
	peer := &vtPeer{cpPeer: &cpPeer{id: ccExecutorID, price: ccPricePerBwS, currency: "TEST", tesla: &pb.HelloResponse{
		TeslaAnchorKey: chain.anchor(), TeslaAnchorTimestampNs: chain.t0.UnixNano(), TeslaDelaySec: 60,
		TeslaDisclosureDelayEpochs: chain.delay, TeslaChainLength: chain.length,
		Capabilities: &pb.ExecutorCapabilities{SchemaVersion: 1, Protocols: []string{"tcp"}, EnforcementMode: "ebpf",
			Tagging: &pb.TaggingMode{Ipv4: "ebpf", Ipv6: "none", Scion: "none", TagSpec: tagspec.ID}},
	}}}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	db, err := sqlitedb.Open(filepath.Join(t.TempDir(), "dispatcher.sqlite"), sqlitedb.Create())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if _, err := sqlitedb.Migrate(t.Context(), db, database.MigrationFS(), sqlitedb.Latest); err != nil {
		t.Fatal(err)
	}
	ph := payments.NewPaymentHandler(db, &config.DispatcherConfig{Sui: config.SuiConfig{Disabled: true}}, zap.NewNop())
	d, err := dispatcher.New(zap.NewNop(), db, "vt-version", time.Minute, time.Minute, ph)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(d.Close)
	stop, err := startClientPeer(ctx, d, ccCapacity, peer)
	if err != nil {
		t.Fatalf("startClientPeer: %v", err)
	}
	t.Cleanup(func() {
		cancel()
		cleanup, done := context.WithTimeout(context.Background(), ccCleanupBound)
		defer done()
		if err := stop(cleanup); err != nil {
			t.Errorf("stop client peer: %v", err)
		}
	})
	e := echo.New()
	e.HideBanner = true
	NewHandler(d, db, zap.NewNop(), append([]Option{MetricsStateDirectory(t.TempDir())}, options...)...).RegisterRoutes(e)
	root := httptest.NewServer(e)
	t.Cleanup(func() {
		root.CloseClientConnections()
		root.Close()
	})
	return &ccFixture{t: t, ctx: ctx, db: db, queries: database.New(db), d: d, peer: peer.cpPeer, root: root}, peer, chain
}

// vtRun submits one run from the fixture's executor, active now from
// 127.0.0.1, and returns its ID.
func vtRun(t *testing.T, f *ccFixture) string {
	t.Helper()
	_, _, owner := authAccount(t, f, "verify owner")
	f.peer.setUploadHook(nil)
	return f.submit(owner, []string{"verify"}).IDs[0]
}

// vtCheckReceipt verifies the receipt of resp under the published key and
// checks that it binds the request's packets and the response's groups, and
// that any changed byte breaks it.
func vtCheckReceipt(t *testing.T, c *client.Client, sent []client.AttributionVerifyPacket, resp client.AttributionVerifyResponse) wire.AttributionReceiptPayload {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), ccRequestBound)
	defer cancel()
	keys, err := c.AttributionReceiptKeys(ctx)
	if err != nil {
		t.Fatalf("AttributionReceiptKeys: %v", err)
	}
	k := slices.IndexFunc(keys.Keys, func(k client.AttributionReceiptKey) bool { return k.KeyID == resp.Receipt.KeyID })
	if k < 0 || keys.Keys[k].ValidTo != nil || client.ReceiptKeyID(keys.Keys[k].PublicKey) != resp.Receipt.KeyID {
		t.Fatalf("receipt key %s is not the published current key: %+v", resp.Receipt.KeyID, keys.Keys)
	}
	public := ed25519.PublicKey(keys.Keys[k].PublicKey)
	r := resp.Receipt
	if !ed25519.Verify(public, r.Payload, r.Signature) {
		t.Fatal("the receipt does not verify under the published key")
	}
	for i := range r.Payload {
		changed := bytes.Clone(r.Payload)
		changed[i] ^= 1
		if ed25519.Verify(public, changed, r.Signature) {
			t.Fatalf("a receipt with byte %d changed still verifies", i)
		}
	}
	for i := range r.Signature {
		changed := bytes.Clone(r.Signature)
		changed[i] ^= 1
		if ed25519.Verify(public, r.Payload, changed) {
			t.Fatalf("a signature with byte %d changed still verifies", i)
		}
	}
	var p wire.AttributionReceiptPayload
	if err := json.Unmarshal(r.Payload, &p); err != nil {
		t.Fatal(err)
	}
	canonical, err := wire.CanonicalReceiptPayload(p)
	if err != nil || !bytes.Equal(canonical, r.Payload) {
		t.Fatalf("the payload is not canonical JSON: %s", r.Payload)
	}
	queryAt, err := time.Parse(time.RFC3339Nano, p.QueryAt)
	if err != nil || time.Since(queryAt) > time.Minute || p.APIVersion != "1.15" || p.Dispatcher == "" {
		t.Fatalf("payload %+v", p)
	}
	if p.PacketsDigest != wire.PacketsDigest(sent) || len(p.Groups) != len(resp.Groups) {
		t.Fatalf("the receipt does not bind the request: %+v", p)
	}
	for i, g := range resp.Groups {
		pg := p.Groups[i]
		if pg.Source != g.Source || pg.Epoch != g.Epoch || pg.ChainID != g.ChainID || pg.ExecutorID != g.ExecutorID || pg.RunID != g.RunID ||
			pg.Verdict != g.Verdict || pg.Reason != g.Reason || pg.Method != g.Method || !slices.Equal(pg.Packets, g.Packets) {
			t.Fatalf("receipt group %d %+v differs from the answer %+v", i, pg, g)
		}
	}
	return p
}

// TestAttributionVerifyRelaysToTheExecutorBeforeDisclosure asks about a group
// whose key is not disclosed: the dispatcher relays it over the control
// session, maps each executor answer to a verdict, spends one query each and
// signs a receipt that binds the packets and the answers.
func TestAttributionVerifyRelaysToTheExecutorBeforeDisclosure(t *testing.T) {
	f, peer, chain := vtFixture(t)
	run := vtRun(t, f)
	anonymous := f.client(f.root.URL, false)
	ctx, cancel := f.requestCtx()
	defer cancel()
	at := time.Now()
	e := chain.epochOf(at)
	sent := []client.AttributionVerifyPacket{
		{Data: vtPacket(chain, "127.0.0.1", e, run, 1), CapturedAt: at},
		{Data: vtPacket(chain, "127.0.0.1", e, run, 2), CapturedAt: at.Add(time.Millisecond)},
	}
	for i, tc := range []struct {
		answer                *pb.VerifyTagsResponse
		err                   error
		verdict, reason, want string
		method                string
	}{
		{answer: &pb.VerifyTagsResponse{Verdict: "matched", RunId: run}, verdict: "verified", want: run, method: "server"},
		{answer: &pb.VerifyTagsResponse{Verdict: "unmatched"}, verdict: "invalid", reason: "tag_mismatch", method: "server"},
		{answer: &pb.VerifyTagsResponse{Verdict: "ambiguous"}, verdict: "unsupported", reason: "ambiguous", method: "server"},
		{answer: &pb.VerifyTagsResponse{Verdict: "unsupported", Reason: "unknown_chain"}, verdict: "unsupported", reason: "unknown_chain", method: "server"},
		// An answer outside the protocol is no answer, but the query is spent.
		{answer: &pb.VerifyTagsResponse{Verdict: "matched", RunId: "00000000-0000-0000-0000-00000000beef"}, verdict: "pending", reason: "executor_unavailable"},
		{err: status.Error(codes.Unavailable, "gone"), verdict: "pending", reason: "executor_unavailable"},
	} {
		var unexpected string
		peer.script(func(req *pb.VerifyTagsRequest) (*pb.VerifyTagsResponse, error) {
			if req.GetEpoch() != e || !bytes.Equal(req.GetChainAnchor(), chain.anchor()) || !slices.Equal(req.GetCandidateRunIds(), []string{run}) ||
				len(req.GetPackets()) != 2 || !bytes.Equal(req.GetPackets()[1], sent[1].Data) || req.GetControlBinding().GetSessionId() == "" {
				unexpected = fmt.Sprintf("unexpected request %v", req)
				return nil, status.Error(codes.InvalidArgument, unexpected)
			}
			return tc.answer, tc.err
		})
		resp, err := anonymous.AttributionVerify(ctx, sent)
		if err != nil {
			t.Fatalf("case %d: %v", i, err)
		}
		if len(resp.Groups) != 1 {
			t.Fatalf("case %d: groups %+v", i, resp.Groups)
		}
		g := resp.Groups[0]
		if g.Verdict != tc.verdict || g.Reason != tc.reason || g.RunID != tc.want || g.Method != tc.method || g.Source != "127.0.0.1" ||
			g.Epoch != e || g.ChainID != tag.ChainID(chain.anchor()) || g.ExecutorID != ccExecutorID || !slices.Equal(g.Packets, []int{0, 1}) {
			t.Fatalf("case %d: group %+v (executor asked %d times; %s)", i, g, peer.callCount(), unexpected)
		}
		if g.Budget == nil || g.Budget.Limit != 16 || g.Budget.Remaining != int64(15-i) || !g.Budget.ResetsAt.Equal(chain.due(e)) {
			t.Fatalf("case %d: budget %+v; want 16, %d remaining, resetting at %s", i, g.Budget, 15-i, chain.due(e))
		}
		vtCheckReceipt(t, anonymous, sent, resp)
	}
	if peer.callCount() != 6 {
		t.Fatalf("the executor was asked %d times; want 6", peer.callCount())
	}
}

// TestAttributionVerifyBudgetIsSharedDurableAndNotRefunded spends the 16
// queries of one epoch, one of them lost, and finds the budget exhausted, also
// after a dispatcher restart on the same database.
func TestAttributionVerifyBudgetIsSharedDurableAndNotRefunded(t *testing.T) {
	f, peer, chain := vtFixture(t)
	run := vtRun(t, f)
	ctx, cancel := f.requestCtx()
	defer cancel()
	at := time.Now()
	e := chain.epochOf(at)
	packets := []dispatcher.VerifyPacket{{Data: vtPacket(chain, "127.0.0.1", e, run, 1), CapturedAt: at}}
	peer.script(func(*pb.VerifyTagsRequest) (*pb.VerifyTagsResponse, error) {
		return nil, status.Error(codes.DeadlineExceeded, "answer lost")
	})
	groups, err := f.d.VerifyAttribution(ctx, packets)
	if err != nil || len(groups) != 1 || groups[0].Verdict != "pending" || groups[0].Reason != "executor_unavailable" || groups[0].Budget.Remaining != 15 {
		t.Fatalf("a lost answer: %+v, %v; want pending with the query spent", groups, err)
	}
	peer.script(func(*pb.VerifyTagsRequest) (*pb.VerifyTagsResponse, error) {
		return &pb.VerifyTagsResponse{Verdict: "matched", RunId: run}, nil
	})
	// Requests from different clients share the budget.
	for i := range 15 {
		c := f.client(f.root.URL, false)
		resp, err := c.AttributionVerify(ctx, []client.AttributionVerifyPacket{{Data: packets[0].Data, CapturedAt: at}})
		if err != nil || resp.Groups[0].Verdict != "verified" || resp.Groups[0].Budget.Remaining != int64(14-i) {
			t.Fatalf("query %d: %+v, %v", i+2, resp.Groups, err)
		}
	}
	groups, err = f.d.VerifyAttribution(ctx, packets)
	if err != nil || groups[0].Verdict != "pending" || groups[0].Reason != "budget_exhausted" || groups[0].Budget.Remaining != 0 ||
		!groups[0].Budget.ResetsAt.Equal(chain.due(e)) || groups[0].Method != "" {
		t.Fatalf("over the budget: %+v, %v; want pending until %s", groups, err, chain.due(e))
	}
	if peer.callCount() != 16 {
		t.Fatalf("the executor was asked %d times; want 16", peer.callCount())
	}
	used, err := f.queries.GetAttributionVerifyBudget(ctx, database.GetAttributionVerifyBudgetParams{ExecutorID: ccExecutorID, ChainID: tag.ChainID(chain.anchor()), Epoch: e})
	if err != nil || used != 16 {
		t.Fatalf("budget on record %d, %v", used, err)
	}
	// Another epoch has its own budget.
	other := []dispatcher.VerifyPacket{{Data: vtPacket(chain, "127.0.0.1", e+1, run, 1), CapturedAt: chain.t0.Add(time.Duration(e+1) * time.Minute)}}
	if groups, err := f.d.VerifyAttribution(ctx, other); err != nil || groups[0].Verdict != "verified" || groups[0].Budget.Remaining != 15 {
		t.Fatalf("another epoch: %+v, %v", groups, err)
	}

	// A restart keeps the count. The restarted dispatcher has no session
	// with the executor, so it asks nothing and spends nothing.
	f.d.Close()
	restarted, err := dispatcher.New(zap.NewNop(), f.db, "restarted", time.Minute, time.Minute,
		payments.NewPaymentHandler(f.db, &config.DispatcherConfig{Sui: config.SuiConfig{Disabled: true}}, zap.NewNop()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(restarted.Close)
	groups, err = restarted.VerifyAttribution(ctx, packets)
	if err != nil || groups[0].Verdict != "pending" || groups[0].Budget.Remaining != 0 {
		t.Fatalf("after a restart: %+v, %v; want the budget still spent", groups, err)
	}
	if groups, err := restarted.VerifyAttribution(ctx, other); err != nil || groups[0].Reason != "executor_unavailable" || groups[0].Budget.Remaining != 15 {
		t.Fatalf("an unavailable executor after a restart: %+v, %v; want nothing spent", groups, err)
	}
}

// TestAttributionVerifyAnswersADisclosedEpochOffline checks groups whose key
// is on record against it, without the executor and without spending budget,
// and decides the packets without a run or without a tag.
func TestAttributionVerifyAnswersADisclosedEpochOffline(t *testing.T) {
	f, peer, chain := vtFixture(t)
	run := vtRun(t, f)
	ctx, cancel := f.requestCtx()
	defer cancel()
	at := time.Now()
	e := chain.epochOf(at)
	// A later key is on record; the epoch's own key derives from it.
	if err := f.queries.InsertAttributionKey(ctx, database.InsertAttributionKeyParams{
		ExecutorID: ccExecutorID, ChainID: tag.ChainID(chain.anchor()), Epoch: e + 2, Key: chain.key(e + 2), DisclosedAtNs: 1,
	}); err != nil {
		t.Fatal(err)
	}
	anonymous := f.client(f.root.URL, false)
	altered := vtPacket(chain, "127.0.0.1", e, run, 3)
	altered[40] ^= 0xFF
	ipv6 := make([]byte, 48)
	ipv6[0] = 0x60
	for _, tc := range []struct {
		name    string
		packets [][]byte
		want    []string
	}{
		{"tagged", [][]byte{vtPacket(chain, "127.0.0.1", e, run, 1), vtPacket(chain, "127.0.0.1", e, run, 2)}, []string{"verified  offline " + run}},
		{"altered", [][]byte{altered}, []string{"invalid tag_mismatch offline "}},
		{"mixed", [][]byte{ipv6, vtPacket(chain, "198.51.100.9", e, "", 1)}, []string{"unsupported ipv6  ", "invalid no_run offline "}},
	} {
		sent := make([]client.AttributionVerifyPacket, len(tc.packets))
		for i, p := range tc.packets {
			sent[i] = client.AttributionVerifyPacket{Data: p, CapturedAt: at}
		}
		resp, err := anonymous.AttributionVerify(ctx, sent)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		var got []string
		for _, g := range resp.Groups {
			got = append(got, strings.Join([]string{g.Verdict, g.Reason, g.Method, g.RunID}, " "))
			if g.Budget != nil && g.Budget.Remaining != 16 {
				t.Errorf("%s: an offline answer spent budget: %+v", tc.name, g.Budget)
			}
		}
		if !slices.Equal(got, tc.want) {
			t.Fatalf("%s: groups %q; want %q", tc.name, got, tc.want)
		}
		vtCheckReceipt(t, anonymous, sent, resp)
		oaCheckResponse(t, oaContract(t), http.MethodPost, routeAttributionVerify, http.StatusOK, mustJSON(t, resp))
	}
	if peer.callCount() != 0 {
		t.Fatalf("the executor was asked %d times about disclosed epochs", peer.callCount())
	}
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// TestAttributionVerifyBounds refuses requests beyond the documented limits.
func TestAttributionVerifyBounds(t *testing.T) {
	f, _, chain := vtFixture(t)
	at := time.Now().UTC().Format(time.RFC3339Nano)
	packet := func(src string) string {
		data, _ := json.Marshal(vtPacket(chain, src, 1, "", 1))
		return `{"data":` + string(data) + `,"captured_at":"` + at + `"}`
	}
	list := func(n int, src func(int) string) []byte {
		items := make([]string, n)
		for i := range items {
			items[i] = packet(src(i))
		}
		return []byte(`{"packets":[` + strings.Join(items, ",") + `]}`)
	}
	same := func(int) string { return "127.0.0.1" }
	for _, tc := range []struct {
		name   string
		body   []byte
		status int
	}{
		{"no packets", []byte(`{"packets":[]}`), http.StatusBadRequest},
		{"unknown field", []byte(`{"packets":[` + packet("127.0.0.1") + `],"extra":1}`), http.StatusBadRequest},
		{"no capture time", []byte(`{"packets":[{"data":"RQ=="}]}`), http.StatusBadRequest},
		{"65 bytes", []byte(`{"packets":[{"data":"` + strings.Repeat("A", 88) + `","captured_at":"` + at + `"}]}`), http.StatusBadRequest},
		{"257 packets", list(257, same), http.StatusBadRequest},
		{"17 groups", list(17, func(i int) string { return fmt.Sprintf("198.51.100.%d", i+1) }), http.StatusBadRequest},
		{"16 groups", list(16, func(i int) string { return fmt.Sprintf("198.51.100.%d", i+1) }), http.StatusOK},
		{"over 64 KiB", []byte(`{"packets":[` + strings.Repeat(" ", 64<<10) + `]}`), http.StatusRequestEntityTooLarge},
	} {
		status, code, body, _ := authRequest(t, f, http.MethodPost, routeAttributionVerify, tc.body, nil)
		if status != tc.status {
			t.Errorf("%s: answered %d %s: %s", tc.name, status, code, body)
		}
	}
	// 256 packets are accepted.
	short := make([]string, 256)
	data, _ := json.Marshal(vtPacket(chain, "127.0.0.1", 1, "", 1)[:20])
	for i := range short {
		short[i] = `{"data":` + string(data) + `,"captured_at":"` + at + `"}`
	}
	if status, code, body, _ := authRequest(t, f, http.MethodPost, routeAttributionVerify, []byte(`{"packets":[`+strings.Join(short, ",")+`]}`), nil); status != http.StatusOK {
		t.Errorf("256 packets answered %d %s: %s", status, code, body)
	}
}

// TestAttributionVerifyRoutesAreRateLimited shares the attribution limiter.
func TestAttributionVerifyRoutesAreRateLimited(t *testing.T) {
	f, _, chain := vtFixture(t)
	e := echo.New()
	h := NewHandler(f.d, f.db, zap.NewNop(), MetricsStateDirectory(t.TempDir()))
	h.attributionLimiter = newAddressLimiter(rate.Every(time.Hour), 2)
	h.RegisterRoutes(e)
	data, _ := json.Marshal(vtPacket(chain, "127.0.0.1", 1, "", 1))
	body := `{"packets":[{"data":` + string(data) + `,"captured_at":"` + time.Now().UTC().Format(time.RFC3339Nano) + `"}]}`
	send := func(method, target, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, target, strings.NewReader(body))
		req.RemoteAddr = "198.51.100.1:4000"
		rec := httptest.NewRecorder()
		e.ServeHTTP(rec, req)
		return rec
	}
	if rec := send(http.MethodPost, routeAttributionVerify, body); rec.Code != http.StatusOK {
		t.Fatalf("verify answered %d: %s", rec.Code, rec.Body)
	}
	if rec := send(http.MethodGet, routeReceiptKeys, ""); rec.Code != http.StatusOK {
		t.Fatalf("receipt keys answered %d: %s", rec.Code, rec.Body)
	}
	for _, target := range []string{routeAttributionVerify, routeReceiptKeys} {
		method := http.MethodGet
		if target == routeAttributionVerify {
			method = http.MethodPost
		}
		rec := send(method, target, body)
		assertEnvelope(t, target, rec, http.StatusTooManyRequests, CodeRateLimited, "")
		if rec.Header().Get("Retry-After") == "" {
			t.Fatalf("%s: no Retry-After", target)
		}
	}
}

// TestAttributionReceiptKeysListRotatedKeys lists the current key and an
// earlier one with the time it was replaced.
func TestAttributionReceiptKeysListRotatedKeys(t *testing.T) {
	f, _, _ := vtFixture(t)
	anonymous := f.client(f.root.URL, false)
	ctx, cancel := f.requestCtx()
	defer cancel()
	first, err := anonymous.AttributionReceiptKeys(ctx)
	if err != nil || len(first.Keys) != 1 || first.Keys[0].ValidTo != nil || len(first.Keys[0].PublicKey) != ed25519.PublicKeySize {
		t.Fatalf("keys %+v, %v; want the current key", first, err)
	}
	// A dispatcher started with another key file replaces it.
	replacement, err := f.d.OpenReceiptSigner(ctx, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	status, _, body, _ := authRequest(t, f, http.MethodGet, routeReceiptKeys, nil, nil)
	var keys client.AttributionReceiptKeys
	if status != http.StatusOK || json.Unmarshal(body, &keys) != nil || len(keys.Keys) != 2 {
		t.Fatalf("after rotation answered %d: %s", status, body)
	}
	old, current := keys.Keys[0], keys.Keys[1]
	if old.KeyID != first.Keys[0].KeyID || old.ValidTo == nil || old.ValidTo.Before(old.ValidFrom) ||
		current.KeyID != replacement.KeyID() || current.ValidTo != nil || current.ValidFrom.Before(*old.ValidTo) {
		t.Fatalf("after rotation %+v; want %s retired and %s current", keys.Keys, first.Keys[0].KeyID, replacement.KeyID())
	}
	oaCheckResponse(t, oaContract(t), http.MethodGet, routeReceiptKeys, http.StatusOK, body)
}
