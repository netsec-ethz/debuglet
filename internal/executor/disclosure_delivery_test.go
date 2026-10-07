// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package executor

import (
	"bytes"
	"context"
	"github.com/netsec-ethz/debuglet/internal/dispatcher"
	dispatcherconfig "github.com/netsec-ethz/debuglet/internal/dispatcher/config"
	dispatcherdb "github.com/netsec-ethz/debuglet/internal/dispatcher/database"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/payments"
	drpc "github.com/netsec-ethz/debuglet/internal/dispatcher/transport/rpc"
	"github.com/netsec-ethz/debuglet/internal/sqlitedb"
	"go.uber.org/zap"
	"path/filepath"
	"testing"
	"time"

	"github.com/netsec-ethz/debuglet/internal/executor/tagger/tesla"
	pb "github.com/netsec-ethz/debuglet/protocol"
)

type deliveryClock struct{ mono, wall time.Duration }

func (c *deliveryClock) Elapsed(time.Time, time.Time) (time.Duration, time.Duration) {
	return c.mono, c.wall
}
func deliverySchedule(t *testing.T, clock *deliveryClock) *tesla.KeySchedule {
	t.Helper()
	s, err := tesla.NewKeySchedule(tesla.Config{Epoch: time.Now(), Clock: clock, EpochLength: time.Second, DisclosureDelay: 2, ChainLength: 100, Seed: []byte("disclosure receipt clock fixture")})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestDisclosureCompletionIncludesSkippedEpochsAndDoesNotRefreshRetries(t *testing.T) {
	clock := &deliveryClock{}
	schedule := deliverySchedule(t, clock)
	var d disclosureDelivery
	at := time.Now()
	observe := func(epoch int64, elapsed time.Duration) *pb.DisclosureDeliveryObservation {
		clock.mono, clock.wall = elapsed, elapsed
		d.acknowledge(schedule, []*pb.TeslaDisclosureReceipt{{Anchor: schedule.Anchor(), StoredThroughEpoch: epoch}}, at)
		return d.report(schedule, at)
	}
	if got := d.report(schedule, at); got != nil {
		t.Fatal("unknown before receipt", got)
	}
	if got := observe(1, 3250*time.Millisecond); got == nil || got.ScheduledToAckNs != int64(250*time.Millisecond) {
		t.Fatal(got)
	}
	// A duplicate reply leaves the original sample instant unchanged.
	if got := observe(1, 5*time.Second); got == nil || got.SampleAgeNs != int64(1750*time.Millisecond) {
		t.Fatal(got)
	}
	// k4 also covers k2 and k3: count from k2's due time, not k4's.
	if got := observe(4, 8*time.Second); got == nil || got.ScheduledToAckNs != int64(4*time.Second) {
		t.Fatal(got)
	}
	d.failed()
	if d.report(schedule, at) != nil || d.through != 4 {
		t.Fatal("failed reply lost coverage or kept sample")
	}
	if observe(4, 9*time.Second) != nil {
		t.Fatal("duplicate after failure revived old sample")
	}
	// Reconnecting shares the same node-owned state; an outage retains k5's due time.
	if got := observe(8, 14*time.Second); got == nil || got.ScheduledToAckNs != int64(7*time.Second) {
		t.Fatal(got)
	}
	clock.mono, clock.wall = 74*time.Second, 74*time.Second
	if d.report(schedule, at) != nil {
		t.Fatal("sample survived exact one minute boundary")
	}
	d.acknowledge(schedule, nil, at)
	if d.through != 8 {
		t.Fatal("missing receipt reset high-water")
	}
}

func TestDisclosureCompletionClockInvalidationIsPermanent(t *testing.T) {
	for _, cause := range []string{"suspend", "backward", "health", "recovered", "unready"} {
		t.Run(cause, func(t *testing.T) {
			clock := &deliveryClock{mono: 4 * time.Second, wall: 4 * time.Second}
			schedule := deliverySchedule(t, clock)
			if cause == "recovered" || cause == "unready" {
				cfg := schedule.Config()
				cfg.DisclosureOnly = cause == "recovered"
				cfg.ClockUnready = cause == "unready"
				var err error
				schedule, err = tesla.NewKeySchedule(cfg)
				if err != nil {
					t.Fatal(err)
				}
			}
			var d disclosureDelivery
			receipt := []*pb.TeslaDisclosureReceipt{{Anchor: schedule.Anchor(), StoredThroughEpoch: 1}}
			d.acknowledge(schedule, receipt, time.Now())
			switch cause {
			case "suspend":
				clock.wall += 2 * time.Second
			case "backward":
				clock.wall -= 2 * time.Second
			case "health":
				d.invalidate()
			}
			if d.report(schedule, time.Now()) != nil {
				t.Fatal("invalid clock published a bound")
			}
			clock.mono, clock.wall = 5*time.Second, 5*time.Second
			receipt[0].StoredThroughEpoch = 2
			d.acknowledge(schedule, receipt, time.Now())
			if d.report(schedule, time.Now()) != nil {
				t.Fatal("generation recovered a timing claim")
			}
		})
	}
}

func TestDisclosureReceiptsMatchBoundedRequest(t *testing.T) {
	anchor, old := bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32)
	req := &pb.HeartbeatRequest{TeslaKeyEpoch: 4, TeslaKey: []byte{1}, ExtraDisclosures: []*pb.TeslaDisclosure{{Anchor: old, Epoch: 5, Key: []byte{2}}}}
	good := []*pb.TeslaDisclosureReceipt{{Anchor: anchor, StoredThroughEpoch: 3}, {Anchor: old, StoredThroughEpoch: 5}}
	if got := matchingDisclosureReceipts(req, &pb.HeartbeatResponse{DisclosureReceipts: good}, anchor); len(got) != 2 {
		t.Fatal(got)
	}
	for _, bad := range [][]*pb.TeslaDisclosureReceipt{
		{{Anchor: anchor, StoredThroughEpoch: 5}}, {{Anchor: old, StoredThroughEpoch: 6}},
		{{Anchor: bytes.Repeat([]byte{3}, 32), StoredThroughEpoch: 1}},
		{good[0], good[0]}, make([]*pb.TeslaDisclosureReceipt, 6), {nil},
	} {
		if got := matchingDisclosureReceipts(req, &pb.HeartbeatResponse{DisclosureReceipts: bad}, anchor); len(got) != 0 {
			t.Fatal(got)
		}
	}
}

// Reuse the existing real leased transport fixture, forwarding application
// calls to the production dispatcher and its SQLite record. This is an owned
// local timing fixture, not independent clock-reference or provider acceptance.
type disclosureTransportPeer struct {
	*dispatcher.Dispatcher
	connected chan *drpc.SessionOwner
	entered   chan struct{}
}

func (p *disclosureTransportPeer) OnExecutorConnected(ctx context.Context, owner *drpc.SessionOwner, hello *pb.HelloResponse, ip string) error {
	if err := p.Dispatcher.OnExecutorConnected(ctx, owner, hello, ip); err != nil {
		return err
	}
	p.connected <- owner
	return nil
}
func (p *disclosureTransportPeer) OnHeartbeat(ctx context.Context, mutation *drpc.Mutation, req *pb.HeartbeatRequest) (*pb.HeartbeatResponse, error) {
	select {
	case p.entered <- struct{}{}:
	default:
	}
	return p.Dispatcher.OnHeartbeat(ctx, mutation, req)
}
func TestDisclosureCompletionRoundTripDurableSQLite(t *testing.T) {
	db, err := sqlitedb.Open(filepath.Join(t.TempDir(), "disclosures.sqlite"), sqlitedb.Create())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if _, err = sqlitedb.Migrate(t.Context(), db, dispatcherdb.MigrationFS(), sqlitedb.Latest); err != nil {
		t.Fatal(err)
	}
	payment, err := payments.NewPaymentHandler(db, &dispatcherconfig.DispatcherConfig{Sui: dispatcherconfig.SuiConfig{Disabled: true}}, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	d, err := dispatcher.New(zap.NewNop(), db, "disclosure-round-trip", time.Minute, time.Second, payment)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(d.Close)
	var peer *disclosureTransportPeer
	f := newRecoveryHarnessWithServer(t, newOperationPeer(), func(f *recoveryHarness) {
		f.server.Close()
		d.Bidi.Close()
		peer = &disclosureTransportPeer{Dispatcher: d, connected: f.peer.connected, entered: make(chan struct{}, 8)}
		server, err := drpc.NewBidiServer(zap.NewNop(), peer, d.ControlIncarnation(), time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		d.Bidi, f.server = server, server
	})
	origin := time.Now().Add(-10 * time.Minute)
	schedule, err := tesla.NewKeySchedule(tesla.Config{Epoch: origin, EpochLength: time.Minute, DisclosureDelay: 2, ChainLength: 100, Seed: []byte("round trip disclosure")})
	if err != nil {
		t.Fatal(err)
	}
	f.node.schedule = schedule
	session, owner, _ := f.start(nil)
	client, err := session.executor.dispatcherClient(t.Context(), owner.Binding())
	if err != nil {
		t.Fatal(err)
	}
	var observation disclosureDelivery
	request := func(epoch int64) *pb.HeartbeatRequest {
		key, _ := schedule.KeyAtEpoch(epoch)
		return &pb.HeartbeatRequest{ExecutorId: f.node.cfg.Identity.ExecutorID, TeslaKeyEpoch: epoch, TeslaKey: key}
	}
	// Holding a real write transaction prevents the key commit from completing.
	tx, err := db.BeginTx(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if _, err = tx.Exec("UPDATE attribution_retention SET retained_from_ns = retained_from_ns"); err != nil {
		t.Fatal(err)
	}
	type result struct {
		response *pb.HeartbeatResponse
		err      error
	}
	done := make(chan result, 1)
	req := request(1)
	sent := time.Now()
	go func() { out, err := client.Heartbeat(t.Context(), req); done <- result{out, err} }()
	select {
	case <-peer.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("real heartbeat did not arrive")
	}
	select {
	case got := <-done:
		t.Fatal("receipt escaped held transaction", got)
	case <-time.After(50 * time.Millisecond):
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	got := <-done
	ack := time.Now()
	if got.err != nil || len(got.response.GetDisclosureReceipts()) != 1 {
		t.Fatal(got)
	}
	observation.acknowledge(schedule, matchingDisclosureReceipts(req, got.response, schedule.Anchor()), ack)
	sample := observation.report(schedule, ack)
	if sample == nil || sample.ScheduledToAckNs != int64(ack.Sub(origin)-3*time.Minute) || ack.Sub(sent) < 50*time.Millisecond {
		t.Fatal("completion did not include held commit", sample)
	}
	var rows int
	if err := db.QueryRow("SELECT count(*) FROM attribution_keys").Scan(&rows); err != nil || rows != 1 {
		t.Fatal("no durable row", rows, err)
	}
	// Lost reply: the second commit succeeds but its response is discarded.
	if _, err := client.Heartbeat(t.Context(), request(3)); err != nil {
		t.Fatal(err)
	}
	observation.failed()
	out, err := client.Heartbeat(t.Context(), request(3))
	if err != nil {
		t.Fatal(err)
	}
	ack = time.Now()
	observation.acknowledge(schedule, matchingDisclosureReceipts(request(3), out, schedule.Anchor()), ack)
	sample = observation.report(schedule, ack)
	if sample == nil || sample.ScheduledToAckNs != int64(ack.Sub(origin)-4*time.Minute) {
		t.Fatal("retry hid oldest newly covered epoch", sample)
	}
	if _, err := db.Exec("CREATE TRIGGER fail_disclosure BEFORE INSERT ON attribution_keys BEGIN SELECT RAISE(FAIL, 'controlled write failure'); END"); err != nil {
		t.Fatal(err)
	}
	out, err = client.Heartbeat(t.Context(), request(4))
	if err != nil || len(out.GetDisclosureReceipts()) != 0 {
		t.Fatal("failed commit acknowledged", out, err)
	}
	observation.acknowledge(schedule, matchingDisclosureReceipts(request(4), out, schedule.Anchor()), time.Now())
	if observation.report(schedule, time.Now()) != nil || observation.through != 3 {
		t.Fatal("failed commit reported fresh or lost prefix")
	}
	t.Logf("owned leased SQLite round trip: held commit %s, receipt coverage k3, storage failure unavailable", ack.Sub(sent))
}
