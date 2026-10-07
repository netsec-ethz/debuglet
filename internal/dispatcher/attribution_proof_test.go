// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package dispatcher

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/netsec-ethz/debuglet/internal/dispatcher/database"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/tag"
	erpc "github.com/netsec-ethz/debuglet/internal/executor/transport/rpc"
	"github.com/netsec-ethz/debuglet/internal/sqlitedb"
	"github.com/netsec-ethz/debuglet/internal/testpeer"
	"github.com/netsec-ethz/debuglet/internal/testtls"
	"github.com/netsec-ethz/debuglet/pkg/wire"
	pb "github.com/netsec-ethz/debuglet/protocol"
	"go.uber.org/zap"
	"google.golang.org/grpc/credentials"
)

func TestAttributionScheduleProofIsBoundAndImmutable(t *testing.T) {
	d, db, _ := newRegistryFixture(t)
	ca, err := testtls.NewAuthority(t.TempDir(), "schedule")
	if err != nil {
		t.Fatal(err)
	}
	identity, err := ca.Issue("executor", testtls.Options{Client: true})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	chain := tag.Chain{Anchor: bytes.Repeat([]byte{4}, 32), Start: now, Interval: time.Minute, DisclosureDelay: 15, Length: 100, TagSpec: 1}
	schedule := wire.AttributionSchedule{ChainID: tag.ChainID(chain.Anchor), K0: chain.Anchor, T0UnixNs: now.UnixNano(), EpochSeconds: 60, DisclosureDelayEpochs: 15, ChainLength: 100, TagSpec: 1}
	proof, err := wire.SignAttributionSchedule("executor", schedule, identity.Certificate)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(proof)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint := wire.AttributionCertificateID(proof.Certificate)
	for _, pin := range []string{"", "unrelated-certificate"} {
		if err := d.recordChain(t.Context(), "executor", chain, raw, pin, now); err == nil {
			t.Fatal("unbound peer proof accepted")
		}
	}
	for range 2 {
		if err := d.recordChain(t.Context(), "executor", chain, raw, fingerprint, now); err != nil {
			t.Fatal(err)
		}
	}
	altered := chain
	altered.DisclosureDelay++
	if err := d.recordChain(t.Context(), "executor", altered, raw, fingerprint, now); err == nil {
		t.Fatal("modified schedule accepted")
	}
	schedule.DisclosureDelayEpochs++
	changed, err := wire.SignAttributionSchedule("executor", schedule, identity.Certificate)
	if err != nil {
		t.Fatal(err)
	}
	conflict, _ := json.Marshal(changed)
	if err := d.recordChain(t.Context(), "executor", altered, conflict, fingerprint, now); err == nil {
		t.Fatal("conflicting signed reannouncement replaced history")
	}
	if err := d.recordChain(t.Context(), "executor", chain, nil, fingerprint, now); err == nil {
		t.Fatal("unsigned downgrade of signed chain accepted")
	}
	// Disclosure writes cannot replace or clear the persisted proof.
	if err := (attributionBackend{db: db}).Save("executor", chain, 1, []byte("key"), now); err != nil {
		t.Fatal(err)
	}
	row, err := database.New(db).GetAttributionChain(t.Context(), database.GetAttributionChainParams{ExecutorID: "executor", ChainID: schedule.ChainID})
	if err != nil || !bytes.Equal(row.ScheduleProof, raw) || row.DelayEpochs != 15 {
		t.Fatalf("recorded proof changed: %+v, %v", row, err)
	}
	// A fresh SQLite connection recovers the original proof, independent of
	// the live executor registry or the key-store's in-memory cache.
	var seq int
	var name, path string
	if err := db.QueryRow("PRAGMA database_list").Scan(&seq, &name, &path); err != nil {
		t.Fatal(err)
	}
	reopened, err := sqlitedb.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	saved, err := database.New(reopened).GetAttributionChain(t.Context(), database.GetAttributionChainParams{ExecutorID: "executor", ChainID: schedule.ChainID})
	if err != nil || !bytes.Equal(saved.ScheduleProof, raw) {
		t.Fatalf("reopened proof differs: %v", err)
	}
	// Registration with an unauthenticated local session must not endorse a
	// certificate merely because it arrives in a syntactically valid proof.
	hello := registryHello("executor")
	hello.TeslaAnchorKey = chain.Anchor
	hello.TeslaAnchorTimestampNs = now.UnixNano()
	hello.TeslaDelaySec = 60
	hello.TeslaDisclosureDelayEpochs = 15
	hello.TeslaChainLength = 100
	hello.TeslaScheduleProof = raw
	hello.Capabilities = &pb.ExecutorCapabilities{SchemaVersion: 1, Tagging: &pb.TaggingMode{TagSpec: "debuglet-tag-v1", Ipv4: "none", Ipv6: "none", Scion: "none"}}
	if err := registryRegisterWithSetup(t.Context(), d, registryOwner(t, "executor"), hello, "127.0.0.1"); err == nil {
		t.Fatal("registration accepted an unbound proof")
	}
}

// Reuse the enrolled TLS transport fixture, with a schedule-bearing hello.
type schedulePeer struct {
	outputPeer
	response *pb.HelloResponse
}

func (p *schedulePeer) Hello(context.Context, *pb.HelloRequest) (*pb.HelloResponse, error) {
	return p.response, nil
}

func TestAttributionScheduleProofFromEnrolledControlPeer(t *testing.T) {
	f := newOutputTLS(t)
	token, err := f.store.Issue(f.ctx, "output-executor", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	anchor := bytes.Repeat([]byte{7}, 32)
	schedule := wire.AttributionSchedule{ChainID: tag.ChainID(anchor), K0: anchor, T0UnixNs: time.Now().UnixNano(), EpochSeconds: 60, DisclosureDelayEpochs: 15, ChainLength: 100, TagSpec: 1}
	proof, err := wire.SignAttributionSchedule("output-executor", schedule, f.identity.Certificate)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(proof)
	hello := &pb.HelloResponse{ExecutorId: "output-executor", EnrollmentToken: &token, Currency: "TEST", PricePerBwS: 1, OutputVersion: pb.OutputVersion,
		TeslaAnchorKey: anchor, TeslaAnchorTimestampNs: schedule.T0UnixNs, TeslaDelaySec: 60, TeslaDisclosureDelayEpochs: 15, TeslaChainLength: 100, TeslaScheduleProof: raw,
		Capabilities: &pb.ExecutorCapabilities{SchemaVersion: 1, Tagging: &pb.TaggingMode{TagSpec: "debuglet-tag-v1", Ipv4: "none", Ipv6: "none", Scion: "none"}}}
	tlsConfig := f.ca.ClientConfig(f.identity, "")
	connection, err := erpc.NewBidiClient(erpc.BidiOptions{Logger: zap.NewNop(), Address: f.direct.Addr().String(), YamuxAddress: f.reverse.Addr().String(), TLSConfig: tlsConfig, TLSCreds: credentials.NewTLS(tlsConfig.Clone())}, testpeer.ExecutorState{Service: &schedulePeer{response: hello}})
	if err != nil {
		t.Fatal(err)
	}
	f.clients = append(f.clients, connection)
	f.workers.Add(1)
	go func() { defer f.workers.Done(); _ = connection.ConnectAndServe(f.ctx) }()
	if err := connection.WaitReadyContext(f.ctx); err != nil {
		t.Fatal(err)
	}
	saved, err := database.New(f.d.db).GetAttributionChain(f.ctx, database.GetAttributionChainParams{ExecutorID: "output-executor", ChainID: schedule.ChainID})
	if err != nil || !bytes.Equal(saved.ScheduleProof, raw) {
		t.Fatalf("enrolled control proof: %v", err)
	}
}
