package executor

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/netsec-ethz/debuglet/internal/controlsession"
	"github.com/netsec-ethz/debuglet/internal/executor/config"
	executordb "github.com/netsec-ethz/debuglet/internal/executor/database"
	"github.com/netsec-ethz/debuglet/internal/executor/ratelimit"
	"github.com/netsec-ethz/debuglet/internal/executor/tagger/tesla"
	"go.uber.org/zap"
)

func chainRecordConfig(seed string) *config.ExecutorConfig {
	return &config.ExecutorConfig{
		Identity: config.IdentityConfig{ExecutorID: "chain-record-test"},
		TLS:      config.TLSConfig{Disable: true},
		Tesla:    config.TeslaConfig{Seed: seed, Delay: 1, ChainLength: 16},
		Network:  config.NetworkConfig{PacketCounter: "fallback"},
	}
}

func startedAnchor(t *testing.T, cfg *config.ExecutorConfig, db *sql.DB) []byte {
	t.Helper()
	n, err := NewNode(cfg, zap.NewNop(), db)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := n.Close(); err != nil {
			t.Error(err)
		}
	})
	return n.schedule.Anchor()
}

func recordedChains(t *testing.T, db *sql.DB) []executordb.TeslaChain {
	t.Helper()
	chains, err := executordb.New(db).ListTeslaChains(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return chains
}

// A configured seed must not rebuild the chain an earlier start disclosed, and
// every chain a start uses, seeded or random, is on record before it is used.
func TestConfiguredSeedStartsANewChainEveryStart(t *testing.T) {
	db := newFixtureDatabase(t)
	first := startedAnchor(t, chainRecordConfig("chain record seed"), db)
	second := startedAnchor(t, chainRecordConfig("chain record seed"), db)
	if bytes.Equal(first, second) {
		t.Fatalf("second start reused the anchor %x", first)
	}
	random := startedAnchor(t, chainRecordConfig(""), db)
	chains := recordedChains(t, db)
	if len(chains) != 3 {
		t.Fatalf("recorded %d chains, want 3", len(chains))
	}
	for i, anchor := range [][]byte{first, second, random} {
		chain := chains[i]
		if chain.Generation != int64(i+1) || !bytes.Equal(chain.Anchor, anchor) {
			t.Errorf("chain %d recorded generation %d anchor %x, node used %x", i+1, chain.Generation, chain.Anchor, anchor)
		}
		if chain.DelayNs != int64(time.Second) || chain.ChainLength != 16 || chain.EpochBase.IsZero() || chain.CreatedAt.IsZero() {
			t.Errorf("chain %d recorded %+v", i+1, chain)
		}
	}
}

// A chain whose anchor is already recorded would reuse disclosed keys: the
// node is refused before it acquires the packet counter.
func TestRecordedAnchorRefusesNodeConstruction(t *testing.T) {
	db := newFixtureDatabase(t)
	cfg := chainRecordConfig("chain record seed")
	tail, err := tesla.ChainSeed([]byte(cfg.Tesla.Seed), 2)
	if err != nil {
		t.Fatal(err)
	}
	reused, err := tesla.NewKeySchedule(tesla.Config{Seed: tail, Delay: time.Second, ChainLength: cfg.Tesla.ChainLength})
	if err != nil {
		t.Fatal(err)
	}
	if err := executordb.New(db).CreateTeslaChain(context.Background(), executordb.CreateTeslaChainParams{
		Generation: 1, Anchor: reused.Anchor(), EpochBase: time.Now().UTC(), DelayNs: int64(time.Second), ChainLength: 16, CreatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatal(err)
	}
	acquired := false
	n, err := newNode(cfg, zap.NewNop(), db, func(*net.Interface, *zap.Logger) (ratelimit.PacketCount, error) {
		acquired = true
		return &nodeCounter{}, nil
	})
	var end *controlsession.EndError
	if n != nil || !errors.As(err, &end) || end.Kind != controlsession.LocalFailure || !strings.Contains(err.Error(), "reuse disclosed keys") || acquired {
		t.Fatalf("node=%v error=%v counter acquired=%v", n, err, acquired)
	}
	if chains := recordedChains(t, db); len(chains) != 1 {
		t.Fatalf("refused start left %d chains", len(chains))
	}
}
