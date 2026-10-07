package executor

import (
	"bytes"
	"context"
	"crypto/tls"
	"database/sql"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/netsec-ethz/debuglet/internal/controlsession"
	"github.com/netsec-ethz/debuglet/internal/executor/config"
	executordb "github.com/netsec-ethz/debuglet/internal/executor/database"
	"github.com/netsec-ethz/debuglet/internal/executor/debuglet/socket"
	"github.com/netsec-ethz/debuglet/internal/executor/isolation"
	"github.com/netsec-ethz/debuglet/internal/executor/outputstore"
	"github.com/netsec-ethz/debuglet/internal/executor/ratelimit"
	"github.com/netsec-ethz/debuglet/internal/executor/scheduler"
	"github.com/netsec-ethz/debuglet/internal/executor/scheduler/sqlite"
	"github.com/netsec-ethz/debuglet/internal/executor/tagger/ebpf"
	"github.com/netsec-ethz/debuglet/internal/executor/tagger/tesla"
	"github.com/netsec-ethz/debuglet/internal/executor/transport/rpc"
	"github.com/netsec-ethz/debuglet/internal/hostprobe"
	"github.com/netsec-ethz/debuglet/protocol"
	"go.uber.org/zap"
	"google.golang.org/grpc/credentials"
)

var (
	ErrNodeClosed = errors.New("executor node is closed")
	ErrNodeBusy   = errors.New("executor node has an unjoined session")
)

// Node retains the resource identity which must survive network reconnects.
// Its one session reservation is lifecycle ownership, never lease authority.
type Node struct {
	cfg          config.ExecutorConfig
	logger       *zap.Logger
	schedule     *tesla.KeySchedule
	packetCount  ratelimit.PacketCount
	socketBudget *socket.DescriptorBudget
	supervisor   *isolation.Supervisor
	iface        *net.Interface
	output       *outputstore.Store
	outputFailed atomic.Bool
	opts         rpc.BidiOptions
	newBidi      func(rpc.BidiOptions, rpc.ExecutorState) (*rpc.BidiClient, error)
	mu           sync.Mutex
	closed       bool
	active       *Session
	closeOnce    sync.Once
	closeErr     error
	// chainReport outlives sessions so the end of the chain is reported once.
	chainReport chainReport
	// retired outlives sessions so the previous chain's tail is disclosed
	// across reconnects.
	retired retiredChain
}

// NewNode records the TESLA chain this start uses in db before it acquires the
// packet counter, so every chain the executor started is on record.
func NewNode(cfg *config.ExecutorConfig, logger *zap.Logger, db *sql.DB) (*Node, error) {
	return newNode(cfg, logger, db, ratelimit.New)
}

// newNode takes the packet-counter factory per construction, so the release
// boundaries can be exercised without a global replacement and without
// pretending an unprivileged process loaded BPF.
func newNode(cfg *config.ExecutorConfig, logger *zap.Logger, db *sql.DB, counter func(*net.Interface, *zap.Logger) (ratelimit.PacketCount, error)) (*Node, error) {
	if cfg == nil || logger == nil || db == nil {
		return nil, sessionEnd(controlsession.LocalFailure, errors.New("executor configuration, logger and database are required"))
	}
	// Check the network configuration with the validator that owns it, before
	// this construction acquires any host resource.
	if err := cfg.Network.Validate(); err != nil {
		return nil, sessionEnd(controlsession.LocalFailure, err)
	}
	// Validate fallible configuration before acquiring the daemon counter.
	if _, err := socket.NewPortManager(cfg.Network.PublicHost, cfg.Network.PublicPorts); err != nil {
		return nil, sessionEnd(controlsession.LocalFailure, fmt.Errorf("invalid public_ports: %w", err))
	}
	if err := cfg.Output.Validate(); err != nil {
		return nil, sessionEnd(controlsession.LocalFailure, err)
	}
	if err := cfg.ValidateIsolation(); err != nil {
		return nil, sessionEnd(controlsession.LocalFailure, err)
	}
	supervisor, err := isolation.New(cfg.Isolation)
	if err != nil {
		return nil, sessionEnd(controlsession.LocalFailure, err)
	}
	owned := false
	defer func() {
		if !owned {
			_ = supervisor.Close()
		}
	}()
	output, err := outputstore.New(db, cfg.Output.Limits())
	if err != nil {
		return nil, sessionEnd(controlsession.LocalFailure, err)
	}
	restoreCtx, restoreDone := context.WithTimeout(context.Background(), scheduler.CleanupTimeout)
	err = output.InterruptOpen(restoreCtx)
	restoreDone()
	if err != nil {
		return nil, sessionEnd(controlsession.LocalFailure, err)
	}
	var iface *net.Interface
	if cfg.Network.PacketCounter != "fallback" && cfg.Network.Interface != "" {
		var err error
		iface, err = net.InterfaceByName(cfg.Network.Interface)
		if err != nil {
			return nil, sessionEnd(controlsession.LocalFailure, fmt.Errorf("get packet-count interface: %w", err))
		}
	}
	var tlsConfig *tls.Config
	var creds credentials.TransportCredentials
	if !cfg.TLS.Disable {
		var err error
		tlsConfig, creds, err = getClientCredentials(cfg)
		if err != nil {
			return nil, sessionEnd(controlsession.LocalFailure, fmt.Errorf("load client credentials: %w", err))
		}
	}
	schedule, generation, clock, err := startChain(context.Background(), db, cfg.Tesla, cfg.Clock.MaxErrorBound())
	if err != nil {
		return nil, sessionEnd(controlsession.LocalFailure, err)
	}
	if schedule.Config().ClockUnready {
		logger.Error("TESLA chain started while the host clock was not ready; packets are not attributable and tagging nodes admit no runs until the executor restarts with a ready clock",
			zap.String("clock_state", clock.State), zap.String("clock_readiness", clock.Readiness), zap.String("clock_reason", clock.Reason))
	}
	// A legacy tc filter of an earlier process outlives it and keeps signing
	// with its last key, so it is removed before that chain's keys can be
	// disclosed; this process has attached no tagger yet.
	signers := ebpf.RetireStaleFilters(iface, logger)
	if signers != nil {
		logger.Warn("Could not retire tagger filters an earlier executor process left attached", zap.String("interface", cfg.Network.Interface), zap.Error(signers))
	}
	retired := deriveRetiredChain(context.Background(), executordb.New(db), cfg.Tesla.Seed, generation, !schedule.Config().ClockUnready, signers, time.Now(), logger)
	pc, err := counter(iface, logger)
	if err != nil {
		if pc != nil {
			err = errors.Join(err, pc.Close())
		}
		return nil, sessionEnd(controlsession.LocalFailure, fmt.Errorf("initialize packet counter: %w", err))
	}
	if pc == nil {
		return nil, sessionEnd(controlsession.LocalFailure, errors.New("packet counter constructor returned nil"))
	}
	n := &Node{supervisor: supervisor, socketBudget: socket.NewDescriptorBudget(socket.DefaultNodeDescriptors), cfg: *cfg, logger: logger, output: output, schedule: schedule, packetCount: pc, iface: iface, newBidi: rpc.NewBidiClient,
		opts: rpc.BidiOptions{Logger: logger, Address: cfg.Dispatcher.Addr, YamuxAddress: cfg.Dispatcher.YamuxAddr, TLSCreds: creds, TLSConfig: tlsConfig}}
	n.retired.schedule, n.retired.logger = retired, logger
	logger.Info("Initialized daemon resources", zap.String("packet_counter", pc.Type()), zap.Time("TESLA_expiry", schedule.Expiry()),
		zap.Duration("TESLA_epoch_length", schedule.Config().EpochLength), zap.Int64("TESLA_disclosure_delay_epochs", schedule.DisclosureDelay()))
	owned = true
	return n, nil
}

// startChain builds the TESLA chain of this start and records it before any of
// its keys is used. A configured seed derives a new tail for every generation;
// without one the tail is random. The anchor is unique in the record, so a
// chain whose keys an earlier start disclosed is refused. The host clock is
// read against clockBound just before the origin: a chain whose clock was not
// ready has no attribution for its life. It returns the chain's generation and
// that clock reading.
func startChain(ctx context.Context, db *sql.DB, cfg config.TeslaConfig, clockBound time.Duration) (*tesla.KeySchedule, int64, hostprobe.Clock, error) {
	queries := executordb.New(db)
	generation, err := queries.NextTeslaChainGeneration(ctx)
	if err != nil {
		return nil, 0, hostprobe.Clock{}, fmt.Errorf("read next TESLA chain generation: %w", err)
	}
	var seed []byte
	if cfg.Seed != "" {
		if seed, err = tesla.ChainSeed([]byte(cfg.Seed), generation); err != nil {
			return nil, 0, hostprobe.Clock{}, fmt.Errorf("derive TESLA chain %d: %w", generation, err)
		}
	}
	clock := hostprobe.ReadClock(clockBound)
	schedule, err := tesla.NewKeySchedule(tesla.Config{Seed: seed, EpochLength: cfg.EpochLength(), DisclosureDelay: cfg.DisclosureDelayEpochs, ChainLength: cfg.ChainLength,
		ClockUnready: clock.Readiness != hostprobe.ReadinessReady})
	if err != nil {
		return nil, 0, hostprobe.Clock{}, fmt.Errorf("create TESLA schedule: %w", err)
	}
	chain := schedule.Config()
	if err := queries.CreateTeslaChain(ctx, executordb.CreateTeslaChainParams{
		Generation: generation, Anchor: schedule.Anchor(), EpochBase: chain.Epoch.UTC(),
		DelayNs: int64(chain.EpochLength), ChainLength: chain.ChainLength, CreatedAt: time.Now().UTC(),
		DisclosureDelay: sql.NullInt64{Int64: chain.DisclosureDelay, Valid: true},
	}); err != nil {
		return nil, 0, hostprobe.Clock{}, fmt.Errorf("record TESLA chain %d (a recorded anchor would reuse disclosed keys): %w", generation, err)
	}
	return schedule, generation, clock, nil
}

// retiredDeliveryLimit bounds how long after its final disclosure a retired
// chain is reconstructed at a start, or offered by a running process, without
// a heartbeat having delivered its final key.
const retiredDeliveryLimit = 24 * time.Hour

// deriveRetiredChain re-derives the chain of the previous start, the one
// before generation, until retiredDeliveryLimit after its final disclosure,
// so the heartbeat can disclose its remaining keys. That needs the configured seed, the chain's
// recorded disclosure delay, a ready clock at this start, whose wall reading
// places the recorded origin, and the earlier process's signers retired
// (signers is nil); and the re-derived anchor must be the recorded one. The
// result is DisclosureOnly and registered with no tagger, so a recorded
// generation never signs again. Its epochs advance on the monotonic clock from
// now (see recoveredClock). Each start logs once why it discloses no tail.
func deriveRetiredChain(ctx context.Context, queries *executordb.Queries, seed string, generation int64, clockReady bool, signers error, now time.Time, logger *zap.Logger) *tesla.KeySchedule {
	if generation <= 1 {
		return nil
	}
	previous, err := queries.GetTeslaChain(ctx, generation-1)
	if err != nil {
		logger.Warn("Previous TESLA chain is not readable; its remaining keys are not disclosed", zap.Int64("generation", generation-1), zap.Error(err))
		return nil
	}
	fields := []zap.Field{zap.Int64("generation", previous.Generation)}
	skip := func(reason string, more ...zap.Field) *tesla.KeySchedule {
		logger.Info("Previous TESLA chain's remaining keys are not disclosed", append(fields, append(more, zap.String("reason", reason))...)...)
		return nil
	}
	if seed == "" {
		return skip("no tesla.seed is configured, so the chain cannot be re-derived")
	}
	if !previous.DisclosureDelay.Valid {
		return skip("the chain's disclosure delay is not on record")
	}
	interval, delay := time.Duration(previous.DelayNs), previous.DisclosureDelay.Int64
	final := previous.EpochBase.Add(time.Duration(previous.ChainLength-1+delay) * interval)
	fields = append(fields, zap.Time("final_disclosure_at", final))
	if !clockReady {
		return skip("the host clock is not ready")
	}
	if signers != nil {
		return skip("tagger filters of the earlier process could not be retired", zap.Error(signers))
	}
	// The bound a running process keeps an undelivered chain for: a chain past
	// its final disclosure carries k_{L-1} on the first heartbeat.
	if !now.Before(final.Add(retiredDeliveryLimit)) {
		return skip("its final key was due more than 24 hours ago")
	}
	tail, err := tesla.ChainSeed([]byte(seed), previous.Generation)
	if err != nil {
		return skip(err.Error())
	}
	retired, err := tesla.NewKeySchedule(tesla.Config{Seed: tail, EpochLength: interval, DisclosureDelay: delay, ChainLength: previous.ChainLength,
		Epoch: previous.EpochBase, DisclosureOnly: true, Clock: recoveredClock{wall: now.Round(0), at: now}})
	if err != nil {
		return skip(err.Error())
	}
	if !bytes.Equal(retired.Anchor(), previous.Anchor) {
		logger.Error("Re-derived previous TESLA chain does not match its recorded anchor; its remaining keys are not disclosed (was tesla.seed changed?)", fields...)
		return nil
	}
	logger.Info("Disclosing the previous TESLA chain's remaining keys", fields...)
	return retired
}

// recoveredClock places a recorded origin, which carries no monotonic reading,
// on the monotonic clock: the wall time from the origin to the recovery
// instant, read on a ready clock, plus the monotonic time since then. A wall
// step after recovery therefore neither advances nor holds back disclosure.
type recoveredClock struct {
	wall time.Time // the recovery instant's wall reading
	at   time.Time // the same instant with its monotonic reading
	// host measures from at; nil uses the readings of the instants, as the
	// current chain's schedule does.
	host tesla.Clock
}

func (c recoveredClock) Elapsed(origin, t time.Time) (time.Duration, time.Duration) {
	since, wall := t.Sub(c.at), t.Round(0).Sub(origin.Round(0))
	if c.host != nil {
		since, _ = c.host.Elapsed(c.at, t)
		_, wall = c.host.Elapsed(origin, t)
	}
	return c.wall.Sub(origin.Round(0)) + since, wall
}

// retiredChain holds the chain the previous start retired until a heartbeat
// that carried its final key k_{L-1} succeeded; a later key covers every
// earlier one, so only the final one needs to arrive.
type retiredChain struct {
	mu       sync.Mutex
	schedule *tesla.KeySchedule
	logger   *zap.Logger
}

// disclosures returns the retired chain's key due at now for the heartbeat.
// A chain whose final key no heartbeat delivered within retiredDeliveryLimit
// of its final disclosure is dropped with a warning.
func (r *retiredChain) disclosures(now time.Time) []*protocol.TeslaDisclosure {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.schedule == nil {
		return nil
	}
	cfg := r.schedule.Config()
	elapsed, _ := cfg.Clock.Elapsed(cfg.Epoch, now)
	if final := r.schedule.FinalDisclosure(); elapsed >= final.Sub(cfg.Epoch)+retiredDeliveryLimit {
		r.logger.Warn("Dropped the previous TESLA chain without a delivered final key", zap.Time("final_disclosure_at", final))
		r.schedule = nil
		return nil
	}
	epoch, key, ok := r.schedule.DisclosedKey(now)
	if !ok {
		return nil
	}
	return []*protocol.TeslaDisclosure{{Anchor: r.schedule.Anchor(), Epoch: epoch, Key: key}}
}

// delivered records that a heartbeat carrying sent succeeded, and drops the
// retired chain once that included its final key.
func (r *retiredChain) delivered(sent []*protocol.TeslaDisclosure) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.schedule == nil {
		return
	}
	for _, d := range sent {
		if d.GetEpoch() == r.schedule.ChainLength()-1 && bytes.Equal(d.GetAnchor(), r.schedule.Anchor()) {
			r.logger.Info("Delivered the previous TESLA chain's final key", zap.Int64("epoch", d.GetEpoch()))
			r.schedule = nil
			return
		}
	}
}

// Close permanently closes new node admission. A busy result consumes nothing:
// a later call still closes the resources once the session has joined.
func (n *Node) Close() error {
	n.mu.Lock()
	n.closed = true
	if n.active != nil {
		n.mu.Unlock()
		return ErrNodeBusy
	}
	n.mu.Unlock()
	n.closeOnce.Do(func() { n.closeErr = errors.Join(n.packetCount.Close(), n.supervisor.Close()) })
	return n.closeErr
}

func (n *Node) reserve() (*Session, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.closed {
		return nil, ErrNodeClosed
	}
	if n.active != nil {
		return nil, ErrNodeBusy
	}
	s := &Session{node: n, runDone: make(chan struct{}), cleanupDone: make(chan struct{})}
	n.active = s
	return s, nil
}

func (n *Node) release(s *Session) {
	n.mu.Lock()
	if n.active == s {
		n.active = nil
	}
	n.mu.Unlock()
}

// NewSession returns a session only once its scheduler guards and the one lease
// controller they commit under are wired. Its restore policy accepts no stored
// binding, so every row an earlier session left is quarantined.
func NewSession(node *Node, db *sql.DB) (*Session, error) {
	if node == nil || db == nil {
		return nil, sessionEnd(controlsession.LocalFailure, errors.New("node and database are required"))
	}
	s, err := node.reserve()
	if err != nil {
		return nil, sessionEnd(controlsession.LocalFailure, err)
	}
	guard := func(start bool) scheduler.AdmissionGuard {
		return func(binding controlsession.Binding, commit func()) error {
			if s.executor == nil || s.executor.Bidi == nil {
				return sessionEnd(controlsession.LocalFailure, errors.New("session construction is incomplete"))
			}
			if start {
				return s.executor.Bidi.CommitLease(binding, commit)
			}
			return s.executor.Bidi.CommitUpload(binding, commit)
		}
	}
	storage, err := sqlite.NewStorage(db, node.output, func(controlsession.Binding) bool { return false }, scheduler.Admission{Insert: guard(false), Start: guard(true)}, scheduler.DefaultQueueLimits())
	if err != nil {
		node.release(s)
		return nil, sessionEnd(controlsession.LocalFailure, err)
	}
	s.storage = storage
	s.restore = func(ctx context.Context) error {
		err := storage.RestoreFromDatabase(ctx)
		node.logger.Info("Retained quarantined executor rows", zap.Int64("count", storage.QuarantinedCount()),
			zap.Int64("unacknowledged_exits", storage.RetainedTerminalCount()))
		return err
	}
	if err := s.initialize(); err != nil {
		node.release(s)
		return nil, sessionEnd(controlsession.LocalFailure, err)
	}
	return s, nil
}

func sessionEnd(kind controlsession.EndKind, err error) error {
	var end *controlsession.EndError
	if errors.As(err, &end) {
		return err
	}
	return &controlsession.EndError{Kind: kind, Err: err}
}
