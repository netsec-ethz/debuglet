package executor

import (
	"context"
	"crypto/tls"
	"database/sql"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/netsec-ethz/debuglet/internal/controlsession"
	"github.com/netsec-ethz/debuglet/internal/executor/config"
	"github.com/netsec-ethz/debuglet/internal/executor/debuglet/socket"
	"github.com/netsec-ethz/debuglet/internal/executor/ratelimit"
	"github.com/netsec-ethz/debuglet/internal/executor/scheduler"
	"github.com/netsec-ethz/debuglet/internal/executor/scheduler/sqlite"
	"github.com/netsec-ethz/debuglet/internal/executor/tagger/tesla"
	"github.com/netsec-ethz/debuglet/internal/executor/transport/rpc"
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
	cfg         config.ExecutorConfig
	logger      *zap.Logger
	schedule    *tesla.KeySchedule
	packetCount ratelimit.PacketCount
	iface       *net.Interface
	opts        rpc.BidiOptions
	newBidi     func(rpc.BidiOptions, rpc.ExecutorState) (*rpc.BidiClient, error)
	mu          sync.Mutex
	closed      bool
	active      *Session
	closeOnce   sync.Once
	closeErr    error
}

func NewNode(cfg *config.ExecutorConfig, logger *zap.Logger) (*Node, error) {
	return newNode(cfg, logger, ratelimit.New)
}

// newNode takes the packet-counter factory per construction, so the release
// boundaries can be exercised without a global replacement and without
// pretending an unprivileged process loaded BPF.
func newNode(cfg *config.ExecutorConfig, logger *zap.Logger, counter func(*net.Interface, *zap.Logger) (ratelimit.PacketCount, error)) (*Node, error) {
	if cfg == nil || logger == nil {
		return nil, sessionEnd(controlsession.LocalFailure, errors.New("executor configuration and logger are required"))
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
	schedule, err := tesla.NewKeySchedule(tesla.Config{Seed: []byte(cfg.Tesla.Seed), Delay: time.Duration(cfg.Tesla.Delay) * time.Second, ChainLength: cfg.Tesla.ChainLength})
	if err != nil {
		return nil, sessionEnd(controlsession.LocalFailure, fmt.Errorf("create TESLA schedule: %w", err))
	}
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
	n := &Node{cfg: *cfg, logger: logger, schedule: schedule, packetCount: pc, iface: iface, newBidi: rpc.NewBidiClient,
		opts: rpc.BidiOptions{Logger: logger, Address: cfg.Dispatcher.Addr, YamuxAddress: cfg.Dispatcher.YamuxAddr, TLSCreds: creds, TLSConfig: tlsConfig}}
	logger.Info("Initialized daemon resources", zap.String("packet_counter", pc.Type()), zap.Time("TESLA_expiry", schedule.Expiry()))
	return n, nil
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
	n.closeOnce.Do(func() { n.closeErr = n.packetCount.Close() })
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
	storage, err := sqlite.NewStorage(db, func(controlsession.Binding) bool { return false }, scheduler.Admission{Insert: guard(false), Start: guard(true)})
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
