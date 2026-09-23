package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"github.com/netsec-ethz/debuglet/internal/demo"
	dispatcherconfig "github.com/netsec-ethz/debuglet/internal/dispatcher/config"
	executorconfig "github.com/netsec-ethz/debuglet/internal/executor/config"
	"github.com/netsec-ethz/debuglet/internal/readiness"
	"github.com/pelletier/go-toml/v2"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type ownedChild struct {
	child   *demo.Child
	capture *limitedCapture
	daemon  bool
}
type local struct {
	opts                 Options
	dir                  string
	children             []*ownedChild
	dispatcher, executor *ownedChild
	record               readiness.Record
	executorStopped      bool
	target               *canaryTarget
	proxy                *http.Server
	proxyListener        net.Listener
	proxyDone            chan struct{}
	proxyTransport       *http.Transport
	proxyErr             error
	handlers             handlerOwnership
}

func newLocalSession(opts Options, dir string) localSession { return &local{opts: opts, dir: dir} }
func (s *local) launch(path string, args []string, daemon bool) (*ownedChild, error) {
	capture := newCapture(captureLimit)
	child, err := demo.StartChild(demo.ChildSpec{Path: path, Dir: s.dir, Args: args, Env: []string{"TMPDIR=" + s.dir, "LANG=C", "LC_ALL=C", "TZ=UTC"}, Stdout: capture.stdout(), Stderr: capture.stderr()})
	if err != nil {
		return nil, err
	}
	owned := &ownedChild{child: child, capture: capture, daemon: daemon}
	s.children = append(s.children, owned)
	return owned, nil
}
func (s *local) StartDispatcher(ctx context.Context) (string, error) {
	db := filepath.Join(s.dir, "dispatcher.sqlite")
	if err := demo.BootstrapFresh(ctx, demo.DispatcherSchema, db); err != nil {
		return "", err
	}
	// This harness drives the candidate as an ordinary client and holds no
	// credential, so the dispatcher it starts has to serve the local
	// development profile. That profile stays an explicit opt-in: the loopback,
	// TLS-off, payments-off environment below is a precondition, not a reason
	// to switch it on by itself.
	cfg := dispatcherconfig.DispatcherConfig{
		Server:    dispatcherconfig.ServerConfig{Version: s.opts.Assets.Manifest.Version, BindHost: "127.0.0.1", LocalDevelopment: true},
		Logging:   dispatcherconfig.LoggingConfig{LogLevel: "info", JSONLogs: true},
		Scheduler: dispatcherconfig.SchedulerConfig{ExecutorTimeout: 10, SchedulerGranularityMs: 100},
		TLS:       dispatcherconfig.TLSConfig{Disable: true}, Database: dispatcherconfig.DatabaseConfig{Path: db}, Sui: dispatcherconfig.SuiConfig{Disabled: true},
	}
	configPath, readyPath := filepath.Join(s.dir, "dispatcher.toml"), filepath.Join(s.dir, "dispatcher-ready.json")
	if err := writeConfig(configPath, cfg); err != nil {
		return "", err
	}
	var err error
	s.dispatcher, err = s.launch(s.opts.Assets.Dispatcher, []string{"--config", configPath, "--ready-file", readyPath}, true)
	if err != nil {
		return "", err
	}
	s.record, err = awaitReady(ctx, readyPath, s.dispatcher, "")
	if err != nil {
		return "", err
	}
	return s.startProxy(ctx, s.record.HTTPAddr)
}
func (s *local) startProxy(ctx context.Context, upstream string) (string, error) {
	if !localAddress(upstream) {
		return "", errors.New("invalid proxy upstream")
	}
	var lc net.ListenConfig
	lis, err := lc.Listen(ctx, "tcp", "127.0.0.1:0")
	if err != nil {
		return "", err
	}
	s.proxyListener = lis
	s.proxyDone = make(chan struct{})
	dest := &url.URL{Scheme: "http", Host: upstream}
	s.proxyTransport = &http.Transport{Proxy: nil, DialContext: (&net.Dialer{Timeout: 5 * time.Second}).DialContext, MaxIdleConns: 4, IdleConnTimeout: time.Second}
	proxy := &httputil.ReverseProxy{Transport: s.proxyTransport, ErrorLog: log.New(io.Discard, "", 0), ErrorHandler: func(w http.ResponseWriter, r *http.Request, e error) {
		http.Error(w, "owned proxy request failed", http.StatusBadGateway)
	}, Rewrite: func(r *httputil.ProxyRequest) {
		r.SetURL(dest)
		r.Out.URL.Path = strings.TrimPrefix(r.In.URL.Path, "/api")
		r.Out.URL.RawPath = ""
		r.Out.Host = dest.Host
	}}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.handlers.begin() {
			http.Error(w, "proxy closing", http.StatusServiceUnavailable)
			return
		}
		defer s.handlers.end()
		if !(r.URL.Path == "/api" || strings.HasPrefix(r.URL.Path, "/api/")) || r.URL.RawPath != "" {
			http.NotFound(w, r)
			return
		}
		proxy.ServeHTTP(w, r)
	})
	s.proxy = &http.Server{Handler: handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 30 * time.Second, MaxHeaderBytes: 16 << 10, BaseContext: func(net.Listener) context.Context { return ctx }}
	go func() { s.proxyErr = s.proxy.Serve(lis); close(s.proxyDone) }()
	return "http://" + lis.Addr().String() + "/api", nil
}

// localExecutorConfiguration is the configuration this check writes for the
// installed executor. It measures against a TCP target on this machine, so the
// executor has to be configured for local targets: the network policy denies
// loopback unless an operator asks for it, and this is that operator asking.
func localExecutorConfiguration(executorID, version, db string, record readiness.Record) executorconfig.ExecutorConfig {
	localTargets := true
	return executorconfig.ExecutorConfig{
		Identity:   executorconfig.IdentityConfig{ExecutorID: executorID, Version: version},
		Dispatcher: executorconfig.DispatcherConfig{Addr: record.GRPCAddr, YamuxAddr: record.HTTPAddr}, TLS: executorconfig.TLSConfig{Disable: true},
		Resources: executorconfig.ResourcesConfig{Capacity: 1_000_000_000, MaxDebuglets: 4}, Tesla: executorconfig.TeslaConfig{Delay: 2, ChainLength: 3600},
		Network: executorconfig.NetworkConfig{PacketCounter: "fallback", DisableSCIONEnvironment: true,
			Policy: executorconfig.PolicyConfig{LocalTargets: &localTargets}},
		Logging:  executorconfig.LoggingConfig{LogLevel: "info", JSONLogs: true},
		Database: executorconfig.DatabaseConfig{Path: db}, Pricing: executorconfig.PricingConfig{PricePerBwS: 1, Currency: "TEST"},
	}
}

func (s *local) StartExecutor(ctx context.Context) error {
	db := filepath.Join(s.dir, "executor.sqlite")
	if err := demo.BootstrapFresh(ctx, demo.ExecutorSchema, db); err != nil {
		return err
	}
	cfg := localExecutorConfiguration(s.opts.Manifest.ExecutorID, s.opts.Assets.Manifest.Version, db, s.record)
	configPath, readyPath := filepath.Join(s.dir, "executor.toml"), filepath.Join(s.dir, "executor-ready.json")
	if err := writeConfig(configPath, cfg); err != nil {
		return err
	}
	var err error
	s.executor, err = s.launch(s.opts.Assets.Executor, []string{"--config", configPath, "--ready-file", readyPath}, true)
	if err != nil {
		return err
	}
	_, err = awaitReady(ctx, readyPath, s.executor, s.opts.Manifest.ExecutorID)
	return err
}
func (s *local) StartTarget(ctx context.Context) (string, string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", "", err
	}
	nonce := hex.EncodeToString(raw[:])
	target, err := startCanaryTarget(ctx, nonce)
	if err != nil {
		return "", "", err
	}
	s.target = target
	return target.addr(), nonce, nil
}
func (s *local) Execute(ctx context.Context, args []string) commandResult {
	if err := s.healthy(); err != nil {
		return commandResult{Err: err}
	}
	if err := ctx.Err(); err != nil {
		return commandResult{Err: err}
	}
	owned, err := s.launch(s.opts.Assets.CLI, args, false)
	if err != nil {
		return commandResult{Err: err}
	}
	err = owned.child.Wait(ctx)
	// A cancelled Wait leaves the child tracked for final cleanup. Never read
	// buffers until their copying goroutines have joined.
	if !channelClosed(owned.child.Done()) {
		return commandResult{Started: true, Err: err}
	}
	// Cache group completion immediately, before a later registry poll could
	// outlive this reaped CLI's numeric PID identity.
	phase, end := context.WithTimeout(ctx, 250*time.Millisecond)
	stopErr := owned.child.Stop(phase)
	end()
	err = errors.Join(err, stopErr)
	data, overflow := owned.capture.result()
	if overflow {
		err = errors.Join(err, errors.New("CLI capture limit exceeded"))
		data = nil
	}
	return commandResult{Started: true, Stdout: data, Err: errors.Join(err, s.healthy())}
}
func (s *local) healthy() error {
	for _, owned := range []*ownedChild{s.dispatcher, s.executor} {
		if owned == nil || owned == s.executor && s.executorStopped {
			continue
		}
		if channelClosed(owned.child.Done()) || owned.capture.exceeded() {
			return errors.New("owned daemon exited or exceeded diagnostics bound")
		}
	}
	if s.proxyDone != nil && channelClosed(s.proxyDone) {
		return errors.New("owned proxy exited")
	}
	return nil
}
func (s *local) TargetACK(ctx context.Context) error { return s.target.wait(ctx) }
func (s *local) CloseTarget(ctx context.Context) error {
	if s.target == nil {
		return nil
	}
	return s.target.stop(ctx)
}
func (s *local) StopExecutor(ctx context.Context) error {
	if s.executor == nil {
		return errors.New("executor was not started")
	}
	if err := s.healthy(); err != nil {
		return err
	}
	s.executorStopped = true
	err := s.executor.child.Stop(ctx)
	if !s.executor.child.CleanupComplete() {
		err = errors.Join(err, errors.New("executor group cleanup incomplete"))
	}
	return err
}
func (s *local) Cleanup(ctx context.Context) (CleanupEvidence, error) {
	var result CleanupEvidence
	var err error
	// Shutdown the owned proxy before stopping its upstream. This joins active
	// requests on success; Close on timeout is followed by the same bounded join.
	if s.proxy != nil {
		phase, end := cleanupPhase(ctx, 3)
		e := s.proxy.Shutdown(phase)
		end()
		if e != nil {
			s.proxy.Close()
			err = errors.Join(err, e)
		}
		select {
		case <-s.proxyDone:
		case <-ctx.Done():
			err = errors.Join(err, ctx.Err())
		}
		s.proxyTransport.CloseIdleConnections()
		joined := s.handlers.close()
		select {
		case <-joined:
		case <-ctx.Done():
			err = errors.Join(err, ctx.Err())
		}
	}
	err = errors.Join(err, s.CloseTarget(ctx))
	forced := 0
	all := s.target == nil || channelClosed(s.target.done)
	// Reaped CLI commands normally join immediately. Give unexpected retained
	// descendants a small share without letting historical commands dilute the
	// live daemon grace periods.
	var active []*ownedChild
	for i := len(s.children) - 1; i >= 0; i-- {
		owned := s.children[i]
		if !channelClosed(owned.child.Done()) {
			active = append(active, owned)
			continue
		}
		if owned.daemon && !(owned == s.executor && s.executorStopped) {
			err = errors.Join(err, errors.New("daemon exited before cleanup"))
		}
		phase, end := context.WithTimeout(ctx, 250*time.Millisecond)
		stopErr := owned.child.Stop(phase)
		end()
		if errors.Is(stopErr, demo.ErrForcedKill) {
			forced++
		}
		if owned.daemon || !owned.child.CleanupComplete() || errors.Is(stopErr, demo.ErrForcedKill) {
			err = errors.Join(err, stopErr)
		}
	}
	for i, owned := range active {
		phase, end := cleanupPhase(ctx, len(active)-i)
		stopErr := owned.child.Stop(phase)
		end()
		if errors.Is(stopErr, demo.ErrForcedKill) {
			forced++
		}
		err = errors.Join(err, stopErr)
	}
	for _, owned := range s.children {
		if !owned.child.CleanupComplete() {
			err = errors.Join(err, owned.child.Stop(ctx))
		}
		all = all && owned.child.CleanupComplete()
		if owned.capture.exceeded() {
			err = errors.Join(err, errors.New("child diagnostics exceeded bound"))
		}
	}
	all = all && (s.proxyDone == nil || channelClosed(s.proxyDone)) && s.handlers.complete()
	if !all {
		err = errors.Join(err, errors.New("owned cleanup incomplete"))
	}
	result.ChildrenReaped, result.ForcedKills = ptr(all), ptr(forced)
	return result, err
}
func cleanupPhase(ctx context.Context, parts int) (context.Context, context.CancelFunc) {
	deadline, _ := ctx.Deadline()
	return context.WithDeadline(ctx, time.Now().Add(time.Until(deadline)/time.Duration(parts)))
}
func writeConfig(path string, value any) error {
	data, err := toml.Marshal(value)
	if err != nil {
		return err
	}
	var config map[string]any
	if err := toml.Unmarshal(data, &config); err != nil {
		return err
	}
	data, err = toml.Marshal(lowerConfigKeys(config))
	if err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	_, err = f.Write(data)
	return errors.Join(err, f.Close())
}

// The server Serve goroutine stops before active request handlers necessarily
// return. Track those callbacks separately; no detached waiter goroutine is used.
type handlerOwnership struct {
	mu      sync.Mutex
	active  int
	closing bool
	done    chan struct{}
}

func (h *handlerOwnership) begin() bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closing {
		return false
	}
	h.active++
	return true
}
func (h *handlerOwnership) end() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.active--
	if h.closing && h.active == 0 {
		close(h.done)
	}
}
func (h *handlerOwnership) close() <-chan struct{} {
	h.mu.Lock()
	defer h.mu.Unlock()
	if !h.closing {
		h.closing = true
		h.done = make(chan struct{})
		if h.active == 0 {
			close(h.done)
		}
	}
	return h.done
}
func (h *handlerOwnership) complete() bool { h.mu.Lock(); defer h.mu.Unlock(); return h.active == 0 }

// Some executor config fields have no TOML tags. Keep using their
// typed definitions while retaining the lowercase on-disk keys.
func lowerConfigKeys(values map[string]any) map[string]any {
	out := make(map[string]any, len(values))
	for key, value := range values {
		if nested, ok := value.(map[string]any); ok {
			value = lowerConfigKeys(nested)
		}
		out[strings.ToLower(key)] = value
	}
	return out
}
