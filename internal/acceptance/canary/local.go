package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"github.com/netsec-ethz/debuglet/internal/demo"
	"github.com/netsec-ethz/debuglet/internal/readiness"
	"github.com/netsec-ethz/debuglet/internal/storagecheck"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type ownedChild struct {
	child   demo.ChildProcess
	capture *limitedCapture
}
type local struct {
	opts                 Options
	dir                  string
	children             []*ownedChild
	dispatcher, executor *ownedChild
	record               readiness.Record
	supervisor           *demo.Supervisor
	target               *canaryTarget
	proxy                *http.Server
	proxyListener        net.Listener
	proxyDone            chan struct{}
	proxyTransport       *http.Transport
	proxyErr             error
	handlers             handlerOwnership
}

func newLocalSession(ctx context.Context, opts Options, dir string) localSession {
	return &local{opts: opts, dir: dir, supervisor: demo.NewSupervisor(ctx)}
}
func (s *local) launch(path string, args []string, daemon bool) (*ownedChild, error) {
	capture := newCapture(captureLimit)
	child, err := s.supervisor.StartChild(filepath.Base(path), demo.ChildSpec{Path: path, Dir: s.dir, Args: args, Env: []string{"TMPDIR=" + s.dir, "LANG=C", "LC_ALL=C", "TZ=UTC"}, Stdout: capture.stdout(), Stderr: capture.stderr()}, daemon)
	if err != nil {
		return nil, err
	}
	owned := &ownedChild{child: child, capture: capture}
	s.children = append(s.children, owned)
	return owned, nil
}
func localDispatcherConfiguration(version, db string) map[string]any {
	cfg := demo.DispatcherConfiguration(version, db)
	cfg["scheduler"].(map[string]any)["executor_timeout"] = 10
	return cfg
}

func (s *local) StartDispatcher(ctx context.Context) (string, error) {
	db := filepath.Join(s.dir, "dispatcher.sqlite")
	if err := storagecheck.BootstrapFresh(ctx, storagecheck.Dispatcher, db); err != nil {
		return "", err
	}
	cfg := localDispatcherConfiguration(s.opts.Assets.Manifest.Version, db)
	configPath, readyPath := filepath.Join(s.dir, "dispatcher.toml"), filepath.Join(s.dir, "dispatcher-ready.json")
	if err := demo.WriteConfig(configPath, cfg); err != nil {
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

// Keep the canary's disclosure cadence while using the local TEST profile.
func localExecutorConfiguration(executorID, version, db string, record readiness.Record) map[string]any {
	cfg := demo.ExecutorConfiguration(version, executorID, db, record)
	cfg["tesla"].(map[string]any)["delay"] = 2
	cfg["tesla"].(map[string]any)["chain_length"] = 3600
	return cfg
}

func (s *local) StartExecutor(ctx context.Context) error {
	db := filepath.Join(s.dir, "executor.sqlite")
	if err := storagecheck.BootstrapFresh(ctx, storagecheck.Executor, db); err != nil {
		return err
	}
	cfg := localExecutorConfiguration(s.opts.Manifest.ExecutorID, s.opts.Assets.Manifest.Version, db, s.record)
	configPath, readyPath := filepath.Join(s.dir, "executor.toml"), filepath.Join(s.dir, "executor-ready.json")
	if err := demo.WriteConfig(configPath, cfg); err != nil {
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
	stopErr := s.supervisor.Stop(phase, owned.child)
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
	if s.supervisor != nil {
		if err := s.supervisor.Healthy(); err != nil {
			return err
		}
	}
	for _, owned := range []*ownedChild{s.dispatcher, s.executor} {
		if owned != nil && owned.capture.exceeded() {
			return errors.New("owned daemon exceeded diagnostics bound")
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
	err := s.supervisor.Stop(ctx, s.executor.child)
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
	children := demo.ProcessCleanup{Joined: true}
	if s.supervisor != nil {
		err = errors.Join(err, s.supervisor.Healthy())
		var stopErr error
		children, stopErr = s.supervisor.Close(ctx)
		err = errors.Join(err, stopErr)
	}
	all := children.Joined && (s.target == nil || channelClosed(s.target.done))
	for _, owned := range s.children {
		if owned.capture.exceeded() {
			err = errors.Join(err, errors.New("child diagnostics exceeded bound"))
		}
	}
	all = all && (s.proxyDone == nil || channelClosed(s.proxyDone)) && s.handlers.complete()
	if !all {
		err = errors.Join(err, errors.New("owned cleanup incomplete"))
	}
	result.ChildrenReaped, result.ForcedKills = ptr(all), ptr(children.ForcedKills)
	return result, err
}
func cleanupPhase(ctx context.Context, parts int) (context.Context, context.CancelFunc) {
	deadline, _ := ctx.Deadline()
	return context.WithDeadline(ctx, time.Now().Add(time.Until(deadline)/time.Duration(parts)))
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
