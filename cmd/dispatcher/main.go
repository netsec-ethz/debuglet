// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 ETH Zurich

package main

import (
	"context"
	"crypto/tls"
	"database/sql"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/soheilhy/cmux"
	"go.uber.org/zap"
	"golang.org/x/sync/errgroup"

	"github.com/netsec-ethz/debuglet/internal/configcheck"
	"github.com/netsec-ethz/debuglet/internal/dispatcher"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/config"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/database"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/enrollment"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/payments"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/transport/api"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/transport/rpc"
	"github.com/netsec-ethz/debuglet/internal/readiness"
	"github.com/netsec-ethz/debuglet/internal/storagecheck"

	"github.com/google/uuid"

	_ "modernc.org/sqlite"
)

func main() {
	cfgPath := flag.String("config", "/etc/debuglet/dispatcher/dispatcher.toml", "Path to dispatcher configuration file")
	readyFile := flag.String("ready-file", "", "Publish startup record at an absent path in an owned private directory")
	grant := flag.String("grant-operator", "", "Give the account with this UUID the operator role in the configured database, then exit")
	revoke := flag.String("revoke-operator", "", "Return the account with this UUID to the ordinary role in the configured database, then exit")
	enroll := flag.String("enroll-executor", "", "Create a single-use enrollment token for this executor ID in the configured database, print it once, then exit")
	unenroll := flag.String("revoke-executor", "", "Delete the node credential enrolled for this executor ID in the configured database, then exit")
	flag.Parse()

	cfg, err := config.LoadConfig(*cfgPath)
	if err != nil {
		panic(fmt.Sprintf("Failed to load dispatcher config: %v", err))
	}

	// Role administration is deliberately not an HTTP operation: the operator
	// role is granted on the dispatcher host, by whoever already controls the
	// database, and never by anything reachable over the network.
	if *grant != "" || *revoke != "" {
		if err := administerRole(context.Background(), cfg, *grant, *revoke); err != nil {
			fmt.Fprintf(os.Stderr, "dispatcher: %v\n", err)
			os.Exit(1)
		}
		return
	}
	// Executor enrollment is administered the same way, and for the same
	// reason: a node credential is bound on the dispatcher host, by whoever
	// already controls the database, never over the network.
	if *enroll != "" || *unenroll != "" {
		if err := administerEnrollment(context.Background(), cfg, *enroll, *unenroll); err != nil {
			fmt.Fprintf(os.Stderr, "dispatcher: %v\n", err)
			os.Exit(1)
		}
		return
	}

	logLevel, err := zap.ParseAtomicLevel(cfg.Logging.LogLevel)
	if err != nil {
		logLevel = zap.NewAtomicLevelAt(zap.InfoLevel)
	}
	logCfg := zap.NewDevelopmentConfig()
	if cfg.Logging.JSONLogs {
		logCfg = zap.NewProductionConfig()
	}
	logCfg.Level = logLevel
	logCfg.OutputPaths = []string{"stdout"}
	logger, _ := logCfg.Build()
	defer logger.Sync()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := runDispatcher(ctx, cfg, *readyFile, logger); err != nil {
		logger.Error("dispatcher exited with error", zap.Error(err))
		logger.Sync()
		os.Exit(1)
	}
}

func runDispatcher(ctx context.Context, cfg *config.DispatcherConfig, readyFile string, logger *zap.Logger) error {
	// Refuse unusable TLS material and an unsupported schema before opening the
	// database for service, restoring the scheduler or binding a listener.
	for _, file := range cfg.TLSFiles() {
		if err := configcheck.File(file.Field, file.Path); err != nil {
			return err
		}
	}
	security, err := config.LoadServerTLS(cfg.TLS)
	if err != nil {
		return err
	}
	if err := storagecheck.Check(ctx, storagecheck.Dispatcher, cfg.Database.Path); err != nil {
		return err
	}
	db, err := sql.Open("sqlite", cfg.Database.Path)
	if err != nil {
		return fmt.Errorf("open database: %w", err)
	}
	db.SetMaxOpenConns(1)
	defer db.Close()
	paymentHandler := payments.NewPaymentHandler(db, cfg, logger)
	d, err := dispatcher.New(logger, db, cfg.Server.Version, time.Duration(cfg.Scheduler.ExecutorTimeout)*time.Second, time.Duration(cfg.Scheduler.SchedulerGranularityMs)*time.Millisecond, paymentHandler)
	if err != nil {
		return fmt.Errorf("create dispatcher: %w", err)
	}
	defer d.Close()
	// An executor ID is bound to a node credential only where the listeners
	// actually verify one; with no client certificate there is nothing to bind.
	if security != nil && security.RequireClientIdentity {
		d.Bidi.EnforceEnrollment(enrollment.NewStore(db))
	} else {
		logger.Warn("Executor identities are unverified: without tls.require_client_cert the dispatcher has no node credential to enrol, " +
			"so any peer that reaches the control port registers under the executor ID it claims and displaces the current holder")
	}
	if err := d.RestoreScheduler(ctx); err != nil {
		return fmt.Errorf("restore scheduler: %w", err)
	}

	httpL, grpcL, err := bindDispatcherListeners(ctx, cfg.Server, (&net.ListenConfig{}).Listen)
	if err != nil {
		return err
	}
	if security != nil {
		grpcL = tls.NewListener(grpcL, security.Direct)
	}
	defer httpL.Close()
	defer grpcL.Close()
	reportTransportSecurity(logger, security, httpL.Addr().String(), grpcL.Addr().String())
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	connection := localConnectionMetadata(cfg, httpL.Addr().String(), grpcL.Addr().String())
	if cfg.Server.LocalDevelopment && connection == nil {
		return errors.New("server.local_development is set but this is not a local environment: " +
			"it requires blockchain payments disabled, the TLS listener disabled and both listeners bound to loopback")
	}
	if localDevelopmentProfile(cfg, connection) {
		logger.Warn("HTTP API is serving the local development profile: requests without a credential are served as this dispatcher's local operator",
			zap.String("profile", "local-development"), zap.String("http_address", httpL.Addr().String()))
	}
	g, subCtx := errgroup.WithContext(ctx)
	g.Go(func() error { return d.Bidi.ServeGRPCListener(subCtx, grpcL) })
	g.Go(func() error {
		return serveCombinedWithMetadata(subCtx, httpL, d, cfg, security, db, logger, connection)
	})
	// A disabled or unconfigured blockchain endpoint runs no payment listener.
	if cfg.Sui.GRPCEndpoint != "" && !cfg.Sui.Disabled {
		g.Go(func() error { return paymentHandler.Start(subCtx) })
	}
	if readyFile != "" {
		err = readiness.Write(readyFile, readiness.Record{
			SchemaVersion: 1, PID: os.Getpid(), HTTPAddr: httpL.Addr().String(), GRPCAddr: grpcL.Addr().String(),
		})
		if err != nil {
			cancel()
			g.Wait()
			return err
		}
		defer os.Remove(readyFile)
	}
	return g.Wait()
}

func bindDispatcherListeners(ctx context.Context, cfg config.ServerConfig, listen func(context.Context, string, string) (net.Listener, error)) (net.Listener, net.Listener, error) {
	httpL, err := listen(ctx, "tcp", net.JoinHostPort(cfg.BindHost, strconv.Itoa(cfg.HTTPPort)))
	if err != nil {
		return nil, nil, fmt.Errorf("HTTP/yamux listen: %w", err)
	}
	grpcL, err := listen(ctx, "tcp", net.JoinHostPort(cfg.BindHost, strconv.Itoa(cfg.GRPCPort)))
	if err != nil {
		httpL.Close()
		return nil, nil, fmt.Errorf("gRPC listen: %w", err)
	}
	return httpL, grpcL, nil
}

func serveCombined(ctx context.Context, lis net.Listener, d *dispatcher.Dispatcher, cfg *config.DispatcherConfig, security *config.ServerTLS, db *sql.DB, logger *zap.Logger) error {
	return serveCombinedWithMetadata(ctx, lis, d, cfg, security, db, logger, nil)
}

func serveCombinedWithMetadata(parent context.Context, lis net.Listener, d *dispatcher.Dispatcher, cfg *config.DispatcherConfig, security *config.ServerTLS, db *sql.DB, logger *zap.Logger, connection *connectionMetadata) error {
	stopCtx, stop := context.WithCancelCause(parent)
	defer stop(nil)
	g, ctx := errgroup.WithContext(stopCtx)
	// cmux.Close does not interrupt a connection still sniffing its protocol.
	// Keep ownership until HTTP/yamux closes it or this listener shuts down.
	owned := &connectionListener{Listener: lis, conns: make(map[*ownedConn]struct{})}
	var muxed net.Listener = owned
	if security != nil {
		// Terminate before the multiplexer, so the HTTP API and the reverse
		// control stream are the same verified connection the direct gRPC
		// listener requires, and so the matcher reads cleartext framing.
		muxed = tls.NewListener(owned, security.Combined)
	}
	m := cmux.New(muxed)
	httpL := m.Match(cmux.HTTP2(), cmux.HTTP1Fast())
	var yamuxL net.Listener = &memberListener{Listener: m.Match(cmux.Any()), stop: stop}
	if security != nil && security.RequireClientIdentity {
		yamuxL = rpc.VerifiedClientListener(yamuxL, logger)
	}
	joined := make(chan struct{})
	go func() {
		defer close(joined)
		<-ctx.Done()
		m.Close()
		owned.Close()
	}()
	// Service ends by closing the multiplexer and the listener, and an accept
	// loop can see that closure before its own context reports the cancellation
	// behind it. Only the caller's context tells a requested stop from a
	// failure: it reports the stop first, and the group's is cancelled by either.
	// The control server's closure under a live context is told apart by its cause, below.
	failure := func(err error) error {
		if parent.Err() != nil && (errors.Is(err, cmux.ErrServerClosed) || errors.Is(err, cmux.ErrListenerClosed) || errors.Is(err, net.ErrClosed)) {
			return nil
		}
		return err
	}
	g.Go(func() error { return failure(m.Serve()) })
	g.Go(func() error { return failure(startHTTPServer(ctx, httpL, d, cfg, db, logger, connection)) })
	g.Go(func() error { return failure(d.Bidi.ServeYamux(ctx, yamuxL)) })
	err := g.Wait()
	<-joined // Wait cancels the errgroup context, including successful exits.
	// The group's context keeps the first cause: a member's own failure, or the
	// control server's closure passed down from stopCtx before the multiplexer
	// was closed. A nil err is a stop the caller requested, whatever the cause.
	if err != nil && errors.Is(context.Cause(ctx), errControlServerClosed) {
		return errControlServerClosed
	}
	return err
}

// errControlServerClosed is returned when the control server is closed while
// the caller's context is live.
var errControlServerClosed = errors.New("control server closed while the combined listener was serving")

// memberListener is the control server's share of the multiplexer. Closing it
// leaves the shared listener open and ends the combined listener deliberately,
// with the control server's closure as the cause, unless an accept has already
// failed: the member is then ending with the multiplexer and asks for nothing.
type memberListener struct {
	net.Listener
	stop  context.CancelCauseFunc
	ended atomic.Bool
}

func (l *memberListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		l.ended.Store(true)
	}
	return conn, err
}

func (l *memberListener) Close() error {
	if !l.ended.Load() {
		l.stop(errControlServerClosed)
	}
	return nil
}

type connectionListener struct {
	net.Listener
	mu     sync.Mutex
	closed bool
	conns  map[*ownedConn]struct{}
}

func (l *connectionListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		conn.Close()
		return nil, net.ErrClosed
	}
	owned := &ownedConn{Conn: conn, owner: l}
	l.conns[owned] = struct{}{}
	return owned, nil
}

func (l *connectionListener) Close() error {
	l.mu.Lock()
	l.closed = true
	conns := make([]*ownedConn, 0, len(l.conns))
	for conn := range l.conns {
		conns = append(conns, conn)
	}
	l.mu.Unlock()
	err := l.Listener.Close()
	for _, conn := range conns {
		conn.Close()
	}
	return err
}

type ownedConn struct {
	net.Conn
	owner *connectionListener
	once  sync.Once
	err   error
}

func (c *ownedConn) Close() error {
	c.once.Do(func() {
		c.err = c.Conn.Close()
		c.owner.mu.Lock()
		delete(c.owner.conns, c)
		c.owner.mu.Unlock()
	})
	return c.err
}

// startHTTPServer runs the Echo-based HTTP API on the given listener.
func startHTTPServer(ctx context.Context, lis net.Listener, manager *dispatcher.Dispatcher, cfg *config.DispatcherConfig, db *sql.DB, logger *zap.Logger, connection *connectionMetadata) error {
	// The local development profile of the HTTP API needs both the operator's
	// explicit opt-in and an environment this command recognises as local:
	// blockchain payments disabled, the TLS listener disabled and both listeners
	// on loopback. Any other configuration, including every generated deployment
	// example, runs the API with authentication and authorization enforced. The
	// cookie's Secure attribute comes from this daemon's own transport, never
	// from a request header, for the reason recorded at the Serve call below.
	handler := api.NewHandler(manager, db, logger,
		api.LocalDevelopment(localDevelopmentProfile(cfg, connection)),
		api.CookieSecure(!cfg.TLS.Disable || cfg.Server.BehindTLSTerminator))

	e := echo.New()
	e.HideBanner = true
	e.HidePort = true
	e.Use(middleware.Recover())
	logFormat := `{"level":"info","ts":${time_unix},"msg":"request","method":"${method}","uri":"${uri}","status":${status},"latency":${latency},"remote_ip":"${remote_ip}","host":"${host}","error":"${error}"}` + "\n"
	if !cfg.Logging.JSONLogs {
		logFormat = "${time_rfc3339}\t${method}\t${uri} ${status} ${latency_human} ${remote_ip}\n"
	}
	e.Use(middleware.LoggerWithConfig(middleware.LoggerConfig{
		Format: logFormat,
	}))
	corsConfig := middleware.DefaultCORSConfig
	corsConfig.ExposeHeaders = []string{api.VersionHeader}
	if len(cfg.CORS.AllowedOrigins) > 0 {
		corsConfig.AllowOrigins = cfg.CORS.AllowedOrigins
		corsConfig.AllowCredentials = true
	}
	e.Use(middleware.CORSWithConfig(corsConfig))

	handler.RegisterRoutes(e)
	if connection != nil {
		e.GET("/connection", func(c echo.Context) error { return c.JSON(http.StatusOK, connection) })
	}

	logger.Info("Dispatcher HTTP API started", zap.String("address", lis.Addr().String()))

	// The combined listener terminates TLS before the protocol multiplexer, so
	// this server always reads the cleartext the multiplexer routed to it: the
	// request carries no TLS state and reports the http scheme even for a
	// connection that was terminated. Anything depending on the real scheme — a
	// session cookie's Secure attribute, an absolute URL, a scheme-dependent
	// redirect — must be told by the listener that accepted the connection,
	// which is the only place that knows.
	server := &http.Server{Handler: e}
	done, joined := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(joined)
		select {
		case <-ctx.Done():
			server.Close()
		case <-done:
		}
	}()
	defer func() { server.Close(); close(done); <-joined }()
	err := server.Serve(lis)
	if ctx.Err() != nil {
		return nil
	}
	return err
}

// administerRole sets the role of one existing account in the configured
// database and returns. It applies the same schema checks the daemon applies
// before serving, so it never writes to a database this build does not
// support, and it reports an identifier that names no account rather than
// creating one.
func administerRole(ctx context.Context, cfg *config.DispatcherConfig, grant, revoke string) error {
	if grant != "" && revoke != "" {
		return errors.New("-grant-operator and -revoke-operator cannot be combined")
	}
	id, role := grant, api.RoleOperator
	if grant == "" {
		id, role = revoke, api.RoleUser
	}
	account, err := uuid.Parse(id)
	if err != nil {
		return fmt.Errorf("account identifier is not a UUID: %w", err)
	}
	if err := storagecheck.Check(ctx, storagecheck.Dispatcher, cfg.Database.Path); err != nil {
		return err
	}
	db, err := sql.Open("sqlite", cfg.Database.Path)
	if err != nil {
		return fmt.Errorf("open database: %w", err)
	}
	db.SetMaxOpenConns(1)
	defer db.Close()
	changed, err := database.New(db).SetUserRole(ctx, database.SetUserRoleParams{Role: role, Uuid: account})
	if err != nil {
		return fmt.Errorf("set account role: %w", err)
	}
	if changed == 0 {
		return fmt.Errorf("no account %s exists in %s", account, cfg.Database.Path)
	}
	fmt.Printf("account %s now has role %s\n", account, role)
	return nil
}

// administerEnrollment creates or deletes one executor's node credential in
// the configured database and returns. It applies the same schema checks the
// daemon applies before serving. The printed token is shown once and stored
// only as a digest, so a lost token is replaced rather than recovered.
func administerEnrollment(ctx context.Context, cfg *config.DispatcherConfig, enroll, revoke string) error {
	if enroll != "" && revoke != "" {
		return errors.New("-enroll-executor and -revoke-executor cannot be combined")
	}
	if err := storagecheck.Check(ctx, storagecheck.Dispatcher, cfg.Database.Path); err != nil {
		return err
	}
	db, err := sql.Open("sqlite", cfg.Database.Path)
	if err != nil {
		return fmt.Errorf("open database: %w", err)
	}
	db.SetMaxOpenConns(1)
	defer db.Close()
	store := enrollment.NewStore(db)
	if revoke != "" {
		removed, err := store.Revoke(ctx, revoke)
		if err != nil {
			return err
		}
		if !removed.Binding && removed.Tokens == 0 {
			return fmt.Errorf("executor %q has no enrolled certificate and no unused token in %s", revoke, cfg.Database.Path)
		}
		if removed.Binding {
			fmt.Printf("executor %s is no longer enrolled; its certificate is refused from now on\n", revoke)
		}
		if removed.Tokens != 0 {
			fmt.Printf("dropped %d unused enrollment token(s) of executor %s\n", removed.Tokens, revoke)
		}
		return nil
	}
	token, err := store.Issue(ctx, enroll, enrollment.DefaultLifetime)
	if err != nil {
		return err
	}
	if !cfg.TLS.RequireClientCert {
		fmt.Fprintln(os.Stderr, "dispatcher: tls.require_client_cert is not set, so this dispatcher does not verify executor identities and will ignore this token")
	}
	// A token the operator never received must not stay usable, so a failed
	// print — a closed pipe, a full disk — takes the row with it.
	if _, err := fmt.Printf("enrollment token for executor %s, usable once and valid for %s:\n%s\n", enroll, enrollment.DefaultLifetime, token); err != nil {
		if _, dropErr := store.DropTokens(ctx, enroll); dropErr != nil {
			return errors.Join(err, dropErr)
		}
		return fmt.Errorf("print enrollment token: %w", err)
	}
	return nil
}

// localDevelopmentProfile reports whether the HTTP API serves its local
// development profile. It takes both the operator's explicit opt-in and an
// environment this daemon recognises as local: neither alone turns
// authentication off, so a deployment that happens to bind loopback behind a
// proxy keeps enforcing it.
func localDevelopmentProfile(cfg *config.DispatcherConfig, connection *connectionMetadata) bool {
	return cfg != nil && cfg.Server.LocalDevelopment && connection != nil
}

// reportTransportSecurity records the profile the listeners actually serve.
// Plaintext stays available for the trusted local profile, where both listeners
// are on this machine's loopback interface, and for a deployment that
// terminates TLS in front of the dispatcher on a network only the terminator
// can reach. Anywhere else it is an exposed control plane, which is said here
// rather than left to be discovered from a packet capture.
func reportTransportSecurity(logger *zap.Logger, security *config.ServerTLS, httpAddress, grpcAddress string) {
	if security != nil {
		logger.Info("Dispatcher listeners terminate TLS",
			zap.Bool("client_certificate_required", security.RequireClientIdentity))
		return
	}
	exposed := make([]string, 0, 2)
	for _, address := range []string{httpAddress, grpcAddress} {
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			continue
		}
		if ip := net.ParseIP(host); ip == nil || !ip.IsLoopback() {
			exposed = append(exposed, address)
		}
	}
	if len(exposed) == 0 {
		logger.Info("Dispatcher listeners serve plaintext on loopback")
		return
	}
	logger.Warn("Dispatcher listeners serve plaintext off loopback: every HTTP request and every control session token on these addresses is readable on the path. Set tls.disable = false with tls.cert_file and tls.key_file, or keep a TLS terminator in front on a network only it can reach",
		zap.Strings("addresses", exposed))
}

// connectionMetadata describes the addresses the listeners actually bound, never
// configured or inferred port numbers. It is served only with payments and TLS
// disabled and both listeners on loopback; it does not require the local
// development opt-in.
type connectionMetadata struct {
	SchemaVersion int    `json:"schema_version"`
	Mode          string `json:"mode"`
	GRPCAddress   string `json:"grpc_address"`
	YamuxAddress  string `json:"yamux_address"`
}

func localConnectionMetadata(cfg *config.DispatcherConfig, httpAddress, grpcAddress string) *connectionMetadata {
	if !cfg.Sui.Disabled || !cfg.TLS.Disable {
		return nil
	}
	for _, address := range []string{httpAddress, grpcAddress} {
		host, port, err := net.SplitHostPort(address)
		ip := net.ParseIP(host)
		number, portErr := strconv.Atoi(port)
		if err != nil || ip == nil || !ip.IsLoopback() || portErr != nil || number < 1 || number > 65535 {
			return nil
		}
	}
	return &connectionMetadata{SchemaVersion: 1, Mode: "local-test", GRPCAddress: grpcAddress, YamuxAddress: httpAddress}
}
