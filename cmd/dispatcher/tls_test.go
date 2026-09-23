package main

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/yamux"
	"github.com/netsec-ethz/debuglet/internal/dispatcher"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/config"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/transport/rpc"
	"github.com/netsec-ethz/debuglet/internal/testtls"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
)

const combinedTestWait = 8 * time.Second

// combinedFixture serves the dispatcher's combined HTTP and control listener
// the way the command builds it: one socket, TLS terminated in front of the
// protocol multiplexer, with the reverse control stream behind it.
type combinedFixture struct {
	ca     *testtls.Authority
	client *testtls.Identity
	addr   string
}

func newCombinedFixture(t *testing.T, requireClientIdentity bool) *combinedFixture {
	t.Helper()
	dir := t.TempDir()
	ca, err := testtls.NewAuthority(dir, "authority")
	if err != nil {
		t.Fatalf("create authority: %v", err)
	}
	server, err := ca.Issue("dispatcher", testtls.Options{Hosts: []string{"127.0.0.1", "localhost"}, Server: true})
	if err != nil {
		t.Fatalf("issue dispatcher identity: %v", err)
	}
	client, err := ca.Issue("executor", testtls.Options{Hosts: []string{"executor.example.org"}, Client: true})
	if err != nil {
		t.Fatalf("issue executor identity: %v", err)
	}
	cfg := &config.DispatcherConfig{TLS: config.TLSConfig{
		CertFile: server.CertFile, KeyFile: server.KeyFile, CAFile: ca.CertFile, RequireClientCert: requireClientIdentity,
	}}
	security, err := config.LoadServerTLS(cfg.TLS)
	if err != nil {
		t.Fatalf("load transport security: %v", err)
	}
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	bidi, err := rpc.NewBidiServer(zap.NewNop(), nil, "00000000-0000-4000-8000-000000000001", time.Minute)
	if err != nil {
		lis.Close()
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- serveCombined(ctx, lis, &dispatcher.Dispatcher{Bidi: bidi}, cfg, security, nil, zap.NewNop())
	}()
	t.Cleanup(func() {
		cancel()
		bidi.Close()
		lis.Close()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("combined listener: %v", err)
			}
		case <-time.After(combinedTestWait):
			t.Error("combined listener did not join")
		}
	})
	return &combinedFixture{ca: ca, client: client, addr: lis.Addr().String()}
}

// httpStatus performs one HTTPS request with the given verification profile.
func (f *combinedFixture) httpStatus(t *testing.T, cfg *tls.Config) (int, error) {
	t.Helper()
	client := &http.Client{Timeout: combinedTestWait, Transport: &http.Transport{TLSClientConfig: cfg}}
	defer client.CloseIdleConnections()
	response, err := client.Get("https://" + f.addr + "/absent")
	if err != nil {
		return 0, err
	}
	defer response.Body.Close()
	return response.StatusCode, nil
}

// controlPing opens the reverse control stream the executor opens: a TLS
// connection carrying yamux, routed by the multiplexer to the control listener.
func (f *combinedFixture) controlPing(t *testing.T, cfg *tls.Config) error {
	t.Helper()
	dialer := &tls.Dialer{Config: cfg}
	ctx, cancel := context.WithTimeout(context.Background(), combinedTestWait)
	defer cancel()
	conn, err := dialer.DialContext(ctx, "tcp", f.addr)
	if err != nil {
		return err
	}
	defer conn.Close()
	session, err := yamux.Client(conn, nil)
	if err != nil {
		return err
	}
	defer session.Close()
	_, err = session.Ping()
	return err
}

// TestCombinedListenerTerminatesTLS keeps both protocols on the shared port
// behind one verified connection: the HTTP API answers a request from a client
// that pinned the dispatcher's authority, the multiplexer still routes a yamux
// connection to the control listener, and a client that cannot verify the
// dispatcher reaches neither.
func TestCombinedListenerTerminatesTLS(t *testing.T) {
	f := newCombinedFixture(t, false)
	status, err := f.httpStatus(t, f.ca.ClientConfig(nil, ""))
	if err != nil || status != http.StatusNotFound {
		t.Fatalf("HTTP API over TLS: status=%d %v", status, err)
	}
	if err := f.controlPing(t, f.ca.ClientConfig(f.client, "")); err != nil {
		t.Fatalf("control stream over TLS: %v", err)
	}
	// The same port refuses a plaintext HTTP request: the multiplexer never
	// sees it, because the connection is terminated before it.
	client := &http.Client{Timeout: combinedTestWait}
	if _, err := client.Get("http://" + f.addr + "/absent"); err == nil {
		t.Fatal("plaintext request accepted on a TLS listener")
	}
	foreign, err := testtls.NewAuthority(t.TempDir(), "foreign")
	if err != nil {
		t.Fatalf("create foreign authority: %v", err)
	}
	if _, err := f.httpStatus(t, foreign.ClientConfig(nil, "")); err == nil || !strings.Contains(err.Error(), "certificate") {
		t.Fatalf("untrusted root accepted by the HTTP API: %v", err)
	}
	if err := f.controlPing(t, foreign.ClientConfig(nil, "")); err == nil || !strings.Contains(err.Error(), "certificate") {
		t.Fatalf("untrusted root accepted by the control stream: %v", err)
	}
	if err := f.controlPing(t, f.ca.ClientConfig(f.client, "other.example.org")); err == nil || !strings.Contains(err.Error(), "certificate is valid for") {
		t.Fatalf("wrong dispatcher name accepted: %v", err)
	}
}

// TestCombinedListenerRequiresControlIdentity keeps the client-certificate
// requirement on the executor's stream only. The HTTP API shares the port with
// submitters who hold no certificate and keeps answering them.
func TestCombinedListenerRequiresControlIdentity(t *testing.T) {
	f := newCombinedFixture(t, true)
	status, err := f.httpStatus(t, f.ca.ClientConfig(nil, ""))
	if err != nil || status != http.StatusNotFound {
		t.Fatalf("HTTP API without a client certificate: status=%d %v", status, err)
	}
	if err := f.controlPing(t, f.ca.ClientConfig(f.client, "")); err != nil {
		t.Fatalf("control stream with an issued identity: %v", err)
	}
	if err := f.controlPing(t, f.ca.ClientConfig(nil, "")); err == nil {
		t.Fatal("control stream admitted a peer without a certificate")
	}
	foreign, err := testtls.NewAuthority(t.TempDir(), "foreign")
	if err != nil {
		t.Fatalf("create foreign authority: %v", err)
	}
	unenrolled, err := foreign.Issue("executor", testtls.Options{Client: true})
	if err != nil {
		t.Fatalf("issue foreign identity: %v", err)
	}
	cfg := f.ca.ClientConfig(unenrolled, "")
	if err := f.controlPing(t, cfg); err == nil {
		t.Fatal("control stream admitted a certificate from another authority")
	}
}

// TestTransportSecurityReport keeps a plaintext listener off loopback from
// starting silently: the exposure is reported, and a terminating listener says
// which profile it serves.
func TestTransportSecurityReport(t *testing.T) {
	for _, tc := range []struct {
		name              string
		security          *config.ServerTLS
		http, grpc, entry string
		level             string
	}{
		{name: "loopback plaintext", http: "127.0.0.1:9000", grpc: "127.0.0.1:9001", entry: "plaintext on loopback", level: "info"},
		{name: "exposed plaintext", http: "0.0.0.0:9000", grpc: "127.0.0.1:9001", entry: "plaintext off loopback", level: "warn"},
		{name: "terminated", security: &config.ServerTLS{}, http: "0.0.0.0:9000", grpc: "0.0.0.0:9001", entry: "terminate TLS", level: "info"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			core, logs := observer.New(zapcore.DebugLevel)
			reportTransportSecurity(zap.New(core), tc.security, tc.http, tc.grpc)
			entries := logs.All()
			if len(entries) != 1 {
				t.Fatalf("startup entries: %d", len(entries))
			}
			if !strings.Contains(entries[0].Message, tc.entry) || entries[0].Level.String() != tc.level {
				t.Fatalf("entry %+v does not report %q at %s", entries[0], tc.entry, tc.level)
			}
		})
	}
}

// TestStartupChecksTLSBeforeStorage keeps the order the command promises: the
// transport material is loaded before the database is opened for service, so an
// unusable certificate stops the daemon without it having created or touched
// any state. The same configuration with a usable certificate reaches the
// storage check, which is what proves the first case stopped where it says.
func TestStartupChecksTLSBeforeStorage(t *testing.T) {
	dir := t.TempDir()
	ca, err := testtls.NewAuthority(dir, "authority")
	if err != nil {
		t.Fatalf("create authority: %v", err)
	}
	server, err := ca.Issue("dispatcher", testtls.Options{Hosts: []string{"127.0.0.1"}, Server: true})
	if err != nil {
		t.Fatalf("issue dispatcher identity: %v", err)
	}
	expired, err := ca.Issue("stale", testtls.Options{
		Hosts:     []string{"127.0.0.1"},
		Server:    true,
		NotBefore: time.Now().Add(-48 * time.Hour),
		NotAfter:  time.Now().Add(-24 * time.Hour),
	})
	if err != nil {
		t.Fatalf("issue expired identity: %v", err)
	}
	database := filepath.Join(dir, "dispatcher.db")
	configure := func(identity *testtls.Identity) *config.DispatcherConfig {
		cfg := &config.DispatcherConfig{}
		cfg.Server = config.ServerConfig{BindHost: "127.0.0.1", Version: "test"}
		cfg.Scheduler = config.SchedulerConfig{ExecutorTimeout: 60, SchedulerGranularityMs: 100}
		cfg.Database.Path = database
		cfg.Sui.Disabled = true
		cfg.TLS = config.TLSConfig{CertFile: identity.CertFile, KeyFile: identity.KeyFile}
		return cfg
	}
	ctx, cancel := context.WithTimeout(context.Background(), combinedTestWait)
	defer cancel()

	err = runDispatcher(ctx, configure(expired), "", zap.NewNop())
	if err == nil || !strings.Contains(err.Error(), "tls.cert_file") {
		t.Fatalf("expired certificate at startup: %v", err)
	}
	if _, statErr := os.Stat(database); !os.IsNotExist(statErr) {
		t.Fatalf("database touched before the transport material was loaded: %v", statErr)
	}

	err = runDispatcher(ctx, configure(server), "", zap.NewNop())
	if err == nil || !strings.Contains(err.Error(), database) {
		t.Fatalf("usable certificate did not reach the storage check: %v", err)
	}
}
