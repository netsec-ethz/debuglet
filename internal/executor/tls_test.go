package executor

import (
	"context"
	"crypto/tls"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/netsec-ethz/debuglet/internal/executor/config"
	"github.com/netsec-ethz/debuglet/internal/testtls"
)

const credentialTestWait = 5 * time.Second

// credentialFixture issues the material an executor configuration names.
type credentialFixture struct {
	ca      *testtls.Authority
	foreign *testtls.Authority
	server  *testtls.Identity
	client  *testtls.Identity
	dir     string
}

func newCredentialFixture(t *testing.T) *credentialFixture {
	t.Helper()
	dir := t.TempDir()
	ca, err := testtls.NewAuthority(dir, "authority")
	if err != nil {
		t.Fatalf("create authority: %v", err)
	}
	foreign, err := testtls.NewAuthority(t.TempDir(), "foreign")
	if err != nil {
		t.Fatalf("create foreign authority: %v", err)
	}
	server, err := ca.Issue("dispatcher", testtls.Options{Hosts: []string{"127.0.0.1", "dispatcher.example.org"}, Server: true})
	if err != nil {
		t.Fatalf("issue dispatcher identity: %v", err)
	}
	client, err := ca.Issue("executor", testtls.Options{Hosts: []string{"executor.example.org"}, Client: true})
	if err != nil {
		t.Fatalf("issue executor identity: %v", err)
	}
	return &credentialFixture{ca: ca, foreign: foreign, server: server, client: client, dir: dir}
}

func (f *credentialFixture) config(serverName string) *config.ExecutorConfig {
	return &config.ExecutorConfig{
		TLS: config.TLSConfig{ServerName: serverName},
		Credentials: config.CredentialConfig{
			CACert:     f.ca.CertFile,
			ClientCert: f.client.CertFile,
			ClientKey:  f.client.KeyFile,
		},
	}
}

// serve runs a TLS listener with the given server identity and returns its
// address. It requires a client certificate, the way a dispatcher configured
// with tls.require_client_cert does.
func serveTLS(t *testing.T, ca *testtls.Authority, identity *testtls.Identity) string {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	lis = tls.NewListener(lis, ca.ServerConfig(identity, true))
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := lis.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				// Reading completes the handshake and reports its outcome.
				conn.SetDeadline(time.Now().Add(credentialTestWait))
				buf := make([]byte, 1)
				conn.Read(buf)
			}()
		}
	}()
	t.Cleanup(func() { lis.Close(); <-done })
	return lis.Addr().String()
}

// handshake dials one connection with the executor's own client profile.
func handshake(t *testing.T, cfg *tls.Config, address string) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), credentialTestWait)
	defer cancel()
	dialer := &tls.Dialer{Config: cfg}
	conn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return err
	}
	defer conn.Close()
	// TLS 1.3 reports a refused client certificate after the client handshake,
	// so a write and a read are what actually settle the exchange.
	conn.SetDeadline(time.Now().Add(credentialTestWait))
	if _, err := conn.Write([]byte{0}); err != nil {
		return err
	}
	buf := make([]byte, 1)
	if _, err := conn.Read(buf); err != nil && !strings.Contains(err.Error(), "EOF") && !strings.Contains(err.Error(), "timeout") {
		return err
	}
	return nil
}

// TestClientCredentialsVerifyTheDispatcher keeps the executor's control profile
// verifying the peer it connects to on both channels, against the configured
// authority and the configured name.
func TestClientCredentialsVerifyTheDispatcher(t *testing.T) {
	f := newCredentialFixture(t)
	cfg, creds, err := getClientCredentials(f.config(""))
	if err != nil {
		t.Fatalf("load credentials: %v", err)
	}
	if cfg.InsecureSkipVerify {
		t.Fatal("the supported profile skips dispatcher verification")
	}
	if cfg.RootCAs == nil {
		t.Fatal("configured authority is not used as a verification root")
	}
	if len(cfg.Certificates) != 1 {
		t.Fatalf("client identity: %d certificates", len(cfg.Certificates))
	}
	if cfg.MinVersion != tls.VersionTLS12 {
		t.Fatalf("minimum version: %x", cfg.MinVersion)
	}
	if creds == nil || creds.Info().SecurityProtocol != "tls" {
		t.Fatalf("direct channel credentials: %+v", creds)
	}

	address := serveTLS(t, f.ca, f.server)
	if err := handshake(t, cfg.Clone(), address); err != nil {
		t.Fatalf("verified dispatcher: %v", err)
	}

	foreign, err := f.foreign.Issue("dispatcher", testtls.Options{Hosts: []string{"127.0.0.1"}, Server: true})
	if err != nil {
		t.Fatalf("issue foreign identity: %v", err)
	}
	if err := handshake(t, cfg.Clone(), serveTLS(t, f.foreign, foreign)); err == nil || !strings.Contains(err.Error(), "certificate") {
		t.Fatalf("untrusted dispatcher accepted: %v", err)
	}

	expired, err := f.ca.Issue("expired", testtls.Options{
		Hosts:     []string{"127.0.0.1"},
		Server:    true,
		NotBefore: time.Now().Add(-48 * time.Hour),
		NotAfter:  time.Now().Add(-24 * time.Hour),
	})
	if err != nil {
		t.Fatalf("issue expired identity: %v", err)
	}
	if err := handshake(t, cfg.Clone(), serveTLS(t, f.ca, expired)); err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("expired dispatcher certificate accepted: %v", err)
	}
}

// TestClientCredentialsVerifyTheConfiguredName covers tls.server_name, which is
// what an executor sets when the address it dials is not the dispatcher's name.
func TestClientCredentialsVerifyTheConfiguredName(t *testing.T) {
	f := newCredentialFixture(t)
	address := serveTLS(t, f.ca, f.server)
	named, _, err := getClientCredentials(f.config("dispatcher.example.org"))
	if err != nil {
		t.Fatalf("load credentials: %v", err)
	}
	if named.ServerName != "dispatcher.example.org" {
		t.Fatalf("server name: %q", named.ServerName)
	}
	if err := handshake(t, named.Clone(), address); err != nil {
		t.Fatalf("configured dispatcher name: %v", err)
	}
	other, _, err := getClientCredentials(f.config("other.example.org"))
	if err != nil {
		t.Fatalf("load credentials: %v", err)
	}
	if err := handshake(t, other.Clone(), address); err == nil || !strings.Contains(err.Error(), "certificate is valid for") {
		t.Fatalf("certificate for another name accepted: %v", err)
	}
}

// TestClientCredentialErrors keeps unusable material a startup failure that
// names the configuration key holding it.
func TestClientCredentialErrors(t *testing.T) {
	f := newCredentialFixture(t)
	stale, err := testtls.NewExpiredAuthority(t.TempDir(), "stale")
	if err != nil {
		t.Fatalf("create expired authority: %v", err)
	}
	issueClient := func(name string, notBefore, notAfter time.Time) *testtls.Identity {
		t.Helper()
		identity, err := f.ca.Issue(name, testtls.Options{Hosts: []string{"executor.example.org"}, Client: true,
			NotBefore: notBefore, NotAfter: notAfter})
		if err != nil {
			t.Fatalf("issue %s client identity: %v", name, err)
		}
		return identity
	}
	expiredClient := issueClient("expired-client", time.Now().Add(-48*time.Hour), time.Now().Add(-24*time.Hour))
	futureClient := issueClient("future-client", time.Now().Add(24*time.Hour), time.Now().Add(48*time.Hour))
	malformed := filepath.Join(f.dir, "malformed.pem")
	if err := os.WriteFile(malformed, []byte("not a certificate\n"), 0o600); err != nil {
		t.Fatalf("write malformed authority: %v", err)
	}
	for _, tc := range []struct {
		name string
		edit func(*config.ExecutorConfig)
		want string
	}{
		{"missing client certificate", func(c *config.ExecutorConfig) {
			c.Credentials.ClientCert = filepath.Join(f.dir, "absent.crt")
		}, "credentials.client_cert"},
		{"mismatched key", func(c *config.ExecutorConfig) {
			c.Credentials.ClientKey = f.server.KeyFile
		}, "credentials.client_key"},
		{"expired client certificate", func(c *config.ExecutorConfig) {
			c.Credentials.ClientCert, c.Credentials.ClientKey = expiredClient.CertFile, expiredClient.KeyFile
		}, "credentials.client_cert"},
		{"not yet valid client certificate", func(c *config.ExecutorConfig) {
			c.Credentials.ClientCert, c.Credentials.ClientKey = futureClient.CertFile, futureClient.KeyFile
		}, "renew it before starting"},
		{"missing authority", func(c *config.ExecutorConfig) {
			c.Credentials.CACert = filepath.Join(f.dir, "absent.crt")
		}, "credentials.ca_cert"},
		{"malformed authority", func(c *config.ExecutorConfig) {
			c.Credentials.CACert = malformed
		}, "holds no PEM certificate"},
		{"expired authority", func(c *config.ExecutorConfig) {
			c.Credentials.CACert = stale.CertFile
		}, `authority "stale" is valid from`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := f.config("")
			tc.edit(cfg)
			profile, creds, err := getClientCredentials(cfg)
			if err == nil || profile != nil || creds != nil {
				t.Fatalf("accepted %s", tc.name)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q does not name %q", err, tc.want)
			}
		})
	}
	// An omitted authority keeps the host's trust store rather than skipping
	// verification.
	cfg := f.config("")
	cfg.Credentials.CACert = ""
	profile, _, err := getClientCredentials(cfg)
	if err != nil {
		t.Fatalf("host trust store: %v", err)
	}
	if profile.RootCAs != nil || profile.InsecureSkipVerify {
		t.Fatalf("host trust store profile: %+v", profile)
	}
}
