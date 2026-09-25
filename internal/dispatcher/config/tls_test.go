package config

import (
	"crypto/tls"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/netsec-ethz/debuglet/internal/testtls"
)

// authority issues the material a listener profile needs, in a directory the
// test owns.
func authority(t *testing.T) (*testtls.Authority, string) {
	t.Helper()
	dir := t.TempDir()
	ca, err := testtls.NewAuthority(dir, "authority")
	if err != nil {
		t.Fatalf("create authority: %v", err)
	}
	return ca, dir
}

// TestServerTLSProfiles checks what the two listeners actually offer: the
// combined listener keeps the HTTP API reachable without a client certificate
// while the direct gRPC listener refuses a missing one, and both present the
// same identity.
func TestServerTLSProfiles(t *testing.T) {
	ca, _ := authority(t)
	server, err := ca.Issue("dispatcher", testtls.Options{Hosts: []string{"dispatcher.example.org", "127.0.0.1"}, Server: true})
	if err != nil {
		t.Fatalf("issue server identity: %v", err)
	}
	base := TLSConfig{CertFile: server.CertFile, KeyFile: server.KeyFile}

	t.Run("without an authority", func(t *testing.T) {
		security, err := LoadServerTLS(base)
		if err != nil {
			t.Fatalf("load: %v", err)
		}
		if security.Combined.ClientAuth != tls.NoClientCert || security.Direct.ClientAuth != tls.NoClientCert {
			t.Fatalf("client authentication without an authority: %v/%v", security.Combined.ClientAuth, security.Direct.ClientAuth)
		}
		if security.RequireClientIdentity {
			t.Fatal("client identity required without tls.require_client_cert")
		}
	})

	t.Run("with an authority", func(t *testing.T) {
		cfg := base
		cfg.CAFile = ca.CertFile
		security, err := LoadServerTLS(cfg)
		if err != nil {
			t.Fatalf("load: %v", err)
		}
		if security.Combined.ClientAuth != tls.VerifyClientCertIfGiven || security.Direct.ClientAuth != tls.VerifyClientCertIfGiven {
			t.Fatalf("offered certificate not verified: %v/%v", security.Combined.ClientAuth, security.Direct.ClientAuth)
		}
	})

	t.Run("client identity required", func(t *testing.T) {
		cfg := base
		cfg.CAFile, cfg.RequireClientCert = ca.CertFile, true
		security, err := LoadServerTLS(cfg)
		if err != nil {
			t.Fatalf("load: %v", err)
		}
		if security.Direct.ClientAuth != tls.RequireAndVerifyClientCert {
			t.Fatalf("direct gRPC listener admits a missing identity: %v", security.Direct.ClientAuth)
		}
		// The HTTP API shares the combined listener with submitters who hold
		// no certificate; the reverse control stream checks it after matching.
		if security.Combined.ClientAuth != tls.VerifyClientCertIfGiven {
			t.Fatalf("combined listener locks out the HTTP API: %v", security.Combined.ClientAuth)
		}
		if !security.RequireClientIdentity {
			t.Fatal("client identity requirement not reported to the listener")
		}
		if security.Combined.ClientCAs == nil || security.Direct.ClientCAs == nil {
			t.Fatal("verification roots missing")
		}
	})

	t.Run("negotiated protocols", func(t *testing.T) {
		security, err := LoadServerTLS(base)
		if err != nil {
			t.Fatalf("load: %v", err)
		}
		// The multiplexer reads cleartext framing, so the shared port must not
		// negotiate HTTP/2; the separate gRPC listener has to.
		if len(security.Combined.NextProtos) != 1 || security.Combined.NextProtos[0] != "http/1.1" {
			t.Fatalf("combined ALPN: %v", security.Combined.NextProtos)
		}
		if len(security.Direct.NextProtos) != 1 || security.Direct.NextProtos[0] != "h2" {
			t.Fatalf("direct ALPN: %v", security.Direct.NextProtos)
		}
		if security.Combined.MinVersion != tls.VersionTLS12 || security.Direct.MinVersion != tls.VersionTLS12 {
			t.Fatal("minimum version lowered")
		}
		if len(security.Combined.Certificates) != 1 || len(security.Direct.Certificates) != 1 {
			t.Fatal("listener presents no identity")
		}
	})

	t.Run("plaintext loads nothing", func(t *testing.T) {
		security, err := LoadServerTLS(TLSConfig{Disable: true, CertFile: "does/not/exist", KeyFile: "does/not/exist"})
		if err != nil || security != nil {
			t.Fatalf("plaintext listener: %+v %v", security, err)
		}
	})
}

// TestServerTLSStartupErrors keeps every unusable combination a startup failure
// that names the key to correct, instead of a downgraded or half-served
// listener.
func TestServerTLSStartupErrors(t *testing.T) {
	ca, dir := authority(t)
	server, err := ca.Issue("dispatcher", testtls.Options{Hosts: []string{"127.0.0.1"}, Server: true})
	if err != nil {
		t.Fatalf("issue server identity: %v", err)
	}
	other, err := ca.Issue("other", testtls.Options{Hosts: []string{"127.0.0.1"}, Server: true})
	if err != nil {
		t.Fatalf("issue second identity: %v", err)
	}
	expired, err := ca.Issue("expired", testtls.Options{
		Hosts:     []string{"127.0.0.1"},
		Server:    true,
		NotBefore: time.Now().Add(-48 * time.Hour),
		NotAfter:  time.Now().Add(-24 * time.Hour),
	})
	if err != nil {
		t.Fatalf("issue expired identity: %v", err)
	}
	stale, err := testtls.NewExpiredAuthority(t.TempDir(), "stale")
	if err != nil {
		t.Fatalf("create expired authority: %v", err)
	}
	empty := filepath.Join(dir, "empty.pem")
	if err := os.WriteFile(empty, []byte("not a certificate\n"), 0o600); err != nil {
		t.Fatalf("write empty authority: %v", err)
	}
	for _, tc := range []struct {
		name string
		cfg  TLSConfig
		want string
	}{
		{"missing certificate", TLSConfig{CertFile: filepath.Join(dir, "absent.crt"), KeyFile: server.KeyFile}, "tls.cert_file"},
		{"mismatched key", TLSConfig{CertFile: server.CertFile, KeyFile: other.KeyFile}, "tls.key_file"},
		{"expired certificate", TLSConfig{CertFile: expired.CertFile, KeyFile: expired.KeyFile}, "renew it before starting"},
		{"unreadable authority", TLSConfig{CertFile: server.CertFile, KeyFile: server.KeyFile, CAFile: filepath.Join(dir, "absent.crt")}, "tls.ca_file"},
		{"authority without a certificate", TLSConfig{CertFile: server.CertFile, KeyFile: server.KeyFile, CAFile: empty}, "holds no PEM certificate"},
		{"expired authority", TLSConfig{CertFile: server.CertFile, KeyFile: server.KeyFile, CAFile: stale.CertFile}, "authority \"stale\" is valid from"},
		{"required identity without an authority", TLSConfig{CertFile: server.CertFile, KeyFile: server.KeyFile, RequireClientCert: true}, "tls.require_client_cert needs tls.ca_file"},
		{"required identity without TLS", TLSConfig{Disable: true, RequireClientCert: true}, "tls.require_client_cert needs tls.disable = false"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			security, err := LoadServerTLS(tc.cfg)
			if err == nil || security != nil {
				t.Fatalf("accepted %s: %+v", tc.name, security)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q does not name %q", err, tc.want)
			}
		})
	}
	// A certificate that is not valid yet is refused for the same reason.
	future, err := ca.Issue("future", testtls.Options{
		Hosts:     []string{"127.0.0.1"},
		Server:    true,
		NotBefore: time.Now().Add(24 * time.Hour),
		NotAfter:  time.Now().Add(48 * time.Hour),
	})
	if err != nil {
		t.Fatalf("issue future identity: %v", err)
	}
	if _, err := LoadServerTLS(TLSConfig{CertFile: future.CertFile, KeyFile: future.KeyFile}); err == nil {
		t.Fatal("accepted a certificate that is not valid yet")
	}
}

// TestTLSConfigurationKeys keeps the configuration file the operator writes in
// step with what the listener does with it.
func TestTLSConfigurationKeys(t *testing.T) {
	database := "\n[database]\npath = '.data/dispatcher.db'\n"
	cfg, err := LoadConfig(writeConfig(t, "[tls]\ndisable = false\ncert_file = 'cert'\nkey_file = 'key'\nca_file = 'ca'\nrequire_client_cert = true\n"+database))
	if err != nil {
		t.Fatalf("mutual TLS configuration: %v", err)
	}
	if !cfg.TLS.RequireClientCert || cfg.TLS.CAFile != "ca" {
		t.Fatalf("TLS keys: %+v", cfg.TLS)
	}
	for _, tc := range []struct{ name, body, want string }{
		{"requirement without an authority", "[tls]\ndisable = false\ncert_file = 'cert'\nkey_file = 'key'\nrequire_client_cert = true\n" + database, "tls.require_client_cert needs tls.ca_file"},
		{"requirement without TLS", "[tls]\ndisable = true\nrequire_client_cert = true\n" + database, "tls.require_client_cert needs tls.disable = false"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := LoadConfig(writeConfig(t, tc.body)); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %v does not name %q", err, tc.want)
			}
		})
	}
}
