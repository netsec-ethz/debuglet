package config

import (
	"strings"
	"testing"
)

// remoteSections points the executor at a dispatcher that is not on this
// machine, which is the configuration a plaintext control transport must not
// keep serving.
const remoteSections = identitySection + "[dispatcher]\naddr='dispatcher.example.org:9001'\nyamux_addr='dispatcher.example.org:9000'\n" +
	resourcesSection + databaseSection

// deployedCredentials is the client material a verified transport needs.
const deployedCredentials = "[credentials]\nca_cert='/etc/debuglet/executor/ca.crt'\nclient_cert='/etc/debuglet/executor/client.crt'\nclient_key='/etc/debuglet/executor/client.key'\n"

// TestPlaintextTransportStaysLocal keeps the cleartext control transport inside
// the profile that documents it. Off this machine it would hand the control
// session token, every uploaded module and every guest output to anyone on the
// path, so the configuration is refused instead of quietly downgraded.
func TestPlaintextTransportStaysLocal(t *testing.T) {
	_, _, err := load(t, remoteSections+"[tls]\ndisable=true\n")
	if err == nil || !strings.Contains(err.Error(), "dispatcher.addr") ||
		!strings.Contains(err.Error(), "tls.disable = true is supported only for a dispatcher reached at a loopback IP address") {
		t.Fatalf("remote plaintext endpoint: %v", err)
	}
	// The same endpoint is accepted once the transport is verified.
	if _, _, err := load(t, remoteSections+"[tls]\ndisable=false\n"+deployedCredentials); err != nil {
		t.Fatalf("remote verified endpoint: %v", err)
	}
	// Only the reverse endpoint being remote is refused too, naming it.
	body := identitySection + "[dispatcher]\naddr='127.0.0.1:9001'\nyamux_addr='dispatcher.example.org:9000'\n" + resourcesSection + databaseSection + "[tls]\ndisable=true\n"
	if _, _, err := load(t, body); err == nil || !strings.Contains(err.Error(), "dispatcher.yamux_addr") {
		t.Fatalf("remote reverse endpoint: %v", err)
	}
	for _, local := range []string{"127.0.0.1:9001", "[::1]:9001", "127.0.0.2:9001"} {
		t.Run(local, func(t *testing.T) {
			body := identitySection + "[dispatcher]\naddr='" + local + "'\n" + resourcesSection + databaseSection + "[tls]\ndisable=true\n"
			if _, _, err := load(t, body); err != nil {
				t.Fatalf("local plaintext profile: %v", err)
			}
		})
	}
	// A name is refused even when it usually resolves to a loopback address:
	// nothing here resolves it, and the SDK draws the same line for its own
	// cleartext endpoints.
	for _, named := range []string{"localhost:9001", "dispatcher.localhost:9001"} {
		t.Run(named, func(t *testing.T) {
			body := identitySection + "[dispatcher]\naddr='" + named + "'\n" + resourcesSection + databaseSection + "[tls]\ndisable=true\n"
			if _, _, err := load(t, body); err == nil || !strings.Contains(err.Error(), "loopback IP address") {
				t.Fatalf("named plaintext endpoint: %v", err)
			}
		})
	}
}

// TestVerifiedNameConfiguration checks the key that names the dispatcher
// certificate to verify when the dialled address is not that name.
func TestVerifiedNameConfiguration(t *testing.T) {
	cfg, _, err := load(t, remoteSections+"[tls]\ndisable=false\nserver_name='dispatcher.example.org'\n"+deployedCredentials)
	if err != nil {
		t.Fatalf("verified name: %v", err)
	}
	if cfg.TLS.ServerName != "dispatcher.example.org" {
		t.Fatalf("server name: %+v", cfg.TLS)
	}
	for _, tc := range []struct{ name, body, want string }{
		{"without TLS", requiredSections + "[tls]\ndisable=true\nserver_name='dispatcher.example.org'\n", "tls.server_name"},
		{"malformed", remoteSections + "[tls]\ndisable=false\nserver_name='not a host'\n" + deployedCredentials, "tls.server_name must be an IP address or a DNS name"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, err := load(t, tc.body); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %v does not name %q", err, tc.want)
			}
		})
	}
}

// TestAuthorityOptional keeps an omitted credentials.ca_cert meaning the host's
// trust store rather than an unverified transport.
func TestAuthorityOptional(t *testing.T) {
	cfg, _, err := load(t, remoteSections+"[tls]\ndisable=false\n[credentials]\nclient_cert='client.crt'\nclient_key='client.key'\n")
	if err != nil {
		t.Fatalf("host trust store: %v", err)
	}
	if cfg.Credentials.CACert != "" || cfg.TLS.Disable {
		t.Fatalf("credentials: %+v %+v", cfg.Credentials, cfg.TLS)
	}
}
