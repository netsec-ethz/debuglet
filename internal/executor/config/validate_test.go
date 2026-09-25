package config

import (
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The sections an executor configuration must set, kept separate so a test can
// leave exactly one of them out.
const (
	identitySection   = "[identity]\nexecutor_id='test'\n"
	dispatcherSection = "[dispatcher]\naddr='127.0.0.1:1'\n"
	resourcesSection  = "[resources]\ncapacity=1000000000\n"
	databaseSection   = "[database]\npath='.data/executor.db'\n"
	tlsSection        = "[tls]\ndisable=true\n"
)

// requiredSections carries the keys every executor configuration must set.
const requiredSections = identitySection + dispatcherSection + resourcesSection + databaseSection

// baseSections adds the disabled transport security the local fixtures use.
const baseSections = requiredSections + tlsSection

// writeExecutorConfig stores body as a TOML file in a per-test temporary
// directory and returns its path.
func writeExecutorConfig(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "executor.toml")
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return path
}

// load parses body without touching the host: an invalid configuration must be
// refused before the default network interface is looked up.
func load(t *testing.T, body string) (*ExecutorConfig, int, error) {
	t.Helper()
	calls := 0
	cfg, err := loadConfig(writeExecutorConfig(t, body), func() (*net.Interface, error) {
		calls++
		return &net.Interface{Name: "discovered"}, nil
	})
	return cfg, calls, err
}

// TestRejectsUnsupportedOrMalformedFields checks that a configuration file is
// refused with the name of the offending key, before interface discovery and
// well before the node opens storage or acquires its packet counter.
func TestRejectsUnsupportedOrMalformedFields(t *testing.T) {
	for _, tc := range []struct{ name, body, want string }{
		{"misspelled key", baseSections + "[network]\ninterfaces = 'eth0'\n", `unsupported configuration key "network.interfaces"`},
		{"unsupported table", baseSections + "[metrics]\nport = 1\n", `unsupported configuration key "metrics"`},
		{"missing executor id", dispatcherSection + resourcesSection + databaseSection + tlsSection, "identity.executor_id is required"},
		{"executor id with a space", "[identity]\nexecutor_id='local executor'\n" + dispatcherSection + resourcesSection + databaseSection + tlsSection, "identity.executor_id must not contain spaces"},
		{"missing dispatcher address", identitySection + resourcesSection + databaseSection + tlsSection, "dispatcher.addr is required"},
		{"dispatcher address without a port", identitySection + "[dispatcher]\naddr='127.0.0.1'\n" + resourcesSection + databaseSection + tlsSection, "dispatcher.addr must be a host:port address"},
		{"dispatcher port zero", identitySection + "[dispatcher]\naddr='127.0.0.1:0'\n" + resourcesSection + databaseSection + tlsSection, "dispatcher.addr must use a port between 1 and 65535"},
		{"malformed yamux address", identitySection + "[dispatcher]\naddr='127.0.0.1:1'\nyamux_addr='127.0.0.1:70000'\n" + resourcesSection + databaseSection + tlsSection, "dispatcher.yamux_addr"},
		{"missing capacity", identitySection + dispatcherSection + databaseSection + tlsSection, "resources.capacity is required and must be positive"},
		{"negative capacity", identitySection + dispatcherSection + "[resources]\ncapacity=-1\n" + databaseSection + tlsSection, "resources.capacity is required and must be positive"},
		{"explicit zero debuglets", identitySection + dispatcherSection + "[resources]\ncapacity=1000\nmax_debuglets=0\n" + databaseSection + tlsSection, "resources.max_debuglets must be positive"},
		{"negative debuglets", identitySection + dispatcherSection + "[resources]\ncapacity=1000\nmax_debuglets=-4\n" + databaseSection + tlsSection, "resources.max_debuglets must be positive"},
		{"missing database path", identitySection + dispatcherSection + resourcesSection + tlsSection, "database.path is required"},
		{"negative TESLA delay", baseSections + "[tesla]\ndelay=-1\n", "tesla.delay must not be negative"},
		{"TESLA delay overflow", baseSections + "[tesla]\ndelay=9223372036854775807\n", "tesla.delay must be at most"},
		{"negative chain length", baseSections + "[tesla]\nchain_length=-1\n", "tesla.chain_length must be between"},
		{"chain length beyond the horizon", baseSections + "[tesla]\nchain_length=604801\n", "tesla.chain_length must be between"},
		{"unknown packet counter", baseSections + "[network]\npacket_counter='ebpf'\n", "network.packet_counter"},
		{"interface name too long", baseSections + "[network]\ninterface='deliberately-nonexistent-interface'\n", "network.interface"},
		{"malformed public host", baseSections + "[network]\npublic_host='not a host'\npublic_ports='2022'\n", "network.public_host"},
		{"reversed port range", baseSections + "[network]\npublic_host='203.0.113.10'\npublic_ports='3005-2025'\n", "network.public_ports"},
		{"unknown log level", baseSections + "[logging]\nlog_level='chatty'\n", "logging.log_level must be debug"},
		{"empty log level", baseSections + "[logging]\nlog_level=''\n", "logging.log_level must not be empty"},
		{"negative price", baseSections + "[pricing]\nprice_per_bw_s=-1\n", "pricing.price_per_bw_s must not be negative"},
		{"negative trial time", baseSections + "[pricing]\ntrial_time_limit=-1\n", "pricing.trial_time_limit must not be negative"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, calls, err := load(t, tc.body)
			if err == nil || cfg != nil {
				t.Fatalf("accepted %s: %+v", tc.name, cfg)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q does not name the field %q", err, tc.want)
			}
			if calls != 0 {
				t.Fatalf("interface discovery ran before validation (%d calls)", calls)
			}
		})
	}
}

// TestOmittedKeysKeepDocumentedDefaults separates an omitted key, which keeps
// its documented default, from an explicit value that is out of range.
func TestOmittedKeysKeepDocumentedDefaults(t *testing.T) {
	cfg, _, err := load(t, baseSections+"[network]\npacket_counter='fallback'\n")
	if err != nil {
		t.Fatalf("minimal configuration: %v", err)
	}
	if cfg.Resources.MaxDebuglets != DefaultMaxDebuglets || cfg.Logging.LogLevel != DefaultLogLevel {
		t.Fatalf("defaults changed: %+v", cfg)
	}
	if cfg.Dispatcher.YamuxAddr != cfg.Dispatcher.Addr {
		t.Fatalf("yamux default: %+v", cfg.Dispatcher)
	}
	// Zero keeps the derived chain length; it is not a missing value.
	if cfg.Tesla.ChainLength != 0 || cfg.Tesla.Delay != 0 {
		t.Fatalf("TESLA defaults: %+v", cfg.Tesla)
	}
}

// TestCredentialsRequiredWhenTLSEnabled makes an enabled transport name its
// client material. Whether those files exist depends on the machine, so node
// construction reads them; a deployment configuration still loads anywhere.
func TestCredentialsRequiredWhenTLSEnabled(t *testing.T) {
	for _, tc := range []struct{ name, body, want string }{
		{"credentials omitted", requiredSections + "[tls]\ndisable=false\n", "credentials.client_cert is required"},
		{"key omitted", requiredSections + "[tls]\ndisable=false\n[credentials]\nclient_cert='client.crt'\n", "credentials.client_key is required"},
		{"token without a certificate", requiredSections + "[tls]\ndisable=false\n[credentials]\nenrollment_token='dbx_selector.verifier'\n", "credentials.enrollment_token needs credentials.client_cert"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, err := load(t, tc.body); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %v does not name %q", err, tc.want)
			}
		})
	}
	deployed := requiredSections + "[tls]\ndisable=false\n[credentials]\nca_cert='/etc/debuglet/certs/ca.crt'\n" +
		"client_cert='/etc/debuglet/certs/client.crt'\nclient_key='/etc/debuglet/certs/client.key'\n"
	cfg, _, err := load(t, deployed)
	if err != nil {
		t.Fatalf("deployment credentials: %v", err)
	}
	if cfg.Credentials.ClientKey != "/etc/debuglet/certs/client.key" {
		t.Fatalf("credentials: %+v", cfg.Credentials)
	}
	// A disabled transport keeps unused paths as they are, and reads none.
	if _, _, err := load(t, baseSections+"[credentials]\nclient_cert='does/not/exist'\n"); err != nil {
		t.Fatalf("disabled TLS with unused paths: %v", err)
	}
}

// TestRepositoryConfigurationLoads keeps every checked-in executor
// configuration loadable, wherever it is read from.
func TestRepositoryConfigurationLoads(t *testing.T) {
	root := filepath.Join("..", "..", "..")
	paths := []string{
		filepath.Join(root, "local", "configs", "executor", "executor.toml"),
		filepath.Join(root, "deploy", "docker", "configs", "executor", "executor.toml"),
	}
	for _, path := range paths {
		t.Run(filepath.ToSlash(path), func(t *testing.T) {
			cfg, err := loadConfig(path, func() (*net.Interface, error) { return &net.Interface{Name: "discovered"}, nil })
			if err != nil {
				t.Fatalf("checked-in configuration: %v", err)
			}
			if cfg.Identity.ExecutorID == "" || cfg.Resources.Capacity != 1_000_000_000 || cfg.Database.Path == "" {
				t.Fatalf("unexpected values: %+v", cfg)
			}
		})
	}
	assertAllConfigurationsCovered(t, root, "executor.toml", paths)
}

// assertAllConfigurationsCovered fails when the repository gains a daemon
// configuration file that no test loads.
func assertAllConfigurationsCovered(t *testing.T, root, name string, covered []string) {
	t.Helper()
	expected := make(map[string]struct{}, len(covered))
	for _, path := range covered {
		expected[filepath.ToSlash(filepath.Clean(path))] = struct{}{}
	}
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			if path != root && strings.HasPrefix(entry.Name(), ".") {
				return fs.SkipDir
			}
			return nil
		}
		if entry.Name() != name {
			return nil
		}
		clean := filepath.ToSlash(filepath.Clean(path))
		if _, ok := expected[clean]; !ok {
			t.Errorf("checked-in configuration %s is not loaded by any test", clean)
		}
		delete(expected, clean)
		return nil
	})
	if err != nil {
		t.Fatalf("walk repository: %v", err)
	}
	for path := range expected {
		t.Errorf("listed configuration %s does not exist", path)
	}
}
