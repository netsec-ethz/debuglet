package config

import (
	"io/fs"
	"path/filepath"
	"strings"
	"testing"
)

// TestRejectsUnsupportedOrMalformedFields checks that a configuration file is
// refused with the name of the offending key, before the command opens the
// database or binds a listener.
func TestRejectsUnsupportedOrMalformedFields(t *testing.T) {
	for _, tc := range []struct{ name, body, want string }{
		{"misspelled key", "[server]\nbind_hosts = '127.0.0.1'\n", `unsupported configuration key "server.bind_hosts"`},
		{"unsupported table", "[metrics]\nport = 1\n", `unsupported configuration key "metrics"`},
		{"misspelled table", "[scheduling]\nexecutor_timeout = 30\n", `unsupported configuration key "scheduling"`},
		{"bind host", "[server]\nbind_host = 'not a host'\n", "server.bind_host"},
		{"http port above range", "[server]\nhttp_port = 70000\n", "server.http_port must be between 0 and 65535"},
		{"negative grpc port", "[server]\ngrpc_port = -1\n", "server.grpc_port must be between 0 and 65535"},
		{"same port twice", "[server]\nhttp_port = 9000\ngrpc_port = 9000\n", "must differ"},
		{"empty version", "[server]\nversion = ''\n", "server.version must not be empty"},
		{"unknown log level", "[logging]\nlog_level = 'chatty'\n", "logging.log_level must be debug"},
		{"empty log level", "[logging]\nlog_level = ''\n", "logging.log_level must not be empty"},
		{"negative granularity", "[scheduler]\nscheduler_granularity_ms = -1\n", "scheduler.scheduler_granularity_ms must not be negative"},
		{"granularity overflow", "[scheduler]\nscheduler_granularity_ms = 9223372036854775807\n", "scheduler.scheduler_granularity_ms must be at most"},
		{"wildcard origin", "[cors]\nallowed_origins = ['*']\n", "cors.allowed_origins[0]"},
		{"origin with path", "[cors]\nallowed_origins = ['https://example.org/app']\n", "without a path"},
		{"origin without scheme", "[cors]\nallowed_origins = ['example.org']\n", "cors.allowed_origins[0]"},
		{"OAuth callback without TLS", "[github_oauth]\nenabled = true\ncallback_url = 'http://example.org/api/auth/github/callback'\nsuccess_url = 'https://example.org/console/'\n", "github_oauth.callback_url"},
		{"OAuth success with credentials", "[github_oauth]\nenabled = true\ncallback_url = 'https://example.org/api/auth/github/callback'\nsuccess_url = 'https://user:secret@example.org/console/'\n", "github_oauth.success_url"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := LoadConfig(writeConfig(t, baseSections+tc.body))
			if err == nil || cfg != nil {
				t.Fatalf("accepted %s: %+v", tc.name, cfg)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q does not name the field %q", err, tc.want)
			}
		})
	}
}

// TestMissingDatabasePath keeps the daemon from opening an unnamed temporary
// database when the path is not configured.
func TestMissingDatabasePath(t *testing.T) {
	_, err := LoadConfig(writeConfig(t, "[tls]\ndisable = true\n[server]\nhttp_port = 0\ngrpc_port = 0\n"))
	if err == nil || !strings.Contains(err.Error(), "database.path is required") {
		t.Fatalf("missing database path: %v", err)
	}
}

// TestOmittedKeysKeepDocumentedDefaults separates an omitted key, which keeps
// its documented default, from an explicit value that is out of range.
func TestOmittedKeysKeepDocumentedDefaults(t *testing.T) {
	cfg, err := LoadConfig(writeConfig(t, baseSections))
	if err != nil {
		t.Fatalf("minimal configuration: %v", err)
	}
	if cfg.Scheduler.ExecutorTimeout != DefaultExecutorTimeout || cfg.Logging.LogLevel != DefaultLogLevel || cfg.Server.Version != DefaultVersion {
		t.Fatalf("defaults changed: %+v", cfg)
	}
	// Port zero is an explicitly supported value, not a missing one.
	if cfg.Server.HTTPPort != 0 || cfg.Server.GRPCPort != 0 {
		t.Fatalf("ports: %+v", cfg.Server)
	}
	if cfg.Scheduler.SchedulerGranularityMs != 0 {
		t.Fatalf("granularity: %+v", cfg.Scheduler)
	}
}

// TestExplicitPortZeroFixtures keeps the local fixtures that ask the operating
// system for an unused port for both listeners.
func TestExplicitPortZeroFixtures(t *testing.T) {
	cfg, err := LoadConfig(writeConfig(t, baseSections+"[server]\nbind_host = '127.0.0.1'\nhttp_port = 0\ngrpc_port = 0\n"))
	if err != nil || cfg.Server.HTTPPort != 0 || cfg.Server.GRPCPort != 0 {
		t.Fatalf("port-zero fixture: %+v %v", cfg, err)
	}
}

// TestTLSCertificatesRequiredWhenEnabled makes an enabled listener name its
// certificate files. Whether those files exist depends on the machine the
// daemon runs on, so the command checks that before it binds anything.
func TestTLSCertificatesRequiredWhenEnabled(t *testing.T) {
	database := "\n[database]\npath = '.data/dispatcher.db'\n"
	for _, tc := range []struct{ name, body, want string }{
		{"section omitted", database, "tls.cert_file is required"},
		{"certificate omitted", "[tls]\ndisable = false\nkey_file = 'key'\n" + database, "tls.cert_file is required"},
		{"key omitted", "[tls]\ndisable = false\ncert_file = 'cert'\n" + database, "tls.key_file is required"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := LoadConfig(writeConfig(t, tc.body)); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %v does not name %q", err, tc.want)
			}
		})
	}
	cfg, err := LoadConfig(writeConfig(t, "[tls]\ndisable = false\ncert_file = 'cert'\nkey_file = 'key'\nca_file = 'ca'\n"+database))
	if err != nil {
		t.Fatalf("complete TLS configuration: %v", err)
	}
	files := cfg.TLSFiles()
	if len(files) != 3 || files[0].Field != "tls.cert_file" || files[2].Path != "ca" {
		t.Fatalf("TLS files: %+v", files)
	}
	// A disabled listener keeps unused paths as they are, and reads none.
	cfg, err = LoadConfig(writeConfig(t, "[tls]\ndisable = true\ncert_file = 'does/not/exist'\nkey_file = 'does/not/exist'\n"+database))
	if err != nil {
		t.Fatalf("disabled TLS with unused paths: %v", err)
	}
	if files := cfg.TLSFiles(); files != nil {
		t.Fatalf("disabled TLS still reads %+v", files)
	}
}

// TestRepositoryConfigurationLoads keeps every checked-in dispatcher
// configuration loadable, wherever it is read from.
func TestRepositoryConfigurationLoads(t *testing.T) {
	root := filepath.Join("..", "..", "..")
	paths := []string{
		filepath.Join(root, "local", "configs", "dispatcher", "dispatcher.toml"),
		filepath.Join(root, "deploy", "docker", "configs", "dispatcher", "dispatcher.toml"),
	}
	for _, path := range paths {
		t.Run(filepath.ToSlash(path), func(t *testing.T) {
			cfg, err := LoadConfig(path)
			if err != nil {
				t.Fatalf("checked-in configuration: %v", err)
			}
			if cfg.Server.HTTPPort != 9000 || cfg.Server.GRPCPort != 9001 ||
				cfg.Scheduler.ExecutorTimeout != 60 || cfg.Database.Path == "" {
				t.Fatalf("unexpected values: %+v", cfg)
			}
		})
	}
	assertAllConfigurationsCovered(t, root, "dispatcher.toml", paths)
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

// TestAcceptedOrigins keeps the documented credentialed-origin lists working.
func TestAcceptedOrigins(t *testing.T) {
	body := baseSections + "[cors]\nallowed_origins = ['https://debuglet.example.org', 'http://127.0.0.1:9000']\n"
	cfg, err := LoadConfig(writeConfig(t, body))
	if err != nil || len(cfg.CORS.AllowedOrigins) != 2 {
		t.Fatalf("origins: %+v %v", cfg, err)
	}
}
