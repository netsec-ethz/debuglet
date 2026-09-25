package main

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/netsec-ethz/debuglet/internal/connections"
	"github.com/netsec-ethz/debuglet/pkg/client"
)

func TestClientConnectionCommands(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	config := filepath.Join(t.TempDir(), "client", "config.json")
	mux := http.NewServeMux()
	mux.HandleFunc("GET /version", func(w http.ResponseWriter, r *http.Request) {
		writeJSONResponse(w, 200, client.ServerVersion{Version: "fixture"})
	})
	mux.HandleFunc("GET /connection", func(w http.ResponseWriter, r *http.Request) {
		writeJSONResponse(w, 200, client.ConnectionInfo{SchemaVersion: 1, Mode: "local-test", GRPCAddress: "127.0.0.1:9001", YamuxAddress: "127.0.0.1:9000"})
	})
	mux.HandleFunc("GET /executors", func(w http.ResponseWriter, r *http.Request) {
		writeJSONResponse(w, 200, []client.Node{{ID: fixExecutor, Ready: true}})
	})
	mux.HandleFunc("PUT /payment/intent", intentOK)
	mux.HandleFunc("PUT /debuglet", submitOK)
	fx := newFixture(t, mux)
	invoke := func(args ...string) (int, string, string) {
		return runCLI(ctx, append([]string{"--config", config, "--output", "json"}, args...)...)
	}
	code, out, errout := invoke("connect", fx.endpoint(), "--name", "saved")
	assertCode(t, code, exitOK, out, errout)
	var profile connections.Profile
	if err := json.Unmarshal([]byte(out), &profile); err != nil || profile.Name != "saved" || profile.Endpoint != fx.endpoint() || profile.GRPCAddress != "127.0.0.1:9001" {
		t.Fatalf("connect record: %+v %v", profile, err)
	}
	if fx.count("GET", "/version") != 1 || fx.count("GET", "/connection") != 1 {
		t.Fatal("connect did not validate version and metadata exactly once")
	}
	before := fx.total()
	for _, args := range [][]string{{"dispatcher", "list"}, {"dispatchers"}} {
		code, out, errout = invoke(args...)
		assertCode(t, code, exitOK, out, errout)
		var cfg connections.Config
		if err := json.Unmarshal([]byte(out), &cfg); err != nil || cfg.Current != "saved" || len(cfg.Dispatchers) != 1 {
			t.Fatalf("saved list: %+v %v", cfg, err)
		}
	}
	if fx.total() != before {
		t.Fatal("listing saved connections probed a server")
	}
	for _, args := range [][]string{{"executor", "list"}, {"executors"}, {"nodes"}} {
		code, out, errout = invoke(args...)
		assertCode(t, code, exitOK, out, errout)
		if !strings.Contains(out, fixExecutor) {
			t.Fatalf("selected dispatcher not queried: %s", out)
		}
	}
	code, out, errout = invoke("run", "--wasm", wasmFile(t))
	assertCode(t, code, exitOK, out, errout)
	if oneJSONDocument(t, out)["executor_id"] != fixExecutor {
		t.Fatal("implicit auto executor was not used")
	}
	if err := connections.Save(config, connections.Profile{Name: "other", Endpoint: "http://127.0.0.1:1"}, false); err != nil {
		t.Fatal(err)
	}
	code, out, errout = invoke("dispatcher", "use", "other")
	assertCode(t, code, exitOK, out, errout)
	if p, err := connections.Resolve(config, ""); err != nil || p.Name != "other" {
		t.Fatalf("use: %+v %v", p, err)
	}
	code, out, errout = invoke("--dispatcher", "saved", "executor", "list")
	assertCode(t, code, exitOK, out, errout)
	code, out, errout = invoke("dispatcher", "remove", "other")
	assertCode(t, code, exitOK, out, errout)
	if cfg, err := connections.Load(config); err != nil || cfg.Current != "" || len(cfg.Dispatchers) != 1 {
		t.Fatalf("remove: %+v %v", cfg, err)
	}
	entries, err := os.ReadDir(filepath.Dir(config))
	if err != nil || len(entries) != 1 || entries[0].Name() != "config.json" {
		t.Fatalf("client command created daemon state: %v %v", entries, err)
	}
}

func TestConnectLegacyAndInvalidMetadata(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		body   any
		want   int
	}{
		{"legacy", 404, map[string]string{"message": "not found"}, exitOK},
		{"malformed", 200, client.ConnectionInfo{SchemaVersion: 1, Mode: "local-test", GRPCAddress: "remote.example:9001", YamuxAddress: "127.0.0.1:9000"}, exitFailure},
		{"refused", 403, map[string]string{"message": "refused"}, exitFailure},
	} {
		t.Run(tc.name, func(t *testing.T) {
			config := filepath.Join(t.TempDir(), "config.json")
			fx := newFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/version" {
					writeJSONResponse(w, 200, client.ServerVersion{Version: "legacy"})
					return
				}
				writeJSONResponse(w, tc.status, tc.body)
			}))
			code, out, errout := runCLI(context.Background(), "--config", config, "--output", "json", "connect", fx.endpoint())
			assertCode(t, code, tc.want, out, errout)
			if tc.want == exitOK {
				p, err := connections.Resolve(config, "")
				if err != nil || p.Endpoint != fx.endpoint() || p.GRPCAddress != "" || p.YamuxAddress != "" {
					t.Fatalf("legacy profile: %+v %v", p, err)
				}
			} else if _, err := os.Stat(config); !os.IsNotExist(err) {
				t.Fatalf("failed connect saved a profile: %v", err)
			}
		})
	}
}

func TestEndpointOverridesSavedConfiguration(t *testing.T) {
	config := filepath.Join(t.TempDir(), "invalid.json")
	if err := os.WriteFile(config, []byte("invalid config"), 0600); err != nil {
		t.Fatal(err)
	}
	fx := newFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { writeJSONResponse(w, 200, []client.Node{}) }))
	code, out, errout := runCLI(context.Background(), "--config", config, "--endpoint", fx.endpoint(), "nodes")
	assertCode(t, code, exitOK, out, errout)
	code, out, errout = runCLI(context.Background(), "--config", config, "version")
	assertCode(t, code, exitOK, out, errout)
	// The other contradictory and blank selections are in the usage-error table
	// of TestCLICommands; a rejected connection name must also reach no server.
	before := fx.total()
	code, out, errout = runCLI(context.Background(), "connect", fx.endpoint(), "--name", "../invalid")
	assertCode(t, code, exitUsage, out, errout)
	if fx.total() != before {
		t.Fatal("an invalid connection name probed the server")
	}
}

// TestCommandsWithAnExplicitEndpointNeedNoConfigurationDirectory covers an
// environment with neither $XDG_CONFIG_HOME nor $HOME, which is what the
// installed acceptance run gives the CLI. A command that names its endpoint
// selects no saved connection, so neither the profile file nor the credential
// file may be located: locating them fails there, and these commands worked
// before saved connections carried credentials at all.
func TestCommandsWithAnExplicitEndpointNeedNoConfigurationDirectory(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	mux := http.NewServeMux()
	mux.HandleFunc("GET /version", func(w http.ResponseWriter, r *http.Request) {
		writeJSONResponse(w, 200, client.ServerVersion{Version: "fixture"})
	})
	mux.HandleFunc("GET /executors", func(w http.ResponseWriter, r *http.Request) {
		writeJSONResponse(w, 200, []client.Node{{ID: fixExecutor, Ready: true}})
	})
	fx := newFixture(t, mux)

	// An unlocatable configuration directory on either platform: Linux needs
	// one of the two variables, macOS needs HOME.
	t.Setenv("XDG_CONFIG_HOME", "")
	t.Setenv("HOME", "")
	if _, err := os.UserConfigDir(); err == nil {
		t.Skip("this platform locates a configuration directory without HOME")
	}

	for _, args := range [][]string{
		{"version", "--server"},
		{"nodes"},
		{"executor", "list"},
	} {
		code, out, errout := runCLI(ctx, append([]string{"--endpoint", fx.endpoint(), "--output", "json"}, args...)...)
		assertCode(t, code, exitOK, out, errout)
		if strings.Contains(errout, "client configuration") {
			t.Fatalf("dbl %v located the client configuration: %s", args, errout)
		}
	}

	// A command that does select a saved connection still reports the missing
	// directory, rather than silently continuing without the credential it
	// was supposed to present.
	code, out, errout := runCLI(ctx, "--dispatcher", "saved", "nodes")
	if code == exitOK {
		t.Fatalf("a saved connection resolved without a configuration directory: %s %s", out, errout)
	}
}
