//go:build linux

package demo

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/netsec-ethz/debuglet/internal/connections"
	"github.com/pelletier/go-toml/v2"
)

func TestRoleIndependentLifecycle(t *testing.T) {
	for _, role := range []SchemaRole{DispatcherSchema, ExecutorSchema} {
		t.Run(string(role), func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "service")
			var identity string
			for attempt := 0; attempt < 2; attempt++ {
				f := newSupervisorFixture(t, "success")
				f.dir = dir
				f.server.Close()
				var metadataReads atomic.Int64
				f.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.URL.Path == "/connection" {
						metadataReads.Add(1)
						json.NewEncoder(w).Encode(map[string]any{"schema_version": 1, "mode": "local-test", "grpc_address": strings.TrimPrefix(f.server.URL, "http://"), "yamux_address": strings.TrimPrefix(f.server.URL, "http://")})
						return
					}
					f.serve(w, r)
				}))
				t.Cleanup(f.server.Close)
				bootstrap := f.deps.bootstrap
				calls := 0
				f.deps.bootstrap = func(ctx context.Context, got SchemaRole, path string) error {
					calls++
					if got != role {
						t.Errorf("started another role database: %s", got)
					}
					return bootstrap(ctx, got, path)
				}
				start := f.deps.startChild
				f.deps.startChild = func(spec ChildSpec) (childProcess, error) {
					if role == ExecutorSchema {
						data, err := os.ReadFile(spec.Args[1])
						if err != nil {
							return nil, err
						}
						var config map[string]map[string]any
						if err := toml.Unmarshal(data, &config); err != nil {
							return nil, err
						}
						if config["tesla"]["chain_length"] != int64(0) || config["dispatcher"]["addr"] != strings.TrimPrefix(f.server.URL, "http://") {
							t.Errorf("executor did not use refreshed metadata and derived horizon: %+v", config)
						}
					}
					return start(spec)
				}
				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				readyCalls := 0
				err := upRole(ctx, role, f.assets, RoleOptions{Name: "service", StateDir: dir,
					Dispatcher: connections.Profile{Endpoint: f.server.URL, GRPCAddress: "obsolete:1", YamuxAddress: "obsolete:2"},
					Ready: func(record RoleEnvironment) error {
						readyCalls++
						if record.State != "ready" || record.Role != string(role) || record.Name != "service" || record.Endpoint != f.server.URL {
							t.Errorf("incorrect role readiness: %+v", record)
						}
						data, err := os.ReadFile(filepath.Join(dir, "ready.json"))
						var saved RoleEnvironment
						if err != nil || json.Unmarshal(data, &saved) != nil || saved != record {
							t.Error("persisted readiness does not match stdout record")
						}
						if role == ExecutorSchema {
							if attempt == 0 {
								identity = record.ExecutorID
							} else if identity == "" || identity != record.ExecutorID {
								t.Error("executor restart changed identity")
							}
						}
						cancel()
						return nil
					}}, f.deps, 2*time.Second)
				cancel()
				if err != nil || readyCalls != 1 || len(f.children) != 1 || !f.children[0].CleanupComplete() {
					t.Fatalf("role lifecycle: ready=%d children=%d err=%v", readyCalls, len(f.children), err)
				}
				if calls != 1-attempt || (role == ExecutorSchema && metadataReads.Load() != 1) {
					t.Fatalf("bootstrap=%d metadata=%d", calls, metadataReads.Load())
				}
				if _, err := os.Stat(filepath.Join(dir, "ready.json")); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("stale ready record: %v", err)
				}
				if _, err := os.Stat(filepath.Join(dir, string(role)+".sqlite")); err != nil {
					t.Fatalf("lost role database: %v", err)
				}
			}
		})
	}
}

func TestRoleStateIdentityKey(t *testing.T) {
	manifest := Manifest{Version: "v1", SourceSHA: strings.Repeat("a", 40)}
	identity := func(state RoleState) string { return state.Identity }
	dir := t.TempDir()
	first, err := readRoleState(dir, DispatcherSchema, manifest)
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(dir, "role-state.json"))
	if err != nil {
		t.Fatal(err)
	}
	var stored map[string]any
	if err := json.Unmarshal(data, &stored); err != nil {
		t.Fatal(err)
	}
	if _, ok := stored["executor_id"]; ok || stored["identity"] != identity(first) || !canonicalUUID(identity(first)) {
		t.Fatalf("state file keys: %s", data)
	}
	again, err := readRoleState(dir, DispatcherSchema, manifest)
	if err != nil || identity(again) != identity(first) {
		t.Fatalf("second read: %q %v, want %q", identity(again), err, identity(first))
	}
	const earlier, current = "0b7c4d1e-2f3a-4b5c-8d6e-7f8091a2b3c4", "1c8d5e2f-3a4b-4c6d-9e7f-8091a2b3c4d5"
	write := func(role SchemaRole, keys string) string {
		dir := t.TempDir()
		content := `{"schema_version":1,"version":"v1","source_sha":"` + manifest.SourceSHA + `","role":"` + string(role) + `",` + keys + `}`
		if err := os.WriteFile(filepath.Join(dir, "role-state.json"), []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
		return dir
	}
	for _, role := range []SchemaRole{DispatcherSchema, ExecutorSchema} {
		state, err := readRoleState(write(role, `"executor_id":"`+earlier+`"`), role, manifest)
		if err != nil || identity(state) != earlier {
			t.Fatalf("%s earlier state: %q %v", role, identity(state), err)
		}
		state, err = readRoleState(write(role, `"executor_id":"`+earlier+`","identity":"`+current+`"`), role, manifest)
		if err != nil || identity(state) != current {
			t.Fatalf("%s state with both keys: %q %v", role, identity(state), err)
		}
		if _, err := readRoleState(write(role, `"executor_id":"not-a-uuid"`), role, manifest); err == nil {
			t.Fatalf("%s accepted an invalid earlier identity", role)
		}
		if _, err := readRoleState(write(role, `"executor_id":"`+earlier+`","identity":"not-a-uuid"`), role, manifest); err == nil {
			t.Fatalf("%s fell back from an invalid identity to the earlier key", role)
		}
	}
}

func canonicalUUID(value string) bool {
	id, err := uuid.Parse(value)
	return err == nil && id != uuid.Nil && id.String() == value
}

func TestRoleRejectsUnmanagedOrRemoteState(t *testing.T) {
	dir := t.TempDir()
	manifest := Manifest{Version: "v1", SourceSHA: strings.Repeat("a", 40)}
	if _, err := readRoleState(dir, DispatcherSchema, manifest); err != nil {
		t.Fatal(err)
	}
	if _, err := readRoleState(dir, ExecutorSchema, manifest); err == nil {
		t.Fatal("executor reused dispatcher role state")
	}
	manifest.SourceSHA = strings.Repeat("b", 40)
	if _, err := readRoleState(dir, DispatcherSchema, manifest); err == nil {
		t.Fatal("different build silently adopted role database metadata")
	}
	for _, endpoint := range []string{"https://example.com", "http://localhost:9000", "http://192.0.2.1:9000"} {
		if err := validateRoleEndpoint(endpoint); err == nil {
			t.Fatalf("remote/nonliteral generated executor endpoint accepted: %s", endpoint)
		}
	}
}
