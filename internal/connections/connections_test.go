package connections

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func TestSavedConnections(t *testing.T) {
	path := filepath.Join(t.TempDir(), "client", "config.json")
	cfg, err := Load(path)
	if err != nil || cfg.SchemaVersion != 1 || cfg.Current != "" || len(cfg.Dispatchers) != 0 || cfg.Dispatchers == nil {
		t.Fatalf("missing configuration: %+v %v", cfg, err)
	}
	first := Profile{Name: "first", Endpoint: "http://127.0.0.1:9000/api", GRPCAddress: "127.0.0.1:9001", YamuxAddress: "127.0.0.1:9000"}
	second := Profile{Name: "second", Endpoint: "http://127.0.0.1:9100"}
	for _, p := range []Profile{first, second} {
		if err := Save(path, p, false); err != nil {
			t.Fatal(err)
		}
	}
	if p, err := Resolve(path, ""); err != nil || p != first {
		t.Fatalf("save changed selected first profile: %+v %v", p, err)
	}
	if err := Select(path, second.Name); err != nil {
		t.Fatal(err)
	}
	if p, err := Resolve(path, ""); err != nil || p != second {
		t.Fatalf("select: %+v %v", p, err)
	}
	first.Endpoint = "http://127.0.0.1:9200"
	if err := Save(path, first, true); err != nil {
		t.Fatal(err)
	}
	cfg, err = Load(path)
	if err != nil || cfg.Current != "first" || !reflect.DeepEqual(cfg.Dispatchers, []Profile{first, second}) {
		t.Fatalf("explicit overwrite/select: %+v %v", cfg, err)
	}
	if err := Remove(path, first.Name); err != nil {
		t.Fatal(err)
	}
	cfg, err = Load(path)
	if err != nil || cfg.Current != "" || !reflect.DeepEqual(cfg.Dispatchers, []Profile{second}) {
		t.Fatalf("remove should not silently select a different endpoint: %+v %v", cfg, err)
	}
	if _, err := Resolve(path, ""); err == nil {
		t.Fatal("missing current connection resolved")
	}
	before, _ := os.ReadFile(path)
	for _, mutate := range []func() error{
		func() error { return Select(path, "missing") },
		func() error { return Remove(path, "missing") },
		func() error { return Save(path, Profile{Name: "../other", Endpoint: first.Endpoint}, true) },
		func() error { return Save(path, Profile{Name: "bad", Endpoint: "http://secret@127.0.0.1"}, true) },
		func() error {
			return Save(path, Profile{Name: "bad", Endpoint: first.Endpoint, GRPCAddress: "example.com:1"}, true)
		},
	} {
		if err := mutate(); err == nil {
			t.Fatal("invalid mutation succeeded")
		}
		after, err := os.ReadFile(path)
		if err != nil || string(before) != string(after) {
			t.Fatalf("invalid mutation changed configuration: %v", err)
		}
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("config mode: %v %v", info, err)
	}
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil || len(entries) != 1 || entries[0].Name() != "config.json" {
		t.Fatalf("temporary config files left behind: %v %v", entries, err)
	}
}

func TestConnectionConfigValidation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	for _, data := range []string{
		`null`, `{}`, `{"schema_version":2}`, `{"schema_version":1} {}`,
		`{"schema_version":1,"current":"missing"}`,
		`{"schema_version":1,"unexpected":true}`,
		`{"schema_version":1,"dispatchers":[{"name":"one","endpoint":"http://127.0.0.1"},{"name":"one","endpoint":"http://127.0.0.1"}]}`,
	} {
		if err := os.WriteFile(path, []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(path); err == nil {
			t.Fatalf("accepted invalid configuration %s", data)
		}
	}
}

func TestDiscoverUsesAnnouncedControlAddresses(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		body   string
		valid  bool
	}{
		{"current", 200, `{"schema_version":1,"mode":"local-test","grpc_address":"127.0.0.1:4567","yamux_address":"[::1]:7654"}`, true},
		{"older", 404, `{}`, false},
		{"foreign control", 200, `{"schema_version":1,"mode":"local-test","grpc_address":"example.com:9001","yamux_address":"127.0.0.1:9000"}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != "GET" || r.URL.Path != "/prefix/connection" {
					t.Errorf("unexpected metadata route %s %s", r.Method, r.URL.Path)
				}
				w.WriteHeader(tc.status)
				fmt.Fprint(w, tc.body)
			}))
			defer srv.Close()
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			profile, err := Discover(ctx, srv.URL+"/prefix")
			if (err == nil) != tc.valid {
				t.Fatalf("discover: %+v %v", profile, err)
			}
			if tc.valid && (profile.Endpoint != srv.URL+"/prefix" || profile.GRPCAddress != "127.0.0.1:4567" || profile.YamuxAddress != "[::1]:7654" || profile.Name != "") {
				t.Fatalf("inferred or changed addresses: %+v", profile)
			}
			cancel()
			if _, err := Discover(ctx, srv.URL); !errors.Is(err, context.Canceled) {
				t.Fatalf("cancellation lost: %v", err)
			}
		})
	}
}
