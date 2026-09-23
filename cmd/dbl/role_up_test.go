package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"path/filepath"
	"strings"
	"testing"

	"github.com/netsec-ethz/debuglet/internal/connections"
	"github.com/netsec-ethz/debuglet/internal/demo"
)

func TestRoleUpSavesDispatcherProfile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	var out, stderr bytes.Buffer
	deps := roleUpDependencies{
		executable: func() (string, error) { return "/installed/bin/dbl", nil },
		resolve:    func(string) (demo.Assets, error) { return demo.Assets{}, nil },
		start: func(ctx context.Context, _ demo.Assets, options demo.RoleOptions) error {
			if _, bounded := ctx.Deadline(); bounded {
				t.Error("role foreground inherited a default deadline")
			}
			if options.Name != "local" || options.Port != 0 || options.GRPCPort != 0 {
				t.Errorf("role defaults/options: %+v", options)
			}
			return options.Ready(demo.RoleEnvironment{State: "ready", Role: "dispatcher", Name: options.Name, Endpoint: "http://127.0.0.1:1234", GRPCAddress: "127.0.0.1:1235", YamuxAddress: "127.0.0.1:1234", StateDir: "/state"})
		},
	}
	if code := roleUpCommand(context.Background(), []string{"--port", "0", "--grpc-port", "0"}, globalOptions{ConfigPath: path, Output: outputJSON}, &out, &stderr, true, deps); code != 0 {
		t.Fatalf("role up exit %d: %s", code, &stderr)
	}
	profile, err := connections.Resolve(path, "local")
	if err != nil || profile.Endpoint != "http://127.0.0.1:1234" || profile.GRPCAddress != "127.0.0.1:1235" {
		t.Fatalf("saved profile: %+v %v", profile, err)
	}
	var ready map[string]any
	dec := json.NewDecoder(&out)
	if err := dec.Decode(&ready); err != nil || len(ready) != 7 || ready["role"] != "dispatcher" {
		t.Fatalf("role ready JSON: %+v %v", ready, err)
	}
	if err := dec.Decode(&ready); err != io.EOF {
		t.Fatalf("extra readiness document: %v", err)
	}
	if profile, err := roleDispatcher(globalOptions{ConfigPath: path}, ""); err != nil || profile.Name != "local" {
		t.Fatalf("executor selected wrong current profile: %+v %v", profile, err)
	}
}

func TestRoleUpValidatesBeforeEffects(t *testing.T) {
	for _, tc := range []struct {
		dispatcher bool
		args       []string
	}{
		{true, []string{"--name", "../escape"}},
		{true, []string{"--port", "65536"}},
		{false, []string{"--dispatcher", " "}},
		{false, []string{"--state-dir", ""}},
	} {
		var out, stderr bytes.Buffer
		deps := roleUpDependencies{executable: func() (string, error) { t.Fatal("invalid role command resolved assets"); return "", nil }}
		if code := roleUpCommand(context.Background(), tc.args, globalOptions{}, &out, &stderr, tc.dispatcher, deps); code != exitUsage {
			t.Fatalf("%v: exit %d: %s", tc.args, code, &stderr)
		}
	}
}

func TestExecutorUpRejectsConflictingSelection(t *testing.T) {
	for _, options := range []globalOptions{
		{EndpointSet: true, Endpoint: "http://127.0.0.1:9000"},
		{Dispatcher: "global"},
	} {
		var out, stderr bytes.Buffer
		options.ConfigPath = filepath.Join(t.TempDir(), "missing.json")
		deps := roleUpDependencies{executable: func() (string, error) { t.Fatal("conflicting selection resolved assets"); return "", nil }}
		code := roleUpCommand(context.Background(), []string{"--dispatcher", "role-selected"}, options, &out, &stderr, false, deps)
		if code != exitUsage || !strings.Contains(stderr.String(), "cannot combine") || out.Len() != 0 {
			t.Fatalf("explicit selection conflict: exit=%d stdout=%q stderr=%q", code, &out, &stderr)
		}
	}
}
