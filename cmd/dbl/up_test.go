package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/netsec-ethz/debuglet/internal/demo"
)

func TestUpCommand(t *testing.T) {
	for _, args := range [][]string{{"--help"}, {"--port", "-1"}, {"--port", "65536"}, {"--state-dir", " "}, {"extra"}} {
		var out, stderr bytes.Buffer
		deps := upDependencies{executable: func() (string, error) { t.Fatal("invalid/help command resolved assets"); return "", nil }}
		want := exitUsage
		if args[0] == "--help" {
			want = exitOK
		}
		if code := upCommandWith(context.Background(), args, globalOptions{}, &out, &stderr, deps); code != want {
			t.Fatalf("%v: exit %d: %s", args, code, &stderr)
		}
	}
	for _, failure := range []error{nil, demo.ErrForcedKill} {
		var out, stderr bytes.Buffer
		ctx, cancel := context.WithCancel(context.Background())
		deps := upDependencies{
			executable: func() (string, error) { return "/installed/bin/dbl", nil },
			resolve:    func(string) (demo.Assets, error) { return demo.Assets{}, nil },
			up: func(ctx context.Context, _ demo.Assets, options demo.LocalOptions) error {
				if _, bounded := ctx.Deadline(); bounded || options.Port != 0 || options.StateDir != "/state" {
					t.Error("foreground context/options changed")
				}
				if err := options.Ready(demo.LocalEnvironment{State: "ready", Endpoint: "http://127.0.0.1:1", ExecutorID: "executor", StateDir: options.StateDir}); err != nil {
					return err
				}
				cancel()
				return failure
			},
		}
		code := upCommandWith(ctx, []string{"--state-dir", "/state", "--port", "0"}, globalOptions{Output: outputJSON}, &out, &stderr, deps)
		cancel()
		if (failure == nil && code != 0) || (failure != nil && code == 0) {
			t.Fatalf("cleanup result %v: exit %d: %s", failure, code, &stderr)
		}
		var ready demo.LocalEnvironment
		dec := json.NewDecoder(&out)
		if err := dec.Decode(&ready); err != nil || ready.State != "ready" {
			t.Fatalf("invalid ready JSON: %+v %v", ready, err)
		}
		if err := dec.Decode(&ready); !errors.Is(err, io.EOF) {
			t.Fatalf("extra stdout: %v", err)
		}
	}
}

// TestCommandTimeoutDefaults pins the whole-command timeout each command gets
// without --timeout. A foreground command must inherit no deadline at all, and
// an explicit non-positive --timeout stays a usage error even for those.
func TestCommandTimeoutDefaults(t *testing.T) {
	if defaultCommandTimeout("up") != 0 || defaultCommandTimeout("nodes") != 30*time.Second ||
		defaultCommandTimeout("demo") != time.Minute || !strings.Contains(demoUsage, "60s") {
		t.Fatal("command default timeout drift")
	}
	for _, command := range []string{"dispatcher", "executor"} {
		if defaultCommandTimeout(command, "up") != 0 || defaultCommandTimeout(command, "list") != 30*time.Second || defaultCommandTimeout(command) != 30*time.Second {
			t.Fatalf("wrong nested default timeout for %s", command)
		}
	}
	for _, tc := range []struct {
		args []string
		want int
	}{
		{[]string{"up", "--help"}, exitOK},
		{[]string{"--timeout", "0", "up", "--help"}, exitUsage},
		{[]string{"--timeout", "-1s", "up", "--help"}, exitUsage},
		{[]string{"--timeout", "1s", "up", "--help"}, exitOK},
		{[]string{"dispatcher", "up", "--help"}, exitOK},
		{[]string{"dispatcher", "list", "--help"}, exitOK},
		{[]string{"--timeout", "1s", "dispatcher", "up", "--help"}, exitOK},
		{[]string{"--timeout", "0", "dispatcher", "up", "--help"}, exitUsage},
		{[]string{"executor", "up", "--help"}, exitOK},
		{[]string{"executor", "list", "--help"}, exitOK},
		{[]string{"--timeout", "1s", "executor", "up", "--help"}, exitOK},
		{[]string{"--timeout", "0", "executor", "up", "--help"}, exitUsage},
	} {
		var out, stderr bytes.Buffer
		if code := run(context.Background(), tc.args, &out, &stderr); code != tc.want {
			t.Fatalf("%v: exit %d: %s", tc.args, code, &stderr)
		}
	}
}
