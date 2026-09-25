package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/netsec-ethz/debuglet/internal/demo"
)

func TestDemoCommand(t *testing.T) {
	for _, tc := range []struct {
		name     string
		args     []string
		endpoint bool
		want     int
	}{
		{"help", []string{"--help"}, false, 0},
		{"argument", []string{"x"}, false, 2},
		{"unknown flag", []string{"--fault"}, false, 2},
		{"explicit endpoint", nil, true, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var out, stderr bytes.Buffer
			deps := demoDependencies{executable: func() (string, error) { t.Fatal("invalid/help command resolved assets"); return "", nil }}
			code := runDemoWith(context.Background(), tc.args, globalOptions{Output: outputJSON, EndpointSet: tc.endpoint}, &out, &stderr, deps)
			if code != tc.want {
				t.Fatalf("exit %d: %s", code, &stderr)
			}
		})
	}
	for _, tc := range []struct {
		name   string
		err    error
		cancel bool
		want   int
	}{
		{"complete", nil, false, 0},
		{"cleanup failure", demo.ErrForcedKill, false, 1},
		{"interrupted", context.Canceled, true, 130},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var out, stderr bytes.Buffer
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			finished := false
			deps := demoDependencies{
				executable: func() (string, error) { return "/installation/bin/dbl", nil },
				resolve:    func(string) (demo.Assets, error) { return demo.Assets{}, nil },
				run: func(context.Context, demo.Assets) (demo.Result, error) {
					if out.Len() != 0 {
						t.Fatal("CLI printed before cleanup completed")
					}
					finished = true
					if tc.cancel {
						cancel()
					}
					return demo.Result{Version: "test", RunID: "run", ExecutorID: "executor", Response: "response", State: "RunStateExited", Cleanup: "complete"}, tc.err
				},
			}
			code := runDemoWith(ctx, nil, globalOptions{Output: outputJSON}, &out, &stderr, deps)
			if code != tc.want || !finished {
				t.Fatalf("exit %d, finished %t: %s", code, finished, &stderr)
			}
			if tc.err != nil {
				if out.Len() != 0 {
					t.Fatal("failure emitted successful JSON")
				}
				return
			}
			var result demo.Result
			dec := json.NewDecoder(&out)
			if err := dec.Decode(&result); err != nil || result.Cleanup != "complete" {
				t.Fatalf("invalid result: %+v %v", result, err)
			}
			if err := dec.Decode(&result); !errors.Is(err, io.EOF) {
				t.Fatalf("extra stdout document: %v", err)
			}
		})
	}
}
