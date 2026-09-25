package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/netsec-ethz/debuglet/internal/demo"
	"github.com/netsec-ethz/debuglet/pkg/client"
)

func TestValidateCommandValidatesLocally(t *testing.T) {
	previous := newClient
	t.Cleanup(func() { newClient = previous })
	newClient = func(string, client.Options) (*client.Client, error) {
		t.Fatal("validate attempted to construct a network client")
		return nil, errors.New("unreachable")
	}

	wasm := wasmFile(t)
	code, stdout, stderr := runCLI(context.Background(),
		"--endpoint", "http://not-a-real-host.invalid:9999", "--output", "json", "validate",
		"--wasm", wasm, "--executor", "chosen-executor", "--duration", "2500ms",
		"--floor-bps", "10", "--ceil-bps", "20", "--allow", "example.invalid",
		"--allow", "2001:db8::1", "--", "example.invalid:443")
	if code != exitOK || stderr != "" {
		t.Fatalf("exit %d, stderr %q, stdout %q", code, stderr, stdout)
	}
	var result validationResult
	if err := json.Unmarshal([]byte(stdout), &result); err != nil {
		t.Fatalf("decode result: %v", err)
	}
	if !result.Valid || result.Source != wasm || result.WasmBytes != 8 || result.ExecutorID != "chosen-executor" ||
		result.DurationMS != 2500 || result.FloorBPS != 10 || result.CeilBPS != 20 {
		t.Fatalf("unexpected result: %+v", result)
	}
	if strings.Join(result.Destinations, ",") != "example.invalid,2001:db8::1" || len(result.Diagnostics) != 0 {
		t.Fatalf("unexpected destinations or diagnostics: %+v", result)
	}

	code, stdout, stderr = runCLI(context.Background(), "validate", "--wasm", wasm)
	if code != exitOK || stderr != "" || !strings.Contains(stdout, "valid: true\n") || !strings.Contains(stdout, "wasm_bytes: 8\n") {
		t.Fatalf("human result: exit %d, stdout %q, stderr %q", code, stdout, stderr)
	}
}

func TestValidateCommandAcceptsInstalledSample(t *testing.T) {
	previousExecutable, previousAssets := validateExecutable, validateAssets
	t.Cleanup(func() { validateExecutable, validateAssets = previousExecutable, previousAssets })
	root := t.TempDir()
	sample := filepath.Join(root, "share", "debuglet", "hello.wasm")
	if err := os.MkdirAll(filepath.Dir(sample), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sample, []byte("\x00asm\x01\x00\x00\x00"), 0o600); err != nil {
		t.Fatal(err)
	}
	validateExecutable = func() (string, error) { return filepath.Join(root, "bin", "dbl"), nil }
	validateAssets = func(string) (demo.Assets, error) { return demo.Assets{Root: root}, nil }

	code, stdout, stderr := runCLI(context.Background(), "--output", "json", "validate", "--sample", "hello")
	if code != exitOK || stderr != "" {
		t.Fatalf("exit %d, stderr %q, stdout %q", code, stderr, stdout)
	}
	var result validationResult
	if err := json.Unmarshal([]byte(stdout), &result); err != nil {
		t.Fatal(err)
	}
	if !result.Valid || result.Source != "sample:hello" || result.WasmBytes != 8 {
		t.Fatalf("unexpected sample result: %+v", result)
	}
}

func TestValidateCommandReportsFieldDiagnostics(t *testing.T) {
	malformed := filepath.Join(t.TempDir(), "malformed.wasm")
	if err := os.WriteFile(malformed, []byte("not wasm"), 0o600); err != nil {
		t.Fatal(err)
	}
	valid := wasmFile(t)
	tests := []struct {
		name    string
		args    []string
		field   string
		message string
	}{
		{name: "malformed wasm", args: []string{"--wasm", malformed}, field: "wasm", message: "module is malformed or unsupported"},
		{name: "duration overflow", args: []string{"--wasm", valid, "--duration", "999999999999999999999h"}, field: "duration", message: "must be a whole number of milliseconds at least 1ms"},
		{name: "bandwidth overflow", args: []string{"--wasm", valid, "--floor-bps", "9223372036854775808"}, field: "floor_bps", message: "must be a base-10 64-bit integer"},
		{name: "invalid destination port", args: []string{"--wasm", valid, "--allow", "example.com:443"}, field: "destinations[0]", message: "ports are not allowed; pass the destination port in the guest arguments"},
		{name: "invalid bracketed destination port", args: []string{"--wasm", valid, "--allow", "[2001:db8::1]:443"}, field: "destinations[0]", message: "ports are not allowed; pass the destination port in the guest arguments"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			args := append([]string{"--endpoint", "http://127.0.0.1:1", "--output", "json", "validate"}, tt.args...)
			code, stdout, stderr := runCLI(context.Background(), args...)
			if code != exitUsage || stderr != "" {
				t.Fatalf("exit %d, stderr %q, stdout %q", code, stderr, stdout)
			}
			var result validationResult
			if err := json.Unmarshal([]byte(stdout), &result); err != nil {
				t.Fatalf("decode result: %v", err)
			}
			if result.Valid || len(result.Diagnostics) != 1 || result.Diagnostics[0].Field != tt.field || result.Diagnostics[0].Message != tt.message {
				t.Fatalf("unexpected result: %+v", result)
			}
		})
	}
}

func TestValidateDestinationSyntaxDoesNotRequireDNS(t *testing.T) {
	for _, valid := range []string{"127.0.0.1", "2001:db8::1", "example.invalid", "host-name.example", "absolute.example."} {
		if err := validateDestination(valid); err != nil {
			t.Errorf("%q rejected: %v", valid, err)
		}
	}
	for _, invalid := range []string{"", " host", "host ", "bad_name", "-host.example", "host..example", "host:443", "[2001:db8::1]:443", "https://host/path"} {
		if err := validateDestination(invalid); err == nil {
			t.Errorf("%q accepted", invalid)
		}
	}
}
