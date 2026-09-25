//go:build linux || darwin

package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/netsec-ethz/debuglet/internal/artifact"
	"github.com/netsec-ethz/debuglet/internal/demo"
	"golang.org/x/sys/unix"
)

func manifestBytes(t *testing.T, m Manifest) []byte {
	t.Helper()
	data, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func loadFixture(t *testing.T, data []byte) (Manifest, error) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "manifest.json")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	return LoadManifest(path)
}

func assetMetadataFixture() demo.Assets {
	return demo.Assets{Manifest: artifact.Manifest{SchemaVersion: 1, Version: "v0.0.0-dev.123456abcdef", SourceSHA: strings.Repeat("b", 40), GoVersion: artifact.Toolchain, GOOS: "linux", GOARCH: "amd64", GuestABI: artifact.GuestABI, Files: payloadFiles("c")}}
}

func TestManifestValidation(t *testing.T) {
	base := manifestFixture()
	t.Run("exact_original_digest", func(t *testing.T) {
		data := append([]byte("\n  "), manifestBytes(t, base)...)
		data = append(data, '\n')
		got, err := loadFixture(t, data)
		if err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256(data)
		base.SourceSHA256 = hex.EncodeToString(digest[:])
		if !reflect.DeepEqual(got, base) {
			t.Fatalf("decoded manifest differs: %+v", got)
		}
		if err := Validate(got, assetMetadataFixture()); err != nil {
			t.Fatal(err)
		}
	})
	for _, tc := range []struct {
		name string
		edit func(*Manifest)
	}{
		{"schema", func(m *Manifest) { m.SchemaVersion = 2 }},
		{"eth_environment", func(m *Manifest) { m.Environment = "eth-dev" }},
		{"unknown_environment", func(m *Manifest) { m.Environment = "private-secret-environment" }},
		{"empty_operator", func(m *Manifest) { m.Operator = "" }},
		{"operator_65", func(m *Manifest) { m.Operator = strings.Repeat("a", 65) }},
		{"operator_leading_space", func(m *Manifest) { m.Operator = " local" }},
		{"operator_shell", func(m *Manifest) { m.Operator = "$(private-secret-command)" }},
		{"operator_newline", func(m *Manifest) { m.Operator = "local\nsecret" }},
		{"operator_unicode", func(m *Manifest) { m.Operator = "local-é" }},
		{"operator_credentials", func(m *Manifest) { m.Operator = "user:private-secret@host" }},
		{"empty_uuid", func(m *Manifest) { m.ExecutorID = "" }},
		{"zero_uuid", func(m *Manifest) { m.ExecutorID = "00000000-0000-0000-0000-000000000000" }},
		{"uppercase_uuid", func(m *Manifest) { m.ExecutorID = strings.ToUpper(m.ExecutorID) }},
		{"uuid_urn", func(m *Manifest) { m.ExecutorID = "urn:uuid:" + m.ExecutorID }},
		{"uuid_braces", func(m *Manifest) { m.ExecutorID = "{" + m.ExecutorID + "}" }},
		{"uuid_no_hyphens", func(m *Manifest) { m.ExecutorID = strings.ReplaceAll(m.ExecutorID, "-", "") }},
		{"api_loopback_supplied", func(m *Manifest) { m.APIBaseURL = "http://127.0.0.1:1/api" }},
		{"api_remote_supplied", func(m *Manifest) { m.APIBaseURL = "https://user:private-secret@outside.invalid/api" }},
		{"grpc_supplied", func(m *Manifest) { m.Control.GRPCAddr = "127.0.0.1:1" }},
		{"yamux_supplied", func(m *Manifest) { m.Control.YamuxAddr = "127.0.0.1:2" }},
		{"wrong_protection", func(m *Manifest) { m.Control.Protection = "tls" }},
		{"target_dns", func(m *Manifest) { m.Target.Host = "localhost" }},
		{"target_ipv6", func(m *Manifest) { m.Target.Host = "::1" }},
		{"target_other", func(m *Manifest) { m.Target.Host = "192.0.2.1" }},
		{"deployment", func(m *Manifest) { m.DeploymentRecord = "private-secret-deployment" }},
		{"execution_zero", func(m *Manifest) { m.Limits.ExecutionMS = 0 }},
		{"execution_negative", func(m *Manifest) { m.Limits.ExecutionMS = -1 }},
		{"execution_above", func(m *Manifest) { m.Limits.ExecutionMS = 15001 }},
		{"ceiling_below", func(m *Manifest) { m.Limits.CeilingBPS = 63999 }},
		{"ceiling_above", func(m *Manifest) { m.Limits.CeilingBPS = 1000001 }},
		{"attempt_zero", func(m *Manifest) { m.Limits.AttemptMS = 0 }},
		{"attempt_above", func(m *Manifest) { m.Limits.AttemptMS = 180001 }},
		{"attempt_gap_short", func(m *Manifest) { m.Limits.AttemptMS = m.Limits.ExecutionMS + 19999 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := manifestFixture()
			tc.edit(&m)
			assertManifestRejected(t, manifestBytes(t, m))
			if err := Validate(m, assetMetadataFixture()); err == nil || strings.Contains(err.Error(), "private-secret") {
				t.Fatalf("Validate did not safely reject input: %v", err)
			}
		})
	}
	for _, tc := range []struct {
		name   string
		limits LimitsManifest
	}{
		{"minimum", LimitsManifest{ExecutionMS: 1, CeilingBPS: 64000, AttemptMS: 20001}},
		{"maximum", LimitsManifest{ExecutionMS: 15000, CeilingBPS: 1000000, AttemptMS: 180000}},
		{"exact_gap", LimitsManifest{ExecutionMS: 15000, CeilingBPS: 64000, AttemptMS: 35000}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := manifestFixture()
			m.Operator = "A" + strings.Repeat("_", 63)
			m.Limits = tc.limits
			if _, err := loadFixture(t, manifestBytes(t, m)); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func assertManifestRejected(t *testing.T, data []byte) {
	t.Helper()
	got, err := loadFixture(t, data)
	if err == nil || !reflect.DeepEqual(got, Manifest{}) || strings.Contains(err.Error(), "private-secret") {
		t.Fatalf("input was not rejected without leaking data: manifest=%+v err=%v", got, err)
	}
}

func TestManifestStrictJSON(t *testing.T) {
	base := string(manifestBytes(t, manifestFixture()))
	for name, input := range map[string]string{
		"empty": "", "null": "null", "array": "[]", "trailing": base + `{}`, "trailing_junk": base + "private-secret",
		"unknown":             strings.Replace(base, `"operator":`, `"private-secret":true,"operator":`, 1),
		"source_digest_input": strings.Replace(base, `"operator":`, `"SourceSHA256":"private-secret","operator":`, 1),
		"daemon_args":         strings.Replace(base, `"operator":`, `"daemon_args":["private-secret"],"operator":`, 1),
		"credentials":         strings.Replace(base, `"operator":`, `"auth_key":"private-secret","operator":`, 1),
		"schema_alias":        strings.Replace(base, `"schema_version"`, `"Schema_Version"`, 1),
		"duplicate":           strings.Replace(base, `"environment":`, `"environment":"local","environment":`, 1),
		"escaped_duplicate":   strings.Replace(base, `"environment":`, `"\u0065nvironment":"local","environment":`, 1),
		"nested_duplicate":    strings.Replace(base, `"grpc_addr":`, `"grpc_addr":"","grpc_addr":`, 1),
		"nested_unknown":      strings.Replace(base, `"grpc_addr":`, `"password":"private-secret","grpc_addr":`, 1),
		"nested_alias":        strings.Replace(base, `"grpc_addr"`, `"GRPC_ADDR"`, 1),
		"string_number":       strings.Replace(base, `"execution_ms":10000`, `"execution_ms":"10000"`, 1),
		"float_number":        strings.Replace(base, `"execution_ms":10000`, `"execution_ms":10000.0`, 1),
		"exponent_number":     strings.Replace(base, `"execution_ms":10000`, `"execution_ms":1e4`, 1),
		"overflow_number":     strings.Replace(base, `"execution_ms":10000`, `"execution_ms":9223372036854775808`, 1),
		"boolean_string":      strings.Replace(base, `"operator":"Local fixture_1.test-run"`, `"operator":true`, 1),
		"nested_array":        strings.Replace(base, `"target":{"host":"127.0.0.1"}`, `"target":[]`, 1),
		"invalid_utf8":        strings.Replace(base, `"operator":"Local fixture_1.test-run"`, "\"operator\":\"private-secret\xff\"", 1),
	} {
		t.Run(name, func(t *testing.T) { assertManifestRejected(t, []byte(input)) })
	}
	// Every required key is tested both absent and explicitly null, including
	// the endpoint fields whose required input value is the empty string.
	var root map[string]json.RawMessage
	if err := json.Unmarshal([]byte(base), &root); err != nil {
		t.Fatal(err)
	}
	for _, parent := range []string{"", "control", "target", "limits"} {
		fields := root
		if parent != "" {
			fields = nil
			if err := json.Unmarshal(root[parent], &fields); err != nil {
				t.Fatal(err)
			}
		}
		for key := range fields {
			for _, mode := range []string{"missing", "null"} {
				t.Run(parent+"/"+key+"/"+mode, func(t *testing.T) {
					var copyRoot map[string]json.RawMessage
					_ = json.Unmarshal([]byte(base), &copyRoot)
					copyFields := copyRoot
					if parent != "" {
						copyFields = nil
						_ = json.Unmarshal(copyRoot[parent], &copyFields)
					}
					if mode == "missing" {
						delete(copyFields, key)
					} else {
						copyFields[key] = json.RawMessage("null")
					}
					if parent != "" {
						copyRoot[parent], _ = json.Marshal(copyFields)
					}
					data, _ := json.Marshal(copyRoot)
					assertManifestRejected(t, data)
				})
			}
		}
	}
}

func TestManifestFileBounds(t *testing.T) {
	data := manifestBytes(t, manifestFixture())
	exact := append(data, bytes.Repeat([]byte(" "), manifestSizeLimit-len(data))...)
	if _, err := loadFixture(t, exact); err != nil {
		t.Fatalf("exactly 64 KiB: %v", err)
	}
	assertManifestRejected(t, append(exact, ' '))
	for _, name := range []string{"missing", "directory", "symlink"} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "private-secret")
			switch name {
			case "directory":
				if err := os.Mkdir(path, 0700); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				if err := os.WriteFile(filepath.Join(dir, "target"), data, 0600); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink("target", path); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := LoadManifest(path); err == nil || strings.Contains(err.Error(), "private-secret") {
				t.Fatalf("unsafe manifest path result: %v", err)
			}
		})
	}
}

func TestManifestFIFOIsBounded(t *testing.T) {
	path := filepath.Join(t.TempDir(), "input.fifo")
	if err := unix.Mkfifo(path, 0600); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { _, err := LoadManifest(path); done <- err }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("FIFO accepted as a manifest")
		}
	case <-time.After(time.Second):
		t.Error("manifest reader blocked on FIFO")
		// This fallback only releases a broken blocking-open implementation,
		// after the failure has been recorded, so the test can join its helper.
		if fd, err := unix.Open(path, unix.O_WRONLY|unix.O_NONBLOCK, 0); err == nil {
			_ = unix.Close(fd)
		}
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("manifest reader did not join after FIFO release")
		}
	}
}

func TestValidateMetadata(t *testing.T) {
	for name, change := range map[string]func(*demo.Assets){
		"schema":          func(a *demo.Assets) { a.Manifest.SchemaVersion = 0 },
		"version":         func(a *demo.Assets) { a.Manifest.Version = "private-secret" },
		"revision":        func(a *demo.Assets) { a.Manifest.SourceSHA = strings.Repeat("B", 40) },
		"dirty":           func(a *demo.Assets) { a.Manifest.Dirty = true },
		"toolchain":       func(a *demo.Assets) { a.Manifest.GoVersion = "go1.24.0" },
		"platform":        func(a *demo.Assets) { a.Manifest.GOOS = "darwin" },
		"architecture":    func(a *demo.Assets) { a.Manifest.GOARCH = "arm64" },
		"abi":             func(a *demo.Assets) { a.Manifest.GuestABI = "unknown" },
		"missing_payload": func(a *demo.Assets) { delete(a.Manifest.Files, "bin/dbl") },
		"extra_payload": func(a *demo.Assets) {
			a.Manifest.Files["private-secret"] = artifact.File{SHA256: strings.Repeat("c", 64), Bytes: 1}
		},
		"bad_payload": func(a *demo.Assets) { a.Manifest.Files["bin/dbl"] = artifact.File{SHA256: "private-secret", Bytes: 1} },
		"empty_payload": func(a *demo.Assets) {
			a.Manifest.Files["bin/dbl"] = artifact.File{SHA256: strings.Repeat("c", 64), Bytes: 0}
		},
	} {
		t.Run(name, func(t *testing.T) {
			a := assetMetadataFixture()
			change(&a)
			if err := Validate(manifestFixture(), a); err == nil || strings.Contains(err.Error(), "private-secret") {
				t.Fatalf("invalid metadata not safely rejected: %v", err)
			}
		})
	}
	for _, digest := range []string{"", strings.Repeat("A", 64), strings.Repeat("a", 63), strings.Repeat("a", 65)} {
		m := manifestFixture()
		m.SourceSHA256 = digest
		if err := Validate(m, assetMetadataFixture()); err == nil {
			t.Error("invalid source digest accepted")
		}
	}
}
