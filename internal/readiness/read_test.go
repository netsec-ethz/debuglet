package readiness

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReadAcceptsWhatWritePublishes(t *testing.T) {
	for _, tc := range []struct {
		name       string
		record     Record
		executorID string
	}{
		{"dispatcher", Record{SchemaVersion: 1, PID: 7, HTTPAddr: "127.0.0.1:40101", GRPCAddr: "127.0.0.1:40102"}, ""},
		{"executor", Record{SchemaVersion: 1, PID: 7, ExecutorID: "executor"}, "executor"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "ready.json")
			if err := Write(path, tc.record); err != nil {
				t.Fatal(err)
			}
			got, err := Read(path, 7, tc.executorID)
			if err != nil || got != tc.record {
				t.Fatalf("Read = %+v, %v; want %+v", got, err, tc.record)
			}
		})
	}
}

func TestReadMissingRecordIsNotExist(t *testing.T) {
	if _, err := Read(filepath.Join(t.TempDir(), "ready.json"), 7, ""); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing record: %v", err)
	}
}

func TestReadRefusesMismatchedRecords(t *testing.T) {
	const dispatcher = `"schema_version":1,"pid":7,"http_addr":"127.0.0.1:20","grpc_addr":"127.0.0.1:21"`
	for _, tc := range []struct {
		name, body, executorID string
	}{
		{"other pid", `{"schema_version":1,"pid":8,"http_addr":"127.0.0.1:20","grpc_addr":"127.0.0.1:21"}`, ""},
		{"other schema", `{"schema_version":2,"pid":7,"http_addr":"127.0.0.1:20","grpc_addr":"127.0.0.1:21"}`, ""},
		{"name address", `{"schema_version":1,"pid":7,"http_addr":"localhost:20","grpc_addr":"127.0.0.1:21"}`, ""},
		{"other loopback", `{"schema_version":1,"pid":7,"http_addr":"127.0.0.2:20","grpc_addr":"127.0.0.1:21"}`, ""},
		{"ipv6 loopback", `{"schema_version":1,"pid":7,"http_addr":"[::1]:20","grpc_addr":"127.0.0.1:21"}`, ""},
		{"zero port", `{"schema_version":1,"pid":7,"http_addr":"127.0.0.1:0","grpc_addr":"127.0.0.1:21"}`, ""},
		{"missing address", `{"schema_version":1,"pid":7,"http_addr":"127.0.0.1:20"}`, ""},
		{"null address", `{"schema_version":1,"pid":7,"http_addr":"127.0.0.1:20","grpc_addr":null}`, ""},
		{"duplicate field", `{` + dispatcher + `,"pid":7}`, ""},
		{"unknown field", `{` + dispatcher + `,"extra":1}`, ""},
		{"dispatcher with identity", `{` + dispatcher + `,"executor_id":"executor"}`, ""},
		{"trailing data", `{` + dispatcher + `} {}`, ""},
		{"not an object", `[]`, ""},
		{"invalid utf8", "{\"schema_version\":1,\"pid\":7,\"http_addr\":\"\xff\",\"grpc_addr\":\"127.0.0.1:21\"}", ""},
		{"oversized", strings.Repeat(" ", MaxRecordSize+1), ""},
		{"other executor", `{"schema_version":1,"pid":7,"executor_id":"other"}`, "executor"},
		{"executor with address", `{"schema_version":1,"pid":7,"executor_id":"executor","http_addr":"127.0.0.1:20"}`, "executor"},
		{"dispatcher record for executor", `{` + dispatcher + `}`, "executor"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "ready.json")
			if err := os.WriteFile(path, []byte(tc.body), 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := Read(path, 7, tc.executorID); err == nil || errors.Is(err, os.ErrNotExist) {
				t.Fatalf("accepted or reported missing: %v", err)
			}
		})
	}
	t.Run("nonpositive pid", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "ready.json")
		if err := os.WriteFile(path, []byte(`{"schema_version":1,"pid":0,"executor_id":"executor"}`), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := Read(path, 0, "executor"); err == nil {
			t.Fatal("accepted PID 0")
		}
	})
	t.Run("symlink", func(t *testing.T) {
		dir := t.TempDir()
		target := filepath.Join(dir, "target.json")
		if err := os.WriteFile(target, []byte(`{`+dispatcher+`}`), 0600); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(dir, "ready.json")
		if err := os.Symlink(target, path); err != nil {
			t.Fatal(err)
		}
		if _, err := Read(path, 7, ""); err == nil {
			t.Fatal("followed a symlink")
		}
	})
}
