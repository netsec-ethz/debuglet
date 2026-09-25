package readiness

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestReadyFileLifecycle(t *testing.T) {
	record := Record{SchemaVersion: 1, PID: 123, HTTPAddr: "127.0.0.1:40101", GRPCAddr: "127.0.0.1:40102"}
	t.Run("atomic complete record", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "ready.json")
		err := write(path, record, func(temp, final string) error {
			if filepath.Dir(temp) != dir || final != path {
				t.Fatalf("rename paths %q %q", temp, final)
			}
			if _, err := os.Lstat(final); !os.IsNotExist(err) {
				t.Fatalf("visible before publication: %v", err)
			}
			assertRecord(t, temp, record)
			return os.Rename(temp, final)
		})
		if err != nil {
			t.Fatal(err)
		}
		assertRecord(t, path, record)
		entries, err := os.ReadDir(dir)
		if err != nil || len(entries) != 1 {
			t.Fatalf("temporary files remain: %v %v", entries, err)
		}
		if err := Write(path, Record{PID: 999}); !errors.Is(err, os.ErrExist) {
			t.Fatalf("overwrite error: %v", err)
		}
		assertRecord(t, path, record)
	})
	t.Run("real writer executor record", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "ready.json")
		r := Record{SchemaVersion: 1, PID: 124, ExecutorID: "fresh-uuid"}
		if err := Write(path, r); err != nil {
			t.Fatal(err)
		}
		assertRecord(t, path, r)
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var fields map[string]any
		if err := json.Unmarshal(data, &fields); err != nil {
			t.Fatal(err)
		}
		if len(fields) != 3 {
			t.Fatalf("unexpected optional fields: %v", fields)
		}
	})
	t.Run("stale symlink", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "ready.json")
		target := filepath.Join(dir, "missing")
		if err := os.Symlink(target, path); err != nil {
			t.Fatal(err)
		}
		if err := Write(path, record); !errors.Is(err, os.ErrExist) {
			t.Fatalf("symlink overwritten: %v", err)
		}
		if got, err := os.Readlink(path); err != nil || got != target {
			t.Fatalf("symlink changed: %q %v", got, err)
		}
	})
	t.Run("failed publication cleans temporary file", func(t *testing.T) {
		dir := t.TempDir()
		sentinel := errors.New("rename failed")
		err := write(filepath.Join(dir, "ready.json"), record, func(temp, final string) error { assertRecord(t, temp, record); return sentinel })
		if !errors.Is(err, sentinel) {
			t.Fatalf("write error: %v", err)
		}
		entries, err := os.ReadDir(dir)
		if err != nil || len(entries) != 0 {
			t.Fatalf("failed write left files: %v %v", entries, err)
		}
	})
	t.Run("missing parent", func(t *testing.T) {
		dir := t.TempDir()
		if err := Write(filepath.Join(dir, "missing", "ready.json"), record); err == nil {
			t.Fatal("missing parent accepted")
		}
		entries, err := os.ReadDir(dir)
		if err != nil || len(entries) != 0 {
			t.Fatalf("failed write left files: %v %v", entries, err)
		}
	})
}

func assertRecord(t *testing.T, path string, want Record) {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("mode %v", info.Mode())
	}
	var got Record
	dec := json.NewDecoder(f)
	if err := dec.Decode(&got); err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("record %+v, want %+v", got, want)
	}
	if err := dec.Decode(new(any)); err != io.EOF {
		t.Fatalf("extra JSON: %v", err)
	}
}
