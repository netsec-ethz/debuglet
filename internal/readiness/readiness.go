// Package readiness publishes daemon startup records in owned private directories.
package readiness

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/netsec-ethz/debuglet/internal/fsutil"
)

type Record struct {
	SchemaVersion int    `json:"schema_version"`
	PID           int    `json:"pid"`
	HTTPAddr      string `json:"http_addr,omitempty"`
	GRPCAddr      string `json:"grpc_addr,omitempty"`
	ExecutorID    string `json:"executor_id,omitempty"`
}

func Write(path string, record Record) error {
	return write(path, record, os.Rename, fsutil.SyncDir)
}

func write(path string, record Record, rename func(string, string) error, syncDir func(string) error) error {
	// The caller owns the private parent directory. In particular, two daemon
	// invocations must never race to publish the same path.
	if err := requireAbsent(path); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".ready-*")
	if err != nil {
		return fmt.Errorf("create readiness temporary file: %w", err)
	}
	defer os.Remove(f.Name())
	if err := json.NewEncoder(f).Encode(record); err != nil {
		f.Close()
		return fmt.Errorf("encode readiness record: %w", err)
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return fmt.Errorf("sync readiness record: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close readiness record: %w", err)
	}
	if err := requireAbsent(path); err != nil {
		return err
	}
	if err := rename(f.Name(), path); err != nil {
		return fmt.Errorf("publish readiness record: %w", err)
	}
	if err := syncDir(filepath.Dir(path)); err != nil {
		// The record is published, but the caller treats a failed Write as
		// unpublished and never removes it. A stale record would refuse the
		// next start, so this one is withdrawn.
		return errors.Join(fmt.Errorf("sync readiness directory: %w", err), os.Remove(path))
	}
	return nil
}

func requireAbsent(path string) error {
	if _, err := os.Lstat(path); err == nil {
		return fmt.Errorf("readiness path already exists: %w", os.ErrExist)
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("inspect readiness path: %w", err)
	}
	return nil
}
