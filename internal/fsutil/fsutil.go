// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

// Package fsutil publishes files so that a reader, including one after a crash
// or power loss, sees either the previous file or the complete new one.
package fsutil

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
)

// WriteFile publishes data at path with the given mode through a temporary
// file in the same directory. The contents reach the disk before the rename,
// and the rename reaches it before WriteFile returns.
func WriteFile(path string, data []byte, mode fs.FileMode) error {
	directory := filepath.Dir(path)
	file, err := os.CreateTemp(directory, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	_, writeErr := file.Write(data)
	if err := errors.Join(writeErr, file.Chmod(mode), file.Sync(), file.Close()); err != nil {
		return err
	}
	if err := os.Rename(file.Name(), path); err != nil {
		return err
	}
	return SyncDir(directory)
}

// SyncFile flushes an already written file to disk, for a caller that
// publishes it with its own rename.
func SyncFile(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	return errors.Join(file.Sync(), file.Close())
}

// SyncDir flushes a directory's entries, so a rename into it survives a crash.
// A filesystem that cannot sync a directory (EINVAL or ENOTSUP, as some network
// and FUSE mounts answer) offers nothing stronger, so that is not an error.
func SyncDir(directory string) error {
	dir, err := os.Open(directory)
	if err != nil {
		return err
	}
	syncErr := dir.Sync()
	if errors.Is(syncErr, syscall.EINVAL) || errors.Is(syncErr, syscall.ENOTSUP) {
		syncErr = nil
	}
	return errors.Join(syncErr, dir.Close())
}
