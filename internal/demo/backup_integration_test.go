// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

//go:build linux && backup_integration

package demo

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

// Run in an owned container with --tmpfs /backup-full:rw,size=1m,mode=700
// and DEBUGLET_BACKUP_ENOSPC_ROOT=/backup-full. Refuse any ordinary filesystem
// or large mount so a mistaken test setup cannot fill the host's storage.
func TestBackupDiskFullPreservesPrevious(t *testing.T) {
	root := os.Getenv("DEBUGLET_BACKUP_ENOSPC_ROOT")
	if !filepath.IsAbs(root) {
		t.Fatal("absolute DEBUGLET_BACKUP_ENOSPC_ROOT on a private small tmpfs is required")
	}
	if err := privateBackupDir(root); err != nil {
		t.Fatal(err)
	}
	var fs unix.Statfs_t
	if err := unix.Statfs(root, &fs); err != nil {
		t.Fatal(err)
	}
	if fs.Type != unix.TMPFS_MAGIC || fs.Blocks*uint64(fs.Bsize) > 16<<20 {
		t.Fatal("disk-full test requires an isolated tmpfs of at most 16 MiB")
	}
	parent, err := os.MkdirTemp(root, "backup-enospc-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(parent)
	source, m := backupFixture(t, "executor")
	first := filepath.Join(parent, "first")
	if _, err := BackupState(t.Context(), BackupOptions{StateDir: source, Destination: first, Offline: true, Package: m}); err != nil {
		t.Fatalf("initial valid backup: %v", err)
	}
	before := backupFiles(t, first)
	// Source data stays on the ordinary test filesystem. Only this dedicated
	// volume fills, during the actual backup copy, after a good backup exists.
	db := openSchemaDB(t, RoleDatabase(source, ExecutorSchema))
	if _, err := db.Exec("CREATE TABLE storage_pressure(data BLOB); INSERT INTO storage_pressure VALUES(zeroblob(?))", int64(fs.Blocks)*fs.Bsize+4096); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	second := filepath.Join(parent, "second")
	_, err = BackupState(t.Context(), BackupOptions{StateDir: source, Destination: second, Offline: true, Package: m})
	if !errors.Is(err, syscall.ENOSPC) {
		t.Fatalf("wanted real ENOSPC from backup copy: %v", err)
	}
	if _, err := os.Stat(second); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("disk-full backup published: %v", err)
	}
	if !reflect.DeepEqual(before, backupFiles(t, first)) {
		t.Fatal("disk-full failure changed the last good backup")
	}
	assertNoBackupStaging(t, parent)
	restored := filepath.Join(privateSchemaDir(t), "restored")
	if _, err := RestoreState(t.Context(), RestoreOptions{BackupDir: first, StateDir: restored, Package: m}); err != nil {
		t.Fatalf("last good backup no longer restores: %v", err)
	}
}
