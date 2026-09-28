// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package observability

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestRSSReadValidatesUnitsAndBounds(t *testing.T) {
	for _, tc := range []struct {
		name, data, unavailable string
		want                    uint64
	}{
		{name: "rollup", data: "00400000-7fffffff ---p 00000000 00:00 0 [rollup]\nRss:  123 kB\nPss: 99 kB\n", want: 123 * 1024},
		{name: "zero is observed", data: "Rss: 0 kB\n"},
		{name: "missing field", data: "Pss: 12 kB\n", unavailable: "invalid"},
		{name: "wrong units", data: "Rss: 12 MB\n", unavailable: "invalid"},
		{name: "negative", data: "Rss: -1 kB\n", unavailable: "invalid"},
		{name: "overflow", data: "Rss: 18446744073709551615 kB\n", unavailable: "invalid"},
		{name: "duplicate", data: "Rss: 1 kB\nRss: 2 kB\n", unavailable: "invalid"},
		{name: "oversized", data: "Rss: 1 kB\n" + strings.Repeat(" ", smapsLimit), unavailable: "limit"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "smaps_rollup")
			if err := os.WriteFile(path, []byte(tc.data), 0600); err != nil {
				t.Fatal(err)
			}
			got := readRSS(path)
			if tc.unavailable != "" {
				assertUnavailable(t, got, tc.unavailable)
			} else if got.Value == nil || *got.Value != tc.want || got.Unavailable != "" {
				t.Fatalf("RSS observation: %+v, want %d bytes", got, tc.want)
			}
		})
	}
}

func TestDescriptorEnumerationRefusesTruncation(t *testing.T) {
	dir := t.TempDir()
	for n := 0; n < 5; n++ {
		if err := os.Symlink("/dev/null", filepath.Join(dir, strconv.Itoa(1000000+n))); err != nil {
			t.Fatal(err)
		}
	}
	assertUnavailable(t, countOpenFDs(dir, 4), "limit")
	if got := countOpenFDs(dir, 5); got.Value == nil || *got.Value != 5 || got.Unavailable != "" {
		t.Fatalf("descriptor count: %+v", got)
	}
	if err := os.WriteFile(filepath.Join(dir, "unexpected"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	assertUnavailable(t, countOpenFDs(dir, 10), "invalid")
}

func TestMissingHostSourcesStayUnavailable(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing")
	assertUnavailable(t, readRSS(missing), "missing")
	assertUnavailable(t, countOpenFDs(missing, openFDLimit), "missing")
	available, capacity := filesystemSpace(missing)
	assertUnavailable(t, available, "missing")
	assertUnavailable(t, capacity, "missing")
}

func TestHostPermissionDenied(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("run this test as an unprivileged user to exercise permission denial")
	}
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "fd"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "smaps_rollup"), []byte("Rss: 1 kB\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0700) })
	assertUnavailable(t, readRSS(filepath.Join(dir, "smaps_rollup")), "permission")
	assertUnavailable(t, countOpenFDs(filepath.Join(dir, "fd"), openFDLimit), "permission")
	available, capacity := filesystemSpace(filepath.Join(dir, "fd"))
	assertUnavailable(t, available, "permission")
	assertUnavailable(t, capacity, "permission")
}

func TestLiveProcessDescriptorPressure(t *testing.T) {
	start := time.Now()
	before := CollectHost(t.TempDir())
	if before.ObservedAt.Before(start) || before.ObservedAt.After(time.Now()) {
		t.Fatal("snapshot did not record collection time")
	}
	for name, value := range map[string]HostValue{"RSS": before.ProcessRSSBytes, "FD": before.OpenFDs, "available": before.StateAvailableBytes, "capacity": before.StateCapacityBytes} {
		if value.Value == nil || value.Unavailable != "" {
			t.Fatalf("live %s unavailable: %+v", name, value)
		}
	}
	if *before.ProcessRSSBytes.Value == 0 || *before.StateCapacityBytes.Value == 0 || *before.StateAvailableBytes.Value > *before.StateCapacityBytes.Value {
		t.Fatal("invalid live memory or filesystem observation")
	}
	var files []*os.File
	t.Cleanup(func() {
		for _, f := range files {
			_ = f.Close()
		}
	})
	for n := 0; n < 32; n++ {
		f, err := os.Open("/dev/null")
		if err != nil {
			t.Fatal(err)
		}
		files = append(files, f)
	}
	after := CollectHost(t.TempDir())
	if after.OpenFDs.Value == nil || *after.OpenFDs.Value != *before.OpenFDs.Value+uint64(len(files)) {
		t.Fatalf("descriptor pressure not observed: before=%+v after=%+v", before.OpenFDs, after.OpenFDs)
	}
	for _, f := range files {
		if err := f.Close(); err != nil {
			t.Fatal(err)
		}
	}
	files = nil
	for n := 0; n < 20; n++ {
		got := CollectHost(t.TempDir())
		if got.OpenFDs.Value == nil || *got.OpenFDs.Value != *before.OpenFDs.Value {
			t.Fatalf("collection leaked a descriptor: before=%+v after=%+v", before.OpenFDs, got.OpenFDs)
		}
	}
}

func TestLocalFilesystemPressure(t *testing.T) {
	var stat unix.Statfs_t
	if err := unix.Statfs("/dev/shm", &stat); err != nil || stat.Type != unix.TMPFS_MAGIC {
		t.Skip("requires the validation container's local /dev/shm tmpfs")
	}
	dir, err := os.MkdirTemp("/dev/shm", "debuglet-host-space-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	before, capacity := filesystemSpace(dir)
	const size = 4 << 20
	if before.Value == nil || capacity.Value == nil || *before.Value < 2*size {
		t.Fatal("fixture requires at least 8 MiB free local tmpfs space")
	}
	f, err := os.Create(filepath.Join(dir, "pressure"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := unix.Fallocate(int(f.Fd()), 0, 0, size); err != nil {
		t.Fatal(err)
	}
	after, afterCapacity := filesystemSpace(dir)
	if after.Value == nil || afterCapacity.Value == nil || *after.Value > *before.Value-size || *afterCapacity.Value != *capacity.Value {
		t.Fatalf("storage pressure not reflected: before=%+v after=%+v", before, after)
	}
}

func assertUnavailable(t *testing.T, value HostValue, reason string) {
	t.Helper()
	if value.Value != nil || value.Unavailable != reason {
		t.Fatalf("want unavailable %q without a numeric value, got %+v", reason, value)
	}
}
