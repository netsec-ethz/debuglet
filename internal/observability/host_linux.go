// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package observability

import (
	"errors"
	"io"
	"math"
	"os"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

const (
	smapsLimit  = 32 << 10
	openFDLimit = 65536
)

// CollectHost reads Linux's current process RSS, open descriptor count and
// available/capacity bytes for the filesystem containing stateDir. stateDir must
// be on a local filesystem. Reads and descriptor enumeration are size-bounded;
// kernel filesystem calls have no imposed deadline. RSS accounting scans the
// process mappings, so collection is on demand rather than constant-time.
func CollectHost(stateDir string) HostSnapshot {
	snapshot := HostSnapshot{ObservedAt: time.Now().UTC()}
	snapshot.ProcessRSSBytes = readRSS("/proc/self/smaps_rollup")
	snapshot.OpenFDs = countOpenFDs("/proc/self/fd", openFDLimit)
	snapshot.StateAvailableBytes, snapshot.StateCapacityBytes = filesystemSpace(stateDir)
	return snapshot
}

func hostReadFailure(err error) HostValue {
	reason := "read"
	switch {
	case errors.Is(err, os.ErrNotExist):
		reason = "missing"
	case errors.Is(err, os.ErrPermission):
		reason = "permission"
	}
	return HostValue{Unavailable: reason}
}

func readRSS(path string) HostValue {
	f, err := os.Open(path)
	if err != nil {
		return hostReadFailure(err)
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, smapsLimit+1))
	if err != nil {
		return hostReadFailure(err)
	}
	if len(data) > smapsLimit {
		return HostValue{Unavailable: "limit"}
	}
	var rss *uint64
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 || fields[0] != "Rss:" {
			continue
		}
		if rss != nil || len(fields) != 3 || fields[2] != "kB" {
			return HostValue{Unavailable: "invalid"}
		}
		value, err := strconv.ParseUint(fields[1], 10, 64)
		if err != nil || value > math.MaxUint64/1024 {
			return HostValue{Unavailable: "invalid"}
		}
		value *= 1024
		rss = &value
	}
	if rss == nil {
		return HostValue{Unavailable: "invalid"}
	}
	return HostValue{Value: rss}
}

func countOpenFDs(path string, limit uint64) HostValue {
	f, err := os.Open(path)
	if err != nil {
		return hostReadFailure(err)
	}
	defer f.Close()
	// Exclude the descriptor this enumeration itself opened.
	own := strconv.FormatUint(uint64(f.Fd()), 10)
	var count uint64
	for {
		names, err := f.Readdirnames(256)
		if err != nil && !errors.Is(err, io.EOF) {
			return hostReadFailure(err)
		}
		for _, name := range names {
			if _, err := strconv.ParseUint(name, 10, 32); err != nil {
				return HostValue{Unavailable: "invalid"}
			}
			if name == own {
				continue
			}
			count++
			if count > limit {
				return HostValue{Unavailable: "limit"}
			}
		}
		if errors.Is(err, io.EOF) {
			return hostValue(count)
		}
	}
}

func filesystemSpace(path string) (HostValue, HostValue) {
	var stat unix.Statfs_t
	if err := unix.Statfs(path, &stat); err != nil {
		value := hostReadFailure(err)
		return value, value
	}
	if stat.Bsize <= 0 || stat.Bavail > stat.Blocks || stat.Blocks > math.MaxUint64/uint64(stat.Bsize) {
		value := HostValue{Unavailable: "invalid"}
		return value, value
	}
	// Bavail excludes blocks reserved for privileged users: a service must
	// not report space its unprivileged identity cannot allocate.
	return hostValue(stat.Bavail * uint64(stat.Bsize)), hostValue(stat.Blocks * uint64(stat.Bsize))
}
