package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

func stateChecks(path string) []doctorCheck {
	dir := filepath.Dir(path)
	permission := doctorCheck{"state_permissions", "pass", "database directory is writable by this process", "service account permissions may differ; no write was attempted"}
	info, err := os.Stat(dir)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0222 == 0 || unix.Access(dir, unix.W_OK|unix.X_OK) != nil {
		permission = doctorCheck{"state_permissions", "failure", "database directory is absent or not writable/searchable by this process", "create the state directory and grant the daemon account the required permissions"}
	} else if db, err := os.Stat(path); err == nil && (db.Mode().Perm()&0222 == 0 || unix.Access(path, unix.W_OK) != nil) {
		permission = doctorCheck{"state_permissions", "failure", "database file is not writable by this process", "grant the daemon account write access to its database"}
	}
	space := doctorCheck{"state_space", "unavailable", "filesystem free space could not be read", "check the state directory's mount and available space"}
	var stat unix.Statfs_t
	if unix.Statfs(dir, &stat) == nil {
		space.Status, space.Detail, space.Next = "pass", fmt.Sprintf("%d bytes available to an unprivileged process", stat.Bavail*uint64(stat.Bsize)), "ensure enough space for expected output and backups; no capacity guarantee is made"
		if stat.Bavail == 0 {
			space.Status, space.Next = "failure", "free space on the state filesystem before starting the daemon"
		}
	}
	return []doctorCheck{permission, space}
}

func capabilityCheck(counter string) doctorCheck {
	check := doctorCheck{"capabilities", "unavailable", "effective Linux capabilities could not be read", "inspect the daemon's service user and capability configuration"}
	data, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return check
	}
	for _, line := range strings.Split(string(data), "\n") {
		value, ok := strings.CutPrefix(line, "CapEff:")
		if !ok {
			continue
		}
		bits, err := strconv.ParseUint(strings.TrimSpace(value), 16, 64)
		if err != nil {
			return check
		}
		has := func(capability uint) bool { return bits&(uint64(1)<<capability) != 0 }
		check.Detail = fmt.Sprintf("current process: CAP_NET_RAW=%t CAP_NET_ADMIN=%t CAP_BPF=%t CAP_PERFMON=%t CAP_SYS_ADMIN=%t", has(13), has(12), has(39), has(38), has(21))
		check.Status, check.Next = "pass", "service capabilities and kernel policy may differ; no packet counter or tagger was attached"
		// The verifier refuses the tagger's pointer comparisons without
		// CAP_PERFMON, so CAP_BPF alone does not load it.
		if !has(13) || (counter != "fallback" && (!has(12) || (!(has(39) && has(38)) && !has(21)))) {
			check.Status, check.Next = "not_checked", "automatic counter selection may use fallback without eBPF privileges (CAP_BPF, CAP_PERFMON and CAP_NET_ADMIN); IPv4 fallback tagging needs CAP_NET_RAW. Check service capabilities; no attachment or readiness was verified"
		}
		return check
	}
	return check
}
