// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

//go:build linux

package ebpf

import (
	"errors"
	"os"
	"strings"

	"golang.org/x/sys/unix"
)

// loadCapabilities are the capabilities the kernel checks when the counter's
// maps and programs are loaded: CAP_BPF for map create and program load, and
// CAP_NET_ADMIN for a traffic-control program. CAP_SYS_ADMIN stands in for
// both, and is the only way to hold them before Linux 5.8 added CAP_BPF.
// CAP_PERFMON is left out: the tagger's verifier needs it, not this load, so
// naming it here could blame a load failure on it wrongly.
var loadCapabilities = []struct {
	name string
	bit  uint
}{
	{"CAP_BPF", unix.CAP_BPF},
	{"CAP_NET_ADMIN", unix.CAP_NET_ADMIN},
}

// missingCapabilities names the load capabilities absent from this
// process's effective set, in loadCapabilities order.
func missingCapabilities() ([]string, error) {
	header := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	var data [2]unix.CapUserData
	if err := unix.Capget(&header, &data[0]); err != nil {
		return nil, err
	}
	effective := uint64(data[1].Effective)<<32 | uint64(data[0].Effective)
	return missingFrom(effective), nil
}

func missingFrom(effective uint64) []string {
	if effective&(1<<unix.CAP_SYS_ADMIN) != 0 {
		return nil
	}
	var missing []string
	for _, c := range loadCapabilities {
		if effective&(1<<c.bit) == 0 {
			missing = append(missing, c.name)
		}
	}
	return missing
}

// missingCapabilityError is a load failure explained by missing capabilities.
// cilium/ebpf reports an unprivileged map create as "MEMLOCK may be too low"
// or, through a feature probe that is itself refused, as "prealloc maps not
// supported", neither of which names the cause; this does. It is a permission
// failure for errors.Is(err, os.ErrPermission), whatever the loader returned.
type missingCapabilityError struct {
	missing []string
	err     error
}

func (e *missingCapabilityError) Error() string {
	return "executor lacks " + strings.Join(e.missing, ", ") +
		" (grant the executor binary executor_capabilities with setcap); loader reported: " + e.err.Error()
}

func (e *missingCapabilityError) Unwrap() error { return e.err }

func (e *missingCapabilityError) Is(target error) bool { return target == os.ErrPermission }

// explainLoadFailure attributes err to missing capabilities when the process
// lacks any; otherwise, or when they cannot be read, err is returned as is.
func explainLoadFailure(err error, missing func() ([]string, error)) error {
	if missing == nil {
		return err
	}
	names, capErr := missing()
	if capErr != nil || len(names) == 0 {
		return err
	}
	var already *missingCapabilityError
	if errors.As(err, &already) {
		return err
	}
	return &missingCapabilityError{missing: names, err: err}
}
