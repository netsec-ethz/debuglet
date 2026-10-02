// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package debuglet

import (
	"errors"
	"golang.org/x/sys/unix"
	"os"
	"runtime"
	"strconv"
	"syscall"
)

func restrictWorker() error {
	runtime.LockOSThread() // exec below inherits this thread's cleared credentials
	defer runtime.UnlockOSThread()
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return err
	}
	// The child never needs the parent's packet-tagging capabilities.
	header := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	caps := [2]unix.CapUserData{}
	if err := unix.Capset(&header, &caps[0]); err != nil {
		return err
	}
	if err := unix.Setrlimit(unix.RLIMIT_CORE, &unix.Rlimit{}); err != nil {
		return err
	}
	if err := unix.Setrlimit(unix.RLIMIT_NOFILE, &unix.Rlimit{Cur: 32, Max: 32}); err != nil {
		return err
	}
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	// Replace any Go threads started before Capset. No-new-privileges prevents
	// executable file capabilities from being reacquired by this exec.
	return syscall.Exec(executable, []string{executable, workerArgument + "-entered"}, os.Environ())
}

func workerPair() (*os.File, *os.File, error) {
	fd, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, nil, err
	}
	return os.NewFile(uintptr(fd[0]), "guest-parent"), os.NewFile(uintptr(fd[1]), "guest-child"), nil
}

func verifyWorkerParent() error {
	header := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	caps := [2]unix.CapUserData{}
	if err := unix.Capget(&header, &caps[0]); err != nil {
		return err
	}
	for _, set := range caps {
		if set.Effective != 0 || set.Permitted != 0 || set.Inheritable != 0 {
			return errors.New("worker retained process capabilities")
		}
	}
	expected, err := strconv.Atoi(os.Getenv("DEBUGLET_WORKER_PARENT_PID"))
	if err != nil || expected <= 1 {
		return errors.New("missing worker parent")
	}
	// Re-arm after exec, which can clear the death signal on a capability-bearing
	// executable even though no-new-privileges prevented those capabilities.
	if err = unix.Prctl(unix.PR_SET_PDEATHSIG, uintptr(unix.SIGKILL), 0, 0, 0); err != nil {
		return err
	}
	if os.Getppid() != expected {
		return errors.New("worker parent exited")
	}
	return nil
}
