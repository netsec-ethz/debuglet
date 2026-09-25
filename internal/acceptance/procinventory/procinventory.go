// Package procinventory reads process identities from procfs for the
// acceptance harnesses, which observe what an installed candidate started
// before they may repair anything themselves.
//
// Listing processes and reading their per-process files are separate steps, so
// a process can exit in between: ESRCH and ENOENT both mean "already exited"
// and count as an absence rather than a failed observation. Only processes
// still present when an inventory completes are reported, so a caller's
// ownership assertions apply to survivors alone.
package procinventory

import (
	"errors"
	"io/fs"
	"syscall"
)

// Process is one process as procfs reported it. Start is the start time in
// clock ticks, which separates a live process from a later reuse of its PID,
// and State is the single-letter state from stat.
type Process struct {
	PID        int      `json:"pid"`
	Parent     int      `json:"parent_pid"`
	Group      int      `json:"group"`
	Start      string   `json:"start_ticks"`
	Executable string   `json:"executable"`
	Command    string   `json:"command"`
	Arguments  []string `json:"arguments,omitempty"`
	State      string   `json:"state"`
}

// Exited reports whether err means the process was already gone when it was
// read, rather than a failure of the observation itself.
func Exited(err error) bool {
	return errors.Is(err, fs.ErrNotExist) || errors.Is(err, syscall.ESRCH)
}

// Same reports whether two readings describe the same process rather than a
// reuse of its PID.
func Same(a, b Process) bool {
	return a.PID == b.PID && a.Start == b.Start && a.Group == b.Group && a.Executable == b.Executable
}

// Live reports whether p was still running rather than a zombie or a dead
// entry awaiting removal.
func Live(p Process) bool { return p.State != "Z" && p.State != "X" }

// Inventory reads every PID in pids and reports, in the order given, the
// processes still present when it completed; every read failure that does not
// mean "already exited" is reported. Each identity comes from the confirming
// read, so a caller holding an earlier one can still recognize a reused PID.
func Inventory(pids []int) ([]Process, error) { return inventory(pids, Read) }

func inventory(pids []int, read func(int) (Process, error)) ([]Process, error) {
	var failures error
	candidates := make([]int, 0, len(pids))
	for _, pid := range pids {
		if _, err := read(pid); err != nil {
			if !Exited(err) {
				failures = errors.Join(failures, err)
			}
			continue
		}
		candidates = append(candidates, pid)
	}
	present := make([]Process, 0, len(candidates))
	for _, pid := range candidates {
		p, err := read(pid)
		if err != nil {
			if !Exited(err) {
				failures = errors.Join(failures, err)
			}
			continue
		}
		present = append(present, p)
	}
	return present, failures
}
