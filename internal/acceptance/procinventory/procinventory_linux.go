//go:build linux

package procinventory

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// Read returns the identity of pid as procfs reports it. A process that has
// already exited yields an error for which Exited reports true. The stat file
// is read again after the other per-process files, so a PID reused during the
// read cannot contribute a mixture of two processes' fields.
func Read(pid int) (Process, error) {
	fields, err := stat(pid)
	if err != nil {
		return Process{}, err
	}
	group, err := strconv.Atoi(fields[2])
	if err != nil {
		return Process{}, err
	}
	parent, err := strconv.Atoi(fields[1])
	if err != nil {
		return Process{}, err
	}
	// A zombie or dead entry has already released its executable.
	executable, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
	if err != nil && fields[0] != "Z" && fields[0] != "X" {
		return Process{}, err
	}
	command, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	if err != nil {
		return Process{}, err
	}
	after, err := stat(pid)
	if err != nil {
		return Process{}, err
	}
	if after[19] != fields[19] || after[2] != fields[2] {
		return Process{}, errors.New("process identity changed during observation")
	}
	return Process{PID: pid, Parent: parent, Group: group, Start: fields[19], Executable: executable,
		Command:   strings.ReplaceAll(string(command), "\x00", " "),
		Arguments: strings.Split(strings.TrimSuffix(string(command), "\x00"), "\x00"),
		State:     after[0]}, nil
}

// Descendants lists the PIDs procfs reports as children of pid across all of
// its threads. A thread, or the whole process, that exits while the lists are
// read contributes nothing instead of failing the listing. The PIDs are the
// ones procfs reported; any of them may have exited by the time a caller reads
// them, which Read then reports through Exited.
func Descendants(pid int) ([]int, error) {
	threads, err := os.ReadDir(fmt.Sprintf("/proc/%d/task", pid))
	if err != nil {
		if Exited(err) {
			return nil, nil
		}
		return nil, err
	}
	var children []int
	var failures error
	for _, thread := range threads {
		data, err := os.ReadFile(fmt.Sprintf("/proc/%d/task/%s/children", pid, thread.Name()))
		if err != nil {
			if !Exited(err) {
				failures = errors.Join(failures, err)
			}
			continue
		}
		for _, field := range strings.Fields(string(data)) {
			child, err := strconv.Atoi(field)
			if err != nil {
				failures = errors.Join(failures, fmt.Errorf("malformed child PID %q: %w", field, err))
				continue
			}
			children = append(children, child)
		}
	}
	return children, failures
}

// stat returns the fields of /proc/<pid>/stat that follow the parenthesized
// executable name, which may itself contain spaces and parentheses.
func stat(pid int) ([]string, error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return nil, err
	}
	end := strings.LastIndexByte(string(data), ')')
	if end < 0 {
		return nil, errors.New("malformed process stat")
	}
	fields := strings.Fields(string(data[end+1:]))
	if len(fields) < 20 {
		return nil, errors.New("short process stat")
	}
	return fields, nil
}
