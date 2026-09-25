//go:build linux

package procinventory

import (
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"
)

// exitedPID starts a process, waits for it to exit and returns its PID, so an
// inventory over that PID observes exactly what a harness observes when a
// process exits between being listed and being read.
func exitedPID(t *testing.T) int {
	t.Helper()
	cmd := exec.Command("/bin/sleep", "0")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	pid := cmd.Process.Pid
	if err := cmd.Wait(); err != nil {
		t.Fatal(err)
	}
	return pid
}

func TestInventorySkipsProcessesThatAlreadyExited(t *testing.T) {
	pid := exitedPID(t)
	if _, err := Read(pid); !Exited(err) {
		t.Fatalf("reading the exited process %d reported %v, want an already exited process", pid, err)
	}
	present, err := Inventory([]int{pid, os.Getpid()})
	if err != nil {
		t.Fatalf("inventory over a list containing an exited PID: %v", err)
	}
	if len(present) != 1 || present[0].PID != os.Getpid() {
		t.Fatalf("inventory reported %+v, want only this process", present)
	}
	self := present[0]
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	if !Live(self) || self.Parent != os.Getppid() || self.Executable != executable || self.Start == "" {
		t.Fatalf("inventory reported an incomplete identity for this process: %+v", self)
	}
	if !Same(self, self) || Same(self, Process{PID: self.PID, Start: "0", Group: self.Group, Executable: self.Executable}) {
		t.Fatal("identity comparison accepted a reused PID or rejected the same process")
	}
}

func TestInventoryOmitsProcessesThatExitWhileItRuns(t *testing.T) {
	surviving := Process{PID: 11, Parent: 1, Group: 11, Start: "11", Executable: "/surviving", State: "S"}
	leaving := Process{PID: 12, Parent: 1, Group: 12, Start: "12", Executable: "/leaving", State: "S"}
	unreadable := errors.New("stat could not be read")
	reads := map[int]int{}
	read := func(pid int) (Process, error) {
		reads[pid]++
		switch {
		case pid == surviving.PID:
			return surviving, nil
		case pid == leaving.PID && reads[pid] == 1:
			return leaving, nil
		case pid == leaving.PID:
			return Process{}, syscall.ESRCH
		case pid == 13:
			return Process{}, fs.ErrNotExist
		default:
			return Process{}, unreadable
		}
	}
	present, err := inventory([]int{surviving.PID, leaving.PID, 13, 14}, read)
	if !errors.Is(err, unreadable) {
		t.Fatalf("inventory reported %v, want the unreadable process", err)
	}
	if len(present) != 1 || !Same(present[0], surviving) {
		t.Fatalf("inventory reported %+v, want only the process that was still present", present)
	}
	if reads[leaving.PID] != 2 {
		t.Fatalf("the leaving process was read %d times, want a confirming read before it is reported", reads[leaving.PID])
	}
}

// An exited process that has not been reaped is still present, so an inventory
// reports it and leaves the caller's cleanup assertions to judge it.
func TestInventoryReportsUnreapedProcesses(t *testing.T) {
	cmd := exec.Command("/bin/sleep", "0")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	pid := cmd.Process.Pid
	defer func() { _ = cmd.Wait() }()
	deadline := time.Now().Add(10 * time.Second)
	for {
		p, err := Read(pid)
		if err != nil && !Exited(err) {
			t.Fatalf("reading the unreaped process %d: %v", pid, err)
		}
		if err == nil && !Live(p) {
			present, inventoryErr := Inventory([]int{pid})
			if inventoryErr != nil || len(present) != 1 || present[0].PID != pid || Live(present[0]) {
				t.Fatalf("inventory of the unreaped process: %+v %v", present, inventoryErr)
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("process %d did not exit within its bound", pid)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestDescendantsListsLiveChildren(t *testing.T) {
	child := exec.Command("/bin/sleep", "30")
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = child.Process.Kill()
		_ = child.Wait()
	})
	children, err := Descendants(os.Getpid())
	if err != nil {
		t.Fatalf("descendants of this process: %v", err)
	}
	if !slices.Contains(children, child.Process.Pid) {
		t.Fatalf("descendants %v do not contain the live child %d", children, child.Process.Pid)
	}
	present, err := Inventory(children)
	if err != nil {
		t.Fatalf("inventory of the listed descendants: %v", err)
	}
	index := slices.IndexFunc(present, func(p Process) bool { return p.PID == child.Process.Pid })
	if index < 0 {
		t.Fatalf("inventory %+v does not contain the live child %d", present, child.Process.Pid)
	}
	if p := present[index]; p.Parent != os.Getpid() || !Live(p) || !strings.HasSuffix(p.Executable, "/sleep") {
		t.Fatalf("the live child was reported as %+v", p)
	}
}

func TestDescendantsToleratesExitedProcesses(t *testing.T) {
	pid := exitedPID(t)
	children, err := Descendants(os.Getpid())
	if err != nil {
		t.Fatalf("descendants of this process: %v", err)
	}
	if slices.Contains(children, pid) {
		t.Fatalf("descendants %v still contain the exited child %d", children, pid)
	}
	listed, err := Descendants(pid)
	if err != nil || len(listed) != 0 {
		t.Fatalf("descendants of the exited process %d: %v %v", pid, listed, err)
	}
}
