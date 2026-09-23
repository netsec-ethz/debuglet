//go:build linux && canary_integration

package main

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/netsec-ethz/debuglet/internal/acceptance/procinventory"
	"github.com/netsec-ethz/debuglet/internal/demo"
	"golang.org/x/sys/unix"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// Both acceptance harnesses read processes through the same inventory: a
// process that exits between being listed and being read has already exited,
// and only processes still present when an inventory completes are reported.
type processIdentity = procinventory.Process

// confirm re-reads an owned process. A process that has exited or become a
// zombie is gone; one whose identity no longer matches is a different process
// on the same PID, which is never signal authority.
func confirm(p processIdentity, what string) (bool, error) {
	current, err := procinventory.Read(p.PID)
	if procinventory.Exited(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if !procinventory.Live(current) {
		return false, nil
	}
	if !procinventory.Same(p, current) {
		return false, errors.New(what + " identity changed during observation")
	}
	return true, nil
}

type listenerIdentity struct {
	Inode   string `json:"inode"`
	Address string `json:"address"`
}

func listeningSockets() (map[string]listenerIdentity, error) {
	found := map[string]listenerIdentity{}
	for _, path := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		data, err := os.ReadFile(path)
		if os.IsNotExist(err) && strings.HasSuffix(path, "tcp6") {
			continue
		}
		if err != nil {
			return nil, err
		}
		for _, line := range strings.Split(string(data), "\n")[1:] {
			f := strings.Fields(line)
			if len(f) < 10 || f[3] != "0A" {
				continue
			}
			parts := strings.Split(f[1], ":")
			if len(parts) != 2 {
				continue
			}
			raw, err := hex.DecodeString(parts[0])
			if err != nil {
				continue
			}
			for i := 0; i < len(raw); i += 4 {
				raw[i], raw[i+3] = raw[i+3], raw[i]
				raw[i+1], raw[i+2] = raw[i+2], raw[i+1]
			}
			port, err := strconv.ParseUint(parts[1], 16, 16)
			if err != nil {
				continue
			}
			found[f[9]] = listenerIdentity{Inode: f[9], Address: net.JoinHostPort(net.IP(raw).String(), strconv.FormatUint(port, 10))}
		}
	}
	return found, nil
}

// Read only bounded regular files through a pinned, nonsymlink immediate
// parent directory. O_NONBLOCK prevents a candidate-created FIFO from wedging
// the harness before its watchdog can be checked.
func boundedCandidateFile(path string, limit int64) ([]byte, error) {
	parent, err := unix.Open(filepath.Dir(path), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	defer unix.Close(parent)
	fd, err := unix.Openat(parent, filepath.Base(path), unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > limit {
		return nil, errors.New("candidate observation is not a bounded regular file")
	}
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, errors.New("candidate observation exceeds limit")
	}
	return data, nil
}

type canaryOwnership struct {
	processes map[int]processIdentity
	sockets   map[string]listenerIdentity
	dirs      map[string]bool
	pending   map[int]bool
}

func newCanaryOwnership() *canaryOwnership {
	return &canaryOwnership{processes: map[int]processIdentity{}, sockets: map[string]listenerIdentity{}, dirs: map[string]bool{}, pending: map[int]bool{}}
}
func (o *canaryOwnership) discover(parent processIdentity, assets demo.Assets) error {
	expected := map[string]bool{assets.CLI: true, assets.Dispatcher: true, assets.Executor: true}
	if live, err := confirm(parent, "driver"); err != nil || !live {
		return err
	}
	queue := []processIdentity{parent}
	visited := map[int]bool{}
	for len(queue) > 0 {
		owner := queue[0]
		queue = queue[1:]
		if visited[owner.PID] {
			continue
		}
		visited[owner.PID] = true
		live, err := confirm(owner, "parent")
		if err != nil {
			return err
		}
		if !live {
			continue
		}
		if err := o.captureSockets(owner); err != nil && !procinventory.Exited(err) {
			return err
		}
		children, err := procinventory.Descendants(owner.PID)
		if err != nil {
			return err
		}
		for _, pid := range children {
			child, readErr := procinventory.Read(pid)
			if readErr != nil {
				if _, err := o.admitChild(pid, child, readErr, owner, expected); err != nil {
					return err
				}
				continue
			}
			// Corroborate the parent after the child snapshot: readiness and argv[0]
			// never confer ownership of an unrelated same-binary process.
			live, err := confirm(owner, "parent")
			if err != nil {
				return err
			}
			if !live {
				continue
			}
			admitted, err := o.admitChild(pid, child, nil, owner, expected)
			if err != nil {
				return err
			}
			if admitted {
				queue = append(queue, child)
			}
		}
	}
	return nil
}

// A procfs children list can expose fork before Setpgid or exec. An
// unqualified snapshot is pending observation, never signal authority. Once a
// stable installed child qualifies, its executable/start/group stay immutable.
func (o *canaryOwnership) admitChild(pid int, child processIdentity, readErr error, owner processIdentity, expected map[string]bool) (bool, error) {
	prior, owned := o.processes[pid]
	if procinventory.Exited(readErr) {
		delete(o.pending, pid)
		return false, nil
	}
	if readErr != nil {
		if owned {
			return false, readErr
		}
		o.pending[pid] = true
		return false, nil
	}
	if owned {
		if child.Start != prior.Start || child.Group != prior.Group || procinventory.Live(child) && child.Executable != prior.Executable {
			return false, errors.New("refusing replacement for already owned child identity")
		}
		return procinventory.Live(child) && child.Parent == owner.PID, nil
	}
	if !procinventory.Live(child) {
		delete(o.pending, pid)
		return false, nil
	}
	if child.PID != pid || child.Parent != owner.PID || child.Group != child.PID || !expected[child.Executable] {
		o.pending[pid] = true
		return false, nil
	}
	o.processes[pid] = child
	delete(o.pending, pid)
	return true, nil
}

func (o *canaryOwnership) captureSockets(p processIdentity) error {
	entries, err := os.ReadDir(fmt.Sprintf("/proc/%d/fd", p.PID))
	if err != nil {
		return err
	}
	sockets, err := listeningSockets()
	if err != nil {
		return err
	}
	if live, err := confirm(p, "process"); err != nil || !live {
		return err
	}
	for _, entry := range entries {
		link, err := os.Readlink(fmt.Sprintf("/proc/%d/fd/%s", p.PID, entry.Name()))
		if err != nil || !strings.HasPrefix(link, "socket:[") {
			continue
		}
		inode := strings.TrimSuffix(strings.TrimPrefix(link, "socket:["), "]")
		if socket, ok := sockets[inode]; ok {
			o.sockets[inode] = socket
		}
	}
	return nil
}
func (o *canaryOwnership) corroborate(pid int, path string) (processIdentity, bool) {
	p, ok := o.processes[pid]
	if !ok || p.Executable != path {
		return p, false
	}
	current, err := procinventory.Read(pid)
	return p, err == nil && procinventory.Same(p, current) && procinventory.Live(current)
}
func (o *canaryOwnership) verifyGone() error {
	var result error
	for pid := range o.pending {
		if _, err := procinventory.Read(pid); !procinventory.Exited(err) {
			result = errors.Join(result, errors.New("unqualified observed child remains or cannot be identified; no signal authority"))
		}
	}
	// Only a process still present when this inventory completes is a failed
	// cleanup; one that exits while it runs was cleaned up before the harness.
	owned := make([]int, 0, len(o.processes))
	for pid := range o.processes {
		owned = append(owned, pid)
	}
	remaining, err := procinventory.Inventory(owned)
	result = errors.Join(result, err)
	present := make(map[int]processIdentity, len(remaining))
	for _, p := range remaining {
		present[p.PID] = p
	}
	for _, p := range o.processes {
		current, live := present[p.PID]
		if live && current.Start == p.Start {
			result = errors.Join(result, fmt.Errorf("owned process %d remains", p.PID))
		}
		if live && current.Start != p.Start {
			continue
		}
		if p.Group == p.PID {
			if err := syscall.Kill(-p.Group, 0); !errors.Is(err, syscall.ESRCH) {
				result = errors.Join(result, fmt.Errorf("owned group %d remains", p.Group))
			}
		}
	}
	sockets, socketErr := listeningSockets()
	result = errors.Join(result, socketErr)
	for inode := range o.sockets {
		if _, ok := sockets[inode]; ok {
			result = errors.Join(result, errors.New("owned listener remains"))
		}
	}
	for dir := range o.dirs {
		if _, err := os.Lstat(dir); !os.IsNotExist(err) {
			result = errors.Join(result, errors.New("owned state remains"))
		}
	}
	return result
}
func (o *canaryOwnership) emergencyKill() {
	groups := map[int]bool{}
	for _, p := range o.processes {
		if p.Group == p.PID {
			groups[p.Group] = true
		}
	}
	for _, p := range o.processes {
		current, err := procinventory.Read(p.PID)
		if err != nil || !procinventory.Same(p, current) || !procinventory.Live(current) {
			continue
		}
		// The same frozen member still corroborates this owned group, even if its
		// original leader exited. Never signal a merely reused numeric PID/PGID.
		if groups[p.Group] {
			_ = syscall.Kill(-p.Group, syscall.SIGCONT)
			_ = syscall.Kill(-p.Group, syscall.SIGKILL)
		} else {
			_ = syscall.Kill(p.PID, syscall.SIGKILL)
		}
	}
}

// Negative controls run inside the named gate; the CI selector cannot silently
// omit its ownership assertions while reporting TestCanaryLocal as passed.
func ownershipControls(t *testing.T, fixture string) {
	t.Helper()
	transitionAdmissionControls(t)
	for _, name := range []string{"ready", "config", "result"} {
		path := filepath.Join(fixture, name+"-fifo")
		if err := syscall.Mkfifo(path, 0600); err != nil {
			t.Fatal(err)
		}
		started := time.Now()
		if _, err := boundedCandidateFile(path, 4096); err == nil {
			t.Fatal("accepted candidate FIFO")
		}
		if time.Since(started) > time.Second {
			t.Fatal("FIFO check was not bounded")
		}
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, make([]byte, 4097), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := boundedCandidateFile(path, 4096); err == nil {
			t.Fatal("accepted oversized candidate file")
		}
	}
	sibling, err := demo.StartChild(demo.ChildSpec{Path: "/bin/sleep", Dir: fixture, Args: []string{"60"}, Env: []string{}, Stdout: io.Discard, Stderr: io.Discard})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		ctx, end := context.WithTimeout(context.Background(), 2*time.Second)
		defer end()
		if err := sibling.Stop(ctx); err != nil {
			t.Error(err)
		}
	}()
	identity, err := procinventory.Read(sibling.PID())
	if err != nil {
		t.Fatal(err)
	}
	track := newCanaryOwnership()
	// Identical executable paths and candidate-provided PIDs do not authorize a
	// same-binary sibling. An empty independently discovered set refuses it.
	if _, ok := track.corroborate(identity.PID, identity.Executable); ok {
		t.Fatal("forged readiness granted ownership")
	}
	stale := identity
	stale.Start = "0"
	track.processes[stale.PID] = stale
	if _, ok := track.corroborate(stale.PID, stale.Executable); ok {
		t.Fatal("stale PID identity accepted")
	}
	track.emergencyKill()
	if channelClosed(sibling.Done()) || syscall.Kill(sibling.PID(), 0) != nil {
		t.Fatal("stale identity signalled unrelated sibling")
	}
	// A live group that was independently created by this harness is a failed
	// cleanup observation. Removing the record would hide this required failure.
	track.processes[identity.PID] = identity
	if track.verifyGone() == nil {
		t.Fatal("surviving process/group accepted as cleaned")
	}
	delete(track.processes, identity.PID)
	for _, name := range []string{"state-first", "state-secondary"} {
		dir := filepath.Join(fixture, name)
		if err := os.Mkdir(dir, 0700); err != nil {
			t.Fatal(err)
		}
		track.dirs[dir] = true
	}
	if err := os.Remove(filepath.Join(fixture, "state-first")); err != nil {
		t.Fatal(err)
	}
	if track.verifyGone() == nil {
		t.Fatal("secondary state directory leak ignored")
	}
	if err := os.Remove(filepath.Join(fixture, "state-secondary")); err != nil {
		t.Fatal(err)
	}
}

func transitionAdmissionControls(t *testing.T) {
	t.Helper()
	owner := processIdentity{PID: 100, Group: 100, Start: "1", Executable: "/driver", State: "S"}
	child := processIdentity{PID: 101, Parent: 100, Group: 100, Start: "2", Executable: "/driver", State: "S"}
	expected := map[string]bool{"/installed/bin/dbl": true}
	track := newCanaryOwnership()
	if admitted, err := track.admitChild(child.PID, child, nil, owner, expected); err != nil || admitted || len(track.processes) != 0 || !track.pending[child.PID] {
		t.Fatal("pre-exec snapshot gained ownership or failed the observer")
	}
	if admitted, err := track.admitChild(child.PID, processIdentity{}, errors.New("identity changed during observation"), owner, expected); err != nil || admitted || len(track.processes) != 0 {
		t.Fatal("mixed initial snapshot failed the observer or gained ownership")
	}
	child.Group = child.PID // Setpgid alone still does not qualify pre-exec bytes.
	if admitted, err := track.admitChild(child.PID, child, nil, owner, expected); err != nil || admitted {
		t.Fatal("pre-exec child qualified after Setpgid alone")
	}
	child.Executable = "/installed/bin/dbl"
	if admitted, err := track.admitChild(child.PID, child, nil, owner, expected); err != nil || !admitted || track.pending[child.PID] {
		t.Fatal("stable installed exec was not admitted")
	}
	for _, field := range []string{"start", "group", "executable"} {
		changed := child
		switch field {
		case "start":
			changed.Start = "3"
		case "group":
			changed.Group = owner.Group
		case "executable":
			changed.Executable = "/other"
		}
		if admitted, err := track.admitChild(child.PID, changed, nil, owner, expected); err == nil || admitted || !procinventory.Same(track.processes[child.PID], child) {
			t.Fatal("already owned identity was replaced:", field)
		}
	}
	if _, err := track.admitChild(child.PID, processIdentity{}, errors.New("changed owned snapshot"), owner, expected); err == nil {
		t.Fatal("uncertain already owned identity was silently reset")
	}
}
