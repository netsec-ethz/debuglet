//go:build linux && demoacceptance

package demo

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/netsec-ethz/debuglet/internal/acceptance/procinventory"
	"github.com/netsec-ethz/debuglet/internal/readiness"
)

// Both acceptance harnesses read processes through the same inventory: a
// process that exits between being listed and being read has already exited,
// and only processes still present when an inventory completes are reported.
type processIdentity = procinventory.Process
type listenerIdentity struct {
	Inode   string `json:"inode"`
	Address string `json:"address"`
}
type ownership struct {
	mu        sync.Mutex
	processes map[int]processIdentity
	listeners map[string]listenerIdentity
	dirs      map[string]bool
	err       error
}

func newOwnership() *ownership {
	return &ownership{processes: map[int]processIdentity{}, listeners: map[string]listenerIdentity{}, dirs: map[string]bool{}}
}
func (o *ownership) recordError(err error) {
	// A process may exit between a procfs enumeration and the next read, and a
	// candidate file that is not there yet is an absence, not a failed read.
	if err == nil || procinventory.Exited(err) {
		return
	}
	o.mu.Lock()
	o.err = errors.Join(o.err, err)
	o.mu.Unlock()
}
func (o *ownership) directory(path string) { o.mu.Lock(); o.dirs[path] = true; o.mu.Unlock() }
func (o *ownership) process(pid int) {
	p, err := procinventory.Read(pid)
	if err != nil {
		o.recordError(err)
		return
	}
	if o.remember(p) {
		o.captureListeners(pid, "")
	}
}
func (o *ownership) remember(p processIdentity) bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	if original, exists := o.processes[p.PID]; exists {
		if !procinventory.Same(original, p) {
			o.err = errors.Join(o.err, fmt.Errorf("owned PID %d identity changed; refusing replacement", p.PID))
			return false
		}
		return true
	}
	o.processes[p.PID] = p
	return true
}
func (o *ownership) owned(pid int) (processIdentity, bool) {
	o.mu.Lock()
	p, ok := o.processes[pid]
	o.mu.Unlock()
	if !ok {
		return processIdentity{}, false
	}
	current, err := procinventory.Read(pid)
	return p, err == nil && procinventory.Same(p, current) && procinventory.Live(current)
}
func signalOwned(p processIdentity, signal syscall.Signal) error {
	current, err := procinventory.Read(p.PID)
	if err != nil {
		return err
	}
	if !procinventory.Same(p, current) || !procinventory.Live(current) {
		return fmt.Errorf("refusing to signal changed PID %d", p.PID)
	}
	return syscall.Kill(p.PID, signal)
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
func (o *ownership) captureListeners(pid int, address string) {
	entries, err := os.ReadDir(fmt.Sprintf("/proc/%d/fd", pid))
	if err != nil {
		o.recordError(err)
		return
	}
	sockets, err := listeningSockets()
	if err != nil {
		o.recordError(err)
		return
	}
	for _, entry := range entries {
		link, err := os.Readlink(fmt.Sprintf("/proc/%d/fd/%s", pid, entry.Name()))
		if err != nil || !strings.HasPrefix(link, "socket:[") {
			continue
		}
		inode := strings.TrimSuffix(strings.TrimPrefix(link, "socket:["), "]")
		if socket, ok := sockets[inode]; ok && (address == "" || socket.Address == address) {
			o.mu.Lock()
			o.listeners[inode] = socket
			o.mu.Unlock()
		}
	}
}
func (o *ownership) snapshot() ([]processIdentity, []listenerIdentity, []string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	var p []processIdentity
	var l []listenerIdentity
	var d []string
	for _, v := range o.processes {
		p = append(p, v)
	}
	for _, v := range o.listeners {
		l = append(l, v)
	}
	for v := range o.dirs {
		d = append(d, v)
	}
	return p, l, d
}
func (o *ownership) verifyGone() error {
	processes, listeners, dirs := o.snapshot()
	o.mu.Lock()
	result := o.err
	o.mu.Unlock()
	owned := make([]int, 0, len(processes))
	for _, p := range processes {
		owned = append(owned, p.PID)
	}
	// Only a process still present when this inventory completes is a failed
	// cleanup; one that exits while it runs was cleaned up before the harness.
	remaining, inventoryErr := procinventory.Inventory(owned)
	result = errors.Join(result, inventoryErr)
	present := make(map[int]processIdentity, len(remaining))
	for _, p := range remaining {
		present[p.PID] = p
	}
	for _, p := range processes {
		current, live := present[p.PID]
		if live && current.Start == p.Start {
			result = errors.Join(result, fmt.Errorf("owned process %d remains", p.PID))
		}
		// If this PID was reused, the original group identity has gone too. Never
		// signal or attribute a newly created unrelated process to the demo.
		if live && current.Start != p.Start {
			continue
		}
		if p.Group == p.PID {
			if err := syscall.Kill(-p.Group, 0); !errors.Is(err, syscall.ESRCH) {
				result = errors.Join(result, fmt.Errorf("owned process group %d remains: %v", p.Group, err))
			}
		}
	}
	sockets, err := listeningSockets()
	if err != nil {
		result = errors.Join(result, err)
	} else {
		for _, s := range listeners {
			if _, ok := sockets[s.Inode]; ok {
				result = errors.Join(result, fmt.Errorf("owned listener remains: %+v", s))
			}
		}
	}
	// Socket identity, rather than port number, permits legitimate port reuse.
	for _, dir := range dirs {
		if _, err := os.Lstat(dir); !os.IsNotExist(err) {
			result = errors.Join(result, fmt.Errorf("owned state remains at %s: %v", dir, err))
		}
	}
	return result
}
func (o *ownership) emergencyKill() error {
	processes, _, _ := o.snapshot()
	groups := map[int]bool{}
	for _, p := range processes {
		if p.PID == p.Group {
			groups[p.Group] = false
		}
	}
	for _, p := range processes {
		current, err := procinventory.Read(p.PID)
		if err == nil && procinventory.Same(current, p) {
			if _, owned := groups[p.Group]; owned {
				// A still-live independently captured member corroborates the
				// original group even after its leader has exited.
				_ = syscall.Kill(-p.Group, syscall.SIGCONT)
				_ = syscall.Kill(-p.Group, syscall.SIGKILL)
				groups[p.Group] = true
			}
		}
	}
	var result error
	for group, signalled := range groups {
		if !signalled && !errors.Is(syscall.Kill(-group, 0), syscall.ESRCH) {
			result = errors.Join(result, fmt.Errorf("cannot prove remaining group %d ownership; refusing emergency signal", group))
		}
	}
	return result
}

// Each CLI gets an unrelated empty working directory and a dedicated TMPDIR.
// Procfs observation belongs only to the test harness; the installed command
// receives no observer or fault-injection environment switches.
func (h *installedHarness) cliCase(t *testing.T, mode string) Result {
	t.Helper()
	base := t.TempDir()
	cwd := filepath.Join(base, "unrelated working directory")
	tmp := filepath.Join(base, "private temporary root")
	for _, dir := range []string{cwd, tmp} {
		if err := os.Mkdir(dir, 0700); err != nil {
			t.Error(err)
			return Result{}
		}
	}
	args := []string{"--output", "json", "demo"}
	bound := 66 * time.Second
	var deadline time.Duration
	if mode == "timeout" {
		// The deadline under test also bounds the demo's own bootstrap, so it
		// is derived from the startups observed on this host rather than fixed
		// short. The harness bound covers that deadline and the cleanup budget.
		deadline = h.timeoutDeadline()
		args = []string{"--timeout", deadline.String(), "--output", "json", "demo"}
		bound = deadline + cleanupTimeout + 2*time.Second
	}
	if mode == "sigint" {
		bound = 9 * time.Second
	}
	var out, stderr acceptanceBuffer
	track := newOwnership()
	child, err := StartChild(ChildSpec{Path: h.entry, Dir: cwd, Args: args, Env: acceptanceEnvironment(tmp), Stdout: &out, Stderr: &stderr})
	if err != nil {
		t.Error(err)
		return Result{}
	}
	track.process(child.PID())
	started := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), bound)
	defer cancel()
	var suspended *processIdentity
	var resumeAt time.Time
	var startupAt time.Time
	startupObserved, signalSent := false, false
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	var runErr error
	timedOut := false
loop:
	for {
		if isDone(child.Done()) {
			runErr = child.Wait(context.Background())
			break loop
		}
		dispatcher, found := captureCLIState(track, child.PID(), tmp, h.assets)
		if found && !startupObserved {
			startupObserved = true
			startupAt = time.Now()
			if strings.HasPrefix(mode, "concurrent_") {
				h.mu.Lock()
				if h.concurrentReady == nil {
					h.concurrentReady = map[string]readyChild{}
				}
				for _, other := range h.concurrentReady {
					p, err := procinventory.Read(other.dispatcher.PID)
					otherCLI, cliErr := procinventory.Read(other.child.PID())
					thisCLI, thisLive := track.owned(child.PID())
					if err == nil && procinventory.Same(other.dispatcher, p) && procinventory.Live(p) && cliErr == nil && procinventory.Same(other.cli, otherCLI) && procinventory.Live(otherCLI) && thisLive && procinventory.Live(thisCLI) && !isDone(other.child.Done()) && !isDone(child.Done()) {
						h.concurrentOverlap = true
					}
				}
				if cli, ok := track.owned(child.PID()); ok {
					h.concurrentReady[mode] = readyChild{child: child, cli: cli, dispatcher: dispatcher}
				}
				h.mu.Unlock()
			}
			switch mode {
			case "sigint":
				p, ok := track.owned(child.PID())
				if !ok {
					runErr = errors.New("installed CLI identity disappeared before SIGINT")
					break loop
				}
				if err := signalOwned(p, syscall.SIGINT); err != nil {
					runErr = err
					break loop
				}
				signalSent = true
			case "timeout":
				if err := signalOwned(dispatcher, syscall.SIGSTOP); err != nil {
					runErr = err
					break loop
				}
				suspended = &dispatcher
				// Releasing the daemon before the deadline expires would let
				// the run complete instead of timing out. This release is
				// failure safety for a candidate that outlives its deadline.
				resumeAt = started.Add(deadline + time.Second)
				signalSent = true
			}
		}
		_, cliLive := track.owned(child.PID())
		if suspended != nil && !time.Now().Before(resumeAt) && cliLive {
			// Fault release is permitted only while the candidate is still active.
			// Once it exits, observe leaks before any harness signal can repair them.
			if isDone(child.Done()) {
				runErr = child.Wait(context.Background())
				break loop
			}
			_ = signalOwned(*suspended, syscall.SIGCONT)
			suspended = nil
		}
		select {
		case <-child.Done():
			runErr = child.Wait(context.Background())
			break loop
		case <-ctx.Done():
			runErr = ctx.Err()
			timedOut = true
			t.Error("installed CLI exceeded execution and cleanup budget")
			break loop
		case <-ticker.C:
		}
	}
	// The deadline under test is honoured by the installed command, so it is
	// measured here; the harness verification below belongs to no budget of its.
	exitedAt := time.Now()
	// Child.Done joins the installed CLI's own stdout/stderr readers. Capture
	// remaining state once more before checking cleanup or killing anything.
	captureCLIState(track, child.PID(), tmp, h.assets)
	cleanErr := track.verifyGone()
	for _, dir := range []string{tmp, cwd} {
		entries, dirErr := os.ReadDir(dir)
		if dirErr != nil || len(entries) != 0 {
			cleanErr = errors.Join(cleanErr, fmt.Errorf("CLI directory %s not empty: entries=%d error=%v", dir, len(entries), dirErr))
		}
	}
	finishedAt := time.Now()
	h.mu.Lock()
	if h.intervals == nil {
		h.intervals = map[string]liveInterval{}
	}
	h.intervals[mode] = liveInterval{start: startupAt, end: finishedAt}
	if startupObserved && mode != "timeout" {
		// An observed bootstrap on this host sizes the timeout case's deadline.
		h.startups = append(h.startups, startupAt.Sub(started))
	}
	h.mu.Unlock()
	e := installedEvidence{Case: mode, Expected: "success", DurationMS: time.Since(started).Milliseconds(), StartupObserved: startupObserved, StartupAt: startupAt, FinishedAt: finishedAt, FaultObserved: signalSent, CleanupBeforeHarness: cleanErr == nil && !timedOut, Diagnostics: stderr.String()}
	if runErr != nil {
		e.Error = runErr.Error()
		var exit interface{ ExitCode() int }
		if errors.As(runErr, &exit) {
			e.ExitCode = exit.ExitCode()
		} else {
			e.ExitCode = -1
		}
	}
	e.Processes, e.Listeners, e.StateDirectories = track.snapshot()
	if mode == "timeout" {
		// The bootstrap budget and the deadline under test are separate; the
		// evidence records the derived deadline and which one this run reached.
		e.Observation = map[string]any{"deadline_ms": deadline.Milliseconds(), "bootstrap_observed": startupObserved}
		if startupObserved {
			e.Observation["bootstrap_ms"] = startupAt.Sub(started).Milliseconds()
		}
	}
	minimumProcesses := 3
	if mode == "timeout" || mode == "sigint" {
		minimumProcesses = 2
	}
	if len(e.Processes) < minimumProcesses || len(e.Listeners) < 3 || len(e.StateDirectories) != 1 {
		t.Errorf("incomplete CLI ownership evidence: processes=%d listeners=%d directories=%d", len(e.Processes), len(e.Listeners), len(e.StateDirectories))
	}
	failure := mode == "timeout" || mode == "sigint"
	if failure {
		e.Expected = "failure"
		want := 124
		if mode == "sigint" {
			want = 130
		}
		switch {
		case mode == "timeout" && !startupObserved:
			// A bootstrap that outran the derived deadline is a slow host, not
			// a timeout the candidate failed to honour after its startup.
			t.Errorf("installed timeout: bootstrap did not reach the started marker within the %s deadline derived for this host: exit=%d stderr=%s", deadline, e.ExitCode, stderr.String())
		case !startupObserved || !signalSent || e.ExitCode != want || out.String() != "":
			t.Errorf("installed %s: started=%t signalled=%t exit=%d stdout=%q stderr=%s", mode, startupObserved, signalSent, e.ExitCode, out.String(), stderr.String())
		case mode == "timeout" && exitedAt.Sub(started) < deadline:
			// Only the deadline under test may end this run with its exit code.
			t.Errorf("installed timeout: exit %d after %s, before its %s deadline: %s", e.ExitCode, exitedAt.Sub(started), deadline, stderr.String())
		}
	} else {
		if runErr != nil {
			t.Errorf("installed demo: %v: %s", runErr, stderr.String())
		}
		if err := decodeOne(out.Bytes(), &e.Result); err != nil {
			t.Errorf("installed JSON: %v: %s", err, out.String())
		}
		if e.Result.Version != h.assets.Manifest.Version || e.Result.Cleanup != "complete" || e.Result.State != "RunStateExited" || !startupObserved {
			t.Errorf("installed result/startup: %+v observed=%t", e.Result, startupObserved)
		}
	}
	if out.Overflow() || stderr.Overflow() {
		t.Error("installed command exceeded harness output bound")
	}
	if cleanErr != nil {
		t.Error("installed cleanup before harness intervention:", cleanErr)
	}
	h.save(t, e)
	// Never count this fallback as acceptance evidence. It runs only after the
	// candidate's observed outcome and remaining resources have been recorded.
	if suspended != nil {
		_ = signalOwned(*suspended, syscall.SIGCONT)
	}
	if !isDone(child.Done()) || cleanErr != nil {
		if err := track.emergencyKill(); err != nil {
			t.Error("emergency cleanup incomplete:", err)
		}
		join, end := context.WithTimeout(context.Background(), 2*time.Second)
		_ = child.Wait(join)
		end()
	}
	return e.Result
}
func captureCLIState(track *ownership, cliPID int, tmp string, assets Assets) (processIdentity, bool) {
	if cli, ok := track.owned(cliPID); ok {
		track.captureListeners(cliPID, "")
		discoverChildren(track, cli, assets, true)
	}
	entries, err := os.ReadDir(tmp)
	track.recordError(err)
	var dispatcher processIdentity
	found := false
	for _, entry := range entries {
		if !entry.IsDir() || !strings.HasPrefix(entry.Name(), "debuglet-demo-") {
			continue
		}
		dir := filepath.Join(tmp, entry.Name())
		track.directory(dir)
		for _, name := range []string{"dispatcher-ready.json", "executor-ready.json"} {
			data, err := readRegularFile(filepath.Join(dir, name), readyLimit)
			if err != nil {
				track.recordError(err)
				continue
			}
			var record readiness.Record
			if json.Unmarshal(data, &record) != nil || record.SchemaVersion != 1 || record.PID <= 0 {
				continue
			}
			// A ready file only corroborates an independently observed child.
			// Candidate-controlled bytes must never grant permission to signal a PID.
			p, owned := track.owned(record.PID)
			if !owned || p.Parent != cliPID {
				continue
			}
			if name == "dispatcher-ready.json" && p.Executable == assets.Dispatcher && validateAddress(record.HTTPAddr) == nil && validateAddress(record.GRPCAddr) == nil {
				// Readiness can appear after this poll's initial socket capture.
				// Capture the CLI target and daemon sockets before SIGINT can
				// close them; waiting for the next poll would lose valid evidence.
				track.captureListeners(cliPID, "")
				track.captureListeners(p.PID, "")
				dispatcher = p
				found = true
			}
		}
	}
	return dispatcher, found
}

func discoverChildren(track *ownership, parent processIdentity, assets Assets, direct bool) {
	children, err := procinventory.Descendants(parent.PID)
	track.recordError(err)
	for _, pid := range children {
		p, err := procinventory.Read(pid)
		if err != nil {
			// A new child can still be crossing fork/exec or Setpgid. Do
			// not grant ownership or fail on a mixed transitional snapshot.
			track.mu.Lock()
			_, alreadyOwned := track.processes[pid]
			track.mu.Unlock()
			if alreadyOwned {
				track.recordError(err)
			}
			continue
		}
		currentParent, err := procinventory.Read(parent.PID)
		if err != nil || !procinventory.Same(parent, currentParent) || p.Parent != parent.PID {
			continue
		}
		if direct && (p.Group != p.PID || (p.Executable != assets.Dispatcher && p.Executable != assets.Executor)) {
			// Procfs can expose fork before exec or Setpgid has completed.
			// Keep this PID unowned until a later observation qualifies it;
			// it cannot supply readiness or receive any harness signal yet.
			continue
		}
		if track.remember(p) {
			track.captureListeners(pid, "")
			// One more generation captures an independently witnessed daemon
			// child for safe group cleanup even if its leader exits first.
			if direct {
				discoverChildren(track, p, assets, false)
			}
		}
	}
}

// These small negative witnesses protect the harness itself: a broken
// candidate must not cause its observer to own or signal an unrelated PID.
func (h *installedHarness) ownershipGuards(t *testing.T) {
	t.Run("ready_pid_cannot_grant_ownership", func(t *testing.T) {
		tmp := t.TempDir()
		dir := filepath.Join(tmp, "debuglet-demo-forged")
		if err := os.Mkdir(dir, 0700); err != nil {
			t.Fatal(err)
		}
		data, err := json.Marshal(readiness.Record{SchemaVersion: 1, PID: h.sibling.PID(), HTTPAddr: "127.0.0.1:1", GRPCAddr: "127.0.0.1:2"})
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "dispatcher-ready.json"), data, 0600); err != nil {
			t.Fatal(err)
		}
		track := newOwnership()
		if _, ready := captureCLIState(track, 0, tmp, h.assets); ready {
			t.Error("forged sibling readiness accepted")
		}
		processes, _, _ := track.snapshot()
		if len(processes) != 0 {
			t.Error("candidate readiness granted PID ownership")
		}
		if err := track.emergencyKill(); err != nil || isDone(h.sibling.Done()) {
			t.Errorf("forged readiness affected sibling: %v", err)
		}
	})
	t.Run("initial_identity_is_immutable", func(t *testing.T) {
		p, err := procinventory.Read(h.sibling.PID())
		if err != nil {
			t.Fatal(err)
		}
		track := newOwnership()
		if !track.remember(p) {
			t.Fatal("initial identity was rejected")
		}
		reused := p
		reused.Start += "-different"
		if track.remember(reused) {
			t.Error("replacement identity was accepted")
		}
		got, _, _ := track.snapshot()
		if len(got) != 1 || !procinventory.Same(got[0], p) {
			t.Error("initial identity changed")
		}
		if err := signalOwned(reused, syscall.SIGCONT); err == nil {
			t.Error("replacement identity was allowed to signal")
		}
	})
	t.Run("surviving_process_fails_cleanup", func(t *testing.T) {
		sibling, err := procinventory.Read(h.sibling.PID())
		if err != nil {
			t.Fatal(err)
		}
		track := newOwnership()
		if !track.remember(sibling) {
			t.Fatal("the observed sibling identity was rejected")
		}
		// Only a process that has exited may be reported as cleaned up; one
		// that is still there is a failure the harness must not absorb.
		if track.verifyGone() == nil {
			t.Error("a surviving owned process was accepted as cleaned up")
		}
		if isDone(h.sibling.Done()) || syscall.Kill(h.sibling.PID(), 0) != nil {
			t.Error("verifying cleanup stopped the unrelated sibling")
		}
	})
	for _, mode := range []string{"fifo", "symlink", "oversized"} {
		t.Run("ready_"+mode+"_rejected", func(t *testing.T) {
			tmp := t.TempDir()
			dir := filepath.Join(tmp, "debuglet-demo-invalid")
			if err := os.Mkdir(dir, 0700); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(dir, "dispatcher-ready.json")
			var err error
			switch mode {
			case "fifo":
				err = syscall.Mkfifo(path, 0600)
			case "symlink":
				err = os.Symlink("/dev/null", path)
			case "oversized":
				err = os.WriteFile(path, make([]byte, readyLimit+1), 0600)
			}
			if err != nil {
				t.Fatal(err)
			}
			track := newOwnership()
			observed := make(chan bool, 1)
			go func() { _, ready := captureCLIState(track, 0, tmp, h.assets); observed <- ready }()
			var ready bool
			select {
			case ready = <-observed:
			case <-time.After(time.Second):
				t.Error("invalid readiness read exceeded its bound")
				// Release an accidentally opened FIFO reader, then join it. This
				// emergency action never changes the failed deadline assertion.
				if mode == "fifo" {
					if fd, err := syscall.Open(path, syscall.O_WRONLY|syscall.O_NONBLOCK, 0); err == nil {
						_ = syscall.Close(fd)
					}
				}
				select {
				case ready = <-observed:
				case <-time.After(time.Second):
					t.Error("invalid readiness observer did not join")
					return
				}
			}
			if ready || track.err == nil {
				t.Error("invalid readiness was not rejected and reported")
			}
		})
	}
}
