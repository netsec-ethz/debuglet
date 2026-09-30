// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package isolation

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"

	"github.com/google/uuid"
	"golang.org/x/sys/unix"
)

// Supervisor belongs to the node, not a reconnecting session. Reservations
// cover the larger phase memory limit until the process is reaped and its
// cgroup is removed, so aggregate pressure cannot select a healthy sibling.
type Supervisor struct {
	cfg              Config
	root             string
	queue, compiling chan struct{}
	mu               sync.Mutex
	memory, pids     int64
	closed           bool
}

func New(c Config) (result *Supervisor, resultErr error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	if !c.Shared() {
		return nil, nil
	}
	if !filepath.IsAbs(c.CgroupRoot) {
		return nil, errors.New("isolation cgroup root must be absolute")
	}
	var fs unix.Statfs_t
	if err := unix.Statfs(c.CgroupRoot, &fs); err != nil {
		return nil, err
	}
	if fs.Type != unix.CGROUP2_SUPER_MAGIC {
		return nil, errors.New("shared isolation requires cgroup v2")
	}
	controls, err := os.ReadFile(filepath.Join(c.CgroupRoot, "cgroup.subtree_control"))
	if err != nil {
		return nil, err
	}
	available := " " + strings.TrimSpace(string(controls)) + " "
	for _, name := range []string{"memory", "cpu", "pids"} {
		if !strings.Contains(available, " "+name+" ") {
			return nil, fmt.Errorf("delegated cgroup lacks enabled %s control", name)
		}
	}
	// The supervisor must run within the same delegation as its children.
	// This also catches an SSH/session scope which can create directories but
	// lacks permission to migrate processes into the delegated subtree.
	membership, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		return nil, err
	}
	inside := false
	for _, line := range strings.Split(string(membership), "\n") {
		if !strings.HasPrefix(line, "0::/") {
			continue
		}
		current := filepath.Join("/sys/fs/cgroup", strings.TrimPrefix(line, "0::/"))
		relative, err := filepath.Rel(c.CgroupRoot, current)
		inside = err == nil && relative != ".." && !strings.HasPrefix(relative, "../")
	}
	if !inside {
		return nil, errors.New("executor must run inside the configured cgroup delegation")
	}
	if err := checkControlCapacity(c, "/sys/fs/cgroup"); err != nil {
		return nil, err
	}
	root := filepath.Join(c.CgroupRoot, "debuglet-"+uuid.NewString())
	if err = os.Mkdir(root, 0700); err != nil {
		return nil, err
	}
	success := false
	defer func() {
		if !success {
			resultErr = errors.Join(resultErr, os.Remove(root))
		}
	}()
	if err = setLimits(root, c.NodeMemoryBytes, c.NodeCPUQuotaUS, c.NodePIDs); err != nil {
		return nil, err
	}
	if err = write(root, "cgroup.subtree_control", "+memory +cpu +pids"); err != nil {
		return nil, err
	}
	if _, err = os.Stat(filepath.Join(root, "cgroup.kill")); err != nil {
		return nil, errors.New("shared isolation requires cgroup.kill (Linux 5.14 or newer)")
	}
	success = true
	return &Supervisor{cfg: c, root: root, queue: make(chan struct{}, c.CompileConcurrency+c.CompileQueue), compiling: make(chan struct{}, c.CompileConcurrency)}, nil
}

func write(root, name, value string) error {
	return os.WriteFile(filepath.Join(root, name), []byte(value), 0600)
}
func setLimits(root string, memory, cpu, pids int64) error {
	for _, p := range [][2]string{{"memory.max", strconv.FormatInt(memory, 10)}, {"memory.swap.max", "0"}, {"memory.oom.group", "1"}, {"cpu.max", fmt.Sprintf("%d 100000", cpu)}, {"pids.max", strconv.FormatInt(pids, 10)}} {
		if err := write(root, p[0], p[1]); err != nil {
			return fmt.Errorf("set worker %s: %w", p[0], err)
		}
	}
	return nil
}

func (s *Supervisor) Config() Config { return s.cfg }
func (s *Supervisor) Close() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	if s.memory != 0 || len(s.queue) != 0 {
		return errors.New("isolation workers have not joined")
	}
	return os.Remove(s.root)
}

// Process is a private, single-run child. Only Close releases its reservation;
// caller timeout or worker exit alone cannot make capacity available again.
type Process struct {
	budgetFailed           atomic.Bool
	supervisor             *Supervisor
	root                   string
	cmd                    *exec.Cmd
	done                   chan struct{}
	compileOnce, closeOnce sync.Once
	closeErr               error
}

func (s *Supervisor) Start(ctx context.Context, child *os.File, argument string) (result *Process, resultErr error) {
	select {
	case s.queue <- struct{}{}:
	default:
		return nil, ErrAdmission
	}
	releaseQueue := true
	defer func() {
		if releaseQueue {
			<-s.queue
		}
	}()
	select {
	case s.compiling <- struct{}{}:
	case <-ctx.Done():
		return nil, context.Cause(ctx)
	}
	releaseCompile := true
	defer func() {
		if releaseCompile {
			<-s.compiling
		}
	}()
	s.mu.Lock()
	memory := max(s.cfg.CompileMemoryBytes, s.cfg.RunMemoryBytes)
	if s.closed || s.memory > s.cfg.NodeMemoryBytes-memory || s.pids > s.cfg.NodePIDs-s.cfg.WorkerPIDs {
		s.mu.Unlock()
		return nil, ErrAdmission
	}
	s.memory += memory
	s.pids += s.cfg.WorkerPIDs
	s.mu.Unlock()
	releaseMemory := true
	defer func() {
		if releaseMemory {
			s.release()
		}
	}()
	if err := ctx.Err(); err != nil {
		return nil, context.Cause(ctx)
	}
	root := filepath.Join(s.root, "run-"+uuid.NewString())
	if err := os.Mkdir(root, 0700); err != nil {
		return nil, err
	}
	remove := true
	defer func() {
		if remove {
			if cleanupErr := os.Remove(root); cleanupErr != nil {
				// An incomplete rollback is retained against the node budget. A caller's
				// failed Start cannot turn uncertain resource ownership into free capacity.
				releaseMemory = false
				resultErr = errors.Join(resultErr, cleanupErr)
			}
		}
	}()
	if err := setLimits(root, s.cfg.CompileMemoryBytes, s.cfg.CompileCPUQuotaUS, s.cfg.WorkerPIDs); err != nil {
		return nil, err
	}
	fd, err := os.Open(root)
	if err != nil {
		return nil, err
	}
	defer fd.Close()
	executable, err := os.Executable()
	if err != nil {
		return nil, err
	}
	cmd := exec.Command(executable, argument)
	cmd.Env = []string{"GOMAXPROCS=1", "GODEBUG=asyncpreemptoff=0", "DEBUGLET_WORKER_PARENT_PID=" + strconv.Itoa(os.Getpid())}
	cmd.ExtraFiles = []*os.File{child}
	cmd.Dir = "/"
	cmd.SysProcAttr = &syscall.SysProcAttr{UseCgroupFD: true, CgroupFD: int(fd.Fd()), Pdeathsig: syscall.SIGKILL}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start isolated worker: %w", err)
	}
	p := &Process{supervisor: s, root: root, cmd: cmd, done: make(chan struct{})}
	go func() { _ = cmd.Wait(); close(p.done) }()
	releaseQueue, releaseCompile, releaseMemory, remove = false, false, false, false
	return p, nil
}
func (s *Supervisor) release() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.memory -= max(s.cfg.CompileMemoryBytes, s.cfg.RunMemoryBytes)
	s.pids -= s.cfg.WorkerPIDs
}
func (p *Process) Compiled() {
	p.compileOnce.Do(func() { <-p.supervisor.compiling; <-p.supervisor.queue })
}
func (p *Process) RunLimits() error {
	c := p.supervisor.cfg
	return setLimits(p.root, c.RunMemoryBytes, c.RunCPUQuotaUS, c.WorkerPIDs)
}
func (p *Process) Done() <-chan struct{} { return p.done }
func (p *Process) Close() error {
	p.closeOnce.Do(func() {
		// Kill the entire owned cgroup, including threads, then reap the child.
		killErr := write(p.root, "cgroup.kill", "1")
		if killErr != nil {
			killErr = errors.Join(killErr, p.cmd.Process.Kill())
		}
		<-p.done
		if data, err := os.ReadFile(filepath.Join(p.root, "memory.events")); err == nil {
			for _, line := range strings.Split(string(data), "\n") {
				fields := strings.Fields(line)
				if len(fields) == 2 && fields[0] == "oom_kill" && fields[1] != "0" {
					p.budgetFailed.Store(true)
				}
			}
		}
		p.Compiled()
		removeErr := os.Remove(p.root)
		p.closeErr = errors.Join(killErr, removeErr)
		if p.closeErr == nil {
			p.supervisor.release()
		}
	})
	return p.closeErr
}

func (p *Process) BudgetExceeded() bool { return p.budgetFailed.Load() }
