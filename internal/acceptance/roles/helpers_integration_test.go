//go:build linux && roles_integration

package roles

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/netsec-ethz/debuglet/internal/acceptance/procinventory"
	"github.com/netsec-ethz/debuglet/internal/demo"
	"github.com/netsec-ethz/debuglet/pkg/client"
)

func isolatedEnvironment(dir string) []string {
	return []string{"LANG=C", "LC_ALL=C", "TZ=UTC", "TMPDIR=" + dir}
}

func sdk(t *testing.T, endpoint string) *client.Client {
	t.Helper()
	c, err := client.New(endpoint, client.Options{RequestTimeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func awaitOutput(t *testing.T, ctx context.Context, c *client.Client, id, want string) []byte {
	t.Helper()
	phase, end := context.WithTimeout(ctx, 10*time.Second)
	defer end()
	var output []byte
	var after int64
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	for {
		page, err := c.Logs(phase, id, client.LogOptions{After: after, Limit: 1})
		if err != nil {
			t.Fatal(err)
		}
		last := after
		for _, entry := range page.Logs {
			if entry.ID <= last || len(output)+len(entry.Output) > 64<<10 {
				t.Fatal("invalid or excessive sample output")
			}
			last = entry.ID
			output = append(output, entry.Output...)
		}
		if page.After != last || page.HasMore && len(page.Logs) == 0 {
			t.Fatal("invalid sample output cursor")
		}
		after = last
		if page.State == client.StateExited && page.Error == "" && !page.HasMore && string(output) == want {
			return output
		}
		if page.Error != "" {
			t.Fatal("sample failed:", page.Error)
		}
		if page.HasMore {
			continue
		}
		select {
		case <-phase.Done():
			t.Fatalf("sample output did not arrive: %v; output=%q", phase.Err(), output)
		case <-ticker.C:
		}
	}
}

func runCommand(ctx context.Context, path, dir string, env []string, args ...string) ([]byte, []byte, error) {
	out := new(capture)
	child, err := demo.StartChild(demo.ChildSpec{Path: path, Dir: dir, Args: args, Env: env, Stdout: captureWriter{out, true}, Stderr: captureWriter{out, false}})
	if err != nil {
		return nil, nil, err
	}
	err = child.Wait(ctx)
	cleanup, done := context.WithTimeout(context.Background(), 5*time.Second)
	err = errors.Join(err, child.Stop(cleanup))
	done()
	if !child.CleanupComplete() {
		err = errors.Join(err, errors.New("command cleanup incomplete"))
	}
	stdout, stderr, overflow := out.snapshot()
	if overflow {
		err = errors.Join(err, errors.New("command output exceeded bound"))
	}
	return stdout, stderr, err
}

type capture struct {
	mu             sync.Mutex
	stdout, stderr bytes.Buffer
	used           int
	overflow       bool
}
type captureWriter struct {
	c      *capture
	stdout bool
}

func (w captureWriter) Write(p []byte) (int, error) {
	w.c.mu.Lock()
	defer w.c.mu.Unlock()
	n := len(p)
	if left := (1 << 20) - w.c.used; len(p) > left {
		p = p[:left]
		w.c.overflow = true
	}
	w.c.used += len(p)
	if w.stdout {
		w.c.stdout.Write(p)
	} else {
		w.c.stderr.Write(p)
	}
	return n, nil
}
func (c *capture) snapshot() ([]byte, []byte, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return bytes.Clone(c.stdout.Bytes()), bytes.Clone(c.stderr.Bytes()), c.overflow
}
func decode(b []byte, out any) error {
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if err := d.Decode(out); err != nil {
		return err
	}
	if err := d.Decode(new(any)); err != io.EOF {
		return errors.New("expected exactly one JSON document")
	}
	return nil
}
func validID(s string) bool {
	id, err := uuid.Parse(s)
	return err == nil && id != uuid.Nil && id.String() == s
}
func readRegular(path string, limit int64) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > limit {
		return nil, errors.New("expected a bounded regular file")
	}
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if len(data) > int(limit) {
		return nil, errors.New("file exceeds bound")
	}
	return data, err
}

// A daemon reparented after an unexpected supervisor exit keeps the identity
// this harness independently established for it.
func alive(p procinventory.Process) bool {
	current, err := procinventory.Read(p.PID)
	return err == nil && procinventory.Same(p, current) && procinventory.Live(current)
}
func (s *role) observeChildren() error {
	children, err := procinventory.Descendants(s.child.PID())
	if err != nil {
		return err
	}
	for _, pid := range children {
		p, err := procinventory.Read(pid)
		if err != nil {
			continue // A fork/exit transition is not signal authority.
		}
		if p.Parent != s.child.PID() || p.Group != p.PID || p.Executable != s.executable {
			continue
		}
		if previous, ok := s.owned[pid]; ok && !procinventory.Same(previous, p) {
			return errors.New("owned child identity changed")
		}
		s.owned[pid] = p
	}
	return nil
}
