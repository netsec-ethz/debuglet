package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"github.com/netsec-ethz/debuglet/internal/artifact"
	"github.com/netsec-ethz/debuglet/internal/readiness"
	"io"
	"net"
	"os"
	"strconv"
	"sync"
	"time"
)

// stdout and stderr share one budget; stderr is deliberately never exposed.
// Continue consuming excess output so pipe draining cannot deadlock cleanup.
type limitedCapture struct {
	mu          sync.Mutex
	out         bytes.Buffer
	used, limit int
	overflow    bool
}
type captureWriter struct {
	capture *limitedCapture
	retain  bool
}

func newCapture(limit int) *limitedCapture  { return &limitedCapture{limit: limit} }
func (c *limitedCapture) stdout() io.Writer { return captureWriter{c, true} }
func (c *limitedCapture) stderr() io.Writer { return captureWriter{c, false} }
func (w captureWriter) Write(p []byte) (int, error) {
	c := w.capture
	c.mu.Lock()
	defer c.mu.Unlock()
	n := len(p)
	remaining := c.limit - c.used
	if n > remaining {
		c.overflow = true
		p = p[:remaining]
	}
	c.used += len(p)
	if w.retain {
		c.out.Write(p)
	}
	return n, nil
}
func (c *limitedCapture) result() ([]byte, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return bytes.Clone(c.out.Bytes()), c.overflow
}
func (c *limitedCapture) exceeded() bool { c.mu.Lock(); defer c.mu.Unlock(); return c.overflow }
func channelClosed(done <-chan struct{}) bool {
	select {
	case <-done:
		return true
	default:
		return false
	}
}
func localAddress(addr string) bool {
	host, port, err := net.SplitHostPort(addr)
	if err != nil || host != "127.0.0.1" {
		return false
	}
	p, err := strconv.Atoi(port)
	return err == nil && p > 0 && p <= 65535
}
func awaitReady(ctx context.Context, path string, owned *ownedChild, id string) (readiness.Record, error) {
	for {
		if err := ctx.Err(); err != nil {
			return readiness.Record{}, err
		}
		if channelClosed(owned.child.Done()) || owned.capture.exceeded() {
			return readiness.Record{}, errors.New("daemon failed before readiness")
		}
		info, err := os.Lstat(path)
		if err == nil {
			if !info.Mode().IsRegular() || info.Size() > 4096 {
				return readiness.Record{}, errors.New("invalid readiness file")
			}
			f, err := os.Open(path)
			if err != nil {
				return readiness.Record{}, err
			}
			data, readErr := io.ReadAll(io.LimitReader(f, 4097))
			closeErr := f.Close()
			if readErr != nil || closeErr != nil || len(data) > 4096 {
				return readiness.Record{}, errors.New("readiness read failed")
			}
			if artifact.CheckUniqueJSON(data) != nil {
				return readiness.Record{}, errors.New("duplicate readiness fields")
			}
			keys := []string{"schema_version", "pid", "http_addr", "grpc_addr"}
			if id != "" {
				keys = []string{"schema_version", "pid", "executor_id"}
			}
			if _, err := strictFields(data, keys, nil, nil); err != nil {
				return readiness.Record{}, errors.New("invalid readiness fields")
			}
			var record readiness.Record
			d := json.NewDecoder(bytes.NewReader(data))
			d.DisallowUnknownFields()
			if d.Decode(&record) != nil || d.Decode(new(any)) != io.EOF || record.SchemaVersion != 1 || record.PID != owned.child.PID() {
				return record, errors.New("readiness identity mismatch")
			}
			if id == "" {
				if record.ExecutorID != "" || !localAddress(record.HTTPAddr) || !localAddress(record.GRPCAddr) {
					return record, errors.New("invalid dispatcher readiness")
				}
			} else if record.ExecutorID != id || record.HTTPAddr != "" || record.GRPCAddr != "" {
				return record, errors.New("invalid executor readiness")
			}
			return record, nil
		}
		if !errors.Is(err, os.ErrNotExist) {
			return readiness.Record{}, err
		}
		timer := time.NewTimer(20 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return readiness.Record{}, ctx.Err()
		case <-timer.C:
		}
	}
}
