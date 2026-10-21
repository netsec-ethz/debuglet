// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package studio

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	WorkerRequestTimeout = 6 * time.Minute
	workerRequestSlots   = 4
)

// ServeWorker serves compilation over a private Unix socket. The dispatcher
// authenticates users; possession of socket access is trusted worker access.
// Its directory must already exist and allow access only to the service and its
// trusted group. Existing paths are never removed, even when they are stale.
func ServeWorker(ctx context.Context, builder *Builder, socket string, ready func(string)) error {
	if builder == nil {
		return errors.New("worker requires --sdk pointing to the matching Debuglet checkout")
	}
	listener, cleanup, err := listenWorker(socket)
	if err != nil {
		return err
	}
	defer cleanup()
	server := &http.Server{
		Handler:           NewWorkerHandler(builder),
		BaseContext:       func(net.Listener) context.Context { return ctx },
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      WorkerRequestTimeout + 5*time.Second,
		IdleTimeout:       30 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}
	done := make(chan struct{})
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		select {
		case <-ctx.Done():
			stop, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := server.Shutdown(stop); err != nil {
				_ = server.Close()
			}
		case <-done:
		}
	}()
	if ready != nil {
		ready(socket)
	}
	err = server.Serve(listener)
	close(done)
	<-stopped
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func listenWorker(socket string) (*net.UnixListener, func(), error) {
	if !filepath.IsAbs(socket) || filepath.Clean(socket) != socket {
		return nil, nil, errors.New("--socket must be an absolute, clean Unix socket path")
	}
	parent, err := os.Stat(filepath.Dir(socket))
	if err != nil {
		return nil, nil, fmt.Errorf("worker socket directory: %w", err)
	}
	// A non-writable group and no access for others also protect the interval
	// between binding and chmod, independent of the caller's umask.
	if !parent.IsDir() || parent.Mode().Perm()&0027 != 0 {
		return nil, nil, errors.New("worker socket directory must deny access to others and group writes (use mode 0750 or 0700)")
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: socket, Net: "unix"})
	if err != nil {
		return nil, nil, fmt.Errorf("bind worker socket (existing paths are not removed): %w", err)
	}
	listener.SetUnlinkOnClose(false)
	info, err := os.Lstat(socket)
	if err != nil {
		_ = listener.Close()
		return nil, nil, err
	}
	var once sync.Once
	cleanup := func() {
		once.Do(func() {
			_ = listener.Close()
			current, err := os.Lstat(socket)
			if err == nil && current.Mode()&os.ModeSocket != 0 && os.SameFile(info, current) {
				_ = os.Remove(socket)
			}
		})
	}
	if err := os.Chmod(socket, 0660); err != nil {
		cleanup()
		return nil, nil, fmt.Errorf("set worker socket permissions: %w", err)
	}
	return listener, cleanup, nil
}

// NewWorkerHandler provides only the five compilation operations. Serve it only
// on a protected Unix socket: authentication belongs to the dispatcher.
func NewWorkerHandler(builder *Builder) http.Handler {
	var compiler authoringCompiler
	if builder != nil {
		workerBuilder := *builder
		workerBuilder.hosted = true
		compiler = &workerBuilder
	}
	return newWorkerHandler(compiler)
}

func newWorkerHandler(compiler authoringCompiler) http.Handler {
	mux := http.NewServeMux()
	authoringRoutes(mux, compiler, "/studio", func(next http.HandlerFunc) http.HandlerFunc { return next })
	return boundWorkerRequests(mux, WorkerRequestTimeout)
}

func boundWorkerRequests(next http.Handler, timeout time.Duration) http.Handler {
	slots := make(chan struct{}, workerRequestSlots)
	buildSlot := make(chan struct{}, 1)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		method := "POST"
		switch r.URL.Path {
		case "/studio/catalog":
			method = "GET"
		case "/studio/validate", "/studio/build", "/studio/experiments/validate", "/studio/experiments/build":
		default:
			writeError(w, http.StatusNotFound, errors.New("unknown studio operation"))
			return
		}
		if r.Method != method {
			w.Header().Set("Allow", method)
			writeError(w, http.StatusMethodNotAllowed, errors.New("method is not supported for this studio operation"))
			return
		}
		if r.URL.RawQuery != "" || r.URL.RawPath != "" {
			writeError(w, http.StatusBadRequest, errors.New("studio operations do not accept query parameters or encoded paths"))
			return
		}
		busy := func() {
			w.Header().Set("Retry-After", "1")
			writeError(w, http.StatusTooManyRequests, errors.New("studio compiler is busy; retry shortly"))
		}
		select {
		case slots <- struct{}{}:
			defer func() { <-slots }()
		default:
			busy()
			return
		}
		if strings.HasSuffix(r.URL.Path, "/build") {
			select {
			case buildSlot <- struct{}{}:
				defer func() { <-buildSlot }()
			default:
				busy()
				return
			}
		}
		ctx, cancel := context.WithTimeout(r.Context(), timeout)
		defer cancel()
		response := &workerResponse{header: make(http.Header)}
		next.ServeHTTP(response, r.WithContext(ctx))
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			writeError(w, http.StatusGatewayTimeout, errors.New("studio operation exceeded its time limit"))
			return
		}
		if ctx.Err() != nil {
			writeError(w, http.StatusRequestTimeout, errors.New("studio operation was cancelled"))
			return
		}
		body := bytes.TrimSuffix(response.body.Bytes(), []byte{'\n'})
		if response.overflow || len(body) > MaxExperimentBundleBytes {
			writeError(w, http.StatusInternalServerError, errors.New("studio response exceeds 32 MiB"))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		status := response.status
		if status == 0 {
			status = http.StatusOK
		}
		w.WriteHeader(status)
		_, _ = w.Write(body)
	})
}

// Buffer a bounded response before committing headers, so an oversized bundle
// becomes a complete JSON error rather than a truncated successful response.
type workerResponse struct {
	header   http.Header
	status   int
	body     bytes.Buffer
	overflow bool
}

func (w *workerResponse) Header() http.Header { return w.header }
func (w *workerResponse) WriteHeader(status int) {
	if w.status == 0 {
		w.status = status
	}
}
func (w *workerResponse) Write(p []byte) (int, error) {
	if len(p) > MaxExperimentBundleBytes+1-w.body.Len() {
		w.overflow = true
		return 0, errors.New("studio response exceeds 32 MiB")
	}
	return w.body.Write(p)
}
