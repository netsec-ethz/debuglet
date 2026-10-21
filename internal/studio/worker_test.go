// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package studio

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/netsec-ethz/debuglet/pkg/workflow"
)

func workerRequest(handler http.Handler, method, path string, body []byte) *httptest.ResponseRecorder {
	request := httptest.NewRequest(method, "http://worker"+path, bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func TestWorkerOperationsAndStrictRoutes(t *testing.T) {
	handler := NewWorkerHandler(nil)
	wf, _ := json.Marshal(sampleWorkflow())
	experiment, err := os.ReadFile("../../examples/workflows/experiments/three-node.json")
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		method, path string
		body         []byte
		status       int
	}{
		{"GET", "/studio/catalog", nil, 200},
		{"POST", "/studio/validate", wf, 200},
		{"POST", "/studio/build", wf, 503},
		{"POST", "/studio/experiments/validate", experiment, 200},
		{"POST", "/studio/experiments/build", experiment, 503},
		{"POST", "/studio/validate", []byte(`{"sdk":"/etc"}`), 400},
		{"POST", "/studio/experiments/validate", append(experiment, []byte(" {}")...), 400},
		{"POST", "/studio/validate", bytes.Repeat([]byte(" "), MaxWorkflowBytes+1), 413},
		{"POST", "/studio/experiments/validate", bytes.Repeat([]byte(" "), MaxExperimentBytes+1), 413},
		{"GET", "/studio/validate", nil, 405},
		{"HEAD", "/studio/catalog", nil, 405},
		{"GET", "/studio/api/session", nil, 404},
		{"GET", "/console/builder", nil, 404},
		{"GET", "/api/account", nil, 404},
		{"POST", "/studio/build?source=/etc/passwd", wf, 400},
		{"GET", "/studio/%63atalog", nil, 400},
	} {
		response := workerRequest(handler, test.method, test.path, test.body)
		if response.Code != test.status || !json.Valid(response.Body.Bytes()) {
			t.Errorf("%s %s: status=%d want=%d body=%s", test.method, test.path, response.Code, test.status, response.Body)
		}
		if response.Header().Get("Cache-Control") != "no-store" {
			t.Error("worker response is cacheable")
		}
	}
	request := httptest.NewRequest("POST", "http://worker/studio/validate", bytes.NewReader(wf))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("missing content type returned %d", response.Code)
	}
	// Unknown body lengths must hit the same limit as Content-Length requests.
	request = httptest.NewRequest("POST", "http://worker/studio/validate", strings.NewReader(strings.Repeat(" ", MaxWorkflowBytes+1)))
	request.ContentLength = -1
	request.Header.Set("Content-Type", "application/json")
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("streaming oversized request returned %d: %s", response.Code, response.Body)
	}
}

type waitingCompiler struct{ started chan struct{} }

func (c *waitingCompiler) Build(ctx context.Context, _ workflow.Workflow) (*Bundle, error) {
	close(c.started)
	<-ctx.Done()
	return nil, ctx.Err()
}
func (c *waitingCompiler) BuildExperiment(ctx context.Context, _ workflow.Experiment) (*ExperimentBundle, error) {
	return nil, nil
}

func TestWorkerRejectsConcurrentBuildAndPropagatesCancellation(t *testing.T) {
	compiler := &waitingCompiler{started: make(chan struct{})}
	handler := newWorkerHandler(compiler)
	wf, _ := json.Marshal(sampleWorkflow())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	request := httptest.NewRequest("POST", "http://worker/studio/build", bytes.NewReader(wf)).WithContext(ctx)
	request.Header.Set("Content-Type", "application/json")
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		done <- response
	}()
	select {
	case <-compiler.started:
	case <-time.After(time.Second):
		t.Fatal("compiler did not start")
	}
	for _, path := range []string{"/studio/build", "/studio/experiments/build"} {
		response := workerRequest(handler, "POST", path, wf)
		if response.Code != 429 || response.Header().Get("Retry-After") != "1" {
			t.Fatalf("parallel build: %d %s", response.Code, response.Body)
		}
	}
	if response := workerRequest(handler, "POST", "/studio/validate", wf); response.Code != 200 {
		t.Fatal("validation was blocked by compilation", response.Code)
	}
	cancel()
	select {
	case response := <-done:
		if response.Code != http.StatusRequestTimeout {
			t.Fatalf("cancelled build returned %d", response.Code)
		}
	case <-time.After(time.Second):
		t.Fatal("request cancellation did not reach compiler")
	}
}

func TestWorkerBoundsAdmissionTimeAndResponse(t *testing.T) {
	entered := make(chan struct{}, workerRequestSlots)
	release := make(chan struct{})
	handler := boundWorkerRequests(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		entered <- struct{}{}
		<-release
		writeJSON(w, 200, map[string]bool{"ok": true})
	}), time.Second)
	done := make(chan struct{}, workerRequestSlots)
	for i := 0; i < workerRequestSlots; i++ {
		go func() {
			workerRequest(handler, "GET", "/studio/catalog", nil)
			done <- struct{}{}
		}()
	}
	for i := 0; i < workerRequestSlots; i++ {
		<-entered
	}
	if response := workerRequest(handler, "GET", "/studio/catalog", nil); response.Code != 429 {
		t.Errorf("admission limit returned %d", response.Code)
	}
	close(release)
	for i := 0; i < workerRequestSlots; i++ {
		<-done
	}
	handler = boundWorkerRequests(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
		writeJSON(w, 200, map[string]bool{"late": true})
	}), time.Millisecond)
	if response := workerRequest(handler, "GET", "/studio/catalog", nil); response.Code != 504 || strings.Contains(response.Body.String(), "late") {
		t.Fatalf("deadline returned %d: %s", response.Code, response.Body)
	}
	handler = boundWorkerRequests(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		chunk := bytes.Repeat([]byte{'x'}, 1<<20)
		for i := 0; i < 33; i++ {
			_, _ = w.Write(chunk)
		}
	}), time.Second)
	if response := workerRequest(handler, "GET", "/studio/catalog", nil); response.Code != 500 || !json.Valid(response.Body.Bytes()) || response.Body.Len() > 1024 {
		t.Fatalf("oversized response not replaced by JSON error: %d, %d bytes", response.Code, response.Body.Len())
	}
}

func socketDirectory(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "dbl-socket-*")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

func TestWorkerSocketPermissionsOwnershipAndCleanup(t *testing.T) {
	path := filepath.Join(socketDirectory(t), "worker.sock")
	listener, cleanup, err := listenWorker(path)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	info, err := os.Lstat(path)
	if err != nil || info.Mode().Perm() != 0660 || info.Mode()&os.ModeSocket == 0 {
		t.Fatalf("incorrect socket permissions: %v %v", info, err)
	}
	if _, _, err := listenWorker(path); err == nil {
		t.Fatal("replaced an active socket")
	}
	connection, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal("failed bind removed the existing listener", err)
	}
	_ = connection.Close()
	_ = listener.Close()
	if _, _, err := listenWorker(path); err == nil {
		t.Fatal("removed a pre-existing stale socket")
	}
	cleanup()
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatal("own socket was not removed", err)
	}
	if err := os.WriteFile(path, []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := listenWorker(path); err == nil {
		t.Fatal("removed an unrelated file")
	}
	cleanup()
	if body, err := os.ReadFile(path); err != nil || string(body) != "keep" {
		t.Fatal("cleanup removed replacement file", err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	replacement, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer replacement.Close()
	cleanup()
	if connection, err := net.Dial("unix", path); err != nil {
		t.Fatal("cleanup removed replacement socket", err)
	} else {
		_ = connection.Close()
	}
}

func TestWorkerServesUnixSocketAndStops(t *testing.T) {
	path := filepath.Join(socketDirectory(t), "worker.sock")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ready := make(chan struct{})
	done := make(chan error, 1)
	go func() { done <- ServeWorker(ctx, &Builder{}, path, func(string) { close(ready) }) }()
	select {
	case <-ready:
	case err := <-done:
		t.Fatal(err)
	case <-time.After(time.Second):
		t.Fatal("worker did not start")
	}
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", path)
	}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: time.Second}
	response, err := client.Get("http://worker/studio/catalog")
	if err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if err != nil || response.StatusCode != 200 || !json.Valid(data) {
		t.Fatalf("worker catalogue: status=%d err=%v", response.StatusCode, err)
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("worker did not stop")
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatal("worker left its socket behind", err)
	}
}

func TestWorkerCleanupPreservesReplacementAndRejectsPublicDirectory(t *testing.T) {
	for _, replacementSocket := range []bool{false, true} {
		path := filepath.Join(socketDirectory(t), "worker.sock")
		_, cleanup, err := listenWorker(path)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(cleanup)
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
		if replacementSocket {
			listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = listener.Close() })
		} else if err := os.WriteFile(path, []byte("keep"), 0600); err != nil {
			t.Fatal(err)
		}
		cleanup()
		if _, err := os.Lstat(path); err != nil {
			t.Fatal("cleanup removed a replacement", err)
		}
	}
	dir := socketDirectory(t)
	if err := os.Chmod(dir, 0755); err != nil {
		t.Fatal(err)
	}
	if _, _, err := listenWorker(filepath.Join(dir, "worker.sock")); err == nil {
		t.Fatal("accepted a publicly accessible socket directory")
	}
}

func TestWorkerBuildsExistingBundleFormats(t *testing.T) {
	if testing.Short() {
		t.Skip("WASI compilation")
	}
	sdk, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	builder, err := NewBuilder(sdk)
	if err != nil {
		t.Fatal(err)
	}
	handler := NewWorkerHandler(builder)
	wf, _ := json.Marshal(sampleWorkflow())
	response := workerRequest(handler, "POST", "/studio/build", wf)
	var bundle Bundle
	if response.Code != 200 || json.Unmarshal(response.Body.Bytes(), &bundle) != nil || !bytes.HasPrefix(bundle.Wasm, []byte{0, 'a', 's', 'm'}) || bundle.WasmSHA256 != digest(bundle.Wasm) {
		t.Fatalf("workflow build returned %d: %.1024s", response.Code, response.Body)
	}
	experiment, err := os.ReadFile("../../examples/workflows/experiments/three-node.json")
	if err != nil {
		t.Fatal(err)
	}
	response = workerRequest(handler, "POST", "/studio/experiments/build", experiment)
	var grouped ExperimentBundle
	if response.Code != 200 || json.Unmarshal(response.Body.Bytes(), &grouped) != nil || len(grouped.Participants) != 3 || grouped.ExperimentSHA256 != digest([]byte(grouped.ExperimentJSON)) {
		t.Fatalf("experiment build returned %d: %.1024s", response.Code, response.Body)
	}
	if builder.hosted {
		t.Fatal("worker changed the original builder's local compilation settings")
	}
}
