// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package studio

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/netsec-ethz/debuglet/internal/guestio"
	"github.com/netsec-ethz/debuglet/pkg/workflow"
	"github.com/tetratelabs/wazero"
)

func sampleWorkflow() workflow.Workflow {
	return workflow.Workflow{Version: 1, Name: "Answer", Entry: "result", Nodes: []workflow.Node{{ID: "result", Block: "emit", Inputs: map[string]any{"name": "answer", "value": float64(42)}}}, Edges: []workflow.Edge{}}
}

func TestHTTPRequiresOwnOriginAndSession(t *testing.T) {
	handler, err := NewHandler(nil, ServerConfig{}, "http://127.0.0.1:8090")
	if err != nil {
		t.Fatal(err)
	}
	request := func(method, path, host, origin, token string, body []byte) *httptest.ResponseRecorder {
		t.Helper()
		r := httptest.NewRequest(method, "http://127.0.0.1:8090"+path, bytes.NewReader(body))
		r.Host = host
		r.Header.Set("Origin", origin)
		r.Header.Set("X-Studio-Token", token)
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w
	}
	for _, pair := range [][2]string{{"evil.example:8090", ""}, {"127.0.0.1:8090", "https://evil.example"}} {
		if got := request("GET", "/studio/api/session", pair[0], pair[1], "", nil).Code; got != 403 {
			t.Fatalf("foreign origin returned %d", got)
		}
	}
	session := request("GET", "/studio/api/session", "127.0.0.1:8090", "", "", nil)
	var auth struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(session.Body.Bytes(), &auth); err != nil || auth.Token == "" {
		t.Fatal("session did not provide a token", err)
	}
	body, _ := json.Marshal(sampleWorkflow())
	if got := request("POST", "/studio/api/validate", "127.0.0.1:8090", "", "", body).Code; got != 403 {
		t.Fatalf("missing token returned %d", got)
	}
	valid := request("POST", "/studio/api/validate", "127.0.0.1:8090", "http://127.0.0.1:8090", auth.Token, body)
	if valid.Code != 200 || !strings.Contains(valid.Body.String(), `"diagnostics":[]`) {
		t.Fatalf("validate: %d %s", valid.Code, valid.Body)
	}
	if got := request("POST", "/studio/api/build", "127.0.0.1:8090", "", auth.Token, body).Code; got != 503 {
		t.Fatalf("missing compiler returned %d", got)
	}
	oversized := request("POST", "/studio/api/validate", "127.0.0.1:8090", "", auth.Token, bytes.Repeat([]byte(" "), MaxWorkflowBytes+1))
	if oversized.Code == 200 {
		t.Fatal("accepted oversized workflow")
	}
}

func TestHTTPProxyIsFixedAndBoundsBodies(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/account" {
			t.Errorf("unexpected path %s", r.URL.Path)
		}
		if r.Header.Get("X-Studio-Token") != "" {
			t.Error("studio token forwarded upstream")
		}
		cookie, err := r.Cookie("session_csrf")
		if err != nil || cookie.Value != "csrf-value" || r.Header.Get("X-Debuglet-CSRF") != "csrf-value" {
			t.Error("CSRF cookie/header not preserved")
		}
		http.SetCookie(w, &http.Cookie{Name: "session_csrf", Value: "next", Domain: "upstream.example", Path: "/"})
		_, _ = io.WriteString(w, `{"ok":true}`)
	}))
	defer upstream.Close()
	handler, err := NewHandler(nil, ServerConfig{Dispatcher: upstream.URL}, "http://127.0.0.1:8090")
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest("GET", "http://127.0.0.1:8090/api/account", nil)
	request.Header.Set("X-Studio-Token", "private")
	request.Header.Set("X-Debuglet-CSRF", "csrf-value")
	request.AddCookie(&http.Cookie{Name: "session_csrf", Value: "csrf-value"})
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != 200 || response.Body.String() != `{"ok":true}` {
		t.Fatalf("proxy: %d %s", response.Code, response.Body)
	}
	for _, cookie := range response.Result().Cookies() {
		if cookie.Domain != "" {
			t.Error("upstream cookie domain retained")
		}
	}
	for _, target := range []string{"file:///etc/passwd", "http://user:password@example.test", "http://example.test/other", "https://dispatcher.example.test", "http://192.168.1.5:8000"} {
		if _, err := NewHandler(nil, ServerConfig{Dispatcher: target}, "http://127.0.0.1:8090"); err == nil {
			t.Errorf("accepted %s", target)
		}
	}
}

func TestWorkflowDecoderRejectsUnknownTrailingAndOversizedJSON(t *testing.T) {
	body, _ := json.Marshal(sampleWorkflow())
	for _, data := range [][]byte{append(append([]byte{}, body...), []byte(" {}")...), []byte(`{"version":1,"shell":"rm"}`), append(append([]byte{}, body...), bytes.Repeat([]byte(" "), MaxWorkflowBytes)...)} {
		if _, err := DecodeWorkflow(bytes.NewReader(data)); err == nil {
			t.Fatal("invalid workflow encoding accepted")
		}
	}
}

func TestMCPPreservesEditableWorkflowAndLimitsFilesystem(t *testing.T) {
	workspace := t.TempDir()
	server, closeServer, err := MCPServer(nil, workspace)
	if err != nil {
		t.Fatal(err)
	}
	defer closeServer()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	serverTransport, clientTransport := mcp.NewInMemoryTransports()
	ss, err := server.Connect(ctx, serverTransport, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ss.Close()
	client := mcp.NewClient(&mcp.Implementation{Name: "studio-test", Version: "1"}, nil)
	cs, err := client.Connect(ctx, clientTransport, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer cs.Close()
	call := func(name string, args any) *mcp.CallToolResult {
		t.Helper()
		result, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: name, Arguments: args})
		if err != nil {
			t.Fatal(err)
		}
		return result
	}
	for _, name := range []string{"catalog", "validate"} {
		args := any(map[string]any{})
		if name == "validate" {
			args = workflowInput{sampleWorkflow()}
		}
		if result := call(name, args); result.IsError {
			t.Fatalf("%s: %+v", name, result)
		}
	}
	if result := call("save_workflow", savedInput{"example", sampleWorkflow()}); result.IsError {
		t.Fatal(result)
	}
	result := call("get_workflow", nameInput{"example"})
	if result.IsError {
		t.Fatal(result)
	}
	data, err := os.ReadFile(filepath.Join(workspace, "example.workflow.json"))
	if err != nil {
		t.Fatal(err)
	}
	expected, _ := json.Marshal(sampleWorkflow())
	if !bytes.Equal(data, expected) {
		t.Fatal("MCP changed the saved graph")
	}
	if result := call("save_workflow", savedInput{"../outside", sampleWorkflow()}); !result.IsError {
		t.Fatal("MCP accepted a path")
	}
	if result := call("read_artifact", artifactInput{"../outside"}); !result.IsError {
		t.Fatal("MCP read an unknown artifact")
	}
	if result := call("build", workflowInput{sampleWorkflow()}); !result.IsError {
		t.Fatal("MCP built without a compiler")
	}
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "private.json"), expected, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(outside, "private.json"), filepath.Join(workspace, "linked.workflow.json")); err != nil {
		t.Fatal(err)
	}
	if result := call("get_workflow", nameInput{"linked"}); !result.IsError {
		t.Fatal("MCP followed a symlink outside its workspace")
	}
}

func TestMCPBuildProducesOfflineWASIBundle(t *testing.T) {
	sdk, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	builder, err := NewBuilder(sdk)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	server, closeServer, err := MCPServer(builder, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer closeServer()
	serverTransport, clientTransport := mcp.NewInMemoryTransports()
	ss, err := server.Connect(ctx, serverTransport, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ss.Close()
	client := mcp.NewClient(&mcp.Implementation{Name: "build-test", Version: "1"}, nil)
	cs, err := client.Connect(ctx, clientTransport, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer cs.Close()
	built, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "build", Arguments: workflowInput{sampleWorkflow()}})
	if err != nil {
		t.Fatal(err)
	}
	if built.IsError {
		t.Fatal(built.Content)
	}
	metaJSON, err := json.Marshal(built.StructuredContent)
	if err != nil {
		t.Fatal(err)
	}
	var meta metadata
	if err := json.Unmarshal(metaJSON, &meta); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(meta.BundlePath)
	if err != nil {
		t.Fatal(err)
	}
	var bundle Bundle
	if err := json.Unmarshal(data, &bundle); err != nil {
		t.Fatal(err)
	}
	read, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "read_artifact", Arguments: artifactInput{meta.ArtifactID}})
	if err != nil || read.IsError {
		t.Fatalf("read original artifact: %v %+v", err, read)
	}
	if !bytes.HasPrefix(bundle.Wasm, []byte{0, 'a', 's', 'm', 1, 0, 0, 0}) {
		t.Fatal("not a WASM module")
	}
	runtime := wazero.NewRuntime(ctx)
	defer runtime.Close(ctx)
	compiled, err := runtime.CompileModule(ctx, bundle.Wasm)
	if err != nil {
		t.Fatal(err)
	}
	defer compiled.Close(ctx)
	for _, imported := range compiled.ImportedFunctions() {
		module, name, _ := imported.Import()
		for _, optional := range guestio.SupportedHostFunctions() {
			if module+"."+name == optional {
				t.Errorf("ordinary workflow unexpectedly requires optional host function %s", optional)
			}
		}
	}
	if bundle.WasmSHA256 != digest(bundle.Wasm) || bundle.WorkflowSHA256 != digest([]byte(bundle.WorkflowJSON)) {
		t.Fatal("bundle digest mismatch")
	}
	wf, err := DecodeWorkflow(strings.NewReader(bundle.WorkflowJSON))
	if err != nil {
		t.Fatal(err)
	}
	program, err := workflow.Generate(wf)
	if err != nil {
		t.Fatal(err)
	}
	if program.Source != bundle.Source {
		t.Fatal("bundle source differs from workflow")
	}
	bundle.Workflow.Name = "Changed independently of canonical graph"
	changed, err := json.Marshal(bundle)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(meta.BundlePath, changed, 0600); err != nil {
		t.Fatal(err)
	}
	read, err = cs.CallTool(ctx, &mcp.CallToolParams{Name: "read_artifact", Arguments: artifactInput{meta.ArtifactID}})
	if err != nil || !read.IsError {
		t.Fatalf("modified artifact not rejected: %v %+v", err, read)
	}
	stopped, stop := context.WithCancel(context.Background())
	stop()
	if _, err := builder.Build(stopped, sampleWorkflow()); err == nil {
		t.Fatal("cancelled build succeeded")
	}
}

func TestProxyTrustsOnlyConfiguredCA(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))
	defer upstream.Close()
	caFile := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: upstream.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	for _, fixture := range []struct {
		ca   string
		want int
	}{{"", 502}, {caFile, 204}} {
		handler, err := NewHandler(nil, ServerConfig{Dispatcher: upstream.URL, CAFile: fixture.ca}, "http://127.0.0.1:8090")
		if err != nil {
			t.Fatal(err)
		}
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest("GET", "http://127.0.0.1:8090/api/account", nil))
		if response.Code != fixture.want {
			t.Fatalf("proxy CA=%q status=%d want=%d", fixture.ca, response.Code, fixture.want)
		}
	}
}
