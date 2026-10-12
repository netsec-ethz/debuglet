// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

//go:build linux && roles_integration

package roles

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/netsec-ethz/debuglet/internal/demo"
	"github.com/netsec-ethz/debuglet/internal/testtls"
	"github.com/netsec-ethz/debuglet/pkg/client"
)

// Exercise the installed join command and the real account-owned enrollment
// endpoint together. No fixture signs a substitute response or rewrites the
// generated executor configuration. All listeners stay on owned loopback.
func TestInstalledEnrollment(t *testing.T) {
	root := os.Getenv("DEBUGLET_LOCAL_INSTALL_ROOT")
	if !filepath.IsAbs(root) {
		t.Fatal("absolute installed package directory required")
	}
	assets, err := demo.ResolveAssets(filepath.Join(root, "bin", "dbl"))
	if err != nil || assets.Manifest.SourceSHA != os.Getenv("DEBUGLET_LOCAL_SOURCE_SHA") {
		t.Fatalf("installed/source identity: %v", err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	defer cancel()
	work := t.TempDir() // Keys, setup tokens and sessions never enter uploaded evidence.
	if err := os.Chmod(work, 0700); err != nil {
		t.Fatal(err)
	}
	ca, err := testtls.NewAuthority(work, "ca")
	if err != nil {
		t.Fatal(err)
	}
	server, err := ca.Issue("server", testtls.Options{Hosts: []string{"127.0.0.1"}, Server: true})
	if err != nil {
		t.Fatal(err)
	}
	database := filepath.Join(work, "dispatcher.sqlite")
	if _, diagnostic, err := runCommand(ctx, assets.Dispatcher, work, isolatedEnvironment(work), "-init-database", database); err != nil {
		t.Fatalf("initialize installed dispatcher: %v; %q", err, diagnostic)
	}
	configuration := map[string]any{
		"server":    map[string]any{"bind_host": "127.0.0.1", "http_port": 0, "grpc_port": 0},
		"tls":       map[string]any{"cert_file": server.CertFile, "key_file": server.KeyFile, "ca_file": ca.CertFile, "require_client_cert": true},
		"logging":   map[string]any{"log_level": "error", "json_logs": true},
		"scheduler": map[string]any{"executor_timeout": 60, "scheduler_granularity_ms": 1000},
		"database":  map[string]any{"path": database}, "sui": map[string]any{"disabled": true},
	}
	dispatcherConfig := filepath.Join(work, "dispatcher.toml")
	writeOutputConfig(t, dispatcherConfig, configuration)
	stop := func(daemon *outputDaemon) {
		t.Helper()
		phase, done := context.WithTimeout(ctx, 8*time.Second)
		defer done()
		if err := daemon.child.Stop(phase); err != nil || !daemon.child.CleanupComplete() {
			t.Fatalf("installed daemon joined shutdown: %v", err)
		}
		daemon.stopped = true
	}
	// Discover available ports with the real dispatcher before advertising them
	// in its enrollment response; subsequent starts keep those exact endpoints.
	initial := startOutputDaemon(t, ctx, assets.Dispatcher, work, dispatcherConfig, "initial-dispatcher")
	stop(initial)
	port := func(address string) int {
		t.Helper()
		_, raw, err := net.SplitHostPort(address)
		if err != nil {
			t.Fatal(err)
		}
		n, err := strconv.Atoi(raw)
		if err != nil || n == 0 {
			t.Fatal("invalid bound port")
		}
		return n
	}
	endpoint := "https://" + initial.ready.HTTPAddr
	configuration["server"] = map[string]any{"bind_host": "127.0.0.1", "http_port": port(initial.ready.HTTPAddr), "grpc_port": port(initial.ready.GRPCAddr)}
	configuration["executor_onboarding"] = map[string]any{
		"enabled": true, "ca_cert": ca.CertFile, "ca_key": ca.KeyFile,
		"dispatcher_url": endpoint, "grpc_address": initial.ready.GRPCAddr, "yamux_address": initial.ready.HTTPAddr,
	}
	writeOutputConfig(t, dispatcherConfig, configuration)
	d := startOutputDaemon(t, ctx, assets.Dispatcher, work, dispatcherConfig, "enrollment-dispatcher")

	cliConfig := filepath.Join(work, "connections.json")
	cli := func(args ...string) []byte {
		t.Helper()
		phase, done := context.WithTimeout(ctx, 30*time.Second)
		defer done()
		env := append(isolatedEnvironment(work), "SSL_CERT_FILE="+ca.CertFile)
		out, diagnostic, err := runCommand(phase, assets.CLI, work, env, append([]string{"--config", cliConfig, "--output", "json"}, args...)...)
		if err != nil {
			t.Fatalf("installed CLI %s: %v; %q", args[0], err, diagnostic)
		}
		return out
	}
	cli("connect", endpoint, "--name", "enrollment")
	keyPath := filepath.Join(work, "account-key")
	cli("login", "--register", "installed enrollment owner", "--account-key-file", keyPath,
		"--recovery-file", filepath.Join(work, "account-recovery"), "--credential-store", "file")
	key, err := readRegular(keyPath, 4096)
	if err != nil {
		t.Fatal(err)
	}
	transport := &http.Transport{TLSClientConfig: ca.ClientConfig(nil, "")}
	t.Cleanup(transport.CloseIdleConnections)
	httpClient := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	c, err := client.New(endpoint, client.Options{HTTPClient: httpClient, RequestTimeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	session, err := c.Login(ctx, strings.TrimSpace(string(key)))
	if err != nil {
		t.Fatal("owner login:", err)
	}
	c, err = c.WithCredential(session.Token)
	if err != nil {
		t.Fatal(err)
	}
	ownerRequest := func(method, path string, body []byte, status int, into any) {
		t.Helper()
		req, err := http.NewRequestWithContext(ctx, method, endpoint+path, bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "Bearer "+session.Token)
		req.Header.Set("Content-Type", "application/json")
		response, err := httpClient.Do(req)
		if err != nil {
			t.Fatal("owner request:", err)
		}
		defer response.Body.Close()
		if response.StatusCode != status {
			t.Fatalf("owner request %s %s: status %d, want %d", method, path, response.StatusCode, status)
		}
		if err := json.NewDecoder(io.LimitReader(response.Body, 64<<10)).Decode(into); err != nil {
			t.Fatal("owner response:", err)
		}
	}
	type ownedNode struct {
		ID      string `json:"id"`
		Status  string `json:"status"`
		Ready   bool   `json:"ready"`
		Version string `json:"version"`
	}
	var setup struct {
		Executor ownedNode `json:"executor"`
		Token    string    `json:"token"`
	}
	ownerRequest(http.MethodPost, "/operator/executors", []byte(`{"name":"Installed node"}`), http.StatusCreated, &setup)
	if !validID(setup.Executor.ID) || setup.Executor.Ready || setup.Executor.Status != "pending" || setup.Token == "" {
		t.Fatal("invalid owned enrollment setup")
	}
	tokenPath := filepath.Join(work, "setup-token")
	if err := os.WriteFile(tokenPath, []byte(setup.Token), 0600); err != nil {
		t.Fatal(err)
	}
	state := filepath.Join(work, "enrolled-executor")
	joined := cli("executor", "join", "--dispatcher", endpoint, "--executor", setup.Executor.ID,
		"--state-dir", state, "--token-file", tokenPath, "--ca-file", ca.CertFile)
	if bytes.Contains(joined, []byte(setup.Token)) {
		t.Fatal("join disclosed enrollment token")
	}
	if err := os.Remove(tokenPath); err != nil {
		t.Fatal(err)
	}
	identity := map[string][]byte{}
	for _, name := range []string{"executor.key", "executor.crt", "ca.crt", "service.toml"} {
		data, err := readRegular(filepath.Join(state, name), 64<<10)
		if err != nil {
			t.Fatal(err)
		}
		identity[name] = data
	}
	ready := func() {
		t.Helper()
		outputEventually(t, ctx, "account-owned enrolled executor readiness", func() bool {
			var list struct {
				Executors []ownedNode `json:"executors"`
			}
			ownerRequest(http.MethodGet, "/operator/executors", nil, http.StatusOK, &list)
			return len(list.Executors) == 1 && list.Executors[0].ID == setup.Executor.ID &&
				list.Executors[0].Ready && list.Executors[0].Status == "online" && list.Executors[0].Version == assets.Manifest.Version
		})
	}
	run := func(argument string) string {
		t.Helper()
		var receipt struct {
			ID         string `json:"id"`
			ExecutorID string `json:"executor_id"`
			State      string `json:"state"`
			Error      string `json:"error"`
		}
		if err := json.Unmarshal(cli("run", "--executor", setup.Executor.ID, "--sample", "hello", "--wait", "--allow-remote-test", "--", argument), &receipt); err != nil || !validID(receipt.ID) || receipt.ExecutorID != setup.Executor.ID || receipt.State != client.StateExited || receipt.Error != "" {
			t.Fatalf("installed enrolled run failed: %+v, %v", receipt, err)
		}
		awaitOutput(t, ctx, c, receipt.ID, hello+argument+"\n")
		return receipt.ID
	}
	e := startOutputDaemon(t, ctx, assets.Executor, work, filepath.Join(state, "service.toml"), "enrolled-executor")
	ready()
	first := run("before-enrolled-restart")
	stop(e)
	stop(d)
	startOutputDaemon(t, ctx, assets.Dispatcher, work, dispatcherConfig, "restarted-enrollment-dispatcher")
	restarted := startOutputDaemon(t, ctx, assets.Executor, work, filepath.Join(state, "service.toml"), "restarted-enrolled-executor")
	if restarted.ready.ExecutorID != setup.Executor.ID {
		t.Fatal("enrolled restart changed executor identity")
	}
	ready()
	awaitOutput(t, ctx, c, first, hello+"before-enrolled-restart\n")
	if run("after-enrolled-restart") == first {
		t.Fatal("fresh enrolled run reused the previous run identity")
	}
	for name, before := range identity {
		after, err := readRegular(filepath.Join(state, name), 64<<10)
		if err != nil || !bytes.Equal(before, after) {
			t.Fatalf("enrolled restart changed %s: %v", name, err)
		}
	}
	t.Log("installed full package enrolled through the real owner API; TLS identity, account session and completed output survived both daemon restarts; fresh TEST work completed")
}
