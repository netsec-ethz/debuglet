// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

//go:build linux && roles_integration

package roles

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/netsec-ethz/debuglet/internal/demo"
	"github.com/netsec-ethz/debuglet/internal/storagecheck"
	"github.com/netsec-ethz/debuglet/pkg/client"
)

// The previous assets are downloaded from the published release, checked
// against its pinned checksums, then installed by ci-roles.sh. Source-built
// substitutes cannot satisfy this test's manifest identity.
func releasedAssets(t *testing.T) (demo.Assets, demo.Assets) {
	t.Helper()
	resolve := func(key string) demo.Assets {
		t.Helper()
		root := os.Getenv(key)
		if !filepath.IsAbs(root) {
			t.Fatalf("%s must name an absolute installed package directory", key)
		}
		assets, err := demo.ResolveAssets(filepath.Join(root, "bin", "dbl"))
		if err != nil {
			t.Fatal(err)
		}
		return assets
	}
	current, previous := resolve("DEBUGLET_LOCAL_INSTALL_ROOT"), resolve("DEBUGLET_PREVIOUS_INSTALL_ROOT")
	if current.Manifest.SourceSHA != os.Getenv("DEBUGLET_LOCAL_SOURCE_SHA") || previous.Manifest.Version != "v0.2.0" || previous.Manifest.SourceSHA != "be5142f7cc2b4b9df93e1f948aa98491fcc8a49c" {
		t.Fatal("installed release/source identity differs from the requested packages")
	}
	return current, previous
}

func releasedRole(t *testing.T, ctx context.Context, assets demo.Assets, work, kind, state, endpoint string) *role {
	t.Helper()
	args := []string{"--config", filepath.Join(work, kind+"-client.json"), "--output", "json", kind, "up", "--name", kind, "--state-dir", state}
	if kind == "dispatcher" {
		args = append(args, "--port", "0", "--grpc-port", "0")
	} else {
		args = append(args, "--dispatcher", endpoint)
	}
	r, err := startRole(assets, work, kind, kind, state, args)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if !r.stopped {
			if err := r.stop(); err != nil {
				t.Error("release role cleanup:", err)
			}
		}
	})
	phase, cancel := context.WithTimeout(ctx, 25*time.Second)
	defer cancel()
	if err := r.ready(phase); err != nil {
		_, diagnostics, _ := r.output.snapshot()
		t.Fatalf("%s %s readiness: %v; %q", assets.Manifest.Version, kind, err, diagnostics)
	}
	return r
}

func releasedRun(t *testing.T, ctx context.Context, assets demo.Assets, work, endpoint, argument string) string {
	t.Helper()
	cli := func(args ...string) []byte {
		t.Helper()
		out, diagnostics, err := runCommand(ctx, assets.CLI, work, isolatedEnvironment(work), append([]string{"--config", filepath.Join(work, "client.json"), "--output", "json"}, args...)...)
		if err != nil {
			t.Fatalf("installed CLI %s: %v; %q", args[0], err, diagnostics)
		}
		return out
	}
	cli("connect", endpoint, "--name", "released")
	var receipt struct {
		ID            string `json:"id"`
		TransactionID string `json:"transaction_id"`
		ExecutorID    string `json:"executor_id"`
		State         string `json:"state"`
		Error         string `json:"error"`
	}
	if err := decode(cli("run", "--sample", "hello", "--wait", "--", argument), &receipt); err != nil || !validID(receipt.ID) || receipt.State != client.StateExited || receipt.Error != "" {
		t.Fatalf("released run: %+v, %v", receipt, err)
	}
	awaitOutput(t, ctx, sdk(t, endpoint), receipt.ID, hello+argument+"\n")
	return receipt.ID
}

func TestInstalledReleasedCompatibility(t *testing.T) {
	current, previous := releasedAssets(t)
	ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	defer cancel()
	work := t.TempDir()
	d := releasedRole(t, ctx, current, work, "dispatcher", filepath.Join(work, "dispatcher"), "")
	e := releasedRole(t, ctx, previous, work, "executor", filepath.Join(work, "executor"), d.record.Endpoint)
	first := releasedRun(t, ctx, current, work, d.record.Endpoint, "released-executor")
	if err := e.stop(); err != nil {
		t.Fatal(err)
	}
	reconnected := releasedRole(t, ctx, previous, work, "executor", e.state, d.record.Endpoint)
	if reconnected.record.ExecutorID != e.record.ExecutorID {
		t.Fatal("released executor reconnect changed its identity")
	}
	assertStatus(t, ctx, sdk(t, d.record.Endpoint), first, e.record.ExecutorID)
	releasedRun(t, ctx, current, work, d.record.Endpoint, "released-reconnect")
	nodes, err := sdk(t, d.record.Endpoint).Nodes(ctx)
	if err != nil || len(nodes) != 1 {
		t.Fatalf("released executor nodes: %+v, %v", nodes, err)
	}
	t.Log("published v0.2.0 executor registered, completed TEST work, reconnected with the same identity and completed fresh work against the installed candidate")
}

func TestInstalledReleasedUpgrade(t *testing.T) {
	current, previous := releasedAssets(t)
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()
	work := t.TempDir()
	d := releasedRole(t, ctx, previous, work, "dispatcher", filepath.Join(work, "dispatcher"), "")
	e := releasedRole(t, ctx, previous, work, "executor", filepath.Join(work, "executor"), d.record.Endpoint)
	first := releasedRun(t, ctx, previous, work, d.record.Endpoint, "before-upgrade")
	for _, r := range []*role{e, d} {
		if err := r.stop(); err != nil {
			t.Fatal(err)
		}
	}
	binding := storedBinding(t, d.state, uuid.MustParse(first))
	wasm, err := os.ReadFile(filepath.Join(previous.Root, "share", "debuglet", "hello.wasm"))
	if err != nil {
		t.Fatal(err)
	}
	retained := seedRetained(t, e.state, binding, wasm)
	// The deployment procedure copies the database and its companions only
	// after the daemon has stopped. Preserve these bytes before upgrading.
	backup := map[string][]byte{}
	for _, r := range []*role{d, e} {
		path := demo.RoleDatabase(r.state, storagecheck.Role(r.kind))
		for _, suffix := range []string{"", "-wal", "-shm"} {
			data, err := os.ReadFile(path + suffix)
			if os.IsNotExist(err) && suffix != "" {
				continue
			}
			if err != nil {
				t.Fatal(err)
			}
			backup[path+suffix] = data
		}
		binary := current.Dispatcher
		if r.kind == "executor" {
			binary = current.Executor
		}
		out, diag, err := runCommand(ctx, binary, work, isolatedEnvironment(work), "-config", filepath.Join(r.state, "service.toml"), "-upgrade-database")
		if err != nil {
			t.Fatalf("installed %s upgrade: %v; %q %q", r.kind, err, out, diag)
		}
		if err := storagecheck.Check(ctx, storagecheck.Role(r.kind), path); err != nil {
			t.Fatal("upgraded database rejected:", err)
		}
	}
	assertRetained(t, e.state, retained)
	config := filepath.Join(work, "upgraded-dispatcher.toml")
	if err := demo.WriteConfig(config, demo.DispatcherConfiguration(current.Manifest.Version, demo.RoleDatabase(d.state, storagecheck.Dispatcher))); err != nil {
		t.Fatal(err)
	}
	d2 := startOutputDaemon(t, ctx, current.Dispatcher, work, config, "upgraded-dispatcher")
	config = filepath.Join(work, "upgraded-executor.toml")
	if err := demo.WriteConfig(config, demo.ExecutorConfiguration(current.Manifest.Version, e.record.ExecutorID, demo.RoleDatabase(e.state, storagecheck.Executor), d2.ready)); err != nil {
		t.Fatal(err)
	}
	e2 := startOutputDaemon(t, ctx, current.Executor, work, config, "upgraded-executor")
	endpoint := "http://" + d2.ready.HTTPAddr
	awaitNodes(t, ctx, sdk(t, endpoint), e.record.ExecutorID)
	assertStatus(t, ctx, sdk(t, endpoint), first, e.record.ExecutorID)
	awaitOutput(t, ctx, sdk(t, endpoint), first, hello+"before-upgrade\n")
	releasedRun(t, ctx, current, work, endpoint, "after-upgrade")
	for _, r := range []*outputDaemon{e2, d2} {
		if err := r.child.Stop(ctx); err != nil || !r.child.CleanupComplete() {
			t.Fatalf("upgraded daemon shutdown: %v", err)
		}
		r.stopped = true
	}
	assertRetained(t, e.state, retained)
	if storedBinding(t, d.state, uuid.MustParse(first)) != binding {
		t.Fatal("upgrade changed the completed run's control binding")
	}
	for _, r := range []*role{d, e} {
		binary := previous.Dispatcher
		if r.kind == "executor" {
			binary = previous.Executor
		}
		path := demo.RoleDatabase(r.state, storagecheck.Role(r.kind))
		before, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		ready := filepath.Join(work, "refused-"+r.kind+".json")
		phase, done := context.WithTimeout(ctx, 10*time.Second)
		out, diagnostics, err := runCommand(phase, binary, work, isolatedEnvironment(work), "-config", filepath.Join(r.state, "service.toml"), "-ready-file", ready)
		done()
		diagnostics = append(out, diagnostics...)
		if err == nil || !bytes.Contains(diagnostics, []byte("newer")) || !bytes.Contains(diagnostics, []byte("install a Debuglet release")) {
			t.Fatalf("old %s did not refuse downgrade with version guidance: %v; %q", r.kind, err, diagnostics)
		}
		if _, err := os.Stat(ready); !os.IsNotExist(err) {
			t.Fatal("refused downgrade published readiness")
		}
		after, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(before, after) {
			t.Fatal("refused downgrade modified the database")
		}
		for _, suffix := range []string{"", "-wal", "-shm"} {
			if data, ok := backup[path+suffix]; ok {
				if err := os.WriteFile(path+suffix, data, 0600); err != nil {
					t.Fatal(err)
				}
			} else if err := os.Remove(path + suffix); err != nil && !os.IsNotExist(err) {
				t.Fatal(err)
			}
		}
	}
	d3 := releasedRole(t, ctx, previous, work, "dispatcher", d.state, "")
	e3 := releasedRole(t, ctx, previous, work, "executor", e.state, d3.record.Endpoint)
	if e3.record.ExecutorID != e.record.ExecutorID {
		t.Fatal("restored release changed executor identity")
	}
	assertStatus(t, ctx, sdk(t, d3.record.Endpoint), first, e.record.ExecutorID)
	awaitOutput(t, ctx, sdk(t, d3.record.Endpoint), first, hello+"before-upgrade\n")
	releasedRun(t, ctx, previous, work, d3.record.Endpoint, "after-rollback")
	t.Log("published v0.2.0 populated state upgraded and served by exact installed candidate; old package refused downgrade; offline backup restored and served by v0.2.0")
}
