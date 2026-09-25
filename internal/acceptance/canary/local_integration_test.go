//go:build linux && canary_integration

package main

import (
	"context"
	"debug/buildinfo"
	"encoding/json"
	"github.com/google/uuid"
	apispec "github.com/netsec-ethz/debuglet/api"
	"github.com/netsec-ethz/debuglet/internal/acceptance/procinventory"
	"github.com/netsec-ethz/debuglet/internal/demo"
	dispatcherconfig "github.com/netsec-ethz/debuglet/internal/dispatcher/config"
	executorconfig "github.com/netsec-ethz/debuglet/internal/executor/config"
	"github.com/netsec-ethz/debuglet/internal/readiness"
	"github.com/netsec-ethz/debuglet/pkg/client"
	"github.com/pelletier/go-toml/v2"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"
)

// This gate invokes the actual repository-only driver and installed payload.
// Missing inputs are failures, never skips. Ownership is inspected before the
// harness can repair a failed driver's cleanup.
func TestCanaryLocal(t *testing.T) {
	root, evidenceRoot, driver := os.Getenv("DEBUGLET_CANARY_INSTALLED_ROOT"), os.Getenv("DEBUGLET_CANARY_EVIDENCE_DIR"), os.Getenv("DEBUGLET_CANARY_DRIVER")
	digest := os.Getenv("DEBUGLET_CANARY_ARCHIVE_SHA256")
	if !filepath.IsAbs(root) || !filepath.IsAbs(evidenceRoot) || !filepath.IsAbs(driver) || !lowerHex(digest, 64) {
		t.Fatal("absolute installed root, evidence root, driver and archive digest are required")
	}
	info, err := os.Lstat(evidenceRoot)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0700 {
		t.Fatal("evidence root must already exist as a private directory")
	}
	assets, err := demo.ResolveAssets(filepath.Join(root, "bin", "dbl"))
	if err != nil {
		t.Fatal(err)
	}
	binaryInfo, err := buildinfo.ReadFile(driver)
	if err != nil {
		t.Fatal("driver build identity:", err)
	}
	revision, modified := "", ""
	for _, setting := range binaryInfo.Settings {
		switch setting.Key {
		case "vcs.revision":
			revision = setting.Value
		case "vcs.modified":
			modified = setting.Value
		}
	}
	if binaryInfo.Path != "github.com/netsec-ethz/debuglet/internal/acceptance/canary" || revision != assets.Manifest.SourceSHA || modified != "false" {
		t.Fatalf("driver/installed source identity mismatch: path=%q revision=%q modified=%q candidate=%q", binaryInfo.Path, revision, modified, assets.Manifest.SourceSHA)
	}
	fixture, err := os.MkdirTemp(evidenceRoot, "canary-harness-")
	if err != nil {
		t.Fatal(err)
	}
	t.Run("ownership_controls", func(t *testing.T) { ownershipControls(t, fixture) })
	manifest := Manifest{SchemaVersion: 1, Environment: "local", Operator: "local CI", ExecutorID: uuid.NewString(), Control: ControlManifest{Protection: "owned-loopback"}, Target: TargetManifest{Host: "127.0.0.1"}, Limits: LimitsManifest{ExecutionMS: 15000, CeilingBPS: 1_000_000, AttemptMS: 180000}}
	manifestBytes, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	manifestPath := filepath.Join(fixture, "manifest.json")
	if err := os.WriteFile(manifestPath, manifestBytes, 0600); err != nil {
		t.Fatal(err)
	}
	evidenceDir := filepath.Join(fixture, "attempt")
	sentinelPath := filepath.Join(fixture, "unrelated-sentinel")
	if err := os.WriteFile(sentinelPath, []byte("keep me"), 0600); err != nil {
		t.Fatal(err)
	}
	sentinel, err := demo.StartChild(demo.ChildSpec{Path: "/bin/sleep", Dir: fixture, Args: []string{"240"}, Env: []string{}, Stdout: io.Discard, Stderr: io.Discard})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, end := context.WithTimeout(context.Background(), 5*time.Second)
		defer end()
		if err := sentinel.Stop(ctx); err != nil {
			t.Error("join sentinel:", err)
		}
	})
	capture := newCapture(captureLimit)
	child, err := demo.StartChild(demo.ChildSpec{Path: driver, Dir: fixture, Args: []string{"-manifest", manifestPath, "-installed-root", root, "-archive-sha256", digest, "-evidence-dir", evidenceDir}, Env: []string{"LANG=C", "LC_ALL=C", "TZ=UTC", "TMPDIR=" + fixture}, Stdout: capture.stdout(), Stderr: capture.stderr()})
	if err != nil {
		t.Fatal(err)
	}
	track := newCanaryOwnership()
	dispatcherObserved, executorObserved, routeObserved := false, false, false
	// This cleanup is emergency repair only and happens after all assertions.
	t.Cleanup(func() {
		ctx, end := context.WithTimeout(context.Background(), 5*time.Second)
		defer end()
		_ = child.Stop(ctx)
		track.emergencyKill()
	})
	driverIdentity, err := procinventory.Read(child.PID())
	if err != nil {
		t.Fatal("capture driver identity:", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 190*time.Second)
	defer cancel()
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
observe:
	for {
		if err := track.discover(driverIdentity, assets); err != nil {
			t.Fatal("discover actual driver descendants:", err)
		}
		dirs, _ := filepath.Glob(filepath.Join(evidenceDir, "state-*"))
		for _, dir := range dirs {
			track.dirs[dir] = true
			for _, name := range []string{"dispatcher", "executor"} {
				if name == "dispatcher" && dispatcherObserved || name == "executor" && executorObserved {
					continue
				}
				data, err := boundedCandidateFile(filepath.Join(dir, name+"-ready.json"), 4096)
				if err != nil {
					if !os.IsNotExist(err) {
						t.Fatal("bounded readiness observation:", err)
					}
					continue
				}
				var record readiness.Record
				if json.Unmarshal(data, &record) != nil || record.SchemaVersion != 1 || record.PID <= 0 {
					t.Error("invalid observed readiness")
					continue
				}
				expected := assets.Dispatcher
				if name == "executor" {
					expected = assets.Executor
				}
				p, ok := track.corroborate(record.PID, expected)
				if !ok {
					// Readiness can appear after this poll's discovery. Wait for
					// independent admission; these bytes never grant ownership.
					continue
				}
				if err := track.captureSockets(p); err != nil && !procinventory.Exited(err) {
					t.Fatal("capture ready daemon sockets:", err)
				}
				if name == "dispatcher" {
					var cfg dispatcherconfig.DispatcherConfig
					configBytes, e := boundedCandidateFile(filepath.Join(dir, "dispatcher.toml"), 64<<10)
					if e != nil || toml.Unmarshal(configBytes, &cfg) != nil {
						t.Fatal("bounded daemon config observation failed")
					}
					if cfg.Server.Version != assets.Manifest.Version || cfg.Server.BindHost != "127.0.0.1" || !cfg.Sui.Disabled || cfg.Scheduler.ExecutorTimeout != 10 || !localAddress(record.HTTPAddr) || !localAddress(record.GRPCAddr) {
						t.Error("dispatcher config/readiness mismatch")
						continue
					}
					dispatcherObserved = true
				} else {
					var cfg executorconfig.ExecutorConfig
					configBytes, e := boundedCandidateFile(filepath.Join(dir, "executor.toml"), 64<<10)
					if e != nil || toml.Unmarshal(configBytes, &cfg) != nil {
						t.Fatal("bounded daemon config observation failed")
					}
					if record.ExecutorID != manifest.ExecutorID || cfg.Identity.ExecutorID != manifest.ExecutorID || cfg.Identity.Version != assets.Manifest.Version || cfg.Tesla.Delay != 2 || cfg.Network.PacketCounter != "fallback" || !cfg.Network.DisableSCIONEnvironment || cfg.Network.PublicHost != "" || cfg.Network.PublicPorts != "" {
						t.Error("executor config/readiness mismatch")
						continue
					}
					executorObserved = true
				}
			}
		}
		// Only independently discovered, still-matching CLI children can
		// corroborate the installed run command's owned /api route.
		for _, p := range track.processes {
			if p.Executable != assets.CLI {
				continue
			}
			current, ok := track.corroborate(p.PID, assets.CLI)
			if !ok {
				continue
			}
			fields := current.Arguments
			if len(fields) > 7 && fields[1] == "--endpoint" && strings.HasSuffix(fields[2], "/api") && fields[3] == "--timeout" && fields[5] == "--output" && fields[7] == "run" {
				address := strings.TrimSuffix(strings.TrimPrefix(fields[2], "http://"), "/api")
				if !localAddress(address) {
					t.Fatal("nonlocal CLI endpoint")
				}
				routeObserved = true
			}
		}
		select {
		case <-child.Done():
			break observe
		case <-ctx.Done():
			t.Error("driver exceeded outer watchdog")
			break observe
		case <-ticker.C:
		}
	}
	waitErr := child.Wait(ctx)
	// No emergency signal or state deletion has happened yet.
	if waitErr != nil {
		t.Error("actual compatibility driver failed:", waitErr)
	}
	if !dispatcherObserved || !executorObserved || !routeObserved {
		t.Errorf("startup observations dispatcher=%t executor=%t installed_run_api=%t", dispatcherObserved, executorObserved, routeObserved)
	}
	if err := track.verifyGone(); err != nil {
		t.Error("cleanup before emergency repair:", err)
	}
	if channelClosed(sentinel.Done()) || syscall.Kill(sentinel.PID(), 0) != nil {
		t.Error("unrelated sentinel process was stopped")
	}
	if data, err := boundedCandidateFile(sentinelPath, 64); err != nil || string(data) != "keep me" {
		t.Error("unrelated sentinel path was removed")
	}
	output, overflow := capture.result()
	if overflow {
		t.Fatal("driver output exceeded bound")
	}
	var ev Evidence
	if json.Unmarshal(output, &ev) != nil {
		t.Fatalf("missing single driver JSON (bytes=%d)", len(output))
	}
	persisted, err := boundedCandidateFile(filepath.Join(evidenceDir, "result.json"), captureLimit)
	if err != nil {
		t.Fatal(err)
	}
	var saved Evidence
	if json.Unmarshal(persisted, &saved) != nil || !reflect.DeepEqual(saved, ev) {
		t.Error("saved and emitted evidence differ")
	}
	if ev.Outcome != "passed" || ev.Phase != "complete" || ev.ETHTestbed != "unconfirmed" || ev.SourceSHA != assets.Manifest.SourceSHA || ev.ArchiveSHA256 != digest || ev.ExecutorID != manifest.ExecutorID || ev.RunID == nil || !canonicalUUID(*ev.RunID) || ev.Submission == nil || ev.Submission.OutcomeUnknown || ev.Submission.State != client.StateExited || ev.Submission.TransactionID == nil || !lowerHex(*ev.Submission.TransactionID, 32) {
		t.Errorf("invalid completed identity/effect evidence: %+v", ev)
	}
	if ev.DispatcherSourceSHA == nil || *ev.DispatcherSourceSHA != assets.Manifest.SourceSHA || ev.ReportedVersion == nil || *ev.ReportedVersion != assets.Manifest.Version || ev.ReportedAPIVersion == nil || *ev.ReportedAPIVersion != apispec.Version || ev.Terminal.State == nil || *ev.Terminal.State != client.StateExited || ev.Terminal.Error == nil || *ev.Terminal.Error != "" || ev.Target.ACK == nil || !*ev.Target.ACK || ev.Target.Nonce == nil || !lowerHex(*ev.Target.Nonce, 32) || ev.OutputMarkerSeen == nil || !*ev.OutputMarkerSeen {
		t.Error("missing actual terminal, target or output observations")
	}
	if ev.Cleanup.ChildrenReaped == nil || !*ev.Cleanup.ChildrenReaped || ev.Cleanup.StateRemoved == nil || !*ev.Cleanup.StateRemoved || ev.Cleanup.RegistryIneligible == nil || !*ev.Cleanup.RegistryIneligible || ev.Cleanup.ForcedKills == nil || *ev.Cleanup.ForcedKills != 0 {
		t.Error("cleanup was not complete and graceful")
	}
	if len(track.sockets) < 3 {
		t.Errorf("insufficient independent listener ownership observations: %d", len(track.sockets))
	}
	loaded, err := LoadManifest(manifestPath)
	if err != nil || ev.ManifestSHA256 != loaded.SourceSHA256 {
		t.Error("original manifest identity mismatch")
	}
	if info, err := os.Lstat(filepath.Join(evidenceDir, "result.json")); err != nil || info.Mode().Perm() != 0600 {
		t.Error("evidence mode mismatch")
	}
	t.Logf("candidate=%s executor=%s evidence=%s ownership_observed_before_emergency_cleanup=true", ev.SourceSHA, ev.ExecutorID, evidenceDir)
}
