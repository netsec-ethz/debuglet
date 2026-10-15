// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/netsec-ethz/debuglet/internal/demo/service"
	"github.com/netsec-ethz/debuglet/internal/storagecheck"
)

type renewalManager struct {
	*recordingManager
	failed bool
}

func (m *renewalManager) State(ctx context.Context, unit string) (service.UnitState, error) {
	state, err := m.recordingManager.State(ctx, unit)
	state.Result = "success"
	if m.failed {
		state.Active, state.Result, state.ExecMainStatus = "failed", "exit-code", 1
	}
	return state, err
}

func TestExecutorJoinRenewManagedCertificate(t *testing.T) {
	for _, scenario := range []string{"success", "expired certificate", "write failure retry", "changed endpoints", "changed issuer", "invalid response", "enabled unit", "running unit", "failed shutdown", "changed identity", "changed settings"} {
		t.Run(scenario, func(t *testing.T) {
			alterResponse := false
			fixture := newJoinFixture(t, func(result *executorJoinResponse) {
				if alterResponse && scenario == "changed endpoints" {
					result.GRPCAddress = "another.example:9001"
				}
				if alterResponse && scenario == "invalid response" {
					result.CertificatePEM = "not a certificate"
				}
			})
			root := t.TempDir()
			state := service.StateDirectory(root, storagecheck.Executor, "worker")
			var stdout, stderr bytes.Buffer
			if code := run(t.Context(), fixture.args(state), &stdout, &stderr); code != exitOK {
				t.Fatalf("join: %d %s", code, stderr.String())
			}
			manager := newRecordingManager()
			deps := serviceTestDependencies(t, manager, root)
			observed := &renewalManager{recordingManager: manager}
			deps.manager = func(string) (service.Manager, error) { return observed, nil }
			deps.lookup = func(string, string) (service.Account, error) { return service.Account{UID: 4242, GID: 4343}, nil }
			if code := serviceCommandWith(t.Context(), []string{"install", "--role", "executor", "--enrolled-state", state, "--start=false", "--enable=false"}, globalOptions{}, &stdout, &stderr, deps); code != exitOK {
				t.Fatalf("install: %d %s", code, stderr.String())
			}
			certPath := filepath.Join(state, "executor.crt")
			if err := os.Chmod(certPath, 0640); err != nil {
				t.Fatal(err)
			}
			if scenario == "expired certificate" {
				pair, err := tls.LoadX509KeyPair(certPath, filepath.Join(state, "executor.key"))
				if err != nil {
					t.Fatal(err)
				}
				key := pair.PrivateKey.(crypto.Signer)
				template := &x509.Certificate{SerialNumber: big.NewInt(99), Subject: pkix.Name{CommonName: joinExecutorID}, NotBefore: time.Now().Add(-2 * time.Hour), NotAfter: time.Now().Add(-time.Hour)}
				der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0640); err != nil {
					t.Fatal(err)
				}
			}
			if scenario == "changed issuer" {
				// The API remains trusted, but its issuer is absent from the saved
				// native roots. Renewal may not silently replace those roots.
				data, _ := os.ReadFile(fixture.caFile)
				if err := os.WriteFile(filepath.Join(state, "ca.crt"), data, 0600); err != nil {
					t.Fatal(err)
				}
			}
			original := map[string][]byte{}
			for _, name := range []string{"executor.key", "executor.crt", "ca.crt", "executor.sqlite", "service.toml"} {
				data, err := os.ReadFile(filepath.Join(state, name))
				if err != nil {
					t.Fatal(err)
				}
				original[name] = data
			}
			info, _ := os.Stat(certPath)
			owner := info.Sys().(*syscall.Stat_t)
			chowned := false
			failWrite := scenario == "write failure retry"
			deps.chown = func(_ *os.File, uid, gid int) error {
				if failWrite {
					return errors.New("fixture refused certificate ownership")
				}
				if uid != int(owner.Uid) || gid != int(owner.Gid) {
					t.Errorf("certificate owner changed: %d:%d", uid, gid)
				}
				chowned = true
				return nil
			}
			args := append(fixture.args(state)[2:], "--renew")
			unit := "debuglet-executor-worker.service"
			switch scenario {
			case "enabled unit":
				manager.enabled[unit] = true
			case "running unit":
				manager.mainPID = 12345
			case "failed shutdown":
				observed.failed = true
			case "changed identity":
				for n, arg := range args {
					if arg == joinExecutorID {
						args[n] = "00000000-1111-2222-3333-444444444444"
					}
				}
			case "changed settings":
				args = append(args, "--capacity", "1000")
			}
			alterResponse = true
			renew := func() int {
				stdout.Reset()
				stderr.Reset()
				return executorJoinCommandWith(context.Background(), args, globalOptions{}, &stdout, &stderr, deps)
			}
			code := renew()
			wantSuccess := scenario == "success" || scenario == "expired certificate"
			if !wantSuccess {
				if code == exitOK || strings.Contains(stdout.String(), "certificate renewed") {
					t.Fatalf("renewal unexpectedly succeeded: %s %s", stdout.String(), stderr.String())
				}
				for name, want := range original {
					got, _ := os.ReadFile(filepath.Join(state, name))
					if !bytes.Equal(got, want) {
						t.Fatalf("failed renewal changed %s", name)
					}
				}
				if scenario != "write failure retry" {
					return
				}
				if !strings.Contains(stderr.String(), "fresh Set up again token") {
					t.Fatalf("missing recovery instructions: %s", stderr.String())
				}
				failWrite = false
				code = renew()
			}
			if code != exitOK || !strings.Contains(stdout.String(), "certificate renewed") || !chowned {
				t.Fatalf("renewal: %d %s %s", code, stdout.String(), stderr.String())
			}
			for name, want := range original {
				got, _ := os.ReadFile(filepath.Join(state, name))
				if bytes.Equal(got, want) == (name == "executor.crt") {
					t.Errorf("unexpected contents after renewal: %s", name)
				}
			}
			info, _ = os.Stat(certPath)
			if info.Mode().Perm() != 0640 || manager.enabled[unit] || manager.mainPID != 0 {
				t.Fatal("renewal changed certificate mode or enabled/started unit")
			}
			if strings.Contains(stdout.String()+stderr.String(), fixSecret) {
				t.Fatal("renewal disclosed token")
			}
		})
	}
}
