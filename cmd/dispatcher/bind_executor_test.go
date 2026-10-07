// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/netsec-ethz/debuglet/internal/dispatcher/enrollment"
	"github.com/netsec-ethz/debuglet/internal/sqlitedb"
	"github.com/netsec-ethz/debuglet/internal/storagecheck"
	"github.com/netsec-ethz/debuglet/internal/testtls"
)

// An executor deployed with a certificate the administrator issued has no
// token to enrol with, so the deployment binds it on the dispatcher host. The
// binding is what the enforcing dispatcher admits the executor by.
func TestBindExecutorAdmitsAnAdministratorIssuedCertificate(t *testing.T) {
	const executorID = "5fe02882-0410-416c-9935-235090bcba0d"
	dir := filepath.Join(t.TempDir(), "state")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "dispatcher.sqlite")
	if err := storagecheck.BootstrapFresh(context.Background(), storagecheck.Dispatcher, path); err != nil {
		t.Fatalf("bootstrap database: %v", err)
	}
	certs := t.TempDir()
	authority, err := testtls.NewAuthority(certs, "deployment-ca")
	if err != nil {
		t.Fatal(err)
	}
	client, err := authority.Issue(executorID, testtls.Options{Client: true})
	if err != nil {
		t.Fatal(err)
	}
	// The deployment copies only the public certificate to the dispatcher.
	certFile := filepath.Join(certs, "client.crt")
	if err := os.WriteFile(certFile, client.CertPEM, 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := dispatcherConfig(path)
	cfg.TLS.Disable = false
	cfg.TLS.CAFile = authority.CertFile
	cfg.TLS.RequireClientCert = true
	sum := sha256.Sum256(client.Certificate.Certificate[0])
	fingerprint := hex.EncodeToString(sum[:])

	bound := func(fingerprint string) error {
		t.Helper()
		db, err := sqlitedb.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		defer db.Close()
		return enrollment.NewStore(db).Bound(context.Background(), executorID, fingerprint)
	}
	if err := bound(fingerprint); !errors.Is(err, enrollment.ErrNotEnrolled) {
		t.Fatalf("before binding: %v", err)
	}

	var out bytes.Buffer
	if err := administerBinding(context.Background(), cfg, executorID, certFile, &out); err != nil {
		t.Fatalf("bind: %v", err)
	}
	if want := "executor " + executorID + " is now bound to certificate sha256:" + fingerprint; !strings.Contains(out.String(), want) {
		t.Fatalf("output %q, want %q", out.String(), want)
	}
	if err := bound(fingerprint); err != nil {
		t.Fatalf("the bound certificate is refused: %v", err)
	}

	// Running the deployment again changes nothing, and says so.
	out.Reset()
	if err := administerBinding(context.Background(), cfg, executorID, certFile, &out); err != nil {
		t.Fatalf("bind again: %v", err)
	}
	if !strings.Contains(out.String(), "is already bound") {
		t.Fatalf("repeated binding printed %q", out.String())
	}

	// A reissued certificate replaces the binding, so the executor that
	// installs it is admitted and the old certificate is not.
	reissued, err := authority.Issue(executorID, testtls.Options{Client: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(certFile, reissued.CertPEM, 0o644); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if err := administerBinding(context.Background(), cfg, executorID, certFile, &out); err != nil {
		t.Fatalf("rebind: %v", err)
	}
	if !strings.Contains(out.String(), "replacing sha256:"+fingerprint) {
		t.Fatalf("rebinding printed %q", out.String())
	}
	if err := bound(fingerprint); !errors.Is(err, enrollment.ErrWrongNode) {
		t.Fatalf("the replaced certificate: %v", err)
	}

	// Refusals record nothing.
	other, err := testtls.NewAuthority(t.TempDir(), "other-ca")
	if err != nil {
		t.Fatal(err)
	}
	foreign, err := other.Issue(executorID, testtls.Options{Client: true})
	if err != nil {
		t.Fatal(err)
	}
	foreignFile := filepath.Join(certs, "foreign.crt")
	if err := os.WriteFile(foreignFile, foreign.CertPEM, 0o644); err != nil {
		t.Fatal(err)
	}
	for name, run := range map[string]func() error{
		"another authority": func() error {
			return administerBinding(context.Background(), cfg, executorID, foreignFile, &out)
		},
		"another executor ID": func() error {
			return administerBinding(context.Background(), cfg, "1144ad6e-2c14-4e5c-ab72-c05a8e8770f2", certFile, &out)
		},
		"a private key": func() error {
			return administerBinding(context.Background(), cfg, executorID, reissued.KeyFile, &out)
		},
		"a missing file": func() error {
			return administerBinding(context.Background(), cfg, executorID, filepath.Join(certs, "absent.crt"), &out)
		},
		"no authority configured": func() error {
			unconfigured := *cfg
			unconfigured.TLS.CAFile = ""
			return administerBinding(context.Background(), &unconfigured, executorID, certFile, &out)
		},
		"an absent database": func() error {
			absent := *cfg
			absent.Database.Path = filepath.Join(dir, "absent.sqlite")
			return administerBinding(context.Background(), &absent, executorID, certFile, &out)
		},
	} {
		if err := run(); err == nil {
			t.Errorf("%s was bound", name)
		}
	}
	sum = sha256.Sum256(reissued.Certificate.Certificate[0])
	if err := bound(hex.EncodeToString(sum[:])); err != nil {
		t.Fatalf("a refused binding changed the recorded one: %v", err)
	}
}

// The two flags name one binding, so either alone is refused before any
// configuration or database is read, and so is combining it with a check.
func TestBindExecutorFlagsGoTogether(t *testing.T) {
	if os.Getenv("DEBUGLET_BIND_COMMAND_TEST") == "dispatcher" {
		index := slices.Index(os.Args, "--")
		os.Args = append([]string{os.Args[0]}, os.Args[index+1:]...)
		flag.CommandLine = flag.NewFlagSet("dispatcher", flag.ExitOnError)
		main()
		return
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	absent := filepath.Join(t.TempDir(), "absent.toml")
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"-config", absent, "-bind-executor", "executor"}, "must be given together"},
		{[]string{"-config", absent, "-bind-certificate", "client.crt"}, "must be given together"},
		{[]string{"-config", absent, "-check-database", "-bind-executor", "executor", "-bind-certificate", "client.crt"}, "cannot be combined"},
	} {
		ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
		command := exec.CommandContext(ctx, executable, append([]string{"-test.run=^TestBindExecutorFlagsGoTogether$", "--"}, tc.args...)...)
		command.Env = append(os.Environ(), "DEBUGLET_BIND_COMMAND_TEST=dispatcher")
		output, err := command.CombinedOutput()
		cancel()
		if err == nil || !strings.Contains(string(output), tc.want) {
			t.Errorf("%v: %v, output %q, want a refusal mentioning %q", tc.args, err, output, tc.want)
		}
	}
}
