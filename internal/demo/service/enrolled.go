package service

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
	executorconfig "github.com/netsec-ethz/debuglet/internal/executor/config"
	"github.com/netsec-ethz/debuglet/internal/storagecheck"
	"github.com/netsec-ethz/debuglet/internal/tlsfiles"
)

// prepareEnrolledState adopts only the canonical, already enrolled directory.
// Configuration, credentials and database are never regenerated or relocated.
func (i *Installer) prepareEnrolledState(ctx context.Context, p *Profile, account Account) error {
	for path := p.StateDir; path != p.Root && path != filepath.Dir(path); path = filepath.Dir(path) {
		info, err := os.Lstat(path)
		if err != nil || !info.IsDir() {
			return fmt.Errorf("enrolled state requires a real directory at %s", path)
		}
	}
	for _, name := range []string{"service.toml", "executor.sqlite", "ca.crt", "executor.crt", "executor.key"} {
		info, err := os.Lstat(filepath.Join(p.StateDir, name))
		if err != nil || !info.Mode().IsRegular() {
			return fmt.Errorf("enrolled state requires a regular %s", name)
		}
	}
	data, err := os.ReadFile(p.ConfigPath)
	if err != nil {
		return err
	}
	cfg, _, err := executorconfig.DecodeConfig(data)
	if err != nil {
		return err
	}
	id, err := uuid.Parse(cfg.Identity.ExecutorID)
	if err != nil || id == uuid.Nil || id.String() != cfg.Identity.ExecutorID ||
		(p.ExecutorID != "" && p.ExecutorID != cfg.Identity.ExecutorID) {
		return errors.New("enrolled configuration has an invalid or changed executor identity")
	}
	if cfg.TLS.Disable || cfg.Database.Path != p.DatabasePath ||
		cfg.Credentials.CACert != filepath.Join(p.StateDir, "ca.crt") ||
		cfg.Credentials.ClientCert != filepath.Join(p.StateDir, "executor.crt") ||
		cfg.Credentials.ClientKey != filepath.Join(p.StateDir, "executor.key") || cfg.Credentials.EnrollmentToken != "" {
		return errors.New("enrolled configuration must retain TLS and its original credentials and database inside the managed directory")
	}
	pair, err := tlsfiles.KeyPair("credentials.client_cert", cfg.Credentials.ClientCert, "credentials.client_key", cfg.Credentials.ClientKey, time.Now())
	if err != nil {
		return err
	}
	if pair.Leaf.IsCA || pair.Leaf.Subject.CommonName != cfg.Identity.ExecutorID {
		return errors.New("enrolled certificate does not identify this executor")
	}
	roots, err := tlsfiles.TrustRoots("credentials.ca_cert", cfg.Credentials.CACert, time.Now())
	if err != nil {
		return err
	}
	intermediates := x509.NewCertPool()
	for _, der := range pair.Certificate[1:] {
		certificate, err := x509.ParseCertificate(der)
		if err != nil {
			return err
		}
		intermediates.AddCert(certificate)
	}
	if _, err := pair.Leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		return fmt.Errorf("verify enrolled certificate: %w", err)
	}
	state, err := i.manager.State(ctx, p.Unit)
	if err != nil {
		return err
	}
	// An identical reinstall may observe its own existing managed process;
	// first adoption never ignores a PID, including a unit without a record.
	ignorePID := 0
	if p.ExecutorID != "" && state.Running() {
		if err := i.verifyRemoval(ctx, *p); err != nil {
			return err
		}
		ignorePID = state.MainPID
	}
	if err := checkEnrolledProcesses("/proc", *p, cfg.Identity.ExecutorID, ignorePID); err != nil {
		return err
	}
	if err := storagecheck.Check(ctx, storagecheck.Executor, p.DatabasePath); err != nil {
		return err
	}
	if err := i.own(p.StateDir, account); err != nil {
		return err
	}
	p.ExecutorID = cfg.Identity.ExecutorID
	p.DispatcherGRPC, p.DispatcherHTTP = cfg.Dispatcher.Addr, cfg.Dispatcher.YamuxAddr
	return writeRecord(*p)
}

// This observes already-running daemons; administrators must keep foreground
// executors stopped throughout adoption. It does not serialize concurrent starts.
func checkEnrolledProcesses(proc string, p Profile, id string, ignorePID int) error {
	return inspectExecutables(proc, ignorePID, func(pid, executable string) error {
		if filepath.Base(strings.TrimSuffix(executable, " (deleted)")) != "debuglet-executor" {
			return nil
		}
		data, err := os.ReadFile(filepath.Join(proc, pid, "cmdline"))
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("inspect executor process %s: %w", pid, err)
		}
		path := executorconfig.DefaultConfigPath
		args := strings.Split(string(data), "\x00")
		for n, arg := range args {
			if (arg == "-config" || arg == "--config") && n+1 < len(args) {
				path = args[n+1]
			} else if strings.HasPrefix(arg, "-config=") || strings.HasPrefix(arg, "--config=") {
				path = strings.SplitN(arg, "=", 2)[1]
			}
		}
		if !filepath.IsAbs(path) {
			path = filepath.Join(proc, pid, "cwd", path)
		}
		data, err = os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("cannot inspect executor process %s configuration; stop it before adoption: %w", pid, err)
		}
		cfg, _, err := executorconfig.DecodeConfig(data)
		if err != nil {
			return fmt.Errorf("cannot inspect executor process %s configuration; stop it before adoption: %w", pid, err)
		}
		database := cfg.Database.Path
		if !filepath.IsAbs(database) {
			database = filepath.Join(proc, pid, "cwd", database)
		}
		sameFile := func(a, b string) bool {
			x, e1 := os.Stat(a)
			y, e2 := os.Stat(b)
			return e1 == nil && e2 == nil && os.SameFile(x, y)
		}
		if cfg.Identity.ExecutorID == id || sameFile(path, p.ConfigPath) || sameFile(database, p.DatabasePath) {
			return fmt.Errorf("executor process %s is using this identity, configuration or database; stop it before service installation", pid)
		}
		return nil
	})
}
