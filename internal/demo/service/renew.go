// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package service

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"

	"github.com/netsec-ethz/debuglet/internal/fsutil"
	"github.com/netsec-ethz/debuglet/internal/storagecheck"
)

// CheckCertificateRenewal requires an enrolled managed executor with a clean,
// disabled shutdown. An expired old certificate remains usable for recovery;
// enrollment is authorized by a fresh account-issued token, not that certificate.
// Administrators must exclude concurrent starts and state changes throughout.
func (i *Installer) CheckCertificateRenewal(ctx context.Context, name string) (Profile, error) {
	p, _, err := i.load(ctx, "renew-certificate", storagecheck.Executor, name)
	if err != nil {
		return p, err
	}
	if !p.Enrolled || p.ExecutorID == "" {
		return p, errors.New("certificate renewal requires an installed enrolled executor")
	}
	state, err := i.manager.State(ctx, p.Unit)
	if err != nil {
		return p, err
	}
	if !state.Loaded || !state.Joined() || state.MainPID != 0 || state.Enabled {
		return p, errors.New("certificate renewal requires a disabled executor with successful joined shutdown; drain it first")
	}
	if _, err := os.Lstat(p.UnitPath); err != nil {
		return p, err
	}
	if err := i.verifyRemoval(ctx, p); err != nil {
		return p, err
	}
	cfg, err := readEnrolledConfig(p)
	if err != nil {
		return p, err
	}
	if cfg.Dispatcher.Addr != p.DispatcherGRPC || cfg.Dispatcher.YamuxAddr != p.DispatcherHTTP ||
		(cfg.Network.PacketCounter == "auto") != p.PacketCapabilities {
		return p, errors.New("certificate renewal cannot change the recorded dispatcher or counter mode")
	}
	// Parse and match the existing key without rejecting an expired leaf.
	if _, err := tls.LoadX509KeyPair(cfg.Credentials.ClientCert, cfg.Credentials.ClientKey); err != nil {
		return p, fmt.Errorf("read retained executor identity: %w", err)
	}
	return p, checkEnrolledProcesses("/proc", p, p.ExecutorID, 0)
}

// RenewCertificate atomically publishes only a certificate valid for the saved
// key and retained trust roots. State, key, configuration, unit and record stay
// intact. It rechecks shutdown after the enrollment request has completed.
func (i *Installer) RenewCertificate(ctx context.Context, name string, certificate []byte) error {
	p, err := i.CheckCertificateRenewal(ctx, name)
	if err != nil {
		return err
	}
	path := filepath.Join(p.StateDir, "executor.crt")
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	owner, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return errors.New("certificate renewal cannot inspect certificate ownership")
	}
	file, err := os.CreateTemp(p.StateDir, ".renew-")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	if _, err := file.Write(certificate); err != nil {
		file.Close()
		return err
	}
	err = errors.Join(i.chown(file, int(owner.Uid), int(owner.Gid)), file.Chmod(info.Mode().Perm()), file.Sync(), file.Close())
	if err != nil {
		return err
	}
	cfg, err := readEnrolledConfig(p)
	if err != nil {
		return err
	}
	if err := validateEnrolledCertificate(cfg, file.Name()); err != nil {
		return err
	}
	if _, err := i.CheckCertificateRenewal(ctx, name); err != nil {
		return err
	}
	if err := os.Rename(file.Name(), path); err != nil {
		return err
	}
	return fsutil.SyncDir(p.StateDir)
}
