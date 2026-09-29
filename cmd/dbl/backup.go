package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/netsec-ethz/debuglet/internal/demo"
)

const backupUsage = `Usage:
  dbl [--timeout 5m] [--output human|json] backup --state-dir DIR --destination BACKUP --offline

Back up a local environment or role after its foreground command has stopped
and joined every child. --offline confirms no unmanaged daemon writes this
state. A recorded clean shutdown and an exclusive state lock are also required.
Direct daemon and systemd service state is not supported by this command.
The destination must not exist. Backups contain private plaintext credentials;
store them privately. External keys, CLI credentials and binaries are excluded.
Use the full installed package that owns the state.
`

const restoreUsage = `Usage:
  dbl [--timeout 5m] [--output human|json] restore --backup BACKUP --state-dir NEWDIR

Verify a backup and restore into a separate, absent state directory using the
same full installed package. The original state and backup remain unchanged.
No service is started and no measurement is replayed. Keep the original roles
stopped: the restored roles retain their identities and credentials.
`

func backupCommand(ctx context.Context, command string, args []string, options globalOptions, stdout, stderr io.Writer) int {
	name, usage := "dbl "+command, backupUsage
	if command == "restore" {
		usage = restoreUsage
	}
	fs := newCommandFlagSet(command)
	var stateDir, backupDir string
	var offline bool
	fs.StringVar(&stateDir, "state-dir", "", "owned state directory")
	if command == "backup" {
		fs.StringVar(&backupDir, "destination", "", "new private backup directory")
		fs.BoolVar(&offline, "offline", false, "confirm all writers have stopped")
	} else {
		fs.StringVar(&backupDir, "backup", "", "verified backup to restore")
	}
	if code, ok := parseCommandFlags(fs, args, usage, stdout, stderr); !ok {
		return code
	}
	if fs.NArg() != 0 || strings.TrimSpace(stateDir) == "" || strings.TrimSpace(backupDir) == "" || options.EndpointSet || options.Dispatcher != "" {
		return usageError(name, usage, stderr, "specify the state and backup directories; this local command takes no remote endpoint or positional arguments")
	}
	if command == "backup" && !offline {
		return usageError(name, usage, stderr, "--offline is required after a successful foreground shutdown")
	}
	exe, err := os.Executable()
	if err != nil {
		return reportFailure(ctx, name, stderr, err)
	}
	assets, err := demo.ResolveAssets(exe)
	if err != nil {
		return reportFailure(ctx, name, stderr, err)
	}
	var manifest demo.BackupManifest
	if command == "backup" {
		manifest, err = demo.BackupState(ctx, demo.BackupOptions{StateDir: stateDir, Destination: backupDir, Offline: offline, Package: assets.Manifest})
	} else {
		manifest, err = demo.RestoreState(ctx, demo.RestoreOptions{BackupDir: backupDir, StateDir: stateDir, Package: assets.Manifest})
	}
	if err != nil {
		return reportFailure(ctx, name, stderr, err)
	}
	return emitReported(ctx, name, options.Output, stdout, stderr, manifest, func(w io.Writer) error {
		if command == "backup" {
			_, err := fmt.Fprintf(w, "Backup created: %s\nKeep this directory private; its contents are not encrypted.\n", backupDir)
			return err
		}
		_, err := fmt.Fprintf(w, "State restored: %s\nNo services started or measurements replayed. Keep the original instance stopped.\n", stateDir)
		return err
	})
}
