package service

import (
	"fmt"
	"strings"

	"github.com/netsec-ethz/debuglet/internal/demo"
)

// Unit renders the service-manager unit of one profile. The text is a pure
// function of the profile, so an unchanged installation rewrites byte-identical
// content and a changed payload version is visible in the unit itself.
//
// The unit states four things an operator has to be able to rely on:
//
//   - It starts one verified payload by absolute path. No search path, no
//     working-directory lookup and no shell are involved.
//   - It runs as an existing unprivileged account with no capabilities and no
//     new privileges, and the only writable location is the role's own
//     persistent state directory plus its runtime directory.
//   - Stopping it sends SIGTERM to the daemon alone and gives it the whole
//     stop budget to revoke admission and join its owned local work. Only
//     after that budget does the service manager kill the remaining processes.
//   - Started is not ready. The daemon publishes a readiness record in its
//     runtime directory; that record, not process creation, is what an
//     installation or a restart observes.
func Unit(p Profile) (string, error) {
	for _, path := range []string{p.Executable, p.ConfigPath, p.ReadyFile, p.StateDir, p.RuntimeDir, p.PayloadRoot} {
		if err := unitSafePath(path); err != nil {
			return "", err
		}
	}
	if p.Role == demo.DispatcherSchema {
		if err := unitSafePath(p.MaintenanceFile); err != nil {
			return "", err
		}
	}
	description := fmt.Sprintf("Debuglet %s %s (%s)", p.Role, p.Name, p.Version)
	var b strings.Builder
	fmt.Fprintf(&b, "[Unit]\n")
	fmt.Fprintf(&b, "Description=%s\n", description)
	fmt.Fprintf(&b, "Documentation=https://github.com/netsec-ethz/debuglet/blob/hardening/docs/environments.md\n")
	fmt.Fprintf(&b, "After=network-online.target\n")
	fmt.Fprintf(&b, "Wants=network-online.target\n\n")
	fmt.Fprintf(&b, "[Service]\n")
	// Type=exec reports started once the daemon has been executed. It is not
	// a readiness statement, which is why the readiness record exists.
	fmt.Fprintf(&b, "Type=exec\n")
	fmt.Fprintf(&b, "User=%s\n", p.User)
	fmt.Fprintf(&b, "Group=%s\n", p.Group)
	// The single-dash spelling is the one the Ansible units use, and the
	// daemons accept it and the double-dash one alike.
	fmt.Fprintf(&b, "ExecStart=%s -config %s -ready-file %s\n", p.Executable, p.ConfigPath, p.ReadyFile)
	fmt.Fprintf(&b, "WorkingDirectory=%s\n", p.StateDir)
	fmt.Fprintf(&b, "Environment=LANG=C LC_ALL=C TZ=UTC\n")
	if p.Role == demo.DispatcherSchema {
		// The maintenance switch is a file in the administration
		// directory, which this account may read and not write: stopping
		// admission needs no network route, no credential and no restart,
		// and a dispatcher cannot take itself out of maintenance.
		fmt.Fprintf(&b, "Environment=%s=%s\n", MaintenanceFileEnv, p.MaintenanceFile)
	}
	fmt.Fprintf(&b, "RuntimeDirectory=%s\n", runtimeDirectoryName(p))
	fmt.Fprintf(&b, "RuntimeDirectoryMode=0700\n")
	// The restart policy of each role is the deployment's: a dispatcher is
	// restarted after a failure, an executor after any exit at all, because
	// an executor that ends for any reason should come back. Neither undoes
	// a deliberate stop, which is what a drain relies on.
	if p.Role == demo.DispatcherSchema {
		fmt.Fprintf(&b, "Restart=on-failure\n")
		fmt.Fprintf(&b, "RestartSec=5\n")
	} else {
		fmt.Fprintf(&b, "Restart=always\n")
		fmt.Fprintf(&b, "RestartSec=10\n")
	}
	fmt.Fprintf(&b, "KillSignal=SIGTERM\n")
	// Signal the daemon alone: it owns the teardown of anything it started,
	// and a group-wide signal would take that ownership away from it.
	fmt.Fprintf(&b, "KillMode=mixed\n")
	fmt.Fprintf(&b, "TimeoutStopSec=%d\n", p.StopBudgetSeconds)
	fmt.Fprintf(&b, "NoNewPrivileges=yes\n")
	fmt.Fprintf(&b, "CapabilityBoundingSet=\n")
	fmt.Fprintf(&b, "AmbientCapabilities=\n")
	fmt.Fprintf(&b, "PrivateTmp=yes\n")
	fmt.Fprintf(&b, "ProtectSystem=strict\n")
	fmt.Fprintf(&b, "ProtectHome=yes\n")
	fmt.Fprintf(&b, "ProtectControlGroups=yes\n")
	fmt.Fprintf(&b, "ProtectKernelModules=yes\n")
	fmt.Fprintf(&b, "ReadWritePaths=%s\n", p.StateDir)
	fmt.Fprintf(&b, "StandardOutput=journal\n")
	fmt.Fprintf(&b, "StandardError=journal\n")
	// The deployment's identifier, so one host's journal reads the same
	// whichever way its daemons were installed. Instances are still told
	// apart by their unit names.
	fmt.Fprintf(&b, "SyslogIdentifier=debuglet-%s\n\n", p.Role)
	fmt.Fprintf(&b, "[Install]\n")
	fmt.Fprintf(&b, "WantedBy=multi-user.target\n")
	return b.String(), nil
}

// runtimeDirectoryName is the runtime directory relative to the manager's own
// runtime root, which is what the unit directive takes.
func runtimeDirectoryName(p Profile) string {
	return fmt.Sprintf("debuglet/%ss/%s", p.Role, p.Name)
}

// unitSafePath refuses a path a unit file cannot carry literally. Quoting or
// escaping one instead would put the exact bytes a service manager executes at
// the mercy of this renderer's escaping rules.
func unitSafePath(path string) error {
	if path == "" {
		return fmt.Errorf("managed service path is empty")
	}
	for _, r := range path {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '/', r == '.', r == '-', r == '_', r == '+', r == ':', r == '@':
		default:
			return fmt.Errorf("managed service path %q contains characters a unit file cannot carry literally", path)
		}
	}
	return nil
}
