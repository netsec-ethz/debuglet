package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/netsec-ethz/debuglet/internal/artifact"
	"github.com/netsec-ethz/debuglet/internal/hostprobe"
	"github.com/netsec-ethz/debuglet/internal/storagecheck"
	"github.com/netsec-ethz/debuglet/internal/tlsfiles"
)

const doctorUsage = `Usage:
  dbl [--timeout 30s] [--output human|json] doctor
      [--role dispatcher|executor --file FILE] [--offline] [--connection]

Check the installed payload and, with a daemon file, its local prerequisites.
--offline confirms the daemon is stopped before inspecting its database schema.
--connection explicitly checks only the selected HTTP dispatcher. No other
network is contacted. Local filesystem/capability checks use this process's
identity, which may differ from the service account. No measurement is launched.
The clock check reads the kernel's own synchronization state and error estimate
(Linux adjtimex, read only) against the executor's clock.max_error_ms; no time
source is queried.

Statuses: pass, failure, unavailable, not_checked. Exit 1 means a failure or
unavailable check; not_checked is inconclusive. This does not certify isolation,
packet enforcement, clock accuracy or readiness of a running daemon.
`

type doctorCheck struct {
	ID     string `json:"id"`
	Status string `json:"status"`
	Detail string `json:"detail"`
	Next   string `json:"next,omitempty"`
}

type doctorReport struct {
	Checks []doctorCheck `json:"checks"`
}

func doctorCommand(ctx context.Context, args []string, options globalOptions, stdout, stderr io.Writer) int {
	fs := newCommandFlagSet("doctor")
	role := fs.String("role", "", "dispatcher or executor")
	file := fs.String("file", "", "daemon TOML file")
	connection := fs.Bool("connection", false, "make one bounded request to the selected dispatcher")
	offline := fs.Bool("offline", false, "confirm the daemon is stopped and inspect its database schema")
	if code, ok := parseCommandFlags(fs, args, doctorUsage, stdout, stderr); !ok {
		return code
	}
	if fs.NArg() != 0 || (*offline && *role == "") || (*role == "") != (*file == "") || (*role != "" && *role != "dispatcher" && *role != "executor") {
		return usageError("dbl doctor", doctorUsage, stderr, "supply --role dispatcher|executor and --file FILE together")
	}
	executable, _ := os.Executable()
	report := doctorReport{Checks: []doctorCheck{payloadCheck(executable)}}
	clockBound := hostprobe.DefaultClockErrorBound
	if *role == "" {
		report.Checks = append(report.Checks, doctorCheck{"config", "not_checked", "no daemon configuration selected", "supply --role and --file to check local daemon prerequisites"})
	} else {
		cfg, err := readDaemonConfig(*role, *file)
		if err != nil {
			report.Checks = append(report.Checks, doctorCheck{"config", "failure", err.Error(), "correct the selected daemon configuration"})
		} else {
			report.Checks = append(report.Checks, doctorCheck{"config", "pass", "startup configuration validation passed", ""})
			report.Checks = append(report.Checks, localDaemonChecks(ctx, *role, cfg, *offline)...)
			if cfg.executor != nil {
				clockBound = cfg.executor.Clock.MaxErrorBound()
			}
		}
	}
	report.Checks = append(report.Checks, clockCheck(readClock(clockBound)))
	if *connection {
		report.Checks = append(report.Checks, dispatcherCheck(ctx, options))
	} else {
		report.Checks = append(report.Checks, doctorCheck{"dispatcher_connection", "not_checked", "network checks were not requested", "use --connection to check the selected HTTP dispatcher"})
	}
	code := emitReported(ctx, "dbl doctor", options.Output, stdout, stderr, report, func(w io.Writer) error {
		for _, check := range report.Checks {
			if _, err := fmt.Fprintf(w, "%s [%s]: %s\n", check.ID, check.Status, check.Detail); err != nil {
				return err
			}
			if check.Next != "" {
				if _, err := fmt.Fprintf(w, "  next: %s\n", check.Next); err != nil {
					return err
				}
			}
		}
		return nil
	})
	if code != exitOK {
		return code
	}
	if ctx.Err() != nil {
		return failureExit(ctx)
	}
	for _, check := range report.Checks {
		if check.Status == "failure" || check.Status == "unavailable" {
			return exitFailure
		}
	}
	return exitOK
}

// readClock is replaced in tests; the host's own clock state is not a fixture.
var readClock = hostprobe.ReadClock

// clockCheck grades the kernel's own clock discipline, read without changing
// it, against the executor's bound (the default without an executor file). No
// external time source is queried, so a pass means the kernel reports a
// disciplined clock within the bound, not that the time is verified.
func clockCheck(c hostprobe.Clock) doctorCheck {
	switch c.Readiness {
	case hostprobe.ReadinessReady:
		return doctorCheck{"clock", "pass", fmt.Sprintf("kernel clock is synchronized; estimated error %v within the %v bound", *c.EstimatedError, c.Bound), ""}
	case hostprobe.ReadinessDegraded:
		// Inconclusive rather than a failure: the executor reports degraded
		// readiness but still admits runs, and development hosts and VMs
		// often run without a time daemon. As for BTF, the detail says why.
		if c.Reason == hostprobe.ReasonUnsynced {
			return doctorCheck{"clock", "not_checked", "kernel clock is not synchronized; the executor would report degraded clock readiness", "run a time daemon such as chrony or systemd-timesyncd and wait for it to synchronize"}
		}
		return doctorCheck{"clock", "not_checked", fmt.Sprintf("kernel estimated clock error %v exceeds the %v bound; the executor would report degraded clock readiness", *c.EstimatedError, c.Bound), "check the time daemon's sources, or raise clock.max_error_ms deliberately"}
	default:
		return doctorCheck{"clock", "not_checked", "kernel clock state is unavailable on this platform; local UTC time is " + time.Now().UTC().Format(time.RFC3339), "verify host clock synchronization; no external time source was queried"}
	}
}

func payloadCheck(executable string) doctorCheck {
	if filepath.IsAbs(executable) {
		real, err := filepath.EvalSymlinks(executable)
		if err == nil && filepath.Base(real) == "dbl" && filepath.Base(filepath.Dir(real)) == "bin" {
			manifest, err := artifact.Verify(filepath.Dir(filepath.Dir(real)))
			if err == nil {
				return doctorCheck{"payload", "pass", "verified installed payload " + manifest.Version + " (" + manifest.SourceSHA + ")", ""}
			}
		}
	}
	return doctorCheck{"payload", "unavailable", "this executable could not verify its installed payload", "run the dbl shipped in a release installation"}
}

func localDaemonChecks(ctx context.Context, role string, cfg daemonConfig, offline bool) []doctorCheck {
	var dbPath, endpoint string
	var cert, key, authority string
	var tlsDisabled bool
	if cfg.dispatcher != nil {
		c := cfg.dispatcher
		dbPath = c.Database.Path
		endpoint = fmt.Sprintf("HTTP %s; gRPC %s", net.JoinHostPort(c.Server.BindHost, fmt.Sprint(c.Server.HTTPPort)), net.JoinHostPort(c.Server.BindHost, fmt.Sprint(c.Server.GRPCPort)))
		cert, key, authority, tlsDisabled = c.TLS.CertFile, c.TLS.KeyFile, c.TLS.CAFile, c.TLS.Disable
	} else {
		c := cfg.executor
		dbPath = c.Database.Path
		endpoint = "gRPC " + c.Dispatcher.Addr + "; reverse control " + c.Dispatcher.YamuxAddr
		cert, key, authority, tlsDisabled = c.Credentials.ClientCert, c.Credentials.ClientKey, c.Credentials.CACert, c.TLS.Disable
	}
	checks := []doctorCheck{{"control_endpoints", "pass", endpoint + " (literal configuration; not contacted)", ""}}
	checks = append(checks, stateChecks(dbPath)...)
	if offline {
		checks = append(checks, schemaCheck(ctx, storagecheck.Role(role), dbPath))
	} else {
		checks = append(checks, doctorCheck{"schema", "not_checked", "offline database inspection was not requested", "stop the daemon and pass --offline to inspect its schema without writing SQLite state"})
	}
	checks = append(checks, certificateCheck(tlsDisabled, cert, key, authority))
	if cfg.executor != nil {
		c := cfg.executor
		checks = append(checks, executorHostChecks(c.Network.Interface, c.Network.PacketCounter)...)
	}
	return checks
}

func certificateCheck(disabled bool, cert, key, authority string) doctorCheck {
	if disabled {
		return doctorCheck{"tls_files", "not_checked", "TLS is disabled in the selected configuration", ""}
	}
	for _, path := range []string{cert, key, authority} {
		if path != "" {
			if _, err := readOperatorFile(path); err != nil {
				return doctorCheck{"tls_files", "failure", "a configured TLS file is missing, unreadable or not a bounded regular file", "check certificate, key and CA file paths and service account permissions"}
			}
		}
	}
	now := time.Now()
	identity, err := tlsfiles.KeyPair("certificate", cert, "key", key, now)
	if err == nil && authority != "" {
		_, err = tlsfiles.TrustRoots("CA", authority, now)
	}
	if err != nil {
		return doctorCheck{"tls_files", "failure", "configured TLS identity or authority is invalid at the local time", "check the key/certificate pair, validity dates, CA bundle and host clock"}
	}
	return doctorCheck{"tls_files", "pass", "key matches certificate; certificate and configured CA dates are valid; leaf expires " + identity.Leaf.NotAfter.UTC().Format(time.RFC3339), "peer trust and hostname verification require the actual control handshake"}
}

func schemaCheck(ctx context.Context, role storagecheck.Role, path string) doctorCheck {
	check := doctorCheck{"schema", "failure", "database could not be inspected", "check database.path and read permissions"}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return check
	}
	path = resolved
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() {
		check.Detail = "configured database is absent or not a readable regular file"
		return check
	}
	// Immutable SQLite cannot see an active journal. Refuse that case rather
	// than create WAL companions or accidentally inspect an older DB image.
	// A rollback journal next to a stopped daemon's database is the
	// unfinished write of a process that was killed; only a writer may roll
	// it back, and doctor never writes.
	if _, err := os.Stat(path + "-journal"); !errors.Is(err, os.ErrNotExist) {
		return doctorCheck{"schema", "not_checked", "database needs crash recovery: a rollback journal from an unfinished write is present or cannot be inspected",
			"start the daemon, or run debuglet-" + string(role) + " -config FILE -upgrade-database, so SQLite rolls the write back; keep the journal and run doctor again"}
	}
	if _, err := os.Stat(path + "-wal"); !errors.Is(err, os.ErrNotExist) {
		return doctorCheck{"schema", "not_checked", "a database journal is present or cannot be inspected", "stop the daemon and checkpoint its database before this offline schema check"}
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return check
	}
	dsn := url.URL{Scheme: "file", Path: filepath.ToSlash(absolute)}
	dsn.RawQuery = url.Values{"mode": {"ro"}, "immutable": {"1"}, "_pragma": {"query_only(1)"}}.Encode()
	db, err := sql.Open("sqlite", dsn.String())
	if err != nil {
		return check
	}
	defer db.Close()
	policy, err := storagecheck.PolicyFor(role)
	if err == nil {
		err = policy.CheckDB(ctx, db)
	}
	if err == nil {
		return doctorCheck{"schema", "pass", "offline database schema is compatible with this build", ""}
	}
	switch {
	case errors.Is(err, storagecheck.ErrOutdated):
		check.Detail, check.Next = "database schema is older than this build supports", "stop and back up the daemon, then run debuglet-"+string(role)+" -config FILE -upgrade-database"
	case errors.Is(err, storagecheck.ErrNewer):
		check.Detail, check.Next = "database schema is newer than this build supports", "install a compatible release; do not downgrade the database"
	case errors.Is(err, storagecheck.ErrUnknown), errors.Is(err, storagecheck.ErrIncomplete):
		check.Detail, check.Next = "database does not contain a complete schema for this role", "check database.path or restore a complete backup"
	}
	return check
}

func dispatcherCheck(ctx context.Context, options globalOptions) doctorCheck {
	check := doctorCheck{"dispatcher_connection", "failure", "the selected dispatcher could not be reached", "check the selected endpoint, service availability and TLS trust"}
	// Connection errors may contain configured URLs; the report uses only
	// fixed diagnostics, not arbitrary server or credential-store text.
	c, _, ok := connect("dbl doctor", options, false, io.Discard)
	if !ok {
		check.Detail, check.Next = "the saved connection could not be loaded", "select a valid saved connection with dbl dispatcher use NAME, or pass --endpoint URL"
		return check
	}
	if _, err := c.Version(ctx); err != nil {
		return check
	}
	return doctorCheck{"dispatcher_connection", "pass", "the selected HTTP dispatcher answered its version route", "this does not verify executor enrollment or control-channel readiness"}
}

func executorHostChecks(iface, counter string) []doctorCheck {
	checks := []doctorCheck{}
	if iface == "" {
		checks = append(checks, doctorCheck{"interface", "not_checked", "no interface is configured; startup discovery was not run", "set network.interface to inspect a specific interface"})
	} else if _, err := net.InterfaceByName(iface); err != nil {
		checks = append(checks, doctorCheck{"interface", "failure", "configured network interface is unavailable", "check network.interface on the executor host"})
	} else {
		checks = append(checks, doctorCheck{"interface", "pass", "configured network interface exists", ""})
	}
	if runtime.GOOS != "linux" {
		return append(checks, doctorCheck{"kernel", "unavailable", "executor host checks require Linux", "run doctor on the supported Linux executor host"})
	}
	if counter == "fallback" {
		checks = append(checks, doctorCheck{"btf", "not_checked", "kernel BTF is not required by the selected fallback counter", ""})
	} else if info, err := os.Stat("/sys/kernel/btf/vmlinux"); err != nil || !info.Mode().IsRegular() {
		checks = append(checks, doctorCheck{"btf", "not_checked", "kernel BTF is unavailable; automatic counter selection may use the fallback", "use a BTF-enabled kernel if eBPF is required; no counter was attached"})
	} else {
		checks = append(checks, doctorCheck{"btf", "pass", "kernel BTF file is present", "presence does not prove an eBPF program can attach"})
	}
	checks = append(checks, capabilityCheck(counter))
	return checks
}
