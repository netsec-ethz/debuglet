package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/netsec-ethz/debuglet/internal/demo"
	"github.com/netsec-ethz/debuglet/internal/demo/service"
)

const drainUsage = `Usage:
  dbl drain (--role dispatcher|executor) [--name NAME] [--reason TEXT]
      [--wait DURATION] [--keep-enabled]
  dbl drain (--role ROLE) [--name NAME] --resume

Take one managed role out of service without losing what it holds.

An executor is stopped: that is what revokes its control eligibility, signals
its running work and joins its own local cleanup. Every other executor keeps
serving. Queued work stays in its database and is never replayed; retained
terminal results stay retained until the dispatcher acknowledges them.

A dispatcher is not stopped. Only the admission of new submissions is switched
off, so accepted debuglets keep their persistence and schedule, executors keep
their control sessions, and results and queries are unaffected. Its switch is a
file an administrator owns and outlives a reboot on its own, so a dispatcher is
never disabled and takes no --keep-enabled.

A drain that does not join within its budget is reported as incomplete. Nothing
may then be deleted, upgraded or reinitialized: the daemon may still own its
database. --resume reverses a drain; it replays nothing.
`

type drainOptions struct {
	Role, Name, Root, Reason string
	Wait                     time.Duration
	KeepEnabled, Resume      bool
}

func drainCommand(ctx context.Context, args []string, options globalOptions, stdout, stderr io.Writer) int {
	return drainCommandWith(ctx, args, options, stdout, stderr, productionServiceDependencies())
}

func drainCommandWith(ctx context.Context, args []string, options globalOptions, stdout, stderr io.Writer, deps serviceDependencies) int {
	fs := newCommandFlagSet("drain")
	var local drainOptions
	drainFlags(fs, &local)
	if code, ok := parseCommandFlags(fs, args, drainUsage, stdout, stderr); !ok {
		return code
	}
	if fs.NArg() != 0 {
		return usageError("dbl drain", drainUsage, stderr, "unexpected positional arguments")
	}
	if options.EndpointSet || options.Dispatcher != "" {
		return usageError("dbl drain", drainUsage, stderr, "drain administers a managed service on this host; it takes no --endpoint or --dispatcher")
	}
	var role demo.SchemaRole
	switch local.Role {
	case string(demo.DispatcherSchema):
		role = demo.DispatcherSchema
	case string(demo.ExecutorSchema):
		role = demo.ExecutorSchema
	case "":
		return usageError("dbl drain", drainUsage, stderr, "--role dispatcher or --role executor is required")
	default:
		return usageError("dbl drain", drainUsage, stderr, "unknown --role %q", local.Role)
	}
	blank := false
	fs.Visit(func(f *flag.Flag) {
		switch f.Name {
		case "name", "root", "reason":
			if strings.TrimSpace(f.Value.String()) == "" {
				blank = true
			}
		}
	})
	if blank {
		return usageError("dbl drain", drainUsage, stderr, "explicit option values must not be blank")
	}
	if local.Wait <= 0 {
		return usageError("dbl drain", drainUsage, stderr, "--wait must be positive")
	}
	if local.Resume && (local.Reason != "" || local.KeepEnabled) {
		return usageError("dbl drain", drainUsage, stderr, "--resume takes neither --reason nor --keep-enabled")
	}
	// Draining a dispatcher stops no unit, so there is nothing to leave
	// startable: its maintenance switch is a file an administrator owns and
	// survives a reboot by itself. Accepting the option here would say
	// otherwise and change nothing.
	if role == demo.DispatcherSchema && local.KeepEnabled {
		return usageError("dbl drain", drainUsage, stderr,
			"--keep-enabled belongs to an executor drain; a dispatcher is not stopped, so it is never disabled and its maintenance switch outlives a reboot on its own")
	}
	if local.Root != "" {
		return usageError("dbl drain", drainUsage, stderr, "--root stages files only; draining acts on the host service manager and cannot be staged")
	}
	if local.Name == "" {
		local.Name = defaultInstanceName(role)
	}
	installer, code, ok := newInstaller("dbl drain", serviceOptions{Root: local.Root}, deps, stderr)
	if !ok {
		return code
	}
	var report service.DrainReport
	var err error
	if local.Resume {
		report, err = installer.Resume(ctx, role, local.Name)
	} else {
		report, err = installer.Drain(ctx, role, local.Name, service.DrainOptions{
			Reason: local.Reason, Timeout: local.Wait, Disable: !local.KeepEnabled,
		})
	}
	if report.Operation != "" {
		if code := emitReported(ctx, "dbl drain", options.Output, stdout, stderr, report,
			func(w io.Writer) error { return writeDrainReport(w, report) }); code != exitOK {
			return code
		}
	}
	if err != nil {
		return reportFailure(ctx, "dbl drain", stderr, err)
	}
	return exitOK
}

// drainFlags registers the drain command's flags, the way serviceFlags does
// for the service subcommands.
func drainFlags(fs *flag.FlagSet, local *drainOptions) {
	fs.StringVar(&local.Role, "role", "", "dispatcher or executor")
	fs.StringVar(&local.Name, "name", "", "name of the managed instance (default local for a dispatcher, worker for an executor)")
	fs.StringVar(&local.Root, "root", "", "staged tree to act on (refused: draining needs the host service manager)")
	fs.StringVar(&local.Reason, "reason", "", "operator note recorded in a dispatcher's maintenance switch")
	fs.DurationVar(&local.Wait, "wait", service.DrainBudget, "how long to wait for local ownership to join")
	fs.BoolVar(&local.KeepEnabled, "keep-enabled", false, "executor only: leave a drained executor startable at boot")
	fs.BoolVar(&local.Resume, "resume", false, "reverse a drain: serve again")
}

// writeDrainReport renders the observation for a reader. The caller emits it
// once, whether or not the drain also failed: an incomplete drain is exactly
// the case an operator must be able to read, so its report is never suppressed
// by the failure that produced it.
func writeDrainReport(stdout io.Writer, report service.DrainReport) error {
	// The join clause is printed only where it is a decision: after a stop,
	// it is what says whether anything may be deleted or upgraded.
	joined := ""
	switch report.Outcome {
	case "drained":
		joined = " (local ownership joined; retained state is released)"
	case "incomplete":
		joined = " (local ownership has NOT joined)"
	}
	if _, err := fmt.Fprintf(stdout, "%s %s %s: %s%s\n", report.Operation, report.Role, report.Name, report.Outcome, joined); err != nil {
		return err
	}
	if report.Active != "" {
		if _, err := fmt.Fprintf(stdout, "  service manager: %s\n", report.Active); err != nil {
			return err
		}
	}
	if d := report.Disposition; d != nil {
		if _, err := fmt.Fprintf(stdout, "  retained: %s\n", d.Summary()); err != nil {
			return err
		}
	}
	if len(report.Changed) > 0 {
		if _, err := fmt.Fprintf(stdout, "  changed: %s\n", strings.Join(report.Changed, ", ")); err != nil {
			return err
		}
	}
	if report.Note != "" {
		if _, err := fmt.Fprintf(stdout, "  note: %s\n", report.Note); err != nil {
			return err
		}
	}
	return nil
}
