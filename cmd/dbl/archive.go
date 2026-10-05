// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package main

import (
	"context"
	"fmt"
	"io"
	"os"

	"github.com/google/uuid"
)

const archiveUsage = `Usage:
  dbl service archive-run [--name worker] [--apply --reason TEXT] RUN_UUID

Inspect one retained run on a successfully drained, disabled managed executor.
By default nothing is changed. --apply records the operator's local disposition
and releases only the execution queue's admission charge. The original run,
output and terminal evidence stay in the database and consume disk space.
Nothing is replayed or reported to the dispatcher. Remote outcomes, account
quotas and payments are unchanged. Resume the executor explicitly afterward.
`

func archiveCommand(ctx context.Context, args []string, options globalOptions, stdout, stderr io.Writer, deps serviceDependencies) int {
	fs := newCommandFlagSet("service archive-run")
	name := fs.String("name", "worker", "managed executor instance")
	apply := fs.Bool("apply", false, "record the local disposition")
	reason := fs.String("reason", "", "private operator incident reference, required with --apply")
	if code, ok := parseCommandFlags(fs, args, archiveUsage, stdout, stderr); !ok {
		return code
	}
	if fs.NArg() != 1 || options.EndpointSet || options.Dispatcher != "" || (*apply && *reason == "") || (!*apply && *reason != "") {
		return usageError("dbl service archive-run", archiveUsage, stderr, "name one local run; only --apply takes and requires --reason")
	}
	id, err := uuid.Parse(fs.Arg(0))
	if err != nil || id == uuid.Nil {
		return usageError("dbl service archive-run", archiveUsage, stderr, "RUN_UUID must be a nonzero UUID")
	}
	if deps.root == "" && os.Geteuid() != 0 {
		return reportFailure(ctx, "dbl service archive-run", stderr, fmt.Errorf("administrator privileges are required"))
	}
	installer, code, ok := newInstaller("dbl service archive-run", serviceOptions{}, deps, stderr)
	if !ok {
		return code
	}
	report, err := installer.ArchiveRun(ctx, *name, id, *reason, *apply)
	if err != nil {
		return reportFailure(ctx, "dbl service archive-run", stderr, err)
	}
	return emitReported(ctx, "dbl service archive-run", options.Output, stdout, stderr, report, func(w io.Writer) error {
		if _, err := fmt.Fprintf(w, "Original session: %s/%s\nRetained evidence: execution=%t terminal=%t output=%t\n",
			report.Run.OriginalBinding.Incarnation, report.Run.OriginalBinding.SessionID,
			report.Run.ExecutionRetained, report.Run.TerminalRetained, report.Run.OutputRetained); err != nil {
			return err
		}
		if report.Run.StartedAt != nil {
			if _, err := fmt.Fprintf(w, "Original start marker: %s\n", report.Run.StartedAt.Format("2006-01-02T15:04:05Z07:00")); err != nil {
				return err
			}
		}
		if report.Run.ArchivedAt == nil {
			_, err := fmt.Fprintf(w, "Run %s remains retained. No change; use --apply --reason TEXT to record a local disposition.\n", id)
			return err
		}
		_, err := fmt.Fprintf(w, "Run %s archived locally at %s (%s). Original evidence and unknown remote outcome preserved; no replay or dispatcher/account-quota change.\n", id, report.Run.ArchivedAt.Format("2006-01-02T15:04:05Z07:00"), report.Run.Reason)
		return err
	})
}
