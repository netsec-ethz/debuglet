// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package main

import (
	"context"
	"fmt"
	"io"
	"time"
)

const recoveryUsage = `Usage:
  dbl recovery ID

Inspects stored outcome, control availability and a dated executor observation.
Unknown observations and failed workloads are successful inspections (exit 0).
No result proves that replaying the workload is safe.
`

func recoveryCommand(ctx context.Context, args []string, options globalOptions, stdout, stderr io.Writer) int {
	fs := newCommandFlagSet("recovery")
	if code, ok := parseCommandFlags(fs, args, recoveryUsage, stdout, stderr); !ok {
		return code
	}
	id, msg := singleID(fs)
	if msg != "" {
		return usageError("dbl recovery", recoveryUsage, stderr, "%s", msg)
	}
	c, code, ok := connect("dbl recovery", options, false, stderr)
	if !ok {
		return code
	}
	doc, err := c.Recovery(ctx, id)
	if err != nil {
		return reportFailure(ctx, "dbl recovery", stderr, err)
	}
	return emit("dbl recovery", options.Output, stdout, stderr, doc, func(w io.Writer) error {
		if _, err := fmt.Fprintf(w, "id: %q\nexecutor_id: %q\nstored state: %q\nstored error: %q\ncontrol: %q\nchecked_at: %q\nobservation: %q\n",
			doc.ID, doc.ExecutorID, doc.State, doc.Error, doc.ControlStatus, doc.CheckedAt.Format(time.RFC3339Nano), doc.Observation.Classification); err != nil {
			return err
		}
		if o := doc.Observation; o.Observer != nil {
			if _, err := fmt.Fprintf(w, "observer: %q\nobserver binding: %q / %q\nreceived_at: %q\ncurrent_at_check: %t\n",
				o.Observer.ExecutorID, o.Observer.Binding.DispatcherIncarnation, o.Observer.Binding.SessionID, o.ReceivedAt.Format(time.RFC3339Nano), *o.CurrentAtCheck); err != nil {
				return err
			}
			if o.Retained != nil {
				if _, err := fmt.Fprintf(w, "retained start marker: %t (not proof of execution)\n", o.Retained.Started); err != nil {
					return err
				}
			}
		}
		_, err := fmt.Fprintln(w, "Inspection does not authorize replay.")
		return err
	})
}
