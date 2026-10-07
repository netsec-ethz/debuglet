// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package main

import (
	"context"
	"fmt"
	"io"
)

const allowanceUsage = `Usage:
  dbl [--dispatcher NAME] allowance

Report the account's granted, reserved, consumed and remaining TEST units.
These are non-transferable usage credits, not money. Requires a saved account
credential and a dispatcher offering allowances (API 1.15 or newer).
`

func allowanceCommand(ctx context.Context, args []string, options globalOptions, stdout, stderr io.Writer) int {
	fs := newCommandFlagSet("allowance")
	if code, ok := parseCommandFlags(fs, args, allowanceUsage, stdout, stderr); !ok {
		return code
	}
	if fs.NArg() != 0 {
		return usageError("dbl allowance", allowanceUsage, stderr, "allowance takes no arguments")
	}
	c, code, ok := connect(ctx, "dbl allowance", options, false, stderr)
	if !ok {
		return code
	}
	allowance, err := c.Allowance(ctx)
	if err != nil {
		return reportFailure(ctx, "dbl allowance", stderr, err)
	}
	return emitReported(ctx, "dbl allowance", options.Output, stdout, stderr, allowance, func(w io.Writer) error {
		_, err := fmt.Fprintf(w, "currency: %s (non-monetary usage units)\ngranted: %s\nreserved: %s\nconsumed: %s\nremaining: %s\npricing rule: %s\n",
			allowance.Currency, allowance.Granted, allowance.Reserved, allowance.Consumed, allowance.Remaining, allowance.PricingRule)
		return err
	})
}
