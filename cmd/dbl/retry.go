// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package main

import (
	"context"
	"fmt"
	"io"
)

const retryUsage = `Usage:
  dbl retry PARENT --request-id UUID --executor ID (--wasm FILE | --sample hello) [run options]

Explicitly create one linked TEST attempt. Keep the same request ID, workload,
executor and options to recover it after a lost reply. A new request ID requests
another execution. The original run may still execute; it is not changed.
Discovery filters are unavailable here. Use dbl run --help for workload options.
`

func retryCommand(ctx context.Context, args []string, options globalOptions, stdout, stderr io.Writer) int {
	if len(args) == 1 && (args[0] == "--help" || args[0] == "-h") {
		fmt.Fprint(stdout, retryUsage)
		return exitOK
	}
	if len(args) == 0 {
		return usageError("dbl retry", retryUsage, stderr, "parent run ID is required")
	}
	o, code, ok := parseSubmissionOptions(args[1:], args[0], stdout, stderr)
	if !ok {
		return code
	}
	return executeSubmission(ctx, o, options, stdout, stderr)
}
