// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"

	"github.com/netsec-ethz/debuglet/pkg/wire"
)

const exportUsage = `Usage:
  dbl export ID

Writes one versioned JSON result to stdout, including admission provenance,
recorded outcome and output completeness. Pending or truncated output is kept
explicit; a successful export does not establish measurement truth.
`

func exportCommand(ctx context.Context, args []string, options globalOptions, stdout, stderr io.Writer) int {
	fs := newCommandFlagSet("export")
	if code, ok := parseCommandFlags(fs, args, exportUsage, stdout, stderr); !ok {
		return code
	}
	id, msg := singleID(fs)
	if msg != "" {
		return usageError("dbl export", exportUsage, stderr, "%s", msg)
	}
	c, code, ok := connect(ctx, "dbl export", options, false, stderr)
	if !ok {
		return code
	}
	doc, err := c.Export(ctx, id)
	if err != nil {
		return reportFailure(ctx, "dbl export", stderr, err)
	}
	encoded, err := json.Marshal(doc)
	if err == nil && len(encoded) > wire.MaxResultBytes {
		err = fmt.Errorf("result exceeds 32 MiB after JSON encoding")
	}
	if err == nil {
		var n int
		n, err = stdout.Write(encoded)
		if err == nil && n != len(encoded) {
			err = io.ErrShortWrite
		}
	}
	if err != nil {
		fmt.Fprintf(stderr, "dbl export: %v\n", err)
		return exitFailure
	}
	return exitOK
}
