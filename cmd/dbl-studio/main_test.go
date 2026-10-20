// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package main

import (
	"bytes"
	"context"
	"path/filepath"
	"testing"
)

func TestValidateExperimentCommand(t *testing.T) {
	for _, name := range []string{"three-node.json", "request-reply.json"} {
		var output, diagnostics bytes.Buffer
		input := filepath.Join("..", "..", "examples", "workflows", "experiments", name)
		err := run(context.Background(), []string{"validate-experiment", "--input", input}, &output, &diagnostics)
		if err != nil || output.String() != "{\"diagnostics\":[]}\n" {
			t.Fatalf("%s: %v %s %s", name, err, &output, &diagnostics)
		}
	}
}
