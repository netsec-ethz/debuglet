// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package main

import (
	"bytes"
	"context"
	"path/filepath"
	"strings"
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

func TestWorkerRequiresOnlySocketAndSDK(t *testing.T) {
	for _, args := range [][]string{
		{"worker"},
		{"worker", "--sdk", "/nonexistent"},
		{"worker", "--socket", "/tmp/build.sock"},
		{"worker", "--socket", "/tmp/build.sock", "--sdk", "/nonexistent", "--listen", "0.0.0.0:8090"},
		{"worker", "--socket", "/tmp/build.sock", "--sdk", "/nonexistent", "--dispatcher", "http://127.0.0.1:8080"},
		{"worker", "--socket", "/tmp/build.sock", "--sdk", "/nonexistent", "--workspace", "/tmp"},
	} {
		var output bytes.Buffer
		err := run(context.Background(), args, &output, &output)
		if err == nil || !strings.HasPrefix(err.Error(), "worker ") {
			t.Fatalf("%v did not reject worker configuration: %v", args, err)
		}
	}
}
