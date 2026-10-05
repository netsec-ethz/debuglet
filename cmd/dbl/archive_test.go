// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package main

import (
	"bytes"
	"context"
	"testing"
)

func TestArchiveCommandRejectsUnsafeArgumentsBeforeHostAccess(t *testing.T) {
	id := "51dfe0b0-58cb-42c7-a1d2-c1b28bd2e673"
	for _, args := range [][]string{
		{"archive-run"}, {"archive-run", "--root", "/tmp/staging", id},
		{"archive-run", "--apply", id}, {"archive-run", "--reason", "incident", id},
		{"archive-run", "not-a-run"}, {"archive-run", id, id},
	} {
		t.Run(args[len(args)-1], func(t *testing.T) {
			var out, errout bytes.Buffer
			if code := serviceCommandWith(context.Background(), args, globalOptions{}, &out, &errout, serviceDependencies{}); code != exitUsage {
				t.Fatalf("code=%d error=%s", code, errout.String())
			}
		})
	}
}
