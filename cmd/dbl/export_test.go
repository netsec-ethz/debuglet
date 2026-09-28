// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package main

import (
	"bytes"
	"context"
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/netsec-ethz/debuglet/pkg/client"
	"github.com/netsec-ethz/debuglet/pkg/wire"
)

func TestExportRejectsExpandedJSONBeforeWriting(t *testing.T) {
	data, err := os.ReadFile("../../pkg/client/testdata/results/v1.0.json")
	if err != nil {
		t.Fatal(err)
	}
	// JSON permits literal '<'; the CLI's encoder escapes each one as six bytes.
	data = bytes.Replace(data, []byte("fixture-executor"), bytes.Repeat([]byte("<"), 6<<20), 1)
	if len(data) >= wire.MaxResultBytes {
		t.Fatal("fixture exceeds the response limit before encoding")
	}
	if _, err := client.ReadResult(bytes.NewReader(data)); err != nil {
		t.Fatalf("alternate response must be a valid portable result: %v", err)
	}
	f := newFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/debuglet/"+fixJobID+"/result" {
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(data)
	}))
	code, stdout, stderr := runCLI(context.Background(), "--endpoint", f.endpoint(), "export", fixJobID)
	if code != exitFailure || stdout != "" || !strings.Contains(stderr, "result exceeds 32 MiB after JSON encoding") {
		t.Fatalf("exit=%d, stdout bytes=%d, stderr=%q", code, len(stdout), stderr)
	}
}
