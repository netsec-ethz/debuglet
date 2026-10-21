// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package studio

import (
	"bytes"
	"context"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"github.com/netsec-ethz/debuglet/pkg/workflow"
)

func TestBuildUsesPinnedSDKDependencyOffline(t *testing.T) {
	if testing.Short() {
		t.Skip("WASI compilation")
	}
	sdk, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	builder, err := NewBuilder(sdk)
	if err != nil {
		t.Fatal(err)
	}
	wf := sampleWorkflow()
	raw, err := json.Marshal(wf)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	// The DNS codec is a pinned SDK dependency. The generated module has no
	// network access and must compile without editing dependency versions.
	program := workflow.Program{Source: `package main
import "golang.org/x/net/dns/dnsmessage"
func main() { println(dnsmessage.TypeA) }
`}
	bundle, err := builder.buildProgram(ctx, wf, raw, program)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(bundle.Wasm, []byte{0, 'a', 's', 'm', 1, 0, 0, 0}) {
		t.Fatal("dependency build did not produce a WASI module")
	}
}
