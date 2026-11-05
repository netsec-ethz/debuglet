// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package studio

import (
	"bytes"
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/netsec-ethz/debuglet/pkg/workflow"
	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/imports/wasi_snapshot_preview1"
)

func TestValidationPreviewsMatchBuildGenerator(t *testing.T) {
	wf := sampleWorkflow()
	code := `func run0() error { return runtime.Record("result", "emit", map[string]any{"value":43}) }`
	wf.GoCode = &code
	for _, experiment := range []bool{false, true} {
		path := "/studio/validate"
		var document any = wf
		if experiment {
			path = "/studio/experiments/validate"
			document = workflow.Experiment{Version: 1, Kind: "experiment", Name: "Edited pair", Channels: []workflow.Channel{}, Participants: []workflow.Participant{{ID: "one", Workflow: wf}, {ID: "two", Workflow: sampleWorkflow()}}}
		}
		raw, _ := json.Marshal(document)
		response := workerRequest(NewWorkerHandler(nil), "POST", path, raw)
		var result struct {
			Diagnostics []workflow.ExperimentDiagnostic `json:"diagnostics"`
			Program     workflow.Program                `json:"program"`
			Programs    []struct {
				ID      string           `json:"id"`
				Program workflow.Program `json:"program"`
			} `json:"programs"`
		}
		if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil || response.Code != 200 || len(result.Diagnostics) != 0 {
			t.Fatalf("preview: %d %s (%v)", response.Code, response.Body, err)
		}
		want, err := workflow.Generate(wf)
		got := result.Program
		if experiment {
			if len(result.Programs) != 2 || result.Programs[0].ID != "one" {
				t.Fatal("missing participant previews")
			}
			_, want, err = workflow.GenerateParticipant(document.(workflow.Experiment), "one")
			got = result.Programs[0].Program
		}
		if err != nil || got.Source != want.Source || got.GoCode != want.GoCode {
			t.Fatal("preview differs from build source", err)
		}
		input, _ := json.Marshal(map[string]any{"kind": map[bool]string{false: "workflow", true: "experiment"}[experiment], "document": document, "message": "Change the blocks"})
		if _, err := DecodeAssistantRequest(bytes.NewReader(input)); err == nil || !strings.Contains(err.Error(), "restore blocks") {
			t.Fatal("assistant could overwrite manual code", err)
		}
	}
}

func TestEditedGoBuildsRunsAndRetainsCanonicalSource(t *testing.T) {
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
	code := `func run0() error { return runtime.Record("result", "emit", map[string]any{"name":"edited", "value":math.Sqrt(81)}) }`
	wf.GoCode = &code
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	bundle, err := builder.Build(ctx, wf)
	if err != nil {
		t.Fatal(err)
	}
	document, _ := json.Marshal(wf)
	compiled, _ := json.Marshal(bundle)
	if _, _, err := ValidateDocument("workflow", document, compiled); err != nil {
		t.Fatal(err)
	}
	var stdout bytes.Buffer
	runtime := wazero.NewRuntime(ctx)
	defer runtime.Close(ctx)
	if _, err := wasi_snapshot_preview1.Instantiate(ctx, runtime); err != nil {
		t.Fatal(err)
	}
	if _, err := runtime.InstantiateWithConfig(ctx, bundle.Wasm, wazero.NewModuleConfig().WithStdout(&stdout).WithStderr(&stdout)); err != nil {
		t.Fatalf("run: %v\n%s", err, &stdout)
	}
	if !strings.Contains(stdout.String(), `"name":"edited"`) || !strings.Contains(stdout.String(), `"value":9`) || strings.Contains(stdout.String(), `"value":42`) {
		t.Fatalf("manual code was not executed: %s", &stdout)
	}
	wf.GoCode = nil
	changed, _ := json.Marshal(wf)
	if _, _, err := ValidateDocument("workflow", changed, compiled); err == nil {
		t.Fatal("manual bundle accepted for restored blocks")
	}
}
