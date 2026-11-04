// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package workflow

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestGoCodePreviewAndOverridePreserveVisualSource(t *testing.T) {
	w := sampleWorkflow()
	visual, err := Generate(w)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(visual.GoCode, "func run0() error") || strings.Contains(visual.GoCode, "func main()") {
		t.Fatal("preview does not separate editable functions from startup")
	}
	code := `func run0() error { return runtime.Record("result", "emit", map[string]any{"name":"edited", "value":math.Sqrt(81)}) }`
	w.GoCode = &code
	edited, err := Generate(w)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(edited.Source, `"math"`) || strings.Contains(edited.GoCode, "func inputs0") || edited.WorkflowSHA256 == visual.WorkflowSHA256 {
		t.Fatal("manual functions were not substituted and fingerprinted")
	}
	raw, _ := json.Marshal(w)
	var saved Workflow
	if err := json.Unmarshal(raw, &saved); err != nil || saved.GoCode == nil || *saved.GoCode != code || saved.Nodes[0].Inputs["value"] != float64(42) {
		t.Fatal("saved source lost manual code or original blocks", err)
	}
	saved.GoCode = nil
	restored, err := Generate(saved)
	if err != nil || restored.Source != visual.Source {
		t.Fatal("restoring blocks changed their generated program", err)
	}
}

func TestGoCodeRejectsStartupChangesAndEmptyOverride(t *testing.T) {
	for _, code := range []string{
		"", "func run0( broken", "func other() error { return nil }",
		"import \"net\"\nfunc run0() error{return nil}",
		"var runtime = 0\nfunc run0() error{return nil}",
		"func main(){}\nfunc run0() error{return nil}",
		"func init(){}\nfunc run0() error{return nil}",
		"func literal(s string) any{return nil}\nfunc run0() error{return nil}",
		"//go:linkname example\nfunc run0() error{return nil}",
		"func run0() error{return nil}\nfunc run0() error{return nil}",
	} {
		w := sampleWorkflow()
		w.GoCode = &code
		if diagnostics := Validate(w); len(diagnostics) == 0 {
			t.Errorf("accepted invalid manual code %q", code)
		}
	}
}

func TestGoCodeExperimentKeepsReadinessAndParticipantIdentity(t *testing.T) {
	e := Experiment{Version: 1, Kind: "experiment", Name: "Two programs", Channels: []Channel{}, Participants: []Participant{
		{ID: "one", Workflow: sampleWorkflow()}, {ID: "two", Workflow: sampleWorkflow()},
	}}
	code := "func run0() error { return nil }"
	e.Participants[0].Workflow.GoCode = &code
	_, one, err := GenerateParticipant(e, "one")
	if err != nil {
		t.Fatal(err)
	}
	_, two, err := GenerateParticipant(e, "two")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(one.Source, "guest.JoinExperiment(") || !strings.Contains(one.Source, "runtime.SetScheduleAnchor(experiment.StartTime())") || !strings.Contains(one.Source, `\"participant\":\"one\"`) || !strings.Contains(two.Source, `\"participant\":\"two\"`) {
		t.Fatal("manual code lost generated readiness, schedule or participant identity")
	}
	if strings.Contains(one.GoCode, "func inputs0") || !strings.Contains(two.GoCode, "func inputs0") {
		t.Fatal("manual edit leaked into another participant")
	}
}
