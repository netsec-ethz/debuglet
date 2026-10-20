// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package workflow

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func sampleExperiment(t *testing.T) Experiment {
	t.Helper()
	raw, err := os.ReadFile("../../examples/workflows/experiments/three-node.json")
	if err != nil {
		t.Fatal(err)
	}
	var e Experiment
	if err = json.Unmarshal(raw, &e); err != nil {
		t.Fatal(err)
	}
	return e
}
func TestExperimentContextIsPartOfProgramIdentity(t *testing.T) {
	e := sampleExperiment(t)
	if ds := ValidateExperiment(e); len(ds) > 0 {
		t.Fatal(ds)
	}
	wf, p, err := GenerateParticipant(e, "A")
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(wf)
	hash := sha256.Sum256(raw)
	if p.WorkflowSHA256 != hex.EncodeToString(hash[:]) {
		t.Fatal("program identity omits injected context")
	}
	if wf.Experiment == nil || wf.Experiment.Participant != "A" || !strings.Contains(p.Source, "guest.JoinExperiment") || !strings.Contains(p.Source, "experiment.Send") || !strings.Contains(p.Source, "experiment.Await") {
		t.Fatal("missing participant setup")
	}
	e.Name = "Different experiment"
	_, changed, err := GenerateParticipant(e, "A")
	if err != nil {
		t.Fatal(err)
	}
	if p.WorkflowSHA256 == changed.WorkflowSHA256 {
		t.Fatal("different experiment has same program identity")
	}
	if _, err := Generate(wf); err == nil {
		t.Fatal("standalone builder accepted injected context")
	}
	if _, err := Generate(e.Participants[0].Workflow); err == nil {
		t.Fatal("standalone builder accepted message blocks")
	}
}
func TestExperimentRejectsInvalidMembershipAndChannels(t *testing.T) {
	cases := map[string]func(*Experiment){
		"duplicate participant": func(e *Experiment) { e.Participants[1].ID = "A" },
		"unknown destination":   func(e *Experiment) { e.Channels[0].To = "missing" },
		"self channel":          func(e *Experiment) { e.Channels[0].To = "A" },
		"duplicate channel":     func(e *Experiment) { e.Channels = append(e.Channels, e.Channels[0]) },
		"wrong type":            func(e *Experiment) { e.Channels[0].Type = "string" },
		"wrong peer":            func(e *Experiment) { e.Participants[0].Workflow.Nodes[0].Inputs["destination"] = "C" },
		"response without request": func(e *Experiment) {
			e.Channels[0].From = "B"
			e.Channels[0].To = "A"
			e.Channels[0].ResponseType = "number"
		},
		"injected context": func(e *Experiment) { e.Participants[0].Workflow.Experiment = &ExperimentContext{} },
		"dynamic destination": func(e *Experiment) {
			w := &e.Participants[0].Workflow
			delete(w.Nodes[0].Inputs, "destination")
			w.Nodes = append(w.Nodes, Node{ID: "peer", Block: "constant", Inputs: map[string]any{"value": "B"}})
			w.Edges = append(w.Edges, edge("data", "peer", "value", "send", "destination"))
		},
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			e := sampleExperiment(t)
			change(&e)
			if len(ValidateExperiment(e)) == 0 {
				t.Fatal("accepted invalid experiment")
			}
		})
	}
}

func TestRequestReplyExamplePreservesCorrelationConnections(t *testing.T) {
	raw, err := os.ReadFile("../../examples/workflows/experiments/request-reply.json")
	if err != nil {
		t.Fatal(err)
	}
	var e Experiment
	if err := json.Unmarshal(raw, &e); err != nil {
		t.Fatal(err)
	}
	for _, participant := range e.Participants {
		_, program, err := GenerateParticipant(e, participant.ID)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(program.Source, `("request_id")`) {
			t.Fatalf("%s does not consume the preceding request handle", participant.ID)
		}
	}
	// Removing the wire must not silently turn the response into a new request.
	w := &e.Participants[0].Workflow
	w.Edges = w.Edges[:len(w.Edges)-1]
	if len(ValidateExperiment(e)) == 0 {
		t.Fatal("accepted a reply wait without its request ID")
	}
}

func TestGeneratedExperimentRetainsTopologyBeforeReadiness(t *testing.T) {
	if testing.Short() {
		t.Skip("generated program compilation")
	}
	e := sampleExperiment(t)
	e.Channels[0].ResponseType = "number"
	w, program, err := GenerateParticipant(e, "A")
	if err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(t.TempDir(), "main.go")
	if err := os.WriteFile(source, []byte(program.Source), 0600); err != nil {
		t.Fatal(err)
	}
	run := func(stdout *bytes.Buffer, output *os.File) string {
		t.Helper()
		cmd := exec.Command("go", "run", source)
		cmd.Env = append(os.Environ(), "GOTOOLCHAIN=local", "GOPROXY=off", "GOSUMDB=off")
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		if output != nil {
			cmd.Stdout = output
		} else {
			cmd.Stdout = stdout
		}
		if err := cmd.Run(); err == nil {
			t.Fatal("native execution unexpectedly joined an experiment")
		}
		return stderr.String()
	}
	var stdout bytes.Buffer
	if stderr := run(&stdout, nil); !strings.Contains(stderr, "SDK calls only work inside a wasip1 guest") {
		t.Fatalf("program did not reach readiness: %s", stderr)
	}
	if bytes.Count(stdout.Bytes(), []byte{'\n'}) != 1 {
		t.Fatalf("expected exactly one complete manifest, got %q", stdout.String())
	}
	var manifest struct {
		Schema           string    `json:"schema"`
		WorkflowSHA256   string    `json:"workflow_sha256"`
		ExperimentSHA256 string    `json:"experiment_sha256"`
		Participant      string    `json:"participant"`
		Participants     []string  `json:"participants"`
		Channels         []Channel `json:"channels"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &manifest); err != nil {
		t.Fatal(err)
	}
	if manifest.Schema != "debuglet.experiment.v1" || manifest.WorkflowSHA256 != program.WorkflowSHA256 ||
		manifest.ExperimentSHA256 != w.Experiment.Fingerprint || manifest.Participant != "A" ||
		!reflect.DeepEqual(manifest.Participants, w.Experiment.Participants) ||
		!reflect.DeepEqual(manifest.Channels, e.Channels) {
		t.Fatalf("manifest differs from the compiled experiment: %+v", manifest)
	}
	if len(stdout.Bytes()) > 65537 {
		t.Fatal("manifest exceeds one bounded output record")
	}
	t.Run("output failure stops before readiness", func(t *testing.T) {
		full, err := os.OpenFile("/dev/full", os.O_WRONLY, 0)
		if err != nil {
			t.Skip("/dev/full is unavailable")
		}
		defer full.Close()
		stderr := run(nil, full)
		if strings.Contains(stderr, "SDK calls only work inside a wasip1 guest") ||
			!strings.Contains(stderr, "no space left on device") {
			t.Fatalf("failed manifest write did not stop execution: %s", stderr)
		}
	})
}
