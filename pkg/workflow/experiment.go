// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package workflow

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
)

// Experiment groups independently executed workflows. Executor selection and
// policy remain submission choices, not embedded guest authority.
type Experiment struct {
	Version      int           `json:"version"`
	Kind         string        `json:"kind"`
	Name         string        `json:"name"`
	Participants []Participant `json:"participants"`
	Channels     []Channel     `json:"channels"`
}

// ExperimentContext is injected by the experiment builder and covered by the
// participant workflow digest. It supplies no executor policy permissions.
type ExperimentContext struct {
	Participant  string    `json:"participant"`
	Fingerprint  string    `json:"fingerprint"`
	Participants []string  `json:"participants"`
	Channels     []Channel `json:"channels"`
}
type Participant struct {
	ID       string   `json:"id"`
	Label    string   `json:"label,omitempty"`
	Workflow Workflow `json:"workflow"`
}

// ResponseType makes the channel request/reply; otherwise it is one-way.
type Channel struct {
	ID           string `json:"id"`
	From         string `json:"from"`
	To           string `json:"to"`
	Type         string `json:"type"`
	ResponseType string `json:"response_type,omitempty"`
}
type ExperimentDiagnostic struct {
	Participant string `json:"participant,omitempty"`
	Diagnostic
}

// ValidateExperiment checks membership and communication boundaries in addition
// to each ordinary workflow. Runtime checks still cover dynamically computed data.
func ValidateExperiment(e Experiment) []ExperimentDiagnostic {
	var ds []ExperimentDiagnostic
	add := func(participant, node, port, message string) {
		ds = append(ds, ExperimentDiagnostic{participant, Diagnostic{node, port, message}})
	}
	if e.Version != 1 || e.Kind != "experiment" {
		add("", "", "", "experiment requires version 1 and kind experiment")
	}
	if strings.TrimSpace(e.Name) == "" || len(e.Name) > 128 {
		add("", "", "", "name must contain 1–128 characters")
	}
	if len(e.Participants) < 2 || len(e.Participants) > 3 {
		add("", "", "", "an experiment requires 2–3 participants")
		return ds
	}
	members := map[string]bool{}
	for _, p := range e.Participants {
		if !identifier.MatchString(p.ID) || members[p.ID] {
			add(p.ID, "", "", "participant id must be valid and unique")
		}
		if len(p.Label) > 128 {
			add(p.ID, "", "", "participant label exceeds 128 characters")
		}
		members[p.ID] = true
		if p.Workflow.Experiment != nil {
			add(p.ID, "", "", "participant source must not contain injected experiment context")
		}
		for _, d := range Validate(p.Workflow) {
			ds = append(ds, ExperimentDiagnostic{p.ID, d})
		}
	}
	if len(e.Channels) > 64 {
		add("", "", "", "experiment has more than 64 channels")
		return ds
	}
	channels := map[string]Channel{}
	for _, c := range e.Channels {
		if !identifier.MatchString(c.ID) || channels[c.ID].ID != "" {
			add("", "", "", "channel id must be valid and unique")
		}
		if !members[c.From] || !members[c.To] || c.From == c.To {
			add("", "", "", "channel endpoints must be distinct experiment participants")
		}
		if !slices.Contains(valueTypes, c.Type) || (c.ResponseType != "" && !slices.Contains(valueTypes, c.ResponseType)) {
			add("", "", "", "unsupported channel value type")
		}
		channels[c.ID] = c
	}
	for _, p := range e.Participants {
		wired := map[Endpoint]bool{}
		for _, edge := range p.Workflow.Edges {
			if edge.Kind == "data" {
				wired[edge.To] = true
			}
		}
		for _, n := range p.Workflow.Nodes {
			if n.Block != "send_message" && n.Block != "await_message" {
				continue
			}
			endpoint := "destination"
			if n.Block == "await_message" {
				endpoint = "source"
			}
			for _, field := range []string{endpoint, "channel"} {
				if wired[Endpoint{n.ID, field}] {
					add(p.ID, n.ID, field, "select a declared participant and channel directly; these fields cannot be wired")
				}
			}
			peer, _ := n.Inputs[endpoint].(string)
			id, _ := n.Inputs["channel"].(string)
			c, found := channels[id]
			if !found {
				add(p.ID, n.ID, "channel", "select an experiment channel")
				continue
			}
			from, to := p.ID, peer
			if n.Block == "await_message" {
				from, to = peer, p.ID
			}
			forward := from == c.From && to == c.To
			reverse := from == c.To && to == c.From && c.ResponseType != ""
			if !forward && !reverse {
				add(p.ID, n.ID, endpoint, "participant does not match the declared channel direction")
				continue
			}
			request, _ := n.Inputs["request_id"].(string)
			hasRequest := request != "" || wired[Endpoint{n.ID, "request_id"}]
			if reverse && !hasRequest {
				add(p.ID, n.ID, "request_id", "a response must use the request_id from the earlier Send or Await")
			}
			if forward && hasRequest {
				add(p.ID, n.ID, "request_id", "leave request_id empty for a new message or request")
			}
			if n.Block == "send_message" && !wired[Endpoint{n.ID, "value"}] {
				typ := c.Type
				if reverse {
					typ = c.ResponseType
				}
				if !matches(n.Inputs["value"], typ) {
					add(p.ID, n.ID, "value", "channel expects "+typ)
				}
			}
		}
	}
	return ds
}

// GenerateParticipant injects the shared readiness manifest into one ordinary
// guest. Identity and listener addresses come from the admitted group at runtime.
func GenerateParticipant(e Experiment, id string) (Workflow, Program, error) {
	if ds := ValidateExperiment(e); len(ds) > 0 {
		return Workflow{}, Program{}, fmt.Errorf("invalid experiment: %s", ds[0].Message)
	}
	raw, err := json.Marshal(e)
	if err != nil {
		return Workflow{}, Program{}, err
	}
	if len(raw) > 4<<20 {
		return Workflow{}, Program{}, fmt.Errorf("experiment exceeds 4 MiB")
	}
	hash := sha256.Sum256(raw)
	ids := make([]string, len(e.Participants))
	var selected *Workflow
	for i, p := range e.Participants {
		ids[i] = p.ID
		if p.ID == id {
			w := p.Workflow
			selected = &w
		}
	}
	if selected == nil {
		return Workflow{}, Program{}, fmt.Errorf("unknown experiment participant %q", id)
	}
	selected.Experiment = &ExperimentContext{id, hex.EncodeToString(hash[:]), ids, e.Channels}
	encoded, err := json.Marshal(selected.Experiment)
	if err != nil {
		return Workflow{}, Program{}, err
	}
	program, err := generate(*selected, string(encoded))
	return *selected, program, err
}
