// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package api

import (
	"net/http"
	"testing"

	"github.com/netsec-ethz/debuglet/pkg/client"
	"github.com/netsec-ethz/debuglet/pkg/workflow"
)

func TestMeasurementListUsesSourceTitleWithoutRenamingParticipants(t *testing.T) {
	f := ccNewFixtureWith(t)
	_, owner, sdk := authAccount(t, f, "Owner")
	_, _, outsider := authAccount(t, f, "Outsider")
	requests := []client.Request{ccRequest(nil), ccRequest(nil)}
	requests[0].Label = "Europe"
	requests[1].Label = "US"
	requests[1].OrderID++
	batch, err := client.Prepare(requests)
	if err != nil {
		t.Fatal(err)
	}
	submission, err := sdk.SubmitTEST(f.ctx, batch)
	if err != nil {
		t.Fatal(err)
	}
	assertPage := func(search, label string, total int64) {
		t.Helper()
		page, err := sdk.Measurements(f.ctx, client.MeasurementOptions{Search: search, Limit: 1})
		if err != nil || page.Total != total || int64(len(page.Measurements)) != total || page.Counts["running"] != total {
			t.Fatalf("search %q: page=%+v err=%v", search, page, err)
		}
		if total != 0 && (page.Measurements[0].ID != submission.TransactionID || page.Measurements[0].Label != label || page.Measurements[0].Children != 2) {
			t.Fatalf("search %q: summary=%+v", search, page.Measurements[0])
		}
	}
	// Old submissions without retained source keep their existing labels.
	assertPage("US", "US", 1)
	document := workflow.Experiment{
		Version: 1, Kind: "experiment", Name: "SCIERA — Where does DNS fail?",
		Participants: []workflow.Participant{
			{ID: "europe", Label: "Europe", Workflow: communityTestWorkflow()},
			{ID: "us", Label: "US", Workflow: communityTestWorkflow()},
		},
	}
	input := sourceTestInput(t, submission)
	input["kind"], input["document"] = "experiment", document
	libraryRequest(t, f, owner, http.MethodPost, "/measurements/"+submission.TransactionID+"/source", input, http.StatusCreated, nil)
	assertPage("sciera", document.Name, 1)
	assertPage("", document.Name, 1)
	assertPage("US", "", 0)
	other, err := outsider.Measurements(f.ctx, client.MeasurementOptions{Search: "sciera"})
	if err != nil || other.Total != 0 || len(other.Measurements) != 0 {
		t.Fatalf("source title escaped ownership boundary: %+v %v", other, err)
	}
	runs, err := sdk.Measurement(f.ctx, submission.TransactionID)
	if err != nil || len(runs.Runs) != 2 || runs.Runs[0].Label != "Europe" || runs.Runs[1].Label != "US" {
		t.Fatalf("participant labels changed: %+v %v", runs, err)
	}
}
