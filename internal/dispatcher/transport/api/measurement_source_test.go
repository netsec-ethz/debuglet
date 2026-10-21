// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package api

import (
	"encoding/json"
	"net/http"
	"reflect"
	"strings"
	"testing"

	"github.com/netsec-ethz/debuglet/pkg/client"
	"github.com/netsec-ethz/debuglet/pkg/wire"
)

func sourceTestSubmission(t *testing.T, f *ccFixture, owner *client.Client) client.Submission {
	t.Helper()
	requests := []client.Request{ccRequest([]string{"first"}), ccRequest([]string{"second"})}
	requests[1].OrderID++
	batch, err := client.Prepare(requests)
	if err != nil {
		t.Fatal(err)
	}
	submission, err := owner.SubmitTEST(f.ctx, batch)
	if err != nil {
		t.Fatal(err)
	}
	return submission
}

func sourceTestInput(t *testing.T, submission client.Submission) map[string]any {
	t.Helper()
	programs := make([]wire.SourceProgram, 0, len(submission.IDs))
	for _, id := range submission.IDs {
		programs = append(programs, wire.SourceProgram{RunID: id, SHA256: communityDocumentDigest(ccGuest)})
	}
	return map[string]any{"kind": "workflow", "document": communityTestWorkflow(), "programs": programs}
}

func TestMeasurementSourceMatchesAdmissionAndRemainsImmutable(t *testing.T) {
	f := ccNewFixtureWith(t)
	_, owner, sdk := authAccount(t, f, "Owner")
	_, outsider, outsiderSDK := authAccount(t, f, "Outsider")
	submission := sourceTestSubmission(t, f, sdk)
	other := f.submit(outsiderSDK, nil)
	path := "/measurements/" + submission.TransactionID + "/source"
	read := "/runs/" + submission.IDs[0] + "/source"
	input := sourceTestInput(t, submission)
	libraryRequest(t, f, owner, http.MethodGet, read, nil, 404, nil)
	libraryRequest(t, f, outsider, http.MethodPost, path, input, 404, nil)
	valid := input["programs"].([]wire.SourceProgram)
	for name, programs := range map[string][]wire.SourceProgram{
		"missing run":   valid[:1],
		"duplicate run": {valid[0], valid[0]},
		"wrong digest":  {{RunID: valid[0].RunID, SHA256: strings.Repeat("a", 64)}, valid[1]},
		"foreign run":   {{RunID: other.IDs[0], SHA256: valid[0].SHA256}, valid[1]},
	} {
		t.Run(name, func(t *testing.T) {
			input["programs"] = programs
			libraryRequest(t, f, owner, http.MethodPost, path, input, 400, nil)
		})
	}
	input["programs"] = valid
	var saved wire.SourceDocument
	libraryRequest(t, f, owner, http.MethodPost, path, input, 201, &saved)
	if saved.Kind != "workflow" || saved.MeasurementID != submission.TransactionID || saved.DocumentSHA256 != communityDocumentDigest(saved.Document) || len(saved.Programs) != 2 {
		t.Fatalf("saved source: %+v", saved)
	}
	input["programs"] = []wire.SourceProgram{valid[1], valid[0]}
	indented, err := json.MarshalIndent(communityTestWorkflow(), "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	input["document"] = json.RawMessage(indented)
	libraryRequest(t, f, owner, http.MethodPost, path, input, 200, nil)
	var loaded wire.SourceDocument
	libraryRequest(t, f, owner, http.MethodGet, read, nil, 200, &loaded)
	if !reflect.DeepEqual(saved, loaded) {
		t.Fatal("immutable source changed during an idempotent attachment")
	}
	changed := communityTestWorkflow()
	changed.Name = "Changed after the run"
	input["document"] = changed
	libraryRequest(t, f, owner, http.MethodPost, path, input, 409, nil)
	libraryRequest(t, f, outsider, http.MethodGet, read, nil, 404, nil)
	if _, err := f.db.ExecContext(f.ctx, "UPDATE measurement_sources SET document='{}' WHERE measurement_id=?", submission.TransactionID); err == nil {
		t.Fatal("stored source can be updated")
	}
}

func TestMeasurementSourceSharingRevocationAndPayloadDeletion(t *testing.T) {
	f := ccNewFixtureWith(t)
	_, owner, sdk := authAccount(t, f, "Owner")
	memberAccount, member, _ := authAccount(t, f, "Member")
	submission := sourceTestSubmission(t, f, sdk)
	input := sourceTestInput(t, submission)
	post := "/measurements/" + submission.TransactionID + "/source"
	read := "/runs/" + submission.IDs[0] + "/source"
	libraryRequest(t, f, owner, http.MethodPost, post, input, 201, nil)
	group := communityCreate(t, f, owner)
	communityJoin(t, f, owner, member, group.ID)
	project := communityProject(t, f, owner, group.ID)
	share := "/community-projects/" + project.ID + "/measurements"
	libraryRequest(t, f, owner, http.MethodPost, share, map[string]string{"measurement_id": submission.TransactionID}, 201, nil)
	libraryRequest(t, f, member, http.MethodGet, read, nil, 200, nil)
	libraryRequest(t, f, member, http.MethodPost, post, input, 404, nil)
	libraryRequest(t, f, owner, http.MethodDelete, share+"/"+submission.TransactionID, nil, 204, nil)
	libraryRequest(t, f, member, http.MethodGet, read, nil, 404, nil)
	libraryRequest(t, f, owner, http.MethodGet, read, nil, 200, nil)
	libraryRequest(t, f, owner, http.MethodPost, share, map[string]string{"measurement_id": submission.TransactionID}, 201, nil)
	libraryRequest(t, f, owner, http.MethodDelete, "/communities/"+group.ID+"/members/"+memberAccount.ID, nil, 204, nil)
	libraryRequest(t, f, member, http.MethodGet, read, nil, 404, nil)
	if _, err := f.db.ExecContext(f.ctx, `INSERT INTO payload_tombstones(debuglet_id,deleted_at,reason)
 SELECT id,unixepoch(),'owner_requested' FROM debuglets WHERE uuid=?`, submission.IDs[0]); err != nil {
		t.Fatal(err)
	}
	libraryRequest(t, f, owner, http.MethodGet, read, nil, 410, nil)
	libraryRequest(t, f, owner, http.MethodGet, "/runs/"+submission.IDs[1]+"/source", nil, 404, nil)
	libraryRequest(t, f, owner, http.MethodPost, post, input, 410, nil)
	var count int
	if err := f.db.QueryRowContext(f.ctx, "SELECT count(*) FROM measurement_sources WHERE measurement_id=?", submission.TransactionID).Scan(&count); err != nil || count != 0 {
		t.Fatalf("deleted payload retained group source: %d, %v", count, err)
	}
}

func TestMeasurementSourceUsesExactSharedRevision(t *testing.T) {
	f := ccNewFixtureWith(t)
	_, owner, sdk := authAccount(t, f, "Owner")
	_, member, _ := authAccount(t, f, "Member")
	submission := f.submit(sdk, nil)
	group := communityCreate(t, f, owner)
	communityJoin(t, f, owner, member, group.ID)
	project := communityProject(t, f, owner, group.ID)
	document := communityTestJSON(t, communityTestWorkflow())
	var experiment wire.CommunityExperiment
	libraryRequest(t, f, owner, http.MethodPost, "/community-projects/"+project.ID+"/experiments", communityExperimentRequest{Name: "Initial", Kind: "workflow", Document: document}, 201, &experiment)
	share := "/community-projects/" + project.ID + "/measurements"
	libraryRequest(t, f, owner, http.MethodPost, share, map[string]any{"measurement_id": submission.TransactionID, "experiment_id": experiment.ID, "experiment_revision": 1}, 201, nil)
	changed := communityTestWorkflow()
	changed.Name = "Later graph"
	libraryRequest(t, f, owner, http.MethodPut, "/community-experiments/"+experiment.ID, communityExperimentRequest{Name: "Later", Kind: "workflow", Revision: 1, Document: communityTestJSON(t, changed)}, 200, nil)
	var source wire.SourceDocument
	read := "/runs/" + submission.IDs[0] + "/source"
	libraryRequest(t, f, member, http.MethodGet, read, nil, 200, &source)
	if source.CommunityExperimentID != experiment.ID || source.Revision != 1 || string(source.Document) != string(document) || len(source.Programs) != 1 || source.Programs[0].RunID != submission.IDs[0] {
		t.Fatalf("source drifted from shared revision: %+v", source)
	}
	libraryRequest(t, f, owner, http.MethodDelete, share+"/"+submission.TransactionID, nil, 204, nil)
	libraryRequest(t, f, member, http.MethodGet, read, nil, 404, nil)
	libraryRequest(t, f, owner, http.MethodGet, read, nil, 404, nil)
}

func TestMeasurementSourceBodyLimit(t *testing.T) {
	f := ccNewFixtureWith(t)
	_, token, sdk := authAccount(t, f, "Owner")
	submission := f.submit(sdk, nil)
	body := []byte(`{"kind":"workflow","document":{"name":"` + strings.Repeat("x", maxMeasurementSourceBytes) + `"},"programs":[]}`)
	status, _, _, _ := authRequest(t, f, http.MethodPost, "/measurements/"+submission.TransactionID+"/source", body, authBearer(token))
	if status != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversize source returned %d", status)
	}
}
