// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package api

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"testing"

	"github.com/netsec-ethz/debuglet/pkg/client"
	"github.com/netsec-ethz/debuglet/pkg/wire"
)

// oaCommunityExchanges records the real collaboration lifecycle through the
// same transport as the public contract test, including its /api deployment.
func oaCommunityExchanges(t *testing.T, f *ccFixture, ctx context.Context, sdk *client.Client, recorder *oaRecorder, base, ownerToken string, owned client.Submission) {
	t.Helper()
	member, err := sdk.CreateAccount(ctx, "contract community member")
	if err != nil {
		t.Fatal(err)
	}
	session, err := sdk.Login(ctx, member.AccountKey)
	if err != nil {
		t.Fatal(err)
	}
	raw := &http.Client{Transport: recorder, Timeout: ccRequestBound}
	t.Cleanup(raw.CloseIdleConnections)
	request := func(token, method, path string, body any, status int, out any) {
		t.Helper()
		var data []byte
		if body != nil {
			data, err = json.Marshal(body)
			if err != nil {
				t.Fatal(err)
			}
		}
		req, err := http.NewRequestWithContext(ctx, method, base+path, bytes.NewReader(data))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "Bearer "+token)
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		response, err := raw.Do(req)
		if err != nil {
			t.Fatalf("%s %s: %v", method, path, err)
		}
		data, readErr := io.ReadAll(response.Body)
		response.Body.Close()
		if readErr != nil {
			t.Fatal(readErr)
		}
		if response.StatusCode != status {
			t.Fatalf("%s %s: status %d, want %d: %s", method, path, response.StatusCode, status, data)
		}
		if out != nil {
			if err := json.Unmarshal(data, out); err != nil {
				t.Fatalf("%s %s: decode response: %v", method, path, err)
			}
		}
	}

	// Use one retained report to exercise the library and source lifecycle through
	// the same recorder, including the mounted API prefix.
	libraryOutput(t, f, owned.IDs[0], "\n"+libraryEvent(7))
	request(ownerToken, http.MethodPost, "/measurements/"+owned.TransactionID+"/source", sourceTestInput(t, owned), 201, nil)
	request(ownerToken, http.MethodGet, "/runs/"+owned.IDs[0]+"/source", nil, 200, nil)
	var highlight wire.Highlight
	request(ownerToken, http.MethodPost, "/result-highlights", map[string]any{"run_id": owned.IDs[0], "event_index": 0, "name": "Contract result"}, 201, &highlight)
	request(ownerToken, http.MethodGet, "/result-highlights", nil, 200, nil)
	request(ownerToken, http.MethodGet, "/result-highlights/"+highlight.ID, nil, 200, nil)
	request(ownerToken, http.MethodPatch, "/result-highlights/"+highlight.ID, map[string]string{"name": "Renamed result"}, 200, nil)
	request(ownerToken, http.MethodDelete, "/result-highlights/"+highlight.ID, nil, 204, nil)

	var personal wire.Template
	template := templateInput{Name: "Contract template", Kind: "workflow", Document: communityTestJSON(t, communityTestWorkflow())}
	request(ownerToken, http.MethodPost, "/templates", template, 201, &personal)
	request(ownerToken, http.MethodGet, "/templates", nil, 200, nil)
	request(ownerToken, http.MethodGet, "/templates/"+personal.ID, nil, 200, nil)
	template.Revision = personal.Revision
	request(ownerToken, http.MethodPut, "/templates/"+personal.ID, template, 200, nil)
	request(ownerToken, http.MethodDelete, "/templates/"+personal.ID, nil, 204, nil)

	var community wire.Community
	request(ownerToken, http.MethodPost, "/communities",
		map[string]string{"name": "Contract community", "description": "Shared measurements"}, 201, &community)
	group := "/communities/" + community.ID
	request(ownerToken, http.MethodGet, "/communities", nil, 200, nil)
	request(ownerToken, http.MethodGet, group, nil, 200, nil)
	request(ownerToken, http.MethodPatch, group,
		map[string]string{"name": "Updated community", "description": "Network experiments"}, 200, nil)
	var invitation struct {
		Token string `json:"token"`
	}
	request(ownerToken, http.MethodPost, group+"/invitations", nil, 201, &invitation)
	request(session.Token, http.MethodPost, "/community-invitations/accept",
		map[string]string{"token": invitation.Token}, 200, nil)
	request(ownerToken, http.MethodGet, group+"/members", nil, 200, nil)
	request(ownerToken, http.MethodGet, group+"/wallet", nil, 200, nil)
	// This fixture deliberately disables chain payments. A valid deposit
	// request reaches that guard; it neither signs nor credits any funds.
	request(ownerToken, http.MethodPost, group+"/wallet/top-ups",
		map[string]string{"amount": "1000", "refund_address": "0x1"}, 503, nil)

	var project wire.CommunityProject
	request(ownerToken, http.MethodPost, group+"/projects",
		map[string]string{"name": "Contract project", "description": "Resolver study"}, 201, &project)
	request(session.Token, http.MethodGet, group+"/projects", nil, 200, nil)
	projectPath := "/community-projects/" + project.ID
	request(session.Token, http.MethodGet, projectPath, nil, 200, nil)
	request(session.Token, http.MethodPatch, projectPath,
		map[string]string{"name": "Updated project", "description": "Repeatable measurements"}, 200, nil)

	var experiment wire.CommunityExperiment
	input := map[string]any{
		"name": "Contract workflow", "kind": "workflow", "document": communityTestWorkflow(),
		"description": "Observe a target", "collection": "HTTP",
	}
	request(ownerToken, http.MethodPost, projectPath+"/experiments", input, 201, &experiment)
	experimentPath := "/community-experiments/" + experiment.ID
	request(session.Token, http.MethodGet, projectPath+"/experiments", nil, 200, nil)
	request(session.Token, http.MethodGet, experimentPath, nil, 200, nil)
	input["revision"] = experiment.Revision
	input["name"] = "Updated workflow"
	request(session.Token, http.MethodPut, experimentPath, input, 200, &experiment)
	request(ownerToken, http.MethodPut, experimentPath, input, 409, nil)
	request(ownerToken, http.MethodGet, experimentPath+"?revision=1", nil, 200, nil)

	shared := map[string]any{
		"measurement_id": owned.TransactionID,
		"experiment_id":  experiment.ID, "experiment_revision": experiment.Revision,
	}
	request(ownerToken, http.MethodPost, projectPath+"/measurements", shared, 201, nil)
	request(session.Token, http.MethodGet, projectPath+"/measurements", nil, 200, nil)
	request(session.Token, http.MethodGet, "/measurements/"+owned.TransactionID, nil, 200, nil)
	request(session.Token, http.MethodGet, "/debuglet/"+owned.IDs[0]+"/detail", nil, 200, nil)
	request(ownerToken, http.MethodDelete, experimentPath, nil, 409, nil)
	request(ownerToken, http.MethodDelete, projectPath+"/measurements/"+owned.TransactionID, nil, 204, nil)
	request(ownerToken, http.MethodDelete, experimentPath, nil, 204, nil)
	request(ownerToken, http.MethodDelete, group+"/members/"+member.ID, nil, 204, nil)
	request(session.Token, http.MethodGet, group, nil, 404, nil)
}
