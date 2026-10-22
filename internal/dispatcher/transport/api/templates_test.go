// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/netsec-ethz/debuglet/pkg/wire"
)

func TestTemplatesOwnershipRevisionAndSharedCopy(t *testing.T) {
	f := ccNewFixtureWith(t)
	_, owner, _ := authAccount(t, f, "Alice")
	_, other, _ := authAccount(t, f, "Bob")
	input := templateInput{Name: "DNS survey", Description: "Editable research method", Collection: "DNS", Kind: "workflow", Document: communityTestJSON(t, communityTestWorkflow())}
	var saved wire.Template
	libraryRequest(t, f, owner, http.MethodPost, "/templates", input, 201, &saved)
	if saved.ID == "" || saved.Revision != 1 || saved.Description != input.Description || saved.Collection != input.Collection {
		t.Fatalf("saved template: %+v", saved)
	}
	path := "/templates/" + saved.ID
	var listed []wire.Template
	libraryRequest(t, f, owner, http.MethodGet, "/templates", nil, 200, &listed)
	if len(listed) != 1 || listed[0].ID != saved.ID || len(listed[0].Document) != 0 {
		t.Fatal("list lost metadata or copied source")
	}
	libraryRequest(t, f, other, http.MethodGet, "/templates", nil, 200, &listed)
	if len(listed) != 0 {
		t.Fatal("another account's template was listed")
	}
	for _, method := range []string{http.MethodGet, http.MethodPut, http.MethodDelete} {
		libraryRequest(t, f, other, method, path, input, 404, nil)
	}
	var loaded wire.Template
	libraryRequest(t, f, owner, http.MethodGet, path, nil, 200, &loaded)
	if !bytes.Equal(loaded.Document, saved.Document) {
		t.Fatal("read changed saved source")
	}
	group := communityCreate(t, f, owner)
	communityJoin(t, f, owner, other, group.ID)
	project := communityProject(t, f, owner, group.ID)
	var shared wire.CommunityExperiment
	libraryRequest(t, f, owner, http.MethodPost, "/community-projects/"+project.ID+"/experiments", communityExperimentRequest{Name: saved.Name, Kind: saved.Kind, Document: saved.Document}, 201, &shared)
	input.Name, input.Revision = "New personal version", saved.Revision
	var graph map[string]any
	if err := json.Unmarshal(input.Document, &graph); err != nil {
		t.Fatal(err)
	}
	graph["name"] = "Modified independent source"
	input.Document = communityTestJSON(t, graph)
	libraryRequest(t, f, owner, http.MethodPut, path, input, 200, &loaded)
	if loaded.Revision != 2 || loaded.Name != input.Name || bytes.Equal(loaded.Document, saved.Document) {
		t.Fatal("update did not replace source and advance revision")
	}
	libraryRequest(t, f, owner, http.MethodPut, path, input, 409, nil)
	libraryRequest(t, f, owner, http.MethodGet, path, nil, 200, &loaded)
	if loaded.Revision != 2 {
		t.Fatal("stale write changed revision")
	}
	libraryRequest(t, f, owner, http.MethodDelete, path, nil, 204, nil)
	libraryRequest(t, f, owner, http.MethodGet, path, nil, 404, nil)
	libraryRequest(t, f, other, http.MethodGet, "/community-experiments/"+shared.ID, nil, 200, &shared)
	if !bytes.Equal(shared.Document, saved.Document) {
		t.Fatal("personal edit or deletion changed shared source")
	}
}

func TestTemplatesRejectInvalidSourceAndBoundLibrary(t *testing.T) {
	f := ccNewFixtureWith(t)
	account, owner, _ := authAccount(t, f, "Alice")
	input := templateInput{Name: "Source", Kind: "workflow", Document: communityTestJSON(t, communityTestWorkflow())}
	libraryRequest(t, f, owner, http.MethodPost, "/templates", map[string]any{"name": "Invalid", "kind": "workflow", "document": map[string]any{}}, 400, nil)
	libraryRequest(t, f, owner, http.MethodPost, "/templates", map[string]any{"name": "Bundle", "kind": "workflow", "document": json.RawMessage(input.Document), "bundle": map[string]any{}}, 400, nil)
	input.Revision = 1
	libraryRequest(t, f, owner, http.MethodPost, "/templates", input, 400, nil)
	input.Revision = 0
	var saved wire.Template
	libraryRequest(t, f, owner, http.MethodPost, "/templates", input, 201, &saved)
	if _, err := f.db.Exec(`WITH RECURSIVE n(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM n WHERE x<255)
 INSERT INTO personal_templates SELECT 'fixture-'||x,user_id,name,description,collection,kind,document,revision,updated_at FROM n,personal_templates WHERE id=?`, saved.ID); err != nil {
		t.Fatal(err)
	}
	libraryRequest(t, f, owner, http.MethodPost, "/templates", input, 409, nil)
	input.Name, input.Revision = "Replace at capacity", 1
	libraryRequest(t, f, owner, http.MethodPut, "/templates/"+saved.ID, input, 200, &saved)
	// Storage bounds apply to aggregate source, including replacements.
	if _, err := f.db.Exec(`UPDATE personal_templates SET document=json_object('padding',replace(hex(zeroblob(2097000)),'0','x')) WHERE id IN (SELECT id FROM personal_templates WHERE user_id=(SELECT id FROM users WHERE uuid=?) LIMIT 18)`, account.ID); err != nil {
		t.Fatal(err)
	}
	input.Revision = saved.Revision
	libraryRequest(t, f, owner, http.MethodPut, "/templates/"+saved.ID, input, 409, nil)
}
