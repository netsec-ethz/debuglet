// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package api

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/netsec-ethz/debuglet/pkg/wire"
)

func libraryEvent(value int) string {
	data, _ := json.Marshal(map[string]any{"schema": "debuglet.workflow.v1", "workflow_sha256": strings.Repeat("a", 64), "node_id": "same", "block": "report_metric", "status": "completed", "outputs": map[string]any{"title": "RTT", "value": value, "unit": "ms"}})
	return string(data) + "\n"
}
func libraryOutput(t *testing.T, f *ccFixture, runID, output string) {
	t.Helper()
	// A JSONL record split across frames must still identify the same event.
	split := len(output) / 2
	for _, part := range []string{output[:split], output[split:]} {
		if _, err := f.db.Exec("INSERT INTO debuglet_logs(debuglet_id,timestamp,output) SELECT id,CURRENT_TIMESTAMP,? FROM debuglets WHERE uuid=?", []byte(part), runID); err != nil {
			t.Fatal(err)
		}
	}
}
func TestResultHighlightsRepeatedEventsAndRetention(t *testing.T) {
	f := ccNewFixtureWith(t)
	_, token, alice := authAccount(t, f, "Alice")
	_, other, _ := authAccount(t, f, "Bob")
	submission := f.submit(alice, nil)
	run := submission.IDs[0]
	uppercase := strings.ReplaceAll(libraryEvent(99), "schema", "SCHEMA")
	libraryOutput(t, f, run, uppercase+"unstructured\n"+libraryEvent(1)+libraryEvent(2)+strings.TrimSuffix(libraryEvent(3), "\n"))
	request := map[string]any{"run_id": run, "event_index": 1, "name": "Second RTT", "note": "repeat", "collection": "DNS"}
	var saved wire.Highlight
	libraryRequest(t, f, token, http.MethodPost, "/result-highlights", request, 201, &saved)
	if saved.EventIndex != 1 || saved.NodeID != "same" || !strings.Contains(string(saved.Event), `"value":2`) || !saved.CanManage {
		t.Fatalf("wrong occurrence: %+v %s", saved, saved.Event)
	}
	libraryRequest(t, f, other, http.MethodGet, "/result-highlights/"+saved.ID, nil, 404, nil)
	libraryRequest(t, f, other, http.MethodPost, "/result-highlights", request, 404, nil)
	var page wire.HighlightPage
	libraryRequest(t, f, token, http.MethodGet, "/result-highlights?search=repeat&collection=DNS&limit=1", nil, 200, &page)
	if page.Total != 1 || len(page.Highlights) != 1 {
		t.Fatalf("listing: %+v", page)
	}
	request["event_index"] = 2
	libraryRequest(t, f, token, http.MethodPost, "/result-highlights", request, 400, nil)
	request["event_index"] = 0
	request["event"] = map[string]any{"value": 999}
	libraryRequest(t, f, token, http.MethodPost, "/result-highlights", request, 400, nil)
	libraryRequest(t, f, token, http.MethodPatch, "/result-highlights/"+saved.ID, map[string]string{"name": "Renamed", "note": "new"}, 200, &saved)
	if saved.Name != "Renamed" || !strings.Contains(string(saved.Event), `"value":2`) {
		t.Fatal("metadata edit changed event")
	}
	if _, err := f.db.Exec("UPDATE result_highlights SET event_sha256=? WHERE id=?", strings.Repeat("0", 64), saved.ID); err != nil {
		t.Fatal(err)
	}
	libraryRequest(t, f, token, http.MethodGet, "/result-highlights/"+saved.ID, nil, 409, nil)

	if _, err := f.db.Exec(`INSERT INTO payload_tombstones(debuglet_id,deleted_at,reason,workload_sha256,certificate_sha256)
 SELECT id,0,'owner_requested','unknown','unknown' FROM debuglets WHERE uuid=?`, run); err != nil {
		t.Fatal(err)
	}
	libraryRequest(t, f, token, http.MethodGet, "/result-highlights/"+saved.ID, nil, 404, nil)
	libraryRequest(t, f, token, http.MethodGet, "/result-highlights", nil, 200, &page)
	if page.Total != 0 || len(page.Highlights) != 0 {
		t.Fatalf("purged source remains in library: %+v", page)
	}
}

func TestResultHighlightsProjectScopeAndRevocation(t *testing.T) {
	f := ccNewFixtureWith(t)
	alice, owner, client := authAccount(t, f, "Alice")
	bob, member, _ := authAccount(t, f, "Bob")
	_, outsider, _ := authAccount(t, f, "Mallory")
	group := communityCreate(t, f, owner)
	communityJoin(t, f, owner, member, group.ID)
	project := communityProject(t, f, owner, group.ID)
	otherProject := communityProject(t, f, owner, group.ID)
	submission := f.submit(client, nil)
	libraryOutput(t, f, submission.IDs[0], libraryEvent(1))
	for _, p := range []wire.CommunityProject{project, otherProject} {
		libraryRequest(t, f, owner, http.MethodPost, "/community-projects/"+p.ID+"/measurements", map[string]string{"measurement_id": submission.TransactionID}, 201, nil)
	}
	input := map[string]any{"run_id": submission.IDs[0], "event_index": 0, "name": "Shared RTT", "project_id": project.ID}
	var saved wire.Highlight
	libraryRequest(t, f, member, http.MethodPost, "/result-highlights", input, 201, &saved)
	libraryRequest(t, f, outsider, http.MethodGet, "/result-highlights/"+saved.ID, nil, 404, nil)
	libraryRequest(t, f, owner, http.MethodGet, "/result-highlights/"+saved.ID, nil, 200, &saved)
	if !saved.CanManage || saved.CreatedBy != bob.ID {
		t.Fatal("community owner management or creator lost")
	}
	var personal wire.Highlight
	delete(input, "project_id")
	libraryRequest(t, f, member, http.MethodPost, "/result-highlights", input, 201, &personal)
	libraryRequest(t, f, owner, http.MethodDelete, "/community-projects/"+project.ID+"/measurements/"+submission.TransactionID, nil, 204, nil)
	// Owning the run and access through another project do not preserve this share.
	for _, token := range []string{owner, member} {
		libraryRequest(t, f, token, http.MethodGet, "/result-highlights/"+saved.ID, nil, 404, nil)
	}
	var page wire.HighlightPage
	libraryRequest(t, f, member, http.MethodGet, "/result-highlights?project_id="+project.ID, nil, 200, &page)
	if page.Total != 0 || len(page.Highlights) != 0 {
		t.Fatal("unshared project leaks pagination totals")
	}
	libraryRequest(t, f, member, http.MethodGet, "/result-highlights/"+personal.ID, nil, 200, nil)
	libraryRequest(t, f, owner, http.MethodDelete, "/communities/"+group.ID+"/members/"+bob.ID, nil, 204, nil)
	libraryRequest(t, f, member, http.MethodGet, "/result-highlights/"+personal.ID, nil, 404, nil)
	libraryRequest(t, f, member, http.MethodGet, "/result-highlights", nil, 200, &page)
	if page.Total != 0 {
		t.Fatal("removed member retained personal bookmark access")
	}
	if alice.ID == bob.ID {
		t.Fatal("distinct account fixture required")
	}
}

func TestRetainedWorkflowEventMatchesCompleteAcceptedRecords(t *testing.T) {
	good := libraryEvent(7)
	invalid := []string{
		strings.ReplaceAll(good, `"schema"`, `"SCHEMA"`),
		strings.ReplaceAll(good, `"outputs":{`, `"outputs":null,"unused":{`),
		strings.TrimSuffix(good, "\n")[:len(strings.TrimSuffix(good, "\n"))-1] + `,"error":null}` + "\n",
		strings.TrimSuffix(good, "\n")[:len(strings.TrimSuffix(good, "\n"))-1] + `,"duration_ms":-1}` + "\n",
		strings.Repeat("x", 65537) + "\n",
	}
	output := []byte(strings.Join(invalid, "") + good + good)
	for index := int64(0); index < 2; index++ {
		event, node, _ := retainedWorkflowEvent(output, index)
		if node != "same" || string(event) != strings.TrimSuffix(good, "\n") {
			t.Fatalf("accepted event %d differs: %s", index, event)
		}
	}
	if event, _, _ := retainedWorkflowEvent(output, 2); event != nil {
		t.Fatal("invalid record shifted accepted ordinal")
	}
}

func TestResultHighlightsRefuseAmbiguousOrUnsupportedEvents(t *testing.T) {
	for name, output := range map[string]string{
		"invalid UTF8":  strings.Replace(libraryEvent(1), "RTT", string([]byte{'R', 0xff, 'T'}), 1) + libraryEvent(2),
		"failed report": strings.Replace(libraryEvent(1), "completed", "failed", 1),
		"nonreport":     strings.Replace(libraryEvent(1), "report_metric", "http", 1),
	} {
		t.Run(name, func(t *testing.T) {
			f := ccNewFixtureWith(t)
			_, token, client := authAccount(t, f, "Alice")
			submission := f.submit(client, nil)
			libraryOutput(t, f, submission.IDs[0], output)
			libraryRequest(t, f, token, http.MethodPost, "/result-highlights", map[string]any{"run_id": submission.IDs[0], "event_index": 0, "name": "Denied"}, 400, nil)
		})
	}
}

// Exercise the public schemas against the actual handler responses as well as
// authorization and retention behavior.
func libraryRequest(t *testing.T, f *ccFixture, token, method, path string, body any, status int, out any) {
	t.Helper()
	var raw []byte
	if body != nil {
		var err error
		raw, err = json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
	}
	got, _, data, _ := authRequest(t, f, method, path, raw, authBearer(token))
	if got != status {
		t.Fatalf("%s %s: status %d want %d: %s", method, path, got, status, data)
	}
	u, err := url.Parse(path)
	if err != nil {
		t.Fatal(err)
	}
	request := raw
	if status >= 400 {
		request = nil
	}
	oaCheckExchange(t, oaContract(t), oaExchange{method: method, route: u.Path, query: u.Query(), request: request, response: data, status: got})
	if out != nil {
		if err := json.Unmarshal(data, out); err != nil {
			t.Fatal(err)
		}
	}
}
