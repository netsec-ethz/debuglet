// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package api

import (
	"encoding/json"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/netsec-ethz/debuglet/pkg/client"
	"github.com/netsec-ethz/debuglet/pkg/wire"
	"github.com/netsec-ethz/debuglet/pkg/workflow"
)

func communityRequest(t *testing.T, f *ccFixture, token, method, path string, body any, status int, out any) {
	t.Helper()
	var raw []byte
	var err error
	if body != nil {
		raw, err = json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
	}
	got, _, data, _ := authRequest(t, f, method, path, raw, authBearer(token))
	if got != status {
		t.Fatalf("%s %s: status %d want %d: %s", method, path, got, status, data)
	}
	if out != nil {
		if err = json.Unmarshal(data, out); err != nil {
			t.Fatal(err)
		}
	}
}
func communityCreate(t *testing.T, f *ccFixture, token string) wire.Community {
	t.Helper()
	var item wire.Community
	communityRequest(t, f, token, http.MethodPost, "/communities", map[string]string{"name": " Netsec ", "description": "Shared network research"}, 201, &item)
	return item
}
func communityJoin(t *testing.T, f *ccFixture, owner, member, community string) {
	t.Helper()
	var invite struct {
		Token     string    `json:"token"`
		ExpiresAt time.Time `json:"expires_at"`
	}
	communityRequest(t, f, owner, http.MethodPost, "/communities/"+community+"/invitations", nil, 201, &invite)
	if len(invite.Token) != 43 || time.Until(invite.ExpiresAt) < 6*24*time.Hour {
		t.Fatal("invalid invitation")
	}
	communityRequest(t, f, member, http.MethodPost, "/community-invitations/accept", map[string]string{"token": invite.Token}, 200, nil)
	communityRequest(t, f, member, http.MethodPost, "/community-invitations/accept", map[string]string{"token": invite.Token}, 404, nil)
}
func communityProject(t *testing.T, f *ccFixture, token, community string) wire.CommunityProject {
	t.Helper()
	var item wire.CommunityProject
	communityRequest(t, f, token, http.MethodPost, "/communities/"+community+"/projects", map[string]string{"name": "DNS study"}, 201, &item)
	return item
}

func TestCommunityMembershipInvitationsAndProjectIsolation(t *testing.T) {
	f := ccNewFixtureWith(t)
	alice, owner, _ := authAccount(t, f, "Alice")
	bob, member, _ := authAccount(t, f, "Bob")
	_, outsider, _ := authAccount(t, f, "Outsider")
	group := communityCreate(t, f, owner)
	if group.Name != "Netsec" || group.Role != "owner" || group.CreatedBy != alice.ID {
		t.Fatalf("created community: %+v", group)
	}
	communityRequest(t, f, member, http.MethodGet, "/communities/"+group.ID, nil, 404, nil)
	communityRequest(t, f, "", http.MethodGet, "/communities", nil, 401, nil)
	communityJoin(t, f, owner, member, group.ID)
	var memberships []wire.Community
	communityRequest(t, f, member, http.MethodGet, "/communities", nil, 200, &memberships)
	if len(memberships) != 1 || memberships[0].Role != "member" {
		t.Fatalf("member list: %+v", memberships)
	}
	var people []wire.CommunityMember
	communityRequest(t, f, member, http.MethodGet, "/communities/"+group.ID+"/members", nil, 200, &people)
	if len(people) != 2 {
		t.Fatalf("member count %d", len(people))
	}
	communityRequest(t, f, member, http.MethodPost, "/communities/"+group.ID+"/invitations", nil, 404, nil)
	communityRequest(t, f, member, http.MethodPatch, "/communities/"+group.ID, map[string]string{"name": "Changed"}, 404, nil)
	project := communityProject(t, f, member, group.ID)
	communityRequest(t, f, owner, http.MethodPatch, "/community-projects/"+project.ID, map[string]string{"name": "Updated study"}, 200, nil)
	communityRequest(t, f, outsider, http.MethodGet, "/community-projects/"+project.ID, nil, 404, nil)
	communityRequest(t, f, owner, http.MethodDelete, "/communities/"+group.ID+"/members/"+alice.ID, nil, 400, nil)
	communityRequest(t, f, owner, http.MethodDelete, "/communities/"+group.ID+"/members/"+bob.ID, nil, 204, nil)
	communityRequest(t, f, member, http.MethodGet, "/community-projects/"+project.ID, nil, 404, nil)
	communityRequest(t, f, member, http.MethodPost, "/communities/"+group.ID+"/projects", map[string]string{"name": "Forbidden"}, 404, nil)
	var invite struct {
		Token string `json:"token"`
	}
	communityRequest(t, f, owner, http.MethodPost, "/communities/"+group.ID+"/invitations", nil, 201, &invite)
	if _, err := f.db.Exec("UPDATE community_invitations SET expires_at=0"); err != nil {
		t.Fatal(err)
	}
	communityRequest(t, f, member, http.MethodPost, "/community-invitations/accept", map[string]string{"token": invite.Token}, 404, nil)
}

func TestCommunityExperimentRevisionConflictRetainsOriginalBundle(t *testing.T) {
	f := ccNewFixtureWith(t)
	_, owner, _ := authAccount(t, f, "Owner")
	_, member, _ := authAccount(t, f, "Member")
	_, outsider, _ := authAccount(t, f, "Outsider")
	group := communityCreate(t, f, owner)
	communityJoin(t, f, owner, member, group.ID)
	project := communityProject(t, f, owner, group.ID)
	wf := communityTestWorkflow()
	program, err := workflow.Generate(wf)
	if err != nil {
		t.Fatal(err)
	}
	input := communityExperimentRequest{Name: "Resolver behavior", Kind: "workflow", Description: "Compare resolvers", Collection: "Resolvers", Document: communityTestJSON(t, wf), Bundle: communityTestJSON(t, communityTestBundle(t, wf, program))}
	var original wire.CommunityExperiment
	communityRequest(t, f, owner, http.MethodPost, "/community-projects/"+project.ID+"/experiments", input, 201, &original)
	if original.Revision != 1 || len(original.Bundle) == 0 || original.Collection != "Resolvers" {
		t.Fatalf("saved %+v", original)
	}
	communityRequest(t, f, outsider, http.MethodGet, "/community-experiments/"+original.ID, nil, 404, nil)
	var list []wire.CommunityExperiment
	communityRequest(t, f, member, http.MethodGet, "/community-projects/"+project.ID+"/experiments", nil, 200, &list)
	if len(list) != 1 || len(list[0].Document) > 0 || len(list[0].Bundle) > 0 {
		t.Fatal("list leaked large documents or missed metadata")
	}
	input.Revision = 1
	input.Name = "Edited"
	input.Bundle = nil
	wf.Name = "Edited source"
	input.Document = communityTestJSON(t, wf)
	body, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	statuses := make(chan int, 2)
	var workers sync.WaitGroup
	for _, token := range []string{owner, member} {
		workers.Add(1)
		go func(token string) {
			defer workers.Done()
			status, _ := authAs(t, f, token, http.MethodPut, "/community-experiments/"+original.ID, body)
			statuses <- status
		}(token)
	}
	workers.Wait()
	close(statuses)
	counts := map[int]int{}
	for status := range statuses {
		counts[status]++
	}
	if counts[200] != 1 || counts[409] != 1 {
		t.Fatalf("concurrent revision results: %v", counts)
	}
	var current, previous wire.CommunityExperiment
	communityRequest(t, f, member, http.MethodGet, "/community-experiments/"+original.ID, nil, 200, &current)
	communityRequest(t, f, member, http.MethodGet, "/community-experiments/"+original.ID+"?revision=1", nil, 200, &previous)
	if current.Revision != 2 || len(current.Bundle) != 0 || previous.Revision != 1 || string(previous.Bundle) != string(original.Bundle) {
		t.Fatal("edit replaced historical revision or retained stale bundle")
	}
	if _, err := f.db.Exec("UPDATE community_experiment_revisions SET name='tampered' WHERE experiment_id=?", original.ID); err == nil {
		t.Fatal("historical revision is mutable")
	}
	communityRequest(t, f, member, http.MethodGet, "/community-experiments/"+original.ID+"?revision=0", nil, 400, nil)
	input.Revision = 32
	communityRequest(t, f, member, http.MethodPut, "/community-experiments/"+original.ID, input, 409, nil)
}

func TestCommunityMeasurementSharingRequiresOwnedBatchAndSameProjectRevision(t *testing.T) {
	f := ccNewFixtureWith(t)
	ownerAccount, owner, ownerClient := authAccount(t, f, "Owner")
	memberAccount, member, _ := authAccount(t, f, "Member")
	_, outsider, _ := authAccount(t, f, "Outsider")
	group := communityCreate(t, f, owner)
	communityJoin(t, f, owner, member, group.ID)
	project := communityProject(t, f, owner, group.ID)
	other := communityProject(t, f, owner, group.ID)
	batch, err := client.Prepare([]client.Request{ccRequest([]string{"shared"})})
	if err != nil {
		t.Fatal(err)
	}
	submission, err := ownerClient.SubmitTEST(f.ctx, batch)
	if err != nil {
		t.Fatal(err)
	}
	input := map[string]any{"measurement_id": submission.TransactionID}
	route := "/community-projects/" + project.ID + "/measurements"
	communityRequest(t, f, member, http.MethodPost, route, input, 404, nil)
	communityRequest(t, f, outsider, http.MethodPost, route, input, 404, nil)
	var experiment wire.CommunityExperiment
	communityRequest(t, f, owner, http.MethodPost, "/community-projects/"+other.ID+"/experiments", communityExperimentRequest{Name: "Other project", Kind: "workflow", Document: communityTestJSON(t, communityTestWorkflow())}, 201, &experiment)
	input["experiment_id"] = experiment.ID
	input["experiment_revision"] = 1
	communityRequest(t, f, owner, http.MethodPost, route, input, 404, nil)
	communityRequest(t, f, owner, http.MethodPost, "/community-projects/"+project.ID+"/experiments", communityExperimentRequest{Name: "Same project", Kind: "workflow", Document: communityTestJSON(t, communityTestWorkflow())}, 201, &experiment)
	input["experiment_id"] = experiment.ID
	if _, err := f.db.Exec("UPDATE transaction_users SET user_id=(SELECT id FROM users WHERE uuid=?) WHERE transaction_id=?", memberAccount.ID, submission.TransactionID); err != nil {
		t.Fatal(err)
	}
	communityRequest(t, f, owner, http.MethodPost, route, input, 404, nil)
	if _, err := f.db.Exec("UPDATE transaction_users SET user_id=(SELECT id FROM users WHERE uuid=?) WHERE transaction_id=?", ownerAccount.ID, submission.TransactionID); err != nil {
		t.Fatal(err)
	}
	var shared wire.CommunityMeasurement
	communityRequest(t, f, owner, http.MethodPost, route, input, 201, &shared)
	var items []wire.CommunityMeasurement
	communityRequest(t, f, member, http.MethodGet, route, nil, 200, &items)
	if len(items) != 1 || items[0].MeasurementID != submission.TransactionID || items[0].ExperimentID != experiment.ID || items[0].ExperimentRevision == nil || *items[0].ExperimentRevision != 1 {
		t.Fatalf("shared list: %+v", items)
	}
	communityRequest(t, f, member, http.MethodDelete, route+"/"+submission.TransactionID, nil, 404, nil)
	communityRequest(t, f, owner, http.MethodDelete, "/community-experiments/"+experiment.ID, nil, 409, nil)
	communityRequest(t, f, owner, http.MethodDelete, route+"/"+submission.TransactionID, nil, 204, nil)
	communityRequest(t, f, member, http.MethodGet, "/measurements/"+submission.TransactionID, nil, 404, nil)
	communityRequest(t, f, owner, http.MethodGet, "/measurements/"+submission.TransactionID, nil, 200, nil)
	communityRequest(t, f, owner, http.MethodPost, route, input, 201, nil)
	communityRequest(t, f, member, http.MethodGet, "/debuglet/"+submission.IDs[0]+"/detail", nil, 200, nil)
	communityRequest(t, f, owner, http.MethodDelete, "/communities/"+group.ID+"/members/"+memberAccount.ID, nil, 204, nil)
	communityRequest(t, f, member, http.MethodGet, "/debuglet/"+submission.IDs[0]+"/detail", nil, 404, nil)
	communityRequest(t, f, owner, http.MethodDelete, route+"/"+submission.TransactionID, nil, 204, nil)
	communityRequest(t, f, owner, http.MethodDelete, "/community-experiments/"+experiment.ID, nil, 204, nil)
	communityRequest(t, f, owner, http.MethodGet, "/debuglet/"+submission.IDs[0]+"/detail", nil, 200, nil)
}

func TestCommunityInvitationSingleUseUnderConcurrentAcceptance(t *testing.T) {
	f := ccNewFixtureWith(t)
	_, owner, _ := authAccount(t, f, "Owner")
	_, one, _ := authAccount(t, f, "One")
	_, two, _ := authAccount(t, f, "Two")
	group := communityCreate(t, f, owner)
	var invite struct {
		Token string `json:"token"`
	}
	communityRequest(t, f, owner, http.MethodPost, "/communities/"+group.ID+"/invitations", nil, 201, &invite)
	body, _ := json.Marshal(map[string]string{"token": invite.Token})
	results := make(chan int, 2)
	var workers sync.WaitGroup
	for _, token := range []string{one, two} {
		workers.Add(1)
		go func(token string) {
			defer workers.Done()
			status, _ := authAs(t, f, token, http.MethodPost, "/community-invitations/accept", body)
			results <- status
		}(token)
	}
	workers.Wait()
	close(results)
	counts := map[int]int{}
	for status := range results {
		counts[status]++
	}
	if counts[200] != 1 || counts[404] != 1 {
		t.Fatalf("invitation results: %v", counts)
	}
}

func TestCommunityQuotasAndExpiredInvitationsDoNotAccumulate(t *testing.T) {
	f := ccNewFixtureWith(t)
	_, owner, _ := authAccount(t, f, "Owner")
	group := communityCreate(t, f, owner)
	for i := 1; i < 16; i++ {
		communityCreate(t, f, owner)
	}
	communityRequest(t, f, owner, http.MethodPost, "/communities", map[string]string{"name": "One too many"}, 409, nil)
	route := "/communities/" + group.ID + "/invitations"
	for i := 0; i < 8; i++ {
		communityRequest(t, f, owner, http.MethodPost, route, nil, 201, nil)
	}
	communityRequest(t, f, owner, http.MethodPost, route, nil, 409, nil)
	if _, err := f.db.Exec("UPDATE community_invitations SET expires_at=0"); err != nil {
		t.Fatal(err)
	}
	communityRequest(t, f, owner, http.MethodPost, route, nil, 201, nil)
	var count int
	if err := f.db.QueryRow("SELECT count(*) FROM community_invitations").Scan(&count); err != nil || count != 1 {
		t.Fatalf("expired invitations remain: %d %v", count, err)
	}
	project := communityProject(t, f, owner, group.ID)
	input := communityExperimentRequest{Name: "Revision limit", Kind: "workflow", Document: communityTestJSON(t, communityTestWorkflow())}
	var experiment wire.CommunityExperiment
	communityRequest(t, f, owner, http.MethodPost, "/community-projects/"+project.ID+"/experiments", input, 201, &experiment)
	for revision := int64(1); revision < 32; revision++ {
		input.Revision = revision
		communityRequest(t, f, owner, http.MethodPut, "/community-experiments/"+experiment.ID, input, 200, nil)
	}
	input.Revision = 32
	communityRequest(t, f, owner, http.MethodPut, "/community-experiments/"+experiment.ID, input, 409, nil)
	communityRequest(t, f, owner, http.MethodGet, "/community-experiments/"+experiment.ID, nil, 200, &experiment)
	if experiment.Revision != 32 {
		t.Fatal("failed update changed revision")
	}
}

func TestCommunityExperimentDeletionReleasesStoredRevisions(t *testing.T) {
	f := ccNewFixtureWith(t)
	_, owner, _ := authAccount(t, f, "Owner")
	_, creator, _ := authAccount(t, f, "Creator")
	_, member, _ := authAccount(t, f, "Member")
	group := communityCreate(t, f, owner)
	communityJoin(t, f, owner, creator, group.ID)
	communityJoin(t, f, owner, member, group.ID)
	project := communityProject(t, f, owner, group.ID)
	wf := communityTestWorkflow()
	program, err := workflow.Generate(wf)
	if err != nil {
		t.Fatal(err)
	}
	input := communityExperimentRequest{Name: "Unused compiled experiment", Kind: "workflow", Document: communityTestJSON(t, wf), Bundle: communityTestJSON(t, communityTestBundle(t, wf, program))}
	var item wire.CommunityExperiment
	route := "/community-projects/" + project.ID + "/experiments"
	communityRequest(t, f, creator, http.MethodPost, route, input, 201, &item)
	input.Revision = 1
	communityRequest(t, f, creator, http.MethodPut, "/community-experiments/"+item.ID, input, 200, nil)
	var before, after int64
	storage := `SELECT COALESCE(sum(length(CAST(document AS BLOB))+COALESCE(length(CAST(bundle AS BLOB)),0)),0) FROM community_experiment_revisions`
	if err = f.db.QueryRow(storage).Scan(&before); err != nil || before == 0 {
		t.Fatalf("storage before deletion %d: %v", before, err)
	}
	communityRequest(t, f, member, http.MethodDelete, "/community-experiments/"+item.ID, nil, 404, nil)
	communityRequest(t, f, creator, http.MethodDelete, "/community-experiments/"+item.ID, nil, 204, nil)
	if err = f.db.QueryRow(storage).Scan(&after); err != nil || after != 0 {
		t.Fatalf("deletion did not free quota bytes %d: %v", after, err)
	}
	communityRequest(t, f, creator, http.MethodGet, "/community-experiments/"+item.ID+"?revision=1", nil, 404, nil)
	input.Revision = 0
	communityRequest(t, f, creator, http.MethodPost, route, input, 201, &item)
	communityRequest(t, f, owner, http.MethodDelete, "/community-experiments/"+item.ID, nil, 204, nil)
}

func TestCommunityFundedHistoryCannotBeUnshared(t *testing.T) {
	s := newCommunityFundingFixture(t, true)
	request := s.request()
	intent := s.intent(t, request)
	route := "/community-projects/" + s.project.ID + "/measurements/" + intent.Intent.TransactionID
	for _, token := range []string{s.ownerToken, s.memberToken} {
		var failure ErrorResponse
		communityRequest(t, s.f, token, http.MethodDelete, route, nil, 409, &failure)
		if failure.Message != "Measurements funded by a community remain in its project history." {
			t.Fatalf("unshare diagnostic: %+v", failure)
		}
	}
	communityRequest(t, s.f, s.outsiderToken, http.MethodDelete, route, nil, 404, nil)
	var ids []string
	communityRequest(t, s.f, s.memberToken, http.MethodPut, "/debuglet", SubmitDebugletsRequest{Debuglets: request.Debuglets, TransactionId: intent.Intent.TransactionID, AuthKey: intent.Intent.AuthKey}, 200, &ids)
	communityRequest(t, s.f, s.ownerToken, http.MethodDelete, route, nil, 409, nil)
	var history []wire.CommunityMeasurement
	communityRequest(t, s.f, s.ownerToken, http.MethodGet, "/community-projects/"+s.project.ID+"/measurements", nil, 200, &history)
	if len(history) != 1 || history[0].MeasurementID != intent.Intent.TransactionID {
		t.Fatal("funded history was lost")
	}
	exported := communityProject(t, s.f, s.ownerToken, s.community.ID)
	exportRoute := "/community-projects/" + exported.ID + "/measurements"
	communityRequest(t, s.f, s.memberToken, http.MethodPost, exportRoute, map[string]string{"measurement_id": intent.Intent.TransactionID}, 201, nil)
	communityRequest(t, s.f, s.memberToken, http.MethodDelete, exportRoute+"/"+intent.Intent.TransactionID, nil, 204, nil)
	communityRequest(t, s.f, s.memberToken, http.MethodGet, "/measurements/"+intent.Intent.TransactionID, nil, 200, nil)
}
