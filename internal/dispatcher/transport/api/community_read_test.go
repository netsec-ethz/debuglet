// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package api

import (
	"bytes"
	"net/http"
	"reflect"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/netsec-ethz/debuglet/pkg/client"
)

type sharedReadFixture struct {
	f                                         *ccFixture
	owner, member                             *client.Client
	memberID, memberToken, creatorToken       string
	outsiderToken, projectID, secondProjectID string
	communityID                               string
	submission                                client.Submission
}

func newSharedReadFixture(t *testing.T) sharedReadFixture {
	t.Helper()
	f := ccNewFixtureWith(t)
	alice, _, owner := authAccount(t, f, "run owner")
	bob, memberToken, member := authAccount(t, f, "community member")
	carol, creatorToken, _ := authAccount(t, f, "community creator")
	_, outsiderToken, _ := authAccount(t, f, "outsider")
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
	s := sharedReadFixture{f: f, owner: owner, member: member, memberID: bob.ID,
		memberToken: memberToken, creatorToken: creatorToken, outsiderToken: outsiderToken,
		communityID: uuid.NewString(), projectID: uuid.NewString(), secondProjectID: uuid.NewString(),
		submission: submission}
	exec := func(query string, args ...any) {
		t.Helper()
		if _, err := f.db.ExecContext(f.ctx, query, args...); err != nil {
			t.Fatal(err)
		}
	}
	exec("INSERT INTO communities(id,name,description,created_by,created_at) SELECT ?, 'Shared measurements', '', id, unixepoch() FROM users WHERE uuid=?", s.communityID, carol.ID)
	for _, account := range []string{alice.ID, bob.ID, carol.ID} {
		exec("INSERT INTO community_members(community_id,user_id,joined_at) SELECT ?,id,unixepoch() FROM users WHERE uuid=?", s.communityID, account)
	}
	// The same measurement may appear in several projects, but every run
	// remains one row when the shared measurement is paginated.
	for _, project := range []string{s.projectID, s.secondProjectID} {
		exec("INSERT INTO community_projects(id,community_id,name,description,created_by,created_at) SELECT ?,?,'Project','',id,unixepoch() FROM users WHERE uuid=?", project, s.communityID, carol.ID)
		exec("INSERT INTO community_measurements(project_id,measurement_id,shared_by,shared_at) SELECT ?,?,id,unixepoch() FROM users WHERE uuid=?", project, submission.TransactionID, alice.ID)
	}
	f.seedLogs(submission.IDs[0], [][]byte{[]byte("shared output")})
	return s
}

func TestCommunityMeasurementReadAccessDoesNotGrantManagement(t *testing.T) {
	s := newSharedReadFixture(t)
	f := s.f
	id := s.submission.IDs[0]
	for offset := int64(0); offset < 3; offset++ {
		page, err := s.member.MeasurementRuns(f.ctx, s.submission.TransactionID, 1, offset)
		if err != nil || page.Total != 2 || page.CanManage || page.Offset != offset {
			t.Fatalf("shared page %d: %+v, %v", offset, page, err)
		}
		if offset < 2 && (len(page.Runs) != 1 || page.Runs[0].RunID != s.submission.IDs[offset]) {
			t.Fatalf("shared pagination duplicated or lost a run: %+v", page.Runs)
		}
		if offset == 2 && len(page.Runs) != 0 {
			t.Fatal("expected empty last page")
		}
		owned, err := s.owner.MeasurementRuns(f.ctx, s.submission.TransactionID, 1, offset)
		if err != nil || !owned.CanManage {
			t.Fatalf("original owner lost management at offset %d: %+v, %v", offset, owned, err)
		}
	}
	original, err := s.owner.RunDetail(f.ctx, id)
	if err != nil || !original.CanManage {
		t.Fatalf("owner detail: %+v, %v", original, err)
	}
	shared, err := s.member.RunDetail(f.ctx, id)
	if err != nil || shared.CanManage || shared.Cost == nil {
		t.Fatalf("shared detail: %+v, %v", shared, err)
	}
	shared.CanManage = true
	shared.Timing.ObservedAt = original.Timing.ObservedAt
	if !reflect.DeepEqual(original, shared) {
		t.Fatal("sharing changed retained configuration, admission or per-run cost")
	}
	originalResult, err := s.owner.Export(f.ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	sharedResult, err := s.member.Export(f.ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	sharedResult.Timing.ObservedAt = originalResult.Timing.ObservedAt
	if !reflect.DeepEqual(originalResult, sharedResult) {
		t.Fatal("sharing changed the export or its provenance")
	}
	for _, token := range []string{s.memberToken, s.creatorToken} {
		for _, suffix := range []string{"detail", "logs", "state", "result", "recovery"} {
			status, _ := authAs(t, f, token, http.MethodGet, "/debuglet/"+id+"/"+suffix, nil)
			if status != http.StatusOK {
				t.Fatalf("shared %s: %d", suffix, status)
			}
		}
		for _, route := range []string{"/debuglet/" + id + "/payload", "/payment/" + s.submission.TransactionID + "/status"} {
			method := http.MethodGet
			if route == "/debuglet/"+id+"/payload" {
				method = http.MethodDelete
			}
			if status, _ := authAs(t, f, token, method, route, nil); status != http.StatusNotFound {
				t.Fatalf("shared member gained private mutation/payment access: %s %s = %d", method, route, status)
			}
		}
	}
	if err := s.member.Cancel(f.ctx, id, ccExecutorID); !authIsNotFound(err) {
		t.Fatalf("member cancellation: %v", err)
	}
	if _, err := s.member.RetryTEST(f.ctx, id, uuid.NewString(), retryBatch(t)); !authIsNotFound(err) {
		t.Fatalf("member retry: %v", err)
	}
	if f.peer.abortCount() != 0 {
		t.Fatal("denied cancellation contacted executor")
	}
	// Reading a stored cancellation is shared; creating one remains the
	// original submitter's action.
	if err := s.owner.Cancel(f.ctx, id, ccExecutorID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.member.Cancellation(f.ctx, id); err != nil || f.peer.abortCount() != 1 {
		t.Fatalf("shared cancellation observation: %v", err)
	}
	private := f.submit(s.owner, []string{"private"})
	if _, err := s.member.RunDetail(f.ctx, private.IDs[0]); !authIsNotFound(err) {
		t.Fatalf("unshared run disclosed: %v", err)
	}
	personal, err := s.member.Measurements(f.ctx, client.MeasurementOptions{})
	if err != nil || personal.Total != 0 {
		t.Fatalf("sharing changed the personal list: %+v, %v", personal, err)
	}
	for _, route := range []string{"/measurements/" + s.submission.TransactionID, "/debuglet/" + id + "/detail", "/debuglet/" + id + "/logs", "/debuglet/" + id + "/state", "/debuglet/" + id + "/result", "/debuglet/" + id + "/recovery", "/debuglet/" + id + "/cancellation"} {
		if status, _ := authAs(t, f, s.outsiderToken, http.MethodGet, route, nil); status != http.StatusNotFound {
			t.Fatalf("outsider %s: %d", route, status)
		}
	}
}

func TestCommunityReadsRespectRemovalUnsharingAndPayloadLimits(t *testing.T) {
	s := newSharedReadFixture(t)
	f := s.f
	id := s.submission.IDs[0]
	if _, err := f.db.ExecContext(f.ctx, "UPDATE debuglet_logs SET output=zeroblob(?) WHERE debuglet_id=(SELECT id FROM debuglets WHERE uuid=?)", 25<<20, id); err != nil {
		t.Fatal(err)
	}
	if status, code := authAs(t, f, s.memberToken, http.MethodGet, "/debuglet/"+id+"/result", nil); status != http.StatusRequestEntityTooLarge || code != CodePayloadTooLarge {
		t.Fatalf("shared oversized export: %d %s", status, code)
	}
	if _, err := s.member.RunDetail(f.ctx, id); err != nil {
		t.Fatalf("shared configuration depends on output size: %v", err)
	}
	if _, err := f.db.ExecContext(f.ctx, "UPDATE debuglet_logs SET output=? WHERE debuglet_id=(SELECT id FROM debuglets WHERE uuid=?)", []byte("shared output"), id); err != nil {
		t.Fatal(err)
	}
	if _, err := f.db.ExecContext(f.ctx, "INSERT INTO payload_tombstones(debuglet_id,deleted_at,reason,workload_sha256,certificate_sha256) SELECT id,unixepoch(),'owner_requested','',NULL FROM debuglets WHERE uuid=?", id); err != nil {
		t.Fatal(err)
	}
	for _, suffix := range []string{"logs", "detail", "result"} {
		if status, code := authAs(t, f, s.memberToken, http.MethodGet, "/debuglet/"+id+"/"+suffix, nil); status != http.StatusGone || code != CodePayloadDeleted {
			t.Fatalf("shared tombstone %s: %d %s", suffix, status, code)
		}
	}
	if status, _ := authAs(t, f, s.memberToken, http.MethodGet, "/debuglet/"+id+"/state", nil); status != http.StatusOK {
		t.Fatalf("retained shared state: %d", status)
	}
	if _, err := f.db.ExecContext(f.ctx, "DELETE FROM community_measurements WHERE project_id=?", s.projectID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.member.Measurement(f.ctx, s.submission.TransactionID); err != nil {
		t.Fatalf("removing one share removed another project's access: %v", err)
	}
	if _, err := f.db.ExecContext(f.ctx, "DELETE FROM community_members WHERE community_id=? AND user_id=(SELECT id FROM users WHERE uuid=?)", s.communityID, s.memberID); err != nil {
		t.Fatal(err)
	}
	for _, route := range []string{"/measurements/" + s.submission.TransactionID, "/debuglet/" + id + "/logs", "/debuglet/" + id + "/detail", "/debuglet/" + id + "/result", "/debuglet/" + id + "/state", "/debuglet/" + id + "/recovery", "/debuglet/" + id + "/cancellation"} {
		if status, _, body, _ := authRequest(t, f, http.MethodGet, route, nil, authBearer(s.memberToken)); status != http.StatusNotFound || bytes.Contains(body, []byte("payload_deleted")) {
			t.Fatalf("removed member can still inspect %s: %d", route, status)
		}
	}
	if _, err := f.db.ExecContext(f.ctx, "DELETE FROM community_measurements WHERE project_id=?", s.secondProjectID); err != nil {
		t.Fatal(err)
	}
	if status, _ := authAs(t, f, s.creatorToken, http.MethodGet, "/measurements/"+s.submission.TransactionID, nil); status != http.StatusNotFound {
		t.Fatalf("unsharing left creator read access: %d", status)
	}
	owned, err := s.owner.Measurement(f.ctx, s.submission.TransactionID)
	if err != nil || !owned.CanManage {
		t.Fatalf("unsharing revoked original ownership: %+v, %v", owned, err)
	}
}

func TestMeasurementManagementFlagsRespectCredentialScopes(t *testing.T) {
	f := credentialFixture(t)
	browser := credentialBrowser(t, f)
	owner, err := f.client(f.root.URL, false).WithCredential(strings.TrimPrefix(browser["Cookie"], sessionCookieName+"="))
	if err != nil {
		t.Fatal(err)
	}
	submission := f.submit(owner, nil)
	for _, scopes := range [][]string{{"measurements:read"}, {"measurements:read", "measurements:write"}} {
		issued := createTestCredential(t, f, browser, scopes...)
		scoped, err := owner.WithCredential(issued.Token)
		if err != nil {
			t.Fatal(err)
		}
		detail, err := scoped.RunDetail(f.ctx, submission.IDs[0])
		if err != nil || detail.CanManage != (len(scopes) == 2) {
			t.Fatalf("scoped detail management: %+v, %v", detail, err)
		}
		group, err := scoped.Measurement(f.ctx, submission.TransactionID)
		if err != nil || group.CanManage != (len(scopes) == 2) {
			t.Fatalf("scoped group management: %+v, %v", group, err)
		}
	}
}
