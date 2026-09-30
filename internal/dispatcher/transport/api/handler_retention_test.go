// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package api

import (
	"context"
	"net/http"
	"testing"

	"github.com/google/uuid"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/models"
	pb "github.com/netsec-ethz/debuglet/protocol"
)

func TestPayloadOwnerDeletionAndExportBoundary(t *testing.T) {
	f := ccNewFixtureWith(t)
	contract := oaContract(t)
	request := func(token, method, target string) (int, string) {
		status, code, body, _ := authRequest(t, f, method, target, nil, authBearer(token))
		oaCheckResponse(t, contract, method, target, status, body)
		return status, code
	}
	_, token, owner := authAccount(t, f, "payload owner")
	_, otherToken, other := authAccount(t, f, "other owner")
	operator, operatorToken, _ := authAccount(t, f, "operator")
	if _, err := f.db.Exec("UPDATE users SET role='operator' WHERE uuid=?", uuid.MustParse(operator.ID)); err != nil {
		t.Fatal(err)
	}
	sub := f.submit(owner, []string{"private argument"})
	sibling := f.submit(other, nil)
	id := uuid.MustParse(sub.IDs[0])
	target := "/debuglet/" + id.String() + "/payload"
	for _, credential := range []string{otherToken, operatorToken, ""} {
		status, _ := request(credential, http.MethodDelete, target)
		if status != http.StatusNotFound && status != http.StatusUnauthorized {
			t.Fatalf("non-owner delete: %d", status)
		}
	}
	if _, err := owner.Export(f.ctx, id.String()); err != nil {
		t.Fatal(err)
	}
	if status, code := request(token, http.MethodDelete, target); status != http.StatusConflict || code != CodePayloadNotDeletable {
		t.Fatalf("active deletion: %d %s", status, code)
	}
	if _, err := f.db.Exec("UPDATE debuglets SET state=? WHERE uuid=?", models.RunStateExited, id); err != nil {
		t.Fatal(err)
	}
	// The peer reports absence, not a terminal report alone. Pending output
	// still prevents deleting data after execution reservations retire.
	f.peer.mu.Lock()
	f.peer.onInspect = func(context.Context, *pb.InspectRetainedRunRequest) (*pb.InspectRetainedRunResponse, error) {
		return &pb.InspectRetainedRunResponse{Status: pb.RetainedRunStatus_RETAINED_RUN_STATUS_ABSENT}, nil
	}
	f.peer.mu.Unlock()
	if status, _ := request(token, http.MethodDelete, target); status != http.StatusConflict {
		t.Fatalf("pending output: %d", status)
	}
	if _, err := f.db.Exec("UPDATE debuglet_output SET final_sequence=committed_sequence,final_cursor=last_log_id,status='complete' WHERE debuglet_id=(SELECT id FROM debuglets WHERE uuid=?)", id); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if status, code := request(token, http.MethodDelete, target); status != http.StatusNoContent {
			t.Fatalf("owner deletion: %d %s", status, code)
		}
	}
	for _, suffix := range []string{"/logs", "/result", "/detail"} {
		if status, code := request(token, http.MethodGet, "/debuglet/"+id.String()+suffix); status != http.StatusGone || code != CodePayloadDeleted {
			t.Fatalf("deleted%s: %d %s", suffix, status, code)
		}
	}
	if status, _ := request(token, http.MethodGet, "/debuglet/"+id.String()+"/state"); status != http.StatusOK {
		t.Fatalf("state: %d", status)
	}
	if _, err := other.Export(f.ctx, sibling.IDs[0]); err != nil {
		t.Fatalf("sibling: %v", err)
	}
}
