package api

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/netsec-ethz/debuglet/internal/dispatcher/models"
	pb "github.com/netsec-ethz/debuglet/protocol"

	"github.com/google/uuid"
)

// While it exists, cancelTrigger makes SQLite refuse every state write on
// debuglets, the terminal one included, with cancelSentinel as its error.
const (
	cancelTrigger  = "cancel_reject_state_write"
	cancelSentinel = "cancel_sentinel_state_write"
)

// TestUnrecordedCancellationIsNotAcknowledged drives DELETE /debuglet through
// the real routes, SQLite and the scripted executor. The executor acknowledges
// the Abort and the database then refuses the terminal write: the answer is
// the typed internal failure saying so, neither 204 nor the database's text. A
// refusal stays cancel_refused. Once the result is recorded the cancellation
// answers 204, and repeating it on the terminal run keeps the recorded result.
// Each answer is one the tracked contract documents for the route.
func TestUnrecordedCancellationIsNotAcknowledged(t *testing.T) {
	f := ccNewFixture(t)
	contract := oaContract(t)
	raw := &wfClient{t: t, base: f.root.URL, http: f.root.Client()}
	f.peer.setUploadHook(nil)
	sub := f.submit(f.client(f.root.URL, false), nil)
	id := uuid.MustParse(sub.IDs[0])
	cancel := DebugletDeleteRequest{DebugletID: id, ExecutorID: ccExecutorID}
	assertRun := func(what string, state models.DebugletRunState, errText string) {
		t.Helper()
		row, err := f.queries.GetDebugletByUUID(f.ctx, id)
		if err != nil {
			t.Fatalf("%s: read run: %v", what, err)
		}
		if row.State != state || row.Error.String != errText {
			t.Fatalf("%s: run is %s with error %q, want %s with %q", what, row.State, row.Error.String, state, errText)
		}
	}

	f.peer.setAbortHook(func(context.Context, *pb.AbortRequest) error { return errors.New("executor refused") })
	status, body := raw.do(http.MethodDelete, "/debuglet", cancel)
	wfExpect(t, "refused cancellation", status, http.StatusBadRequest, body)
	if envelope := envelopeOf(t, "refused cancellation", body); envelope.Code != CodeCancelRefused || envelope.Message != "cancellation refused" {
		t.Fatalf("refused cancellation answered %+v", envelope)
	}
	oaCheckResponse(t, contract, http.MethodDelete, "/debuglet", status, body)
	assertRun("refused cancellation", models.RunStateUploaded, "")

	// The executor acknowledges the Abort, and only then does the database
	// start refusing writes.
	f.peer.setAbortHook(func(context.Context, *pb.AbortRequest) error {
		if _, err := f.db.Exec(fmt.Sprintf("CREATE TRIGGER %s BEFORE UPDATE OF state ON debuglets BEGIN SELECT RAISE(ABORT, '%s'); END", cancelTrigger, cancelSentinel)); err != nil {
			t.Errorf("make the database refuse state writes: %v", err)
		}
		return nil
	})
	aborts := f.peer.abortCount()
	status, body = raw.do(http.MethodDelete, "/debuglet", cancel)
	wfExpect(t, "unrecorded cancellation", status, http.StatusInternalServerError, body)
	if envelope := envelopeOf(t, "unrecorded cancellation", body); envelope.Code != CodeInternal || envelope.Message != "cancellation acknowledged but its result was not recorded" {
		t.Fatalf("unrecorded cancellation answered %+v", envelope)
	}
	oaCheckResponse(t, contract, http.MethodDelete, "/debuglet", status, body)
	for _, private := range []string{cancelSentinel, "mark debuglet exited", "SQL"} {
		if strings.Contains(string(body), private) {
			t.Fatalf("the database diagnostic reached the client: %s", body)
		}
	}
	if f.peer.abortCount() != aborts+1 {
		t.Fatal("the Abort did not reach the executor")
	}
	assertRun("unrecorded cancellation", models.RunStateUploaded, "")

	f.peer.setAbortHook(nil)
	if _, err := f.db.Exec("DROP TRIGGER " + cancelTrigger); err != nil {
		t.Fatalf("drop trigger: %v", err)
	}
	status, body = raw.do(http.MethodDelete, "/debuglet", cancel)
	wfExpect(t, "recorded cancellation", status, http.StatusNoContent, body)
	oaCheckResponse(t, contract, http.MethodDelete, "/debuglet", status, body)
	assertRun("recorded cancellation", models.RunStateExited, "cancelled via API")

	status, body = raw.do(http.MethodDelete, "/debuglet", cancel)
	wfExpect(t, "repeated cancellation", status, http.StatusNoContent, body)
	assertRun("repeated cancellation", models.RunStateExited, "cancelled via API")
}

func TestLocalCancellationDatabaseFailureIsInternal(t *testing.T) {
	for _, failure := range []string{"terminal write", "terminal classification"} {
		t.Run(failure, func(t *testing.T) {
			f := ccNewFixture(t)
			contract := oaContract(t)
			raw := &wfClient{t: t, base: f.root.URL, http: f.root.Client()}
			f.peer.setUploadHook(nil)
			id := uuid.MustParse(f.submit(f.client(f.root.URL, false), nil).IDs[0])
			// A previous binding takes the local path even while a successor
			// executor session is connected.
			if _, err := f.db.Exec("UPDATE debuglets SET session_id = ? WHERE uuid = ?", uuid.NewString(), id); err != nil {
				t.Fatal(err)
			}
			wantState, wantError := models.RunStateUploaded, ""
			switch failure {
			case "terminal write":
				if _, err := f.db.Exec(fmt.Sprintf("CREATE TRIGGER %s BEFORE UPDATE OF state ON debuglets BEGIN SELECT RAISE(ABORT, '%s'); END", cancelTrigger, cancelSentinel)); err != nil {
					t.Fatal(err)
				}
			case "terminal classification":
				// The terminal guard rejects the write, then the timestamp
				// makes the full-row classification read fail to scan.
				wantState, wantError = models.RunStateExited, "earlier outcome"
				if _, err := f.db.Exec("UPDATE debuglets SET state = ?, error = ?, start_time = ? WHERE uuid = ?", wantState, wantError, cancelSentinel, id); err != nil {
					t.Fatal(err)
				}
			}
			aborts := f.peer.abortCount()
			status, body := raw.do(http.MethodDelete, "/debuglet", DebugletDeleteRequest{DebugletID: id, ExecutorID: ccExecutorID})
			wfExpect(t, failure, status, http.StatusInternalServerError, body)
			if envelope := envelopeOf(t, failure, body); envelope.Code != CodeInternal || envelope.Message != "failed to process cancellation" {
				t.Fatalf("local cancellation failure answered %+v", envelope)
			}
			oaCheckResponse(t, contract, http.MethodDelete, "/debuglet", status, body)
			if strings.Contains(string(body), cancelSentinel) || strings.Contains(string(body), "acknowledged") {
				t.Fatalf("local failure disclosed database text or claimed executor acknowledgement: %s", body)
			}
			if f.peer.abortCount() != aborts {
				t.Fatal("local cancellation contacted the successor executor")
			}
			var state models.DebugletRunState
			var errText sql.NullString
			if err := f.db.QueryRow("SELECT state, error FROM debuglets WHERE uuid = ?", id).Scan(&state, &errText); err != nil {
				t.Fatal(err)
			}
			if state != wantState || errText.String != wantError {
				t.Fatalf("failed cancellation changed result to %s / %q, want %s / %q", state, errText.String, wantState, wantError)
			}
		})
	}
}
