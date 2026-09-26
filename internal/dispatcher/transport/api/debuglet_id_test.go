package api

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
)

// The HTTP routes accept exactly the run IDs the control protocol accepts, and
// refuse the other spellings uuid.Parse would read as the same or no run.
func TestDebugletRoutesAcceptOnlyCanonicalIDs(t *testing.T) {
	f := newMaintenanceFixture(t)
	const id = "3f2c1a9e-7b4d-4e6a-9c1b-2d3e4f5a6b7c"
	refused := []string{
		"00000000-0000-0000-0000-000000000000",
		strings.ToUpper(id),
		"{" + id + "}",
		"urn:uuid:" + id,
		strings.ReplaceAll(id, "-", ""),
		id + "0",
	}
	accepted := []string{id}
	for _, route := range []string{"state", "logs"} {
		get := func(value string) (int, ErrorResponse) {
			t.Helper()
			response, err := f.server.Client().Get(f.server.URL + "/debuglet/" + value + "/" + route)
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			var envelope ErrorResponse
			body, err := io.ReadAll(response.Body)
			if err != nil {
				t.Fatal(err)
			}
			_ = json.Unmarshal(body, &envelope)
			return response.StatusCode, envelope
		}
		for _, value := range refused {
			if status, envelope := get(value); status != http.StatusBadRequest || envelope.Code != CodeInvalidRequest {
				t.Errorf("%s %q: %d %q, want 400 %q", route, value, status, envelope.Code, CodeInvalidRequest)
			}
		}
		// An accepted ID reaches the lookup, which finds no such run.
		for _, value := range accepted {
			if status, envelope := get(value); status != http.StatusNotFound || envelope.Code != CodeNotFound {
				t.Errorf("%s %q: %d %q, want 404 %q", route, value, status, envelope.Code, CodeNotFound)
			}
		}
	}

	// DELETE /debuglet carries the ID in its body and holds it to the same
	// rule.
	for _, value := range refused {
		payload, err := json.Marshal(map[string]string{"debuglet_id": value, "executor_id": "executor"})
		if err != nil {
			t.Fatal(err)
		}
		request, err := http.NewRequest(http.MethodDelete, f.server.URL+"/debuglet", bytes.NewReader(payload))
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("Content-Type", "application/json")
		response, err := f.server.Client().Do(request)
		if err != nil {
			t.Fatal(err)
		}
		var envelope ErrorResponse
		_ = json.NewDecoder(response.Body).Decode(&envelope)
		response.Body.Close()
		if response.StatusCode != http.StatusBadRequest || envelope.Code != CodeInvalidRequest {
			t.Errorf("DELETE %q: %d %q, want 400 %q", value, response.StatusCode, envelope.Code, CodeInvalidRequest)
		}
	}
}
