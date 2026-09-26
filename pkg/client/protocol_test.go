package client

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"reflect"
	"strings"
	"testing"
)

// Keep the expected diagnostic independent of production helpers so these
// regressions also compile when exercising the previous implementation.
const omittedResponseDiagnostic = "response body omitted"

func TestClientProtocol(t *testing.T) {
	t.Run("SubmitTEST happy path", func(t *testing.T) {
		f := newFakeServer(t, "/api")
		f.defaults()
		f.handle("PUT /debuglet", jsonHandler(http.StatusOK, `["A94C47E1-E09E-4EF2-A00F-E4DB0EB4CDB0"]`))
		c := f.client(t, Options{})
		sub, err := c.SubmitTEST(testContext(t), sampleBatch(t))
		if err != nil {
			t.Fatalf("SubmitTEST: %v", err)
		}
		if sub.TransactionID != fixtureTx || len(sub.IDs) != 1 || sub.IDs[0] != "A94C47E1-E09E-4EF2-A00F-E4DB0EB4CDB0" {
			t.Fatalf("submission %+v", sub)
		}
		reqs := f.requests()
		if len(reqs) != 2 {
			t.Fatalf("%d requests", len(reqs))
		}
		wantIntent := `{"debuglets":` + sampleDebuglets + `,"payment_method":"TEST","refund_address":""}`
		wantSubmit := `{"debuglets":` + sampleDebuglets + `,"transaction_id":"` + fixtureTx + `","auth_key":""}`
		if reqs[0].Method != "PUT" || reqs[0].Path != "/api/payment/intent" || string(reqs[0].Body) != wantIntent {
			t.Fatalf("intent request %s %s %s", reqs[0].Method, reqs[0].Path, reqs[0].Body)
		}
		if reqs[1].Method != "PUT" || reqs[1].Path != "/api/debuglet" || string(reqs[1].Body) != wantSubmit {
			t.Fatalf("submit request %s %s %s", reqs[1].Method, reqs[1].Path, reqs[1].Body)
		}
	})

	t.Run("intent failures", func(t *testing.T) {
		f := newFakeServer(t, "/api")
		f.defaults()
		c := f.client(t, Options{})
		cases := []struct {
			name    string
			handler http.HandlerFunc
			unknown bool
			status  int
			text    string
		}{
			{"wrong method", jsonHandler(http.StatusOK, `{"method":"USDC","intent":{"transaction_id":"tx","auth_key":""}}`), true, 0, "not TEST"},
			{"empty transaction id", jsonHandler(http.StatusOK, `{"method":"TEST","intent":{"transaction_id":"","auth_key":"k"}}`), true, 0, "missing transaction_id"},
			{"blank transaction id", jsonHandler(http.StatusOK, `{"method":"TEST","intent":{"transaction_id":"  ","auth_key":""}}`), true, 0, "missing transaction_id"},
			{"null intent", jsonHandler(http.StatusOK, `{"method":"TEST","intent":null}`), true, 0, "missing transaction_id"},
			{"malformed", jsonHandler(http.StatusOK, `{"method":"TEST"`), true, 0, "malformed JSON"},
			{"trailing", jsonHandler(http.StatusOK, `{"method":"TEST","intent":{"transaction_id":"tx","auth_key":""}} {}`), true, 0, "trailing data"},
			{"400 json string", jsonHandler(http.StatusBadRequest, `"unknown payment method: UNKNOWN"`), false, 400, "unknown payment method: UNKNOWN"},
			{"404", jsonHandler(http.StatusNotFound, `{"message":"Not Found"}`), false, 404, "Not Found"},
			{"503", jsonHandler(http.StatusServiceUnavailable, `{"message":"blockchain payments are disabled"}`), true, 503, "blockchain payments are disabled"},
			{"503 service_unavailable", jsonHandler(http.StatusServiceUnavailable, `{"code":"service_unavailable","message":"dispatcher is in maintenance"}`), false, 503, "dispatcher is in maintenance"},
			{"503 payments_disabled", jsonHandler(http.StatusServiceUnavailable, `{"code":"payments_disabled","message":"blockchain payments are disabled"}`), false, 503, "blockchain payments are disabled"},
			{"500 service_unavailable", jsonHandler(http.StatusInternalServerError, `{"code":"service_unavailable","message":"unavailable"}`), true, 500, "unavailable"},
			{"500", jsonHandler(http.StatusInternalServerError, `"failed to generate id"`), true, 500, "failed to generate id"},
			{"502 text", textHandler(http.StatusBadGateway, "upstream unavailable"), true, 502, "upstream unavailable"},
			{"201 other 2xx", jsonHandler(http.StatusCreated, `{"method":"TEST","intent":{"transaction_id":"tx","auth_key":""}}`), false, 201, omittedResponseDiagnostic},
			{"connection dropped", hijackClose, false, 0, ""},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				f.reset()
				f.handle("PUT /payment/intent", tc.handler)
				_, err := c.SubmitTEST(testContext(t), sampleBatch(t))
				se := asSubmissionError(t, err)
				if se.Stage != "intent" || se.TransactionID != "" || se.OutcomeUnknown != tc.unknown {
					t.Fatalf("%+v", se)
				}
				if tc.status != 0 {
					he := asHTTPError(t, err)
					if he.StatusCode != tc.status || he.Message != tc.text || he.Path != "/api/payment/intent" || he.Method != "PUT" {
						t.Fatalf("%+v", he)
					}
				} else if tc.text != "" && !strings.Contains(err.Error(), tc.text) {
					t.Fatalf("error %q does not mention %q", err, tc.text)
				}
				if f.count("PUT", "/api/payment/intent") != 1 || f.count("PUT", "/api/debuglet") != 0 {
					t.Fatalf("requests: %+v", f.requests())
				}
			})
		}
	})

	t.Run("submit failures retain the transaction id and never retry", func(t *testing.T) {
		f := newFakeServer(t, "/api")
		f.defaults()
		f.handle("PUT /payment/intent", intentHandler(fixtureTx, "secret-key"))
		c := f.client(t, Options{})
		two := []Request{sampleRequests()[0], sampleRequests()[0]}
		two[1].OrderID = 1
		twoBatch, err := Prepare(two)
		if err != nil {
			t.Fatal(err)
		}
		cases := []struct {
			name    string
			batch   *PreparedBatch
			handler http.HandlerFunc
			unknown bool
			status  int
			text    string
		}{
			{"400 hash mismatch", sampleBatch(t), jsonHandler(http.StatusBadRequest, `{"message":"Request does not match the intent"}`), false, 400, "Request does not match the intent"},
			{"401", sampleBatch(t), jsonHandler(http.StatusUnauthorized, `{"message":"Invalid auth key"}`), false, 401, "Invalid auth key"},
			{"409", sampleBatch(t), jsonHandler(http.StatusConflict, `{"message":"capacity exceeded"}`), false, 409, "capacity exceeded"},
			{"500", sampleBatch(t), jsonHandler(http.StatusInternalServerError, `{"message":"failed to initialize debuglets"}`), true, 500, "failed to initialize debuglets"},
			{"503", sampleBatch(t), textHandler(http.StatusServiceUnavailable, "down"), true, 503, "down"},
			{"503 service_unavailable", sampleBatch(t), jsonHandler(http.StatusServiceUnavailable, `{"code":"service_unavailable","message":"dispatcher is in maintenance"}`), true, 503, "dispatcher is in maintenance"},
			{"503 payments_disabled", sampleBatch(t), jsonHandler(http.StatusServiceUnavailable, `{"code":"payments_disabled","message":"blockchain payments are disabled"}`), true, 503, "blockchain payments are disabled"},
			{"201 other 2xx", sampleBatch(t), jsonHandler(http.StatusCreated, `["`+fixtureID+`"]`), true, 201, omittedResponseDiagnostic},
			{"202 other 2xx", sampleBatch(t), jsonHandler(http.StatusAccepted, `{"message":"queued"}`), true, 202, "queued"},
			{"204 other 2xx", sampleBatch(t), textHandler(http.StatusNoContent, ""), true, 204, ""},
			{"299 other 2xx", sampleBatch(t), textHandler(299, "accepted"), true, 299, "accepted"},
			{"connection dropped after send", sampleBatch(t), hijackClose, true, 0, ""},
			{"malformed success", sampleBatch(t), jsonHandler(http.StatusOK, `["`+fixtureID+`"`), true, 0, "malformed JSON"},
			{"trailing success", sampleBatch(t), jsonHandler(http.StatusOK, `["`+fixtureID+`"] []`), true, 0, "trailing data"},
			{"empty success", sampleBatch(t), jsonHandler(http.StatusOK, ``), true, 0, "empty body"},
			{"null ids", sampleBatch(t), jsonHandler(http.StatusOK, `null`), true, 0, "returned 0 ids for 1"},
			{"too many ids", sampleBatch(t), jsonHandler(http.StatusOK, `["`+fixtureID+`","00000001-0000-4000-8000-000000000001"]`), true, 0, "returned 2 ids for 1"},
			{"too few ids", twoBatch, jsonHandler(http.StatusOK, `["`+fixtureID+`"]`), true, 0, "returned 1 ids for 2"},
			{"not a uuid", sampleBatch(t), jsonHandler(http.StatusOK, `["not-a-uuid"]`), true, 0, "not a canonical UUID"},
			{"unhyphenated uuid", sampleBatch(t), jsonHandler(http.StatusOK, `["`+strings.ReplaceAll(fixtureID, "-", "")+`"]`), true, 0, "not a canonical UUID"},
			{"nil uuid", sampleBatch(t), jsonHandler(http.StatusOK, `["00000000-0000-0000-0000-000000000000"]`), true, 0, "nil UUID"},
			{"non-string id", sampleBatch(t), jsonHandler(http.StatusOK, `[7]`), true, 0, "malformed JSON"},
			{"duplicate ids differing in case", twoBatch, jsonHandler(http.StatusOK, `["`+fixtureID+`","`+strings.ToUpper(fixtureID)+`"]`), true, 0, "duplicates"},
			{"oversized success", sampleBatch(t), jsonHandler(http.StatusOK, `["`+strings.Repeat("a", maxSuccessBody)+`"]`), true, 0, "exceeds 4 MiB"},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				f.reset()
				f.handle("PUT /debuglet", tc.handler)
				_, err := c.SubmitTEST(testContext(t), tc.batch)
				se := asSubmissionError(t, err)
				if se.Stage != "submit" || se.TransactionID != fixtureTx || se.OutcomeUnknown != tc.unknown {
					t.Fatalf("%+v", se)
				}
				if tc.status != 0 {
					he := asHTTPError(t, err)
					if he.StatusCode != tc.status || he.Message != tc.text || he.Path != "/api/debuglet" || he.Method != "PUT" {
						t.Fatalf("%+v", he)
					}
				} else if tc.text != "" && !strings.Contains(err.Error(), tc.text) {
					t.Fatalf("error %q does not mention %q", err, tc.text)
				}
				if strings.Contains(err.Error(), "secret-key") || strings.Contains(err.Error(), "AQID") {
					t.Fatalf("error leaks auth key or wasm: %v", err)
				}
				if f.count("PUT", "/api/payment/intent") != 1 || f.count("PUT", "/api/debuglet") != 1 {
					t.Fatalf("requests: %+v", f.requests())
				}
				// The stage/outcome are visible in the message.
				if tc.unknown && !strings.Contains(err.Error(), "outcome unknown") {
					t.Fatalf("message %q", err)
				}
				if !tc.unknown && !strings.Contains(err.Error(), "rejected") {
					t.Fatalf("message %q", err)
				}
			})
		}
	})

	t.Run("submission diagnostics redact credentials", func(t *testing.T) {
		const secret = "dummy-auth-key-DO-NOT-PRINT"
		cases := []struct {
			name    string
			stage   string
			status  int
			body    string
			unknown bool
			want    string
		}{
			{"unexpected intent envelope", "intent", 201, `{"method":"TEST","intent":{"transaction_id":"tx","auth_key":"` + secret + `"}}`, false, omittedResponseDiagnostic},
			{"nested Echo message", "intent", 503, `{"message":{"code":1,"details":[{"auth_key":"` + secret + `","reason":"denied ` + secret + `"}]} }`, true, `{"code":1,"details":[{"reason":"denied [redacted]"}]}`},
			{"sibling credential", "intent", 400, `{"message":"denied ` + secret + `","intent":{"auth_key":"` + secret + `"}}`, false, "denied [redacted]"},
			{"duplicate credential fields", "intent", 400, `{"auth_key":"` + secret + `","auth_key":"second-dummy-key","message":"denied ` + secret + ` and second-dummy-key"}`, false, "denied [redacted] and [redacted]"},
			{"escaped field name", "intent", 400, `{"message":{"auth\u005fkey":"` + secret + `","reason":"denied"}}`, false, `{"reason":"denied"}`},
			{"case insensitive field name", "intent", 400, `{"message":{"AUTH_KEY":"` + secret + `","reason":"denied"}}`, false, `{"reason":"denied"}`},
			{"known key plain text", "submit", 401, "invalid " + secret, false, "invalid [redacted]"},
			{"known key JSON string", "submit", 503, `"failed with ` + secret + `"`, true, "failed with [redacted]"},
			{"known key Echo message", "submit", 201, `{"message":"accepted ` + secret + `"}`, true, "accepted [redacted]"},
			{"known key nested Echo message", "submit", 202, `{"message":{"details":["accepted ` + secret + `"]}}`, true, `{"details":["accepted [redacted]"]}`},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				f := newFakeServer(t, "/api")
				f.defaults()
				f.handle("PUT /payment/intent", intentHandler(fixtureTx, secret))
				route := "PUT /payment/intent"
				wantTx, submitAttempts := "", 0
				if tc.stage == "submit" {
					route, wantTx, submitAttempts = "PUT /debuglet", fixtureTx, 1
				}
				f.handle(route, jsonHandler(tc.status, tc.body))
				hc, counting := newCountingClient(t)
				c := f.client(t, Options{HTTPClient: hc})
				_, err := c.SubmitTEST(testContext(t), sampleBatch(t))
				se, he := asSubmissionError(t, err), asHTTPError(t, err)
				if se.Stage != tc.stage || se.TransactionID != wantTx || se.OutcomeUnknown != tc.unknown || he.StatusCode != tc.status || he.Message != tc.want {
					t.Fatalf("unexpected sanitized failure: %+v; HTTP message %q", se, he.Message)
				}
				for _, diagnostic := range []string{he.Message, he.Error(), se.Error(), se.Err.Error()} {
					if strings.Contains(diagnostic, secret) || strings.Contains(diagnostic, "auth_key") {
						t.Fatal("credential exposed in a public diagnostic")
					}
				}
				if !errors.Is(err, he) {
					t.Fatal("sanitization broke the HTTP error chain")
				}
				if f.count("PUT", "/api/payment/intent") != 1 || f.count("PUT", "/api/debuglet") != submitAttempts {
					t.Fatal("incorrect intent or submit attempt count")
				}
				if counting.open.Load() != 0 || int(counting.total.Load()) != 1+submitAttempts {
					t.Fatal("response bodies were not all observed and closed")
				}
			})
		}

		t.Run("escaped known key in structured message", func(t *testing.T) {
			const key = "dummy-\"key\"\n<&>"
			f := newFakeServer(t, "")
			f.defaults()
			f.handle("PUT /payment/intent", intentHandler(fixtureTx, key))
			body, err := json.Marshal(map[string]any{"message": map[string]string{"reason": "denied " + key}})
			if err != nil {
				t.Fatal(err)
			}
			f.handle("PUT /debuglet", jsonHandler(http.StatusUnauthorized, string(body)))
			_, err = f.client(t, Options{}).SubmitTEST(testContext(t), sampleBatch(t))
			he := asHTTPError(t, err)
			if he.Message != `{"reason":"denied [redacted]"}` || strings.Contains(err.Error(), "dummy-") {
				t.Fatal("escaped credential exposed in a diagnostic")
			}
		})

		t.Run("decoded wrong method equals auth key", func(t *testing.T) {
			f := newFakeServer(t, "/api")
			f.defaults()
			f.handle("PUT /payment/intent", jsonHandler(http.StatusOK, `{"method":"`+secret+`","intent":{"transaction_id":"tx","auth_key":"`+secret+`"}}`))
			hc, counting := newCountingClient(t)
			_, err := f.client(t, Options{HTTPClient: hc}).SubmitTEST(testContext(t), sampleBatch(t))
			se, pe := asSubmissionError(t, err), asProtocolError(t, err)
			if se.Stage != "intent" || se.TransactionID != "" || !se.OutcomeUnknown || !strings.Contains(err.Error(), "not TEST") {
				t.Fatalf("wrong-method failure: %v", err)
			}
			if strings.Contains(err.Error(), secret) || strings.Contains(pe.Error(), secret) {
				t.Fatal("decoded intent credential exposed")
			}
			if f.count("PUT", "/api/payment/intent") != 1 || f.count("PUT", "/api/debuglet") != 0 || counting.open.Load() != 0 || counting.total.Load() != 1 {
				t.Fatal("wrong-method failure sent a submit or left its response open")
			}
		})
	})

	t.Run("Nodes", func(t *testing.T) {
		f := newFakeServer(t, "/api")
		c := f.client(t, Options{})
		ctx := testContext(t)
		f.handle("GET /executors", jsonHandler(http.StatusOK, `null`))
		nodes, err := c.Nodes(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if nodes == nil || len(nodes) != 0 {
			t.Fatalf("null nodes = %#v", nodes)
		}
		f.handle("GET /executors", jsonHandler(http.StatusOK, fixtureNodes))
		nodes, err = c.Nodes(ctx)
		if err != nil {
			t.Fatal(err)
		}
		want := Node{ID: fixtureExecutor, LastSeen: 1700000000, Version: "fixture", TeslaDelaySec: 5, TeslaAnchorTimestampNs: 1700000000000000000, TeslaAnchorKey: []byte{1, 2, 3, 4}, Currency: "TEST"}
		if !reflect.DeepEqual(nodes, []Node{want}) {
			t.Fatalf("nodes = %+v, want %+v", nodes, want)
		}
		f.handle("GET /executors", jsonHandler(http.StatusOK, `[{"id":"x","tesla_anchor_key":"!!!"}]`))
		if _, err := c.Nodes(ctx); err == nil {
			t.Fatalf("invalid base64 accepted")
		}
		f.handle("GET /executors", jsonHandler(http.StatusOK, `{}`))
		if _, err := c.Nodes(ctx); err == nil {
			t.Fatalf("object accepted as node array")
		}
	})

	t.Run("Status", func(t *testing.T) {
		f := newFakeServer(t, "/api")
		c := f.client(t, Options{})
		ctx := testContext(t)
		f.handle("GET /debuglet/{id}/state", jsonHandler(http.StatusOK, `{"state":"RunStateSomethingNew","error":"","executor_id":"exec-1","extra":true}`))
		state, err := c.Status(ctx, fixtureID)
		if err != nil {
			t.Fatal(err)
		}
		if state.State != "RunStateSomethingNew" || state.Error != "" || state.ExecutorID != "exec-1" {
			t.Fatalf("state = %+v", state)
		}
		f.handle("GET /debuglet/{id}/state", jsonHandler(http.StatusOK, fixtureState))
		state, err = c.Status(ctx, fixtureID)
		if err != nil || state.State != StateExited || state.Error != "debuglet exited with code 7" {
			t.Fatalf("state = %+v, %v", state, err)
		}
		for _, body := range []string{`{"state":"","executor_id":"e"}`, `{"state":"  ","executor_id":"e"}`, `{"executor_id":"e"}`, `{"state":"RunStateExited","executor_id":""}`, `{"state":"RunStateExited"}`, `null`, `{}`} {
			f.handle("GET /debuglet/{id}/state", jsonHandler(http.StatusOK, body))
			if _, err := c.Status(ctx, fixtureID); err == nil {
				t.Errorf("body %q accepted", body)
			} else {
				asProtocolError(t, err)
			}
		}
		f.handle("GET /debuglet/{id}/state", jsonHandler(http.StatusNotFound, `{"message":"debuglet not found"}`))
		_, err = c.Status(ctx, fixtureID)
		he := asHTTPError(t, err)
		if he.StatusCode != 404 || he.Message != "debuglet not found" || he.Path != "/api/debuglet/"+fixtureID+"/state" {
			t.Fatalf("%+v", he)
		}
	})

	t.Run("Logs", func(t *testing.T) {
		f := newFakeServer(t, "/api")
		f.defaults()
		c := f.client(t, Options{})
		ctx := testContext(t)
		page, err := c.Logs(ctx, fixtureID, LogOptions{After: 0, Limit: 1})
		if err != nil {
			t.Fatal(err)
		}
		if page.State != StateExited || page.After != 7 || !page.HasMore || page.Error != "debuglet exited with code 7" || len(page.Logs) != 1 {
			t.Fatalf("page = %+v", page)
		}
		if e := page.Logs[0]; e.ID != 7 || e.Timestamp != "2026-09-08T12:00:00Z" || !bytes.Equal(e.Output, []byte{0x00, 0xff, 0x0a}) {
			t.Fatalf("entry = %+v", e)
		}
		next, err := c.Logs(ctx, fixtureID, LogOptions{After: page.After, Limit: 1})
		if err != nil {
			t.Fatal(err)
		}
		if next.Logs == nil || len(next.Logs) != 0 || next.After != 7 || next.HasMore {
			t.Fatalf("next = %+v", next)
		}
		reqs := f.requests()
		if reqs[0].Query != "after=0&limit=1" || reqs[1].Query != "after=7&limit=1" {
			t.Fatalf("queries %q %q", reqs[0].Query, reqs[1].Query)
		}
		f.reset()
		if _, err := c.Logs(ctx, fixtureID, LogOptions{After: 7}); err != nil {
			t.Fatal(err)
		}
		if _, err := c.Logs(ctx, fixtureID, LogOptions{After: 7, Limit: 1000}); err != nil {
			t.Fatal(err)
		}
		reqs = f.requests()
		if reqs[0].Query != "after=7&limit=100" || reqs[1].Query != "after=7&limit=1000" {
			t.Fatalf("queries %q %q", reqs[0].Query, reqs[1].Query)
		}
		f.reset()
		for _, opts := range []LogOptions{{After: -1}, {Limit: -1}, {Limit: 1001}, {After: -5, Limit: 5}} {
			if _, err := c.Logs(ctx, fixtureID, opts); err == nil {
				t.Errorf("options %+v accepted", opts)
			}
		}
		if n := len(f.requests()); n != 0 {
			t.Fatalf("%d requests for invalid options", n)
		}
		multi := `{"state":"RunStateRunning","after":9,"logs":[{"id":8,"timestamp":"a","output":"AA=="},{"id":9,"timestamp":"b","output":""}],"has_more":true}`
		f.handle("GET /debuglet/{id}/logs", jsonHandler(http.StatusOK, multi))
		page, err = c.Logs(ctx, fixtureID, LogOptions{After: 7, Limit: 2})
		if err != nil || len(page.Logs) != 2 || page.After != 9 || !bytes.Equal(page.Logs[0].Output, []byte{0}) || len(page.Logs[1].Output) != 0 {
			t.Fatalf("multi page %+v %v", page, err)
		}
		bad := map[string]struct {
			after int64
			body  string
		}{
			"backward ids":                 {7, `{"state":"s","after":8,"logs":[{"id":9,"timestamp":"a","output":""},{"id":8,"timestamp":"b","output":""}],"has_more":false}`},
			"repeated id":                  {7, `{"state":"s","after":8,"logs":[{"id":8,"timestamp":"a","output":""},{"id":8,"timestamp":"b","output":""}],"has_more":false}`},
			"id not above cursor":          {7, `{"state":"s","after":7,"logs":[{"id":7,"timestamp":"a","output":""}],"has_more":false}`},
			"id below cursor":              {7, `{"state":"s","after":3,"logs":[{"id":3,"timestamp":"a","output":""}],"has_more":false}`},
			"wrong after on nonempty page": {7, `{"state":"s","after":9,"logs":[{"id":8,"timestamp":"a","output":""}],"has_more":false}`},
			"wrong after on empty page":    {7, `{"state":"s","after":8,"logs":[],"has_more":false}`},
			"wrong after on null page":     {7, `{"state":"s","after":0,"logs":null,"has_more":false}`},
			"empty page has_more":          {7, `{"state":"s","after":7,"logs":[],"has_more":true}`},
			"invalid base64":               {7, `{"state":"s","after":8,"logs":[{"id":8,"timestamp":"a","output":"!!!"}],"has_more":false}`},
			"blank state":                  {7, `{"state":" ","after":7,"logs":[],"has_more":false}`},
			"missing state":                {7, `{"after":7,"logs":[],"has_more":false}`},
			"trailing json":                {7, `{"state":"s","after":7,"logs":[],"has_more":false} {}`},
			"null page":                    {7, `null`},
		}
		for name, tc := range bad {
			f.handle("GET /debuglet/{id}/logs", jsonHandler(http.StatusOK, tc.body))
			_, err := c.Logs(ctx, fixtureID, LogOptions{After: tc.after, Limit: 10})
			if err == nil {
				t.Errorf("%s: accepted", name)
				continue
			}
			asProtocolError(t, err)
		}
	})

	t.Run("Cancel", func(t *testing.T) {
		f := newFakeServer(t, "/api")
		f.defaults()
		c := f.client(t, Options{})
		ctx := testContext(t)
		if err := c.Cancel(ctx, fixtureID, fixtureExecutor); err != nil {
			t.Fatal(err)
		}
		reqs := f.requests()
		want := `{"debuglet_id":"` + fixtureID + `","executor_id":"` + fixtureExecutor + `"}`
		if len(reqs) != 1 || reqs[0].Method != "DELETE" || reqs[0].Path != "/api/debuglet" || string(reqs[0].Body) != want {
			t.Fatalf("cancel request %+v", reqs)
		}
		if reqs[0].Header.Get("Content-Type") != "application/json" {
			t.Fatalf("Content-Type %q", reqs[0].Header.Get("Content-Type"))
		}
		f.handle("DELETE /debuglet", jsonHandler(http.StatusOK, `{}`))
		err := c.Cancel(ctx, fixtureID, fixtureExecutor)
		he := asHTTPError(t, err)
		if he.StatusCode != http.StatusOK || he.Method != "DELETE" || he.Path != "/api/debuglet" {
			t.Fatalf("200 on cancel: %+v", he)
		}
		f.handle("DELETE /debuglet", jsonHandler(http.StatusBadRequest, `{"message":"debuglet does not exist"}`))
		err = c.Cancel(ctx, fixtureID, fixtureExecutor)
		he = asHTTPError(t, err)
		if he.StatusCode != http.StatusBadRequest || he.Message != "debuglet does not exist" {
			t.Fatalf("400 on cancel: %+v", he)
		}
		f.handle("DELETE /debuglet", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusAccepted) })
		if err := c.Cancel(ctx, fixtureID, fixtureExecutor); asHTTPError(t, err).StatusCode != http.StatusAccepted {
			t.Fatalf("202 on cancel: %v", err)
		}
	})

	t.Run("Version", func(t *testing.T) {
		f := newFakeServer(t, "")
		f.defaults()
		c := f.client(t, Options{})
		v, err := c.Version(testContext(t))
		if err != nil || v.Version != "fixture" {
			t.Fatalf("%+v %v", v, err)
		}
		if got := f.requests()[0]; got.Method != "GET" || got.Path != "/version" || got.Header.Get("Accept") != "application/json" || got.Header.Get("Content-Type") != "" {
			t.Fatalf("version request %+v", got)
		}
	})

	t.Run("HTTPError message extraction", func(t *testing.T) {
		f := newFakeServer(t, "/api")
		c := f.client(t, Options{})
		ctx := testContext(t)
		cases := []struct {
			name    string
			handler http.HandlerFunc
			status  int
			message string
		}{
			{"echo object", jsonHandler(http.StatusNotFound, `{"message":"debuglet not found"}`), 404, "debuglet not found"},
			{"echo object with non-string message", jsonHandler(http.StatusBadRequest, `{"message":{"code":1}}`), 400, `{"code":1}`},
			{"json string", jsonHandler(http.StatusBadRequest, `"unknown payment method: UNKNOWN"`), 400, "unknown payment method: UNKNOWN"},
			{"plain text", textHandler(http.StatusBadGateway, "upstream unavailable\n"), 502, "upstream unavailable"},
			{"html-ish text", textHandler(http.StatusServiceUnavailable, "<html>down</html>"), 503, "<html>down</html>"},
			{"object without message", jsonHandler(http.StatusInternalServerError, `{"error":"x"}`), 500, omittedResponseDiagnostic},
			{"array", jsonHandler(http.StatusBadRequest, `[{"auth_key":"array-dummy-secret"}]`), 400, omittedResponseDiagnostic},
			{"malformed object", jsonHandler(http.StatusBadRequest, `{"auth_key":"malformed-dummy-secret"`), 400, omittedResponseDiagnostic},
			{"malformed array", jsonHandler(http.StatusBadRequest, `["malformed-dummy-secret"`), 400, omittedResponseDiagnostic},
			{"malformed JSON string", jsonHandler(http.StatusBadRequest, `"malformed-dummy-secret`), 400, omittedResponseDiagnostic},
			{"trailing JSON", jsonHandler(http.StatusBadRequest, `{"message":"safe"} {"auth_key":"trailing-dummy-secret"}`), 400, omittedResponseDiagnostic},
			{"echo array message", jsonHandler(http.StatusBadRequest, `{"message":[{"code":1},"denied"]}`), 400, `[{"code":1},"denied"]`},
			{"echo number message", jsonHandler(http.StatusBadRequest, `{"message":9007199254740993}`), 400, "9007199254740993"},
			{"echo null message", jsonHandler(http.StatusBadRequest, `{"message":null}`), 400, "null"},
			{"empty body", textHandler(http.StatusTeapot, ""), 418, ""},
			{"invalid utf8", textHandler(http.StatusBadRequest, "bad\xffbyte"), 400, "bad�byte"},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				f.handle("GET /version", tc.handler)
				_, err := c.Version(ctx)
				he := asHTTPError(t, err)
				if he.StatusCode != tc.status || he.Message != tc.message || he.Method != "GET" || he.Path != "/api/version" {
					t.Fatalf("%+v", he)
				}
				if !errors.Is(err, he) {
					t.Fatalf("errors.Is failed")
				}
			})
		}
		f.handle("GET /version", textHandler(http.StatusTeapot, ""))
		_, err := c.Version(ctx)
		if err.Error() != "GET /api/version: unexpected status 418" {
			t.Fatalf("Error() = %q", err.Error())
		}
	})
}
