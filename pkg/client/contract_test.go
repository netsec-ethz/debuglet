package client

import (
	"errors"
	"net/http"
	"reflect"
	"strings"
	"testing"
)

// The SDK announces the HTTP contract version it was written against on every
// request, and reads back the server's separate version identities. A server
// written before the contract was versioned keeps working.

func TestClientAnnouncesContractVersionOnEveryRequest(t *testing.T) {
	f := newFakeServer(t, "/api")
	f.defaults()
	routes := exerciseAll(t, f.client(t, Options{}), "/api")

	requests := f.requests()
	if len(requests) != len(routes) {
		t.Fatalf("recorded %d requests, want every call", len(requests))
	}
	for _, request := range requests {
		if got := request.Header.Get("Debuglet-API-Version"); got != APIVersion {
			t.Fatalf("%s %s announced %q, want %q", request.Method, request.Path, got, APIVersion)
		}
	}
}

func TestVersionReportsSeparateIdentities(t *testing.T) {
	f := newFakeServer(t, "")
	f.handle("GET /version", jsonHandler(http.StatusOK,
		`{"version":"cfg","api_version":"1.2","api_versions":["1"],"binary_version":"v0.3.1","binary_revision":"deadbeef","protocol_version":"3"}`))
	c := f.client(t, Options{})

	version, err := c.Version(testContext(t))
	if err != nil {
		t.Fatalf("Version: %v", err)
	}
	want := ServerVersion{Version: "cfg", APIVersion: APIVersion, APIVersions: []string{"1"},
		BinaryVersion: "v0.3.1", BinaryRevision: "deadbeef", ProtocolVersion: "3"}
	if !reflect.DeepEqual(version, want) {
		t.Fatalf("identities were not reported separately: %+v, want %+v", version, want)
	}
}

// A dispatcher written before the contract was versioned answers with the
// original body. It must keep working, with the new identities empty.
func TestVersionFromDispatcherWithoutContractVersioning(t *testing.T) {
	f := newFakeServer(t, "")
	f.handle("GET /version", jsonHandler(http.StatusOK, fixtureVersion))
	c := f.client(t, Options{})

	version, err := c.Version(testContext(t))
	if err != nil {
		t.Fatalf("Version: %v", err)
	}
	if !reflect.DeepEqual(version, ServerVersion{Version: "fixture"}) {
		t.Fatalf("an older dispatcher reported more than its configured string: %+v", version)
	}
}

// A dispatcher that cannot serve the announced contract answers with an
// ordinary typed HTTP error, so the caller sees a rejection rather than a
// decoded body from a contract it does not speak.
func TestIncompatibleContractVersionIsATypedHTTPError(t *testing.T) {
	f := newFakeServer(t, "")
	f.handle("GET /executors", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Debuglet-API-Version") != "9.0" {
			jsonHandler(http.StatusBadRequest,
				`{"message":"unsupported Debuglet-API-Version request header; this dispatcher implements 9.0"}`)(w, r)
			return
		}
		jsonHandler(http.StatusOK, fixtureNodes)(w, r)
	})
	c := f.client(t, Options{})

	_, err := c.Nodes(testContext(t))
	var httpErr *HTTPError
	if !errors.As(err, &httpErr) {
		t.Fatalf("error = %T %v, want *HTTPError", err, err)
	}
	if httpErr.StatusCode != http.StatusBadRequest || httpErr.Path != "/executors" {
		t.Fatalf("unexpected rejection: %+v", httpErr)
	}
	if httpErr.Message == "" {
		t.Fatal("the incompatibility carries no diagnostic")
	}
}

// Failures expose the dispatcher's stable code, so a caller never has to match
// on the human-readable message. A server that sends no documented envelope,
// or a code that is not a bounded identifier, leaves Code empty rather than
// letting response text reach the caller through it.

func TestHTTPErrorExposesTheDocumentedCode(t *testing.T) {
	cases := []struct {
		name    string
		status  int
		body    string
		code    string
		message string
	}{
		{"documented envelope", http.StatusConflict, `{"code":"capacity_exhausted","message":"capacity exceeded"}`, CodeCapacityExhausted, "capacity exceeded"},
		{"envelope without a code", http.StatusNotFound, `{"message":"debuglet not found"}`, "", "debuglet not found"},
		{"code without a message", http.StatusNotFound, `{"code":"not_found"}`, CodeNotFound, omittedResponseDiagnostic},
		{"untyped json string", http.StatusBadRequest, `"unknown payment method: EUR"`, "", "unknown payment method: EUR"},
		{"code that is not an identifier", http.StatusBadRequest, `{"code":"Not A Code!","message":"x"}`, "", "x"},
		{"code that is not a string", http.StatusBadRequest, `{"code":42,"message":"x"}`, "", "x"},
		{"oversized code", http.StatusBadRequest, `{"code":"` + strings.Repeat("a", 65) + `","message":"x"}`, "", "x"},
		{"plain text body", http.StatusBadGateway, `gateway said no`, "", "gateway said no"},
		{"payload too large", http.StatusRequestEntityTooLarge, `{"code":"payload_too_large","message":"request body exceeds 33554432 bytes"}`, CodePayloadTooLarge, "request body exceeds 33554432 bytes"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeServer(t, "")
			f.handle("GET /executors", jsonHandler(tc.status, tc.body))
			c := f.client(t, Options{})

			_, err := c.Nodes(testContext(t))
			var httpErr *HTTPError
			if !errors.As(err, &httpErr) {
				t.Fatalf("error = %T %v, want *HTTPError", err, err)
			}
			if httpErr.StatusCode != tc.status {
				t.Fatalf("status = %d, want %d", httpErr.StatusCode, tc.status)
			}
			if httpErr.Code != tc.code {
				t.Fatalf("code = %q, want %q", httpErr.Code, tc.code)
			}
			if httpErr.Message != tc.message {
				t.Fatalf("message = %q, want %q", httpErr.Message, tc.message)
			}
			if tc.code != "" && !strings.Contains(httpErr.Error(), tc.code) {
				t.Fatalf("the formatted error hides the code: %s", httpErr.Error())
			}
		})
	}
}

// The code is available on a failed submission without disturbing the
// rejection versus uncertain-outcome classification.
func TestSubmissionErrorExposesCodesAndKeepsUncertainty(t *testing.T) {
	batch := func(t *testing.T) *PreparedBatch {
		t.Helper()
		prepared, err := Prepare([]Request{{OrderID: 1, ExecutorID: fixtureExecutor, Wasm: []byte("\x00asm"), Policy: Policy{TimeoutMS: 1000}}})
		if err != nil {
			t.Fatalf("Prepare: %v", err)
		}
		return prepared
	}

	cases := []struct {
		name    string
		install func(f *fakeServer)
		stage   string
		code    string
		unknown bool
		knownTx bool
	}{
		{
			name: "rejected intent",
			install: func(f *fakeServer) {
				f.handle("PUT /payment/intent", jsonHandler(http.StatusBadRequest, `{"code":"invalid_policy","message":"invalid policy"}`))
			},
			stage: "intent", code: CodeInvalidPolicy, unknown: false, knownTx: false,
		},
		{
			name: "rejected submission",
			install: func(f *fakeServer) {
				f.handle("PUT /payment/intent", intentHandler(fixtureTx, ""))
				f.handle("PUT /debuglet", jsonHandler(http.StatusConflict, `{"code":"capacity_exhausted","message":"capacity exceeded"}`))
			},
			stage: "submit", code: CodeCapacityExhausted, unknown: false, knownTx: true,
		},
		{
			name: "submission with an unknown outcome",
			install: func(f *fakeServer) {
				f.handle("PUT /payment/intent", intentHandler(fixtureTx, ""))
				f.handle("PUT /debuglet", jsonHandler(http.StatusInternalServerError, `{"code":"internal_error","message":"failed to initialize debuglets"}`))
			},
			stage: "submit", code: CodeInternal, unknown: true, knownTx: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeServer(t, "")
			tc.install(f)
			c := f.client(t, Options{})

			_, err := c.SubmitTEST(testContext(t), batch(t))
			var submissionErr *SubmissionError
			if !errors.As(err, &submissionErr) {
				t.Fatalf("error = %T %v, want *SubmissionError", err, err)
			}
			if submissionErr.Stage != tc.stage || submissionErr.OutcomeUnknown != tc.unknown {
				t.Fatalf("stage %q unknown %t, want %q and %t", submissionErr.Stage, submissionErr.OutcomeUnknown, tc.stage, tc.unknown)
			}
			if (submissionErr.TransactionID != "") != tc.knownTx {
				t.Fatalf("transaction id %q, known = %t", submissionErr.TransactionID, tc.knownTx)
			}
			if submissionErr.Code() != tc.code {
				t.Fatalf("code = %q, want %q", submissionErr.Code(), tc.code)
			}
		})
	}
}

// A code is never a channel for response text: one that carries the submission
// key is redacted and then dropped, like any other value that is not a bounded
// identifier.
func TestErrorCodeNeverCarriesTheSubmissionKey(t *testing.T) {
	const key = "dummykeyvalue"
	f := newFakeServer(t, "")
	f.handle("PUT /payment/intent", intentHandler(fixtureTx, key))
	f.handle("PUT /debuglet", jsonHandler(http.StatusBadRequest, `{"code":"`+key+`","message":"rejected with `+key+`"}`))
	c := f.client(t, Options{})

	prepared, err := Prepare([]Request{{OrderID: 1, ExecutorID: fixtureExecutor, Wasm: []byte("\x00asm"), Policy: Policy{TimeoutMS: 1000}}})
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	_, err = c.SubmitTEST(testContext(t), prepared)
	var httpErr *HTTPError
	if !errors.As(err, &httpErr) {
		t.Fatalf("error = %T %v, want *HTTPError", err, err)
	}
	if httpErr.Code != "" {
		t.Fatalf("code = %q, want it dropped", httpErr.Code)
	}
	if strings.Contains(err.Error(), key) {
		t.Fatalf("the submission key survived in %q", err.Error())
	}
}
