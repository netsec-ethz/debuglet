package api

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	apispec "github.com/netsec-ethz/debuglet/api"
	"github.com/netsec-ethz/debuglet/internal/controlsession"
	"github.com/netsec-ethz/debuglet/pkg/client"
	pb "github.com/netsec-ethz/debuglet/protocol"

	"github.com/labstack/echo/v4"
	"go.uber.org/zap"
)

// The contract document is the published wire description of this API. These
// tests read the tracked file, check that it describes exactly the routes the
// dispatcher registers, and validate real handler responses and real SDK
// requests against it, at the root and behind the /api prefix.

const oaDocumentPath = "../../../../api/openapi.yaml"

// oaContract loads the tracked document and proves the binary embeds it
// unchanged, so a served contract is the contract of the running build.
func oaContract(t *testing.T) *contract {
	t.Helper()
	data, err := os.ReadFile(oaDocumentPath)
	if err != nil {
		t.Fatalf("read %s: %v", oaDocumentPath, err)
	}
	if !bytes.Equal(data, apispec.OpenAPI) {
		t.Fatalf("the embedded contract differs from %s", oaDocumentPath)
	}
	parsed, err := newContract(data)
	if err != nil {
		t.Fatalf("parse %s: %v", oaDocumentPath, err)
	}
	return parsed
}

func TestContractDocumentIdentifiesTheImplementedVersion(t *testing.T) {
	c := oaContract(t)
	info, ok := c.root["info"].(map[string]any)
	if !ok {
		t.Fatal("the contract has no info section")
	}
	if version, _ := info["version"].(string); version != apispec.Version {
		t.Fatalf("info.version = %q, want %q", version, apispec.Version)
	}
	if client.APIVersion != apispec.Version {
		t.Fatalf("the SDK announces contract version %q, the server implements %q", client.APIVersion, apispec.Version)
	}
	if openapi, _ := c.root["openapi"].(string); !strings.HasPrefix(openapi, "3.") {
		t.Fatalf("openapi = %q, want an OpenAPI 3 document", openapi)
	}
	// Both supported deployments are described, because a base path prefix is
	// part of what a client has to get right.
	servers, ok := c.root["servers"].([]any)
	if !ok {
		t.Fatal("the contract lists no servers")
	}
	var urls []string
	for _, entry := range servers {
		server, _ := entry.(map[string]any)
		value, _ := server["url"].(string)
		urls = append(urls, value)
	}
	sort.Strings(urls)
	if len(urls) != 2 || urls[0] != "/" || urls[1] != "/api" {
		t.Fatalf("documented servers = %v, want / and /api", urls)
	}
}

// TestContractCoversEveryRegisteredRoute compares the contract against the
// routes RegisterRoutes installs. That is the whole public surface except
// GET /connection, which cmd/dispatcher registers separately and only when it
// was started with local connection metadata; its registration is in package
// main and cannot be inspected from here, so the contract's description of it
// is not verified by this test.
func TestContractCoversEveryRegisteredRoute(t *testing.T) {
	c := oaContract(t)
	e := echo.New()
	NewHandler(nil, nil, zap.NewNop()).RegisterRoutes(e)

	documented := map[string]bool{}
	for _, operation := range c.operations() {
		documented[operation] = true
	}
	registered := map[string]bool{}
	for _, route := range e.Routes() {
		key := route.Method + " " + oaTemplate(route.Path)
		registered[key] = true
		if !documented[key] {
			t.Errorf("route %s is registered but not documented in %s", key, oaDocumentPath)
		}
	}
	for operation := range documented {
		// See the note above: this one is registered outside RegisterRoutes.
		if operation == "GET /connection" {
			continue
		}
		if !registered[operation] {
			t.Errorf("operation %s is documented but no route serves it", operation)
		}
	}
}

// oaTemplate converts an Echo route path to the contract's path template.
func oaTemplate(path string) string {
	segments := strings.Split(path, "/")
	for i, segment := range segments {
		if strings.HasPrefix(segment, ":") {
			segments[i] = "{" + segment[1:] + "}"
		}
	}
	return strings.Join(segments, "/")
}

func TestVersionEndpointDistinguishesAPIBinaryAndProtocol(t *testing.T) {
	c := oaContract(t)
	f := modeNewFixture(t)

	rec := oaServe(f.e, http.MethodGet, routeVersion, nil, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", rec.Code, rec.Body.String())
	}
	oaCheckResponse(t, c, http.MethodGet, routeVersion, rec.Code, rec.Body.Bytes())

	var response VersionResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode version response: %v", err)
	}
	if response.APIVersion != apispec.Version {
		t.Fatalf("api_version = %q, want %q", response.APIVersion, apispec.Version)
	}
	if len(response.APIVersions) != 1 || response.APIVersions[0] != "1" {
		t.Fatalf("api_versions = %v, want [1]", response.APIVersions)
	}
	// The configured dispatcher version is the binary identity of an unstamped
	// build and stays available under its original key.
	if response.Version != "test" || response.BinaryVersion != "test" {
		t.Fatalf("version = %q, binary_version = %q, want the configured string in both", response.Version, response.BinaryVersion)
	}
	if response.ProtocolVersion != "3" || response.ProtocolVersion == response.APIVersion {
		t.Fatalf("protocol_version = %q, want the control protocol version %d", response.ProtocolVersion, controlsession.ProtocolVersion)
	}
	if rec.Header().Get(apispec.VersionHeader) != apispec.Version {
		t.Fatalf("%s response header = %q, want %q", apispec.VersionHeader, rec.Header().Get(apispec.VersionHeader), apispec.Version)
	}
}

func TestContractVersionNegotiation(t *testing.T) {
	f := modeNewFixture(t)

	t.Run("accepted requirements reach the handler", func(t *testing.T) {
		// An absent or blank header states no requirement, which is what every
		// client written before the contract was versioned sends.
		for _, required := range []string{"absent", "", " ", "1", "1.0", "1.1", "1.2", "1.3"} {
			headers := map[string]string{}
			if required != "absent" {
				headers[apispec.VersionHeader] = required
			}
			rec := oaServe(f.e, http.MethodGet, "/user-ids", nil, headers)
			// /user-ids reaches the database, which the fixture does not
			// script; the negotiation decision is what is under test, so any
			// status other than the negotiation rejection proves it passed.
			if rec.Code == http.StatusBadRequest {
				t.Fatalf("required %q was rejected: %s", required, rec.Body.String())
			}
			if got := rec.Header().Get(apispec.VersionHeader); got != apispec.Version {
				t.Fatalf("required %q: response header %q, want %q", required, got, apispec.Version)
			}
		}
	})

	t.Run("incompatible requirements are rejected explicitly", func(t *testing.T) {
		// None of these is a substring of the implemented version, so a
		// message naming that version cannot be mistaken for an echo of the
		// value the caller sent.
		for _, required := range []string{"4", "2.0", "0.9", "1.4", "one", "1.0.0", "-1", "1.0; drop"} {
			rec := oaServe(f.e, http.MethodPut, "/user", []byte(`{"name":"x"}`),
				map[string]string{apispec.VersionHeader: required})
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("required %q: status %d, want 400; body: %s", required, rec.Code, rec.Body.String())
			}
			var body struct {
				Message string `json:"message"`
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
				t.Fatalf("required %q: response is not an error envelope: %v; body: %s", required, err, rec.Body.String())
			}
			if !strings.Contains(body.Message, apispec.VersionHeader) || !strings.Contains(body.Message, apispec.Version) {
				t.Fatalf("required %q: message %q does not name the header and implemented version", required, body.Message)
			}
			if strings.Contains(body.Message, required) {
				t.Fatalf("required %q: the rejected value is echoed back: %q", required, body.Message)
			}
		}
	})

	t.Run("discovery answers whatever the client requires", func(t *testing.T) {
		for _, route := range []string{routeVersion, routeOpenAPI} {
			rec := oaServe(f.e, http.MethodGet, route, nil, map[string]string{apispec.VersionHeader: "99"})
			if rec.Code != http.StatusOK {
				t.Fatalf("%s with an incompatible requirement: status %d, want 200", route, rec.Code)
			}
		}
	})
}

func TestServedContractIsTheEmbeddedDocument(t *testing.T) {
	c := oaContract(t)
	f := modeNewFixture(t)

	rec := oaServe(f.e, http.MethodGet, routeOpenAPI, nil, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if !bytes.Equal(rec.Body.Bytes(), apispec.OpenAPI) {
		t.Fatal("the served document is not the embedded contract")
	}
	if contentType := rec.Header().Get(echo.HeaderContentType); !strings.HasPrefix(contentType, apispec.MediaType) {
		t.Fatalf("content type = %q, want %q", contentType, apispec.MediaType)
	}
	if _, _, err := c.operation(http.MethodGet, routeOpenAPI); err != nil {
		t.Fatalf("the contract does not document its own route: %v", err)
	}
}

// TestExecutorListDocumentsItsNullBody pins the nullability the contract
// claims: an empty registry answers with a JSON null, not an empty array.
func TestExecutorListDocumentsItsNullBody(t *testing.T) {
	c := oaContract(t)
	f := modeNewFixture(t)

	rec := oaServe(f.e, http.MethodGet, "/executors", nil, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if got := strings.TrimSpace(rec.Body.String()); got != "null" {
		t.Fatalf("empty registry body = %s, want null", got)
	}
	oaCheckResponse(t, c, http.MethodGet, "/executors", rec.Code, rec.Body.Bytes())
}

// TestContractDescribesHandlerResponsesAndSDKRequests drives the public SDK
// and raw requests against the real routes, at the root and behind /api, and
// checks every request body, query parameter, status code and response body
// against the published contract.
func TestContractDescribesHandlerResponsesAndSDKRequests(t *testing.T) {
	c := oaContract(t)
	f := ccNewFixture(t)

	// A second executor with a known source IP makes the by-IP lookup and the
	// TESLA schedule deterministic without depending on the peer's socket.
	oaRegisterExecutor(t, f)

	for _, deployment := range []struct {
		name string
		base string
		url  string
	}{
		{name: "root", base: "", url: f.root.URL},
		{name: "api prefix", base: "/api", url: f.prefix.URL + "/api"},
	} {
		t.Run(deployment.name, func(t *testing.T) {
			recorder := &oaRecorder{base: deployment.base}
			sdk, err := client.New(deployment.url, client.Options{
				RequestTimeout: ccRequestBound,
				HTTPClient:     &http.Client{Transport: recorder},
			})
			if err != nil {
				t.Fatalf("client.New(%s): %v", deployment.url, err)
			}
			ctx, cancel := context.WithTimeout(f.ctx, ccCommandBound)
			defer cancel()

			if _, err := sdk.Version(ctx); err != nil {
				t.Fatalf("Version: %v", err)
			}
			if _, err := sdk.Nodes(ctx); err != nil {
				t.Fatalf("Nodes: %v", err)
			}
			batch, err := client.Prepare([]client.Request{ccRequest([]string{"127.0.0.1:8080"})})
			if err != nil {
				t.Fatalf("Prepare: %v", err)
			}
			submission, err := sdk.SubmitTEST(ctx, batch)
			if err != nil {
				t.Fatalf("SubmitTEST: %v", err)
			}
			if _, err := sdk.Status(ctx, submission.IDs[0]); err != nil {
				t.Fatalf("Status: %v", err)
			}
			if _, err := sdk.Logs(ctx, submission.IDs[0], client.LogOptions{Limit: 5}); err != nil {
				t.Fatalf("Logs: %v", err)
			}
			// A rejected lookup exercises the documented 400 and 404 shapes.
			if _, err := sdk.Status(ctx, "00000000-0000-0000-0000-00000000dead"); err == nil {
				t.Fatal("Status of an unknown debuglet succeeded")
			}
			if err := sdk.Cancel(ctx, submission.IDs[0], ccExecutorID); err != nil {
				t.Fatalf("Cancel: %v", err)
			}

			// The session routes, driven through the SDK so that the documented
			// request and response shapes are the ones a real client sends and
			// reads. Recovery replaces the credentials it was issued with.
			account, err := sdk.CreateAccount(ctx, "contract account")
			if err != nil {
				t.Fatalf("CreateAccount: %v", err)
			}
			session, err := sdk.Login(ctx, account.AccountKey)
			if err != nil {
				t.Fatalf("Login: %v", err)
			}
			authenticated, err := sdk.WithCredential(session.Token)
			if err != nil {
				t.Fatalf("WithCredential: %v", err)
			}
			if _, err := authenticated.Whoami(ctx); err != nil {
				t.Fatalf("Whoami: %v", err)
			}
			if err := authenticated.Logout(ctx); err != nil {
				t.Fatalf("Logout: %v", err)
			}
			// Recovery is last: it revokes every session of the account.
			if _, err := sdk.Recover(ctx, account.RecoveryCode); err != nil {
				t.Fatalf("Recover: %v", err)
			}

			// Routes outside the SDK surface, driven as an ordinary client.
			raw := &http.Client{Transport: recorder, Timeout: ccRequestBound}
			t.Cleanup(raw.CloseIdleConnections)
			oaRaw(t, raw, http.MethodGet, deployment.url+"/me", nil)
			oaRaw(t, raw, http.MethodGet, deployment.url+"/list-debuglets?limit=5&offset=0", nil)
			oaRaw(t, raw, http.MethodPut, deployment.url+"/user", []byte(`{"name":"contract"}`))
			oaRaw(t, raw, http.MethodGet, deployment.url+"/user-ids", nil)
			oaRaw(t, raw, http.MethodGet, deployment.url+routeLiveness, nil)
			oaRaw(t, raw, http.MethodGet, deployment.url+routeReadiness, nil)
			oaRaw(t, raw, http.MethodGet, deployment.url+routeHealth, nil)
			oaRaw(t, raw, http.MethodGet, deployment.url+"/auth/github", nil)
			oaRaw(t, raw, http.MethodGet, deployment.url+"/auth/github/callback", nil)
			oaRaw(t, raw, http.MethodGet, deployment.url+"/executors/by-ip?ip=127.0.0.1&n=5", nil)
			oaRaw(t, raw, http.MethodGet, deployment.url+"/executors/by-ip?ip=203.0.113.7", nil)
			oaRaw(t, raw, http.MethodGet, deployment.url+"/executors/by-ip", nil)
			oaRaw(t, raw, http.MethodGet, deployment.url+"/executors/"+oaExecutorID+"/tesla", nil)
			oaRaw(t, raw, http.MethodGet, deployment.url+"/executors/no-such-executor/tesla", nil)
			oaRaw(t, raw, http.MethodPatch, deployment.url+"/destination", []byte(`{"destination":"127.0.0.1","limit":1000000}`))
			oaRaw(t, raw, http.MethodGet, deployment.url+"/payment/"+submission.TransactionID+"/status", nil)
			oaRaw(t, raw, http.MethodPut, deployment.url+"/user", []byte(`{"name":"   "}`))
			// A client requiring a contract this dispatcher does not serve is
			// rejected on an ordinary route, which every operation documents.
			oaRawWith(t, raw, http.MethodGet, deployment.url+"/executors", nil,
				map[string]string{apispec.VersionHeader: "2"})

			exchanges := recorder.recorded()
			if len(exchanges) < 24 {
				t.Fatalf("recorded %d exchanges, want the complete public surface", len(exchanges))
			}
			covered := map[string]bool{}
			for _, exchange := range exchanges {
				operation, template := oaCheckExchange(t, c, exchange)
				if operation != nil {
					covered[exchange.method+" "+template] = true
				}
			}
			// Every documented route except the optional connection route and
			// the served document itself is exercised above.
			for _, documented := range c.operations() {
				switch documented {
				case "GET /connection", "GET /openapi.yaml":
					continue
				}
				if !covered[documented] {
					t.Errorf("no exchange exercised the documented operation %s", documented)
				}
			}
		})
	}
}

const oaExecutorID = "oa-executor"

// oaRegisterExecutor publishes a second executor with a fixed source IP and a
// TESLA anchor through the real registry callbacks.
func oaRegisterExecutor(t *testing.T, f *ccFixture) {
	t.Helper()
	owner := apiTestOwner(t, f.d, oaExecutorID)
	ctx, cancel := context.WithTimeout(f.ctx, ccRequestBound)
	defer cancel()
	hello := &pb.HelloResponse{
		ExecutorId: oaExecutorID, Version: "contract", TeslaDelaySec: 3,
		TeslaAnchorTimestampNs: time.Now().UnixNano(), TeslaAnchorKey: []byte{1, 2, 3, 4},
		PricePerBwS: 1, Currency: "TEST",
	}
	if err := apiTestRegister(ctx, f.d, owner, hello, "127.0.0.1"); err != nil {
		t.Fatalf("register contract executor: %v", err)
	}
	if !owner.MarkRegistered() {
		t.Fatal("contract executor retired before registration completed")
	}
}

// ------------------------------------------------------------------- fixtures

// oaServe runs one request through registered routes without a network.
func oaServe(e *echo.Echo, method, target string, body []byte, headers map[string]string) *httptest.ResponseRecorder {
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req := httptest.NewRequest(method, target, reader)
	if body != nil {
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	}
	for name, value := range headers {
		req.Header.Set(name, value)
	}
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)
	return rec
}

// oaRaw performs one request that the SDK does not make, so that routes
// outside its surface are exercised by the same recorder.
func oaRaw(t *testing.T, c *http.Client, method, target string, body []byte) {
	t.Helper()
	oaRawWith(t, c, method, target, body, nil)
}

// oaRawWith is oaRaw with request headers.
func oaRawWith(t *testing.T, c *http.Client, method, target string, body []byte, headers map[string]string) {
	t.Helper()
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequest(method, target, reader)
	if err != nil {
		t.Fatalf("%s %s: %v", method, target, err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for name, value := range headers {
		req.Header.Set(name, value)
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, target, err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
}

// oaExchange is one recorded request and its response.
type oaExchange struct {
	method   string
	route    string
	query    url.Values
	status   int
	request  []byte
	response []byte
	// announced is the contract version the response carried, and served
	// reports whether the exchange went over the network at all: a response
	// built by an httptest recorder in another test carries no headers to
	// check.
	announced string
	served    bool
}

// oaRecorder records complete exchanges while leaving both bodies readable.
type oaRecorder struct {
	base string
	mu   sync.Mutex
	seen []oaExchange
}

func (r *oaRecorder) RoundTrip(req *http.Request) (*http.Response, error) {
	var request []byte
	if req.GetBody != nil {
		if body, err := req.GetBody(); err == nil {
			request, _ = io.ReadAll(body)
			body.Close()
		}
	}
	resp, err := http.DefaultTransport.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	response, readErr := io.ReadAll(resp.Body)
	resp.Body.Close()
	if readErr != nil {
		return nil, readErr
	}
	resp.Body = io.NopCloser(bytes.NewReader(response))
	r.mu.Lock()
	r.seen = append(r.seen, oaExchange{
		method:    req.Method,
		route:     strings.TrimPrefix(req.URL.Path, r.base),
		query:     req.URL.Query(),
		status:    resp.StatusCode,
		request:   request,
		response:  response,
		announced: resp.Header.Get(apispec.VersionHeader),
		served:    true,
	})
	r.mu.Unlock()
	return resp, nil
}

func (r *oaRecorder) recorded() []oaExchange {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]oaExchange(nil), r.seen...)
}

// ------------------------------------------------------------------ assertions

// oaCheckExchange validates one recorded exchange against the contract and
// returns the documented operation it matched.
func oaCheckExchange(t *testing.T, c *contract, exchange oaExchange) (map[string]any, string) {
	t.Helper()
	operation, template, err := c.operation(exchange.method, exchange.route)
	if err != nil {
		t.Errorf("%s %s: %v", exchange.method, exchange.route, err)
		return nil, ""
	}
	where := exchange.method + " " + template

	if len(bytes.TrimSpace(exchange.request)) > 0 {
		schema := jsonSchema(operation, "requestBody")
		if schema == nil {
			t.Errorf("%s: sent a request body that the contract does not document", where)
		} else {
			for _, problem := range c.validateJSON(schema, exchange.request, where+" request") {
				t.Errorf("%s", problem)
			}
		}
	}

	documentedQuery, requiredQuery := parameterNames(operation)
	for name := range exchange.query {
		if !documentedQuery[name] {
			t.Errorf("%s: query parameter %q is not documented", where, name)
		}
	}
	for name := range requiredQuery {
		if _, present := exchange.query[name]; !present && exchange.status < 400 {
			t.Errorf("%s: required query parameter %q was accepted although it was absent", where, name)
		}
	}

	if exchange.served {
		if !documentsVersionHeader(operation, exchange.status) {
			t.Errorf("%s: %d does not document the %s response header", where, exchange.status, apispec.VersionHeader)
		}
		if exchange.announced != apispec.Version {
			t.Errorf("%s: %d answered %s %q, want %q", where, exchange.status, apispec.VersionHeader, exchange.announced, apispec.Version)
		}
	}

	schema, documented, hasBody := responseSchema(operation, exchange.status)
	switch {
	case !documented:
		t.Errorf("%s: answered %d, which the contract does not document", where, exchange.status)
	case !hasBody:
		if len(bytes.TrimSpace(exchange.response)) != 0 {
			t.Errorf("%s: %d is documented without a body but answered %s", where, exchange.status, exchange.response)
		}
	case schema == nil:
		// A documented body in a representation other than JSON.
	default:
		for _, problem := range c.validateJSON(schema, exchange.response, where+" "+http.StatusText(exchange.status)) {
			t.Errorf("%s", problem)
		}
	}
	return operation, template
}

// documentsVersionHeader reports whether the contract declares the contract
// version header on one documented response.
func documentsVersionHeader(operation map[string]any, status int) bool {
	responses, ok := operation["responses"].(map[string]any)
	if !ok {
		return false
	}
	response, ok := responses[strconv.Itoa(status)].(map[string]any)
	if !ok {
		return false
	}
	headers, ok := response["headers"].(map[string]any)
	if !ok {
		return false
	}
	_, declared := headers[apispec.VersionHeader]
	return declared
}

// oaCheckResponse validates one response captured without the recorder.
func oaCheckResponse(t *testing.T, c *contract, method, route string, status int, body []byte) {
	t.Helper()
	oaCheckExchange(t, c, oaExchange{method: method, route: route, status: status, response: body})
}

// TestContractDeclaresWhichOperationsNeedACredential compares the document's
// security declarations with the access matrix the runtime tests enforce. A
// route that needs a credential must not opt out of the document's requirement,
// and a route that needs none must say so explicitly rather than inherit one.
func TestContractDeclaresWhichOperationsNeedACredential(t *testing.T) {
	c := oaContract(t)
	root, ok := c.root["security"].([]any)
	if !ok || len(root) == 0 {
		t.Fatalf("the contract declares no default security requirement: %v", c.root["security"])
	}
	schemes, ok := c.root["components"].(map[string]any)["securitySchemes"].(map[string]any)
	if !ok || len(schemes) == 0 {
		t.Fatal("the contract declares no security schemes")
	}
	for _, requirement := range root {
		named, ok := requirement.(map[string]any)
		if !ok || len(named) != 1 {
			t.Fatalf("default security requirement %v is not one named scheme", requirement)
		}
		for name := range named {
			if _, defined := schemes[name]; !defined {
				t.Errorf("the default security requirement names undefined scheme %q", name)
			}
		}
	}

	documented := map[string]bool{}
	for _, operation := range c.operations() {
		documented[operation] = true
	}
	for route, policy := range authAccessMatrix {
		method, path, _ := strings.Cut(route, " ")
		template := oaTemplate(path)
		operation, _, err := c.operation(method, template)
		if err != nil {
			t.Errorf("%s %s: %v", method, template, err)
			continue
		}
		effective := oaSecurity(operation, root)
		if policy.public && len(effective) != 0 {
			t.Errorf("%s %s is reachable without a credential but the contract requires one", method, template)
		}
		if !policy.public && len(effective) == 0 {
			t.Errorf("%s %s requires a credential but the contract says it needs none", method, template)
		}
		delete(documented, method+" "+template)
	}
	// The optional connection route is registered outside RegisterRoutes, so
	// the matrix does not cover it; it announces local listeners and grants
	// nothing, and the contract says it needs no credential.
	for operation := range documented {
		if operation != "GET /connection" {
			t.Errorf("operation %s is documented but the access matrix states no policy for it", operation)
			continue
		}
		item, _, err := c.operation(http.MethodGet, "/connection")
		if err != nil {
			t.Fatalf("GET /connection: %v", err)
		}
		if len(oaSecurity(item, root)) != 0 {
			t.Error("GET /connection grants nothing but the contract requires a credential for it")
		}
	}
}

// oaSecurity returns the security requirement that applies to one operation:
// its own when it declares one, the document's default otherwise.
func oaSecurity(operation map[string]any, root []any) []any {
	declared, present := operation["security"]
	if !present {
		return root
	}
	own, ok := declared.([]any)
	if !ok {
		return root
	}
	return own
}
