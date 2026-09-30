// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"sync/atomic"
	"testing"

	"github.com/google/uuid"
	"github.com/netsec-ethz/debuglet/internal/dispatcher"
	"github.com/netsec-ethz/debuglet/pkg/client"
	"github.com/netsec-ethz/debuglet/pkg/wire"
)

func retryBatch(t *testing.T) *client.PreparedBatch {
	t.Helper()
	batch, err := client.Prepare([]client.Request{ccRequest([]string{"new attempt"})})
	if err != nil {
		t.Fatal(err)
	}
	return batch
}

// Drop exactly one committed HTTP reply. The upstream handler finishes its
// real SQLite/control work before the proxy closes the downstream connection.
func retryLostReply(t *testing.T, f *ccFixture, path, token string) *client.Client {
	t.Helper()
	target, err := url.Parse(f.root.URL)
	if err != nil {
		t.Fatal(err)
	}
	proxy := httputil.NewSingleHostReverseProxy(target)
	var dropped atomic.Bool
	proxy.ModifyResponse = func(r *http.Response) error {
		if r.Request.URL.Path == path && dropped.CompareAndSwap(false, true) {
			_ = r.Body.Close()
			return errors.New("drop committed response")
		}
		return nil
	}
	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		conn, _, hijackErr := w.(http.Hijacker).Hijack()
		if hijackErr == nil {
			_ = conn.Close()
		}
	}
	server := httptest.NewServer(proxy)
	t.Cleanup(server.Close)
	c, err := f.client(server.URL, false).WithCredential(token)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestExplicitRetryLostResponsesAndParentPreservation(t *testing.T) {
	for _, path := range []string{"/payment/intent", "/debuglet"} {
		t.Run(path, func(t *testing.T) {
			f := ccNewFixtureWith(t)
			_, token, owner := authAccount(t, f, "retry owner")
			if path == "/payment/intent" {
				f.peer.setUploadHook(f.exitHook(0, nil))
			}
			parent := f.submit(owner, []string{"parent"}).IDs[0]
			f.seedLogs(parent, [][]byte{[]byte("unchanged parent output")})
			before, err := owner.Export(f.ctx, parent)
			if err != nil {
				t.Fatal(err)
			}
			if before.Version != wire.ResultVersion {
				t.Fatalf("parent result version = %q, want %q", before.Version, wire.ResultVersion)
			}
			requestID := uuid.NewString()
			c := retryLostReply(t, f, path, token)
			batch := retryBatch(t)
			if _, err := c.RetryTEST(f.ctx, parent, requestID, batch); err == nil {
				t.Fatal("lost reply unexpectedly succeeded")
			}
			if got := iaCount(t, f.db, "retry_requests"); got != 1 {
				t.Fatalf("retry records = %d", got)
			}
			child, err := c.RetryTEST(f.ctx, parent, requestID, batch)
			if err != nil {
				t.Fatal(err)
			}
			if len(child.IDs) != 1 || child.IDs[0] == parent || f.peer.uploadCount() != 2 || iaCount(t, f.db, "transactions") != 2 {
				t.Fatal("repeat created a different or extra attempt")
			}
			doc, err := owner.Export(f.ctx, child.IDs[0])
			if err != nil {
				t.Fatal(err)
			}
			if doc.Version != "1.2" || doc.Provenance == nil || doc.Provenance.Retry == nil || *doc.Provenance.Retry != (wire.RetryLink{ParentRunID: parent, RequestID: requestID}) {
				t.Fatal("missing immutable retry lineage")
			}
			after, err := owner.Export(f.ctx, parent)
			if err != nil {
				t.Fatal(err)
			}
			after.Timing.ObservedAt = before.Timing.ObservedAt
			if !reflect.DeepEqual(before, after) {
				t.Fatal("parent changed")
			}
			// Receipt recovery does not need the executor, fresh admission or a live
			// dispatcher registry, and still works through a freshly opened DB handle.
			paused := filepath.Join(t.TempDir(), "maintenance.json")
			if err := os.WriteFile(paused, []byte(`{"schema_version":1,"paused":true}`), 0600); err != nil {
				t.Fatal(err)
			}
			t.Setenv(dispatcher.MaintenanceFileEnv, paused)
			f.d.Close()
			db := iaReopen(t, f)
			if iaCount(t, db, "retry_requests") != 1 {
				t.Fatal("retry identity not durable")
			}
			again, err := owner.RetryTEST(f.ctx, parent, requestID, batch)
			if err != nil || !reflect.DeepEqual(again, child) {
				t.Fatalf("receipt recovery during maintenance: %v", err)
			}
			if f.peer.uploadCount() != 2 {
				t.Fatal("recovery uploaded again")
			}
			if _, err := f.db.Exec("UPDATE retry_requests SET parent_run_id = parent_run_id"); err == nil {
				t.Fatal("retry lineage is mutable")
			}
		})
	}
}

func TestExplicitRetryConcurrentRequestsAndMismatch(t *testing.T) {
	f := ccNewFixtureWith(t)
	_, token, owner := authAccount(t, f, "owner")
	_, _, other := authAccount(t, f, "other")
	parent := f.submit(owner, nil).IDs[0]
	key := uuid.NewString()
	batch := retryBatch(t)
	type result struct {
		sub client.Submission
		err error
	}
	results := make(chan result, 6)
	for i := 0; i < cap(results); i++ {
		go func() { sub, err := owner.RetryTEST(f.ctx, parent, key, batch); results <- result{sub, err} }()
	}
	var first client.Submission
	for i := 0; i < cap(results); i++ {
		r := <-results
		if r.err != nil {
			t.Fatal(r.err)
		}
		if i == 0 {
			first = r.sub
		} else if !reflect.DeepEqual(first, r.sub) {
			t.Fatal("concurrent repeats diverged")
		}
	}
	if f.peer.uploadCount() != 2 || iaCount(t, f.db, "transactions") != 2 {
		t.Fatal("concurrent duplicate side effects")
	}
	if _, err := other.RetryTEST(f.ctx, parent, key, batch); err == nil {
		t.Fatal("foreign parent accepted")
	}
	req := PaymentIntentRequest{Debuglets: []DebugletRequest{iaDebuglet(0, ccFloorBW, ccDurationMS)}, PaymentMethod: "TEST", Retry: &wire.RetryLink{ParentRunID: parent, RequestID: key}}
	data, _ := json.Marshal(req)
	status, _, _, _ := authRequest(t, f, http.MethodPut, "/payment/intent", data, authBearer(token))
	if status != http.StatusConflict {
		t.Fatalf("changed request = %d", status)
	}
	// The parent lookup remains an authorization boundary, not a key oracle.
	req.Retry.ParentRunID = uuid.NewString()
	data, _ = json.Marshal(req)
	status, _, _, _ = authRequest(t, f, http.MethodPut, "/payment/intent", data, authBearer(token))
	if status != http.StatusNotFound {
		t.Fatalf("missing parent = %d", status)
	}
	if f.peer.uploadCount() != 2 {
		t.Fatal("refusal uploaded work")
	}
	otherParent := f.submit(other, nil).IDs[0]
	if _, err := other.RetryTEST(f.ctx, otherParent, key, batch); err != nil {
		t.Fatalf("another caller's independent key: %v", err)
	}
	if f.peer.uploadCount() != 4 || iaCount(t, f.db, "retry_requests") != 2 {
		t.Fatal("caller scopes collided")
	}

}

func TestExplicitRetryIntentAndAdmissionRollback(t *testing.T) {
	f := ccNewFixtureWith(t)
	_, _, owner := authAccount(t, f, "owner")
	parent := f.submit(owner, nil).IDs[0]
	batch := retryBatch(t)
	key := uuid.NewString()
	if _, err := f.db.Exec("CREATE TRIGGER reject_retry BEFORE INSERT ON retry_requests BEGIN SELECT RAISE(ABORT, 'refused'); END"); err != nil {
		t.Fatal(err)
	}
	if _, err := owner.RetryTEST(f.ctx, parent, key, batch); err == nil {
		t.Fatal("refused insert succeeded")
	}
	if iaCount(t, f.db, "transactions") != 1 || iaCount(t, f.db, "retry_requests") != 0 || f.peer.uploadCount() != 1 {
		t.Fatal("partial intent persisted")
	}
	if _, err := f.db.Exec("DROP TRIGGER reject_retry"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.db.Exec("CREATE TRIGGER reject_child BEFORE INSERT ON debuglet_provenance BEGIN SELECT RAISE(ABORT, 'refused'); END"); err != nil {
		t.Fatal(err)
	}
	if _, err := owner.RetryTEST(f.ctx, parent, key, batch); err == nil {
		t.Fatal("refused admission succeeded")
	}
	if iaCount(t, f.db, "transactions") != 2 || iaCount(t, f.db, "retry_requests") != 1 || iaCount(t, f.db, "debuglets") != 1 || f.peer.uploadCount() != 1 {
		t.Fatal("partial child or duplicate intent persisted")
	}
	if _, err := f.db.Exec("DROP TRIGGER reject_child"); err != nil {
		t.Fatal(err)
	}
	sub, err := owner.RetryTEST(f.ctx, parent, key, batch)
	if err != nil || len(sub.IDs) != 1 || iaCount(t, f.db, "transactions") != 2 || f.peer.uploadCount() != 2 {
		t.Fatalf("explicit repeat after rollback: %v", err)
	}
}

func TestExplicitRetryCLIUsesFixedIdentity(t *testing.T) {
	f := ccNewFixtureWith(t)
	f.dbl = ccBuildCLI(t)
	account, _, owner := authAccount(t, f, "cli owner")
	parent := f.submit(owner, nil).IDs[0]
	dir := t.TempDir()
	config, keyfile, wasm := filepath.Join(dir, "client.json"), filepath.Join(dir, "account.key"), filepath.Join(dir, "guest.wasm")
	if err := os.WriteFile(keyfile, []byte(account.AccountKey), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(wasm, ccGuest, 0600); err != nil {
		t.Fatal(err)
	}
	if code, _, stderr := f.runCLI("--config", config, "connect", f.root.URL); code != 0 {
		t.Fatalf("connect: %s", stderr)
	}
	if code, _, stderr := f.runCLI("--config", config, "login", "--account-key-file", keyfile); code != 0 {
		t.Fatalf("login: %s", stderr)
	}
	key := uuid.NewString()
	args := []string{"--config", config, "--output", "json", "retry", parent, "--request-id", key, "--executor", ccExecutorID, "--wasm", wasm, "--floor-bps", "0", "--ceil-bps", "0"}
	code, first, stderr := f.runCLI(args...)
	if code != 0 {
		t.Fatalf("retry: %s", stderr)
	}
	code, second, stderr := f.runCLI(args...)
	if code != 0 || !bytes.Equal(first, second) || f.peer.uploadCount() != 2 {
		t.Fatalf("repeat: code=%d %s", code, stderr)
	}
	ccAssertNoAuthKey(t, "retry receipt", first, second, stderr)
	if !bytes.Contains(first, []byte(key)) || !bytes.Contains(first, []byte(parent)) {
		t.Fatal("receipt lost retry identity")
	}
}

func TestExplicitRetryWireContract(t *testing.T) {
	f := ccNewFixtureWith(t)
	_, token, owner := authAccount(t, f, "contract owner")
	parent := f.submit(owner, nil).IDs[0]
	contract := oaContract(t)
	for _, deployment := range []struct{ base, endpoint string }{{"", f.root.URL}, {"/api", f.prefix.URL + "/api"}} {
		recorder := &oaRecorder{base: deployment.base}
		c, err := client.New(deployment.endpoint, client.Options{Credential: token, HTTPClient: &http.Client{Transport: recorder}})
		if err != nil {
			t.Fatal(err)
		}
		key := uuid.NewString()
		sub, err := c.RetryTEST(f.ctx, parent, key, retryBatch(t))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := c.RetryTEST(f.ctx, parent, key, retryBatch(t)); err != nil {
			t.Fatal(err)
		}
		if _, err := c.Export(f.ctx, sub.IDs[0]); err != nil {
			t.Fatal(err)
		}
		for _, exchange := range recorder.recorded() {
			oaCheckExchange(t, contract, exchange)
		}
		// The second step cannot discard lineage by omitting its metadata.
		var submit SubmitDebugletsRequest
		for _, exchange := range recorder.recorded() {
			if exchange.method == http.MethodPut && exchange.route == "/debuglet" {
				if err := json.Unmarshal(exchange.request, &submit); err != nil {
					t.Fatal(err)
				}
			}
		}
		submit.Retry = nil
		body, _ := json.Marshal(submit)
		status, _, _, _ := authRequest(t, f, http.MethodPut, "/debuglet", body, authBearer(token))
		if status != http.StatusBadRequest {
			t.Fatalf("omitted lineage accepted: %d", status)
		}
	}
}
