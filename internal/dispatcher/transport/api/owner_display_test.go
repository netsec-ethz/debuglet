// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package api

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/netsec-ethz/debuglet/internal/dispatcher"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/config"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/database"
	"github.com/netsec-ethz/debuglet/pkg/wire"
	pb "github.com/netsec-ethz/debuglet/protocol"
	"go.uber.org/zap"
)

func TestOwnedExecutorDisplayOwnershipLiveUpdateAndRestart(t *testing.T) {
	f, _ := operatorFixture(t)
	_, alice, _ := authAccount(t, f, "Alice")
	_, bob, _ := authAccount(t, f, "Bob")
	var setup ExecutorSetupResponse
	operatorRequest(t, f, alice, http.MethodPost, "/operator/executors", map[string]string{"name": "private name"}, 201, &setup)
	id := setup.Executor.ID
	path := "/operator/executors/" + id
	for _, token := range []string{bob} {
		operatorRequest(t, f, token, http.MethodPatch, path, map[string]string{"display_name": "other"}, 404, nil)
	}
	operatorRequest(t, f, "", http.MethodPatch, path, map[string]string{"city": "Bern"}, 401, nil)
	status, _ := authStatus(t, f, http.MethodPatch, path, []byte(`{"city":"Bern"}`), map[string]string{"Cookie": sessionCookieName + "=" + alice})
	if status != http.StatusForbidden {
		t.Fatalf("missing CSRF: %d", status)
	}
	var result OwnedExecutorResponse
	operatorRequest(t, f, alice, http.MethodPatch, path, map[string]string{"display_name": "Public node", "city": "Zurich", "country": "CH", "network": "Research"}, 200, &result)
	if result.Name != "private name" || result.OwnerDisplay.City != "Zurich" || *result.Display.City.Source != wire.SourceOwner || *result.Display.DisplayName.Value != "Public node" {
		t.Fatalf("labels: %+v", result)
	}
	owner := apiTestOwner(t, f.d, id)
	if err := apiTestRegister(f.ctx, f.d, owner, &pb.HelloResponse{ExecutorId: id, Version: "display-test", Currency: "TEST"}, "127.0.0.1"); err != nil {
		t.Fatal(err)
	}
	if !owner.MarkRegistered() {
		t.Fatal("mark registered")
	}
	before, ok := f.d.GetExecutor(id)
	if !ok || *before.Display().City.Value != "Zurich" {
		t.Fatal("registration lost owner display")
	}
	operatorRequest(t, f, alice, http.MethodPatch, path, map[string]string{"city": "Bern", "network": ""}, 200, &result)
	after, _ := f.d.GetExecutor(id)
	if *after.Display().City.Value != "Bern" || after.Display().Network.Value != nil || *before.Display().City.Value != "Zurich" {
		t.Fatal("edit did not update live display or rewrote snapshot")
	}
	if result.OwnerDisplay.DisplayName != "Public node" {
		t.Fatal("partial edit cleared omitted field")
	}
	status, _, data, _ := authRequest(t, f, http.MethodGet, "/executors", nil, authBearer(alice))
	if status != 200 || !strings.Contains(string(data), `"value":"Bern","source":"owner"`) {
		t.Fatalf("public list: %d %s", status, data)
	}
	oaCheckResponse(t, oaContract(t), http.MethodGet, "/executors", status, data)
	// A fresh dispatcher reconstructs owner labels from the database. Its
	// configured labels override only the fields explicitly supplied.
	restarted, err := dispatcher.New(zap.NewNop(), f.db, "restart", time.Minute, time.Minute, f.d.Payment)
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.Close()
	if err := restarted.ConfigureExecutorDisplay(map[string]config.ExecutorDisplay{id: {City: "Operator city"}}); err != nil {
		t.Fatal(err)
	}
	display := restarted.ConfiguredDisplay(id)
	if *display.City.Value != "Operator city" || *display.City.Source != wire.SourceOperator || *display.DisplayName.Value != "Public node" || *display.DisplayName.Source != wire.SourceOwner {
		t.Fatalf("restart/override: %+v", display)
	}
	for _, invalid := range []map[string]string{{"city": " padded"}, {"city": "bad\ncity"}, {"display_name": strings.Repeat("é", 65)}, {"country": "ch"}, {"country": "XX"}} {
		operatorRequest(t, f, alice, http.MethodPatch, path, invalid, 400, nil)
	}
	operatorRequest(t, f, alice, http.MethodPatch, "/operator/executors/00000000-0000-0000-0000-000000000001", map[string]string{"city": "Bern"}, 404, nil)
}

func TestOwnerDisplayConcurrentPartialEditsAndCancellation(t *testing.T) {
	f, _ := operatorFixture(t)
	account, token, _ := authAccount(t, f, "owner")
	user := uuid.MustParse(account.ID)
	var setup ExecutorSetupResponse
	operatorRequest(t, f, token, http.MethodPost, "/operator/executors", map[string]string{"name": "node"}, 201, &setup)
	id := setup.Executor.ID
	var wg sync.WaitGroup
	errs := make(chan error, 2)
	for _, params := range []database.UpdateOwnedExecutorDisplayParams{
		{Uuid: user, ExecutorID: id, City: sql.NullString{String: "Bern", Valid: true}},
		{Uuid: user, ExecutorID: id, Network: sql.NullString{String: "Research", Valid: true}},
	} {
		wg.Add(1)
		go func() { defer wg.Done(); errs <- f.d.UpdateOwnerDisplay(f.ctx, params) }()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithCancel(f.ctx)
	cancel()
	if err := f.d.UpdateOwnerDisplay(ctx, database.UpdateOwnedExecutorDisplayParams{Uuid: user, ExecutorID: id, City: sql.NullString{String: "Canceled", Valid: true}}); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled update: %v", err)
	}
	// Cancellation immediately after successful storage must not delay cache
	// publication; discovery and a subsequent storage read agree.
	ctx, cancel = context.WithCancel(f.ctx)
	if err := f.d.UpdateOwnerDisplay(ctx, database.UpdateOwnedExecutorDisplayParams{Uuid: user, ExecutorID: id, DisplayName: sql.NullString{String: "Public", Valid: true}}); err != nil {
		t.Fatal(err)
	}
	cancel()
	row, err := f.queries.GetOwnedExecutor(f.ctx, database.GetOwnedExecutorParams{Uuid: user, ExecutorID: id})
	if err != nil {
		t.Fatal(err)
	}
	display := f.d.ConfiguredDisplay(id)
	if row.City != "Bern" || row.Network != "Research" || row.DisplayName != "Public" || *display.City.Value != row.City || *display.Network.Value != row.Network || *display.DisplayName.Value != row.DisplayName {
		t.Fatalf("cache/storage mismatch: %+v %+v", row, display)
	}
}

func TestOwnerDisplayRequiresExecutorWriteScope(t *testing.T) {
	f := credentialFixture(t)
	browser := credentialBrowser(t, f)
	reader := createTestCredential(t, f, browser, "executors:read")
	writer := createTestCredential(t, f, browser, "executors:write")
	path := "/operator/executors/00000000-0000-0000-0000-000000000001"
	if status, _ := authAs(t, f, reader.Token, http.MethodPatch, path, []byte(`{"city":"Bern"}`)); status != 403 {
		t.Fatalf("read scope edited metadata: %d", status)
	}
	if status, _ := authAs(t, f, writer.Token, http.MethodPatch, path, []byte(`{"city":"Bern"}`)); status != 404 {
		t.Fatalf("write scope did not reach ownership check: %d", status)
	}
}
