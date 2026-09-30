// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package api

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"reflect"
	"strings"
	"testing"

	"github.com/netsec-ethz/debuglet/pkg/client"
	"github.com/netsec-ethz/debuglet/pkg/wire"
)

func sampleProfile() wire.ProfileConfig {
	digest := sha256.Sum256(ccGuest)
	return wire.ProfileConfig{
		Version: 1, Name: "Owned service check", ExecutorID: ccExecutorID,
		Program: wire.ProfileProgram{SHA256: hex.EncodeToString(digest[:]), Wasm: ccGuest},
		Args:    []string{"two words", "", "quote\"here"},
		Policy:  wire.Policy{FloorBW: 100, CeilBW: 100, TimeoutMS: 2000, Addresses: []string{"127.0.0.1"}},
	}
}

func TestMeasurementProfileReloadEditSubmitAndIsolation(t *testing.T) {
	f := ccNewFixtureWith(t)
	_, _, alice := authAccount(t, f, "Alice")
	_, _, bob := authAccount(t, f, "Bob")
	ctx, cancel := f.requestCtx()
	defer cancel()
	config := sampleProfile()
	saved, err := alice.SaveProfile(ctx, "", config)
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := alice.Profile(ctx, saved.ID)
	if err != nil || !reflect.DeepEqual(loaded, saved) {
		t.Fatalf("reload differs: %v", err)
	}
	for _, operation := range []func() error{
		func() error { _, err := bob.Profile(ctx, saved.ID); return err },
		func() error { _, err := bob.SaveProfile(ctx, saved.ID, config); return err },
		func() error { return bob.DeleteProfile(ctx, saved.ID) },
	} {
		var failure *client.HTTPError
		if err := operation(); !errors.As(err, &failure) || failure.StatusCode != http.StatusNotFound {
			t.Fatalf("non-owner access: %v", err)
		}
	}
	if list, err := bob.Profiles(ctx); err != nil || len(list) != 0 {
		t.Fatalf("non-owner list: %v %v", list, err)
	}
	loaded.Config.Name = "Updated check"
	loaded.Config.Args = append(loaded.Config.Args, "edited")
	updated, err := alice.SaveProfile(ctx, saved.ID, loaded.Config)
	if err != nil {
		t.Fatal(err)
	}
	list, err := alice.Profiles(ctx)
	if err != nil || len(list) != 1 || list[0].Name != updated.Config.Name {
		t.Fatalf("profile list: %v %v", list, err)
	}
	request := client.Request{OrderID: 0, ExecutorID: loaded.Config.ExecutorID, Args: loaded.Config.Args, Policy: loaded.Config.Policy, Wasm: loaded.Config.Program.Wasm}
	batch, err := client.Prepare([]client.Request{request})
	if err != nil {
		t.Fatal(err)
	}
	run, err := alice.SubmitTEST(ctx, batch)
	if err != nil || len(run.IDs) != 1 {
		t.Fatalf("saved profile submit: %v", err)
	}
	result, err := alice.Export(ctx, run.IDs[0])
	if err != nil || result.Provenance == nil || !reflect.DeepEqual(result.Provenance.Arguments, updated.Config.Args) {
		t.Fatalf("submitted profile args: %v", err)
	}
	if err := alice.DeleteProfile(ctx, saved.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := alice.Profile(ctx, saved.ID); err == nil {
		t.Fatal("deleted profile still readable")
	}
}

func TestMeasurementProfilesRefuseCredentialsVersionsAndChangedPrograms(t *testing.T) {
	f := ccNewFixtureWith(t)
	_, token, _ := authAccount(t, f, "Alice")
	for _, field := range []string{"auth_key", "transaction_id", "start_time", "refund_address"} {
		data, _ := json.Marshal(sampleProfile())
		var object map[string]any
		_ = json.Unmarshal(data, &object)
		object[field] = "not retained"
		body, _ := json.Marshal(object)
		status, _ := authAs(t, f, token, http.MethodPost, "/measurement-profiles", body)
		if status != http.StatusBadRequest {
			t.Fatalf("field %s: %d", field, status)
		}
	}
	for _, change := range []func(*wire.ProfileConfig){
		func(p *wire.ProfileConfig) { p.Version = 2 },
		func(p *wire.ProfileConfig) { p.Program.SHA256 = wire.ProbeSHA256 },
		func(p *wire.ProfileConfig) { p.Template = &wire.TemplateReference{ID: "http", Version: 1} },
		func(p *wire.ProfileConfig) { p.Policy.TimeoutMS = 0 },
	} {
		config := sampleProfile()
		change(&config)
		body, _ := json.Marshal(config)
		status, _ := authAs(t, f, token, http.MethodPost, "/measurement-profiles", body)
		if status != http.StatusBadRequest {
			t.Fatalf("invalid profile status %d", status)
		}
	}
}

func TestMeasurementProfileLimitAndCatalogue(t *testing.T) {
	f := ccNewFixtureWith(t)
	_, _, alice := authAccount(t, f, "Alice")
	ctx, cancel := f.requestCtx()
	defer cancel()
	for i := 0; i < wire.MaxProfilesPerAccount; i++ {
		if _, err := alice.SaveProfile(ctx, "", sampleProfile()); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := alice.SaveProfile(ctx, "", sampleProfile()); err == nil {
		t.Fatal("profile limit not enforced")
	}
	templates, err := alice.MeasurementTemplates(ctx)
	if err != nil || len(templates) != 3 {
		t.Fatalf("catalogue: %v", err)
	}
	for _, template := range templates {
		if template.Version != 1 || template.ProgramSHA256 != wire.ProbeSHA256 || template.Arguments.Type != "object" || template.DefaultPolicy.TimeoutMS != 30000 {
			t.Fatalf("incomplete template: %+v", template)
		}
	}
}

func TestMeasurementProfileBodyLimitNamesProfileBound(t *testing.T) {
	f := ccNewFixtureWith(t)
	_, token, _ := authAccount(t, f, "Alice")
	body := []byte(`{"name":"` + strings.Repeat("x", wire.MaxProfileBytes) + `"}`)
	status, code, data, _ := authRequest(t, f, http.MethodPost, "/measurement-profiles", body, authBearer(token))
	if status != http.StatusRequestEntityTooLarge || code != CodePayloadTooLarge || !strings.Contains(string(data), "8 MiB") {
		t.Fatalf("profile limit response: %d %s", status, data)
	}
}
