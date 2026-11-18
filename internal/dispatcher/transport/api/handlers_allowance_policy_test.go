// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package api

import (
	"github.com/google/uuid"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/config"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/database"
	"net/http"
	"testing"
)

func TestAllowancePolicyOperatorApprovalAndRead(t *testing.T) {
	issuer := uuid.New()
	f := alNewFixtureWithAllowance(t, config.AllowanceConfig{Enabled: true, PolicyIssuer: issuer.String(), DailyBase: 100, PublicTrial: 10})
	if _, err := f.queries.CreateUserWithRole(t.Context(), database.CreateUserWithRoleParams{Uuid: issuer, Name: "policy operator", Role: "operator"}); err != nil {
		t.Fatal(err)
	}
	_, operatorToken, userID, userToken := alAccounts(t, f)
	path := "/operator/accounts/" + userID + "/allowance-policy"
	body := []byte(`{"researcher":true,"approved_executor_ids":[]}`)
	for _, tc := range []struct {
		token string
		want  int
	}{{userToken, http.StatusForbidden}, {operatorToken, http.StatusOK}} {
		status, _, data, _ := authRequest(t, f, http.MethodPut, path, body, authBearer(tc.token))
		if status != tc.want {
			t.Fatalf("PUT status=%d want=%d: %s", status, tc.want, data)
		}
	}
	for _, body := range []string{`{"approved_executor_ids":[]}`, `{"researcher":null,"approved_executor_ids":[]}`, `{"researcher":true,"approved_executor_ids":[],"unexpected":true}`, `{"researcher":false,"approved_executor_ids":null}`} {
		status, _, data, _ := authRequest(t, f, http.MethodPut, path, []byte(body), authBearer(operatorToken))
		if status != http.StatusBadRequest {
			t.Fatalf("malformed policy accepted: %d %s", status, data)
		}
	}
	status, _, a := alAllowance(t, f, userToken)
	if status != http.StatusOK || a.Remaining != "100" || a.Policy == nil || a.Policy.Kind != "daily" || a.Policy.NextReset == nil {
		t.Fatalf("GET: %d %+v", status, a)
	}
	// An unknown owned node fails before replacing the existing researcher approval.
	invalid := []byte(`{"researcher":false,"approved_executor_ids":["` + uuid.NewString() + `"]}`)
	status, _, data, _ := authRequest(t, f, http.MethodPut, path, invalid, authBearer(operatorToken))
	if status != http.StatusBadRequest {
		t.Fatalf("invalid approval: %d %s", status, data)
	}
	var approved bool
	if err := f.db.QueryRow(`SELECT researcher FROM allowance_eligibility e JOIN users u ON u.id=e.user_id WHERE u.uuid=?`, userID).Scan(&approved); err != nil || !approved {
		t.Fatalf("failed approval changed eligibility: %v %v", approved, err)
	}
}

func TestAllowancePolicyPublicTrialReadIsIdempotent(t *testing.T) {
	issuer := uuid.New()
	f := alNewFixtureWithAllowance(t, config.AllowanceConfig{Enabled: true, PolicyIssuer: issuer.String(), PublicTrial: 10})
	if _, err := f.queries.CreateUserWithRole(t.Context(), database.CreateUserWithRoleParams{Uuid: issuer, Name: "issuer", Role: "operator"}); err != nil {
		t.Fatal(err)
	}
	_, token, _ := authAccount(t, f, "public")
	for range 2 {
		status, _, a := alAllowance(t, f, token)
		if status != http.StatusOK || a.Granted != "10" || a.Policy == nil || a.Policy.Kind != "trial" || a.Policy.NextReset != nil {
			t.Fatalf("trial response: %d %+v", status, a)
		}
	}
}

func TestManagedCreditsNormalAccountRead(t *testing.T) {
	issuer := uuid.New()
	f := alNewFixtureWithAllowance(t, config.AllowanceConfig{Enabled: true, PolicyIssuer: issuer.String(), DailyBase: 100, BalanceCap: 500, HostingHourlyRate: 20})
	if _, err := f.queries.CreateUserWithRole(t.Context(), database.CreateUserWithRoleParams{Uuid: issuer, Name: "issuer", Role: "operator"}); err != nil {
		t.Fatal(err)
	}
	_, token, _ := authAccount(t, f, "credit user")
	for range 2 {
		status, _, a := alAllowance(t, f, token)
		if status != http.StatusOK || a.Granted != "100" || a.Remaining != "100" || a.Policy == nil {
			t.Fatalf("managed credit response: %d %+v", status, a)
		}
		p := a.Policy
		if p.Kind != "credits" || p.DailyGrant != "100" || p.Credited != "100" || p.BalanceCap != "500" || p.HostingRate != "20" || p.HostingSeconds != "0" || p.HostingEarned != "0" || p.NextReset == nil {
			t.Fatalf("managed policy: %+v", p)
		}
	}
}
