// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package api

import (
	"database/sql"
	"net/http"
	"reflect"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/database"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/models"
	"github.com/netsec-ethz/debuglet/pkg/wire"
	"github.com/netsec-ethz/debuglet/pkg/workflow"
)

type communityFundingFixture struct {
	f                                                         *ccFixture
	ownerID, ownerToken, memberID, memberToken, outsiderToken string
	community                                                 wire.Community
	project                                                   wire.CommunityProject
}

func newCommunityFundingFixture(t *testing.T, allowances bool) communityFundingFixture {
	t.Helper()
	f := ccNewFixtureWith
	if allowances {
		f = alNewFixture
	}
	s := communityFundingFixture{f: f(t)}
	owner, ownerToken, _ := authAccount(t, s.f, "Community creator")
	member, memberToken, _ := authAccount(t, s.f, "Member")
	_, outsiderToken, _ := authAccount(t, s.f, "Outsider")
	s.ownerID, s.ownerToken = owner.ID, ownerToken
	s.memberID, s.memberToken, s.outsiderToken = member.ID, memberToken, outsiderToken
	s.community = communityCreate(t, s.f, s.ownerToken)
	communityJoin(t, s.f, s.ownerToken, s.memberToken, s.community.ID)
	s.project = communityProject(t, s.f, s.ownerToken, s.community.ID)
	if allowances {
		authGrantOperator(t, s.f, owner.ID)
		for _, grant := range []struct{ account, body string }{
			{owner.ID, `{"amount":"5000","reason":"shared research","idempotency_key":"owner"}`},
			{member.ID, `{"amount":"3000","reason":"personal research","idempotency_key":"member"}`},
		} {
			if status, _, _ := alGrant(t, s.f, s.ownerToken, grant.account, grant.body); status != http.StatusCreated {
				t.Fatalf("grant: %d", status)
			}
		}
	}
	return s
}

func (s communityFundingFixture) request() PaymentIntentRequest {
	return PaymentIntentRequest{CommunityProjectID: s.project.ID, PaymentMethod: "TEST", Debuglets: []DebugletRequest{iaDebuglet(1, 1000, 2000)}}
}

type communityFundingIntent struct {
	Method   string      `json:"method"`
	Currency string      `json:"currency"`
	Intent   DummyIntent `json:"intent"`
}

func (s communityFundingFixture) intent(t *testing.T, request PaymentIntentRequest) communityFundingIntent {
	t.Helper()
	var response communityFundingIntent
	communityRequest(t, s.f, s.memberToken, http.MethodPut, "/payment/intent", request, http.StatusOK, &response)
	if response.Method != "COMMUNITY" || response.Currency != "TEST" || response.Intent.TransactionID == "" {
		t.Fatalf("funding response: %+v", response)
	}
	return response
}

func (s communityFundingFixture) assertAllowances(t *testing.T, owner, member wire.Allowance) {
	t.Helper()
	for _, want := range []struct {
		token     string
		allowance wire.Allowance
	}{{s.ownerToken, owner}, {s.memberToken, member}} {
		if status, _, got := alAllowance(t, s.f, want.token); status != http.StatusOK || got != want.allowance {
			t.Fatalf("allowance %d: %+v, want %+v", status, got, want.allowance)
		}
	}
}

func TestCommunityFundingIntentKeepsActorAndSponsorSeparate(t *testing.T) {
	s := newCommunityFundingFixture(t, true)
	request := s.request()
	response := s.intent(t, request)
	s.assertAllowances(t, alWant("5000", "2000", "0", "3000"), alWant("3000", "0", "0", "3000"))
	actor, err := s.f.queries.GetTransactionOwnerUUID(t.Context(), response.Intent.TransactionID)
	if err != nil || actor.String() != s.memberID {
		t.Fatalf("intent owner: %s, %v", actor, err)
	}
	var wallet communityWalletResponse
	communityRequest(t, s.f, s.memberToken, http.MethodGet, "/communities/"+s.community.ID+"/wallet", nil, 200, &wallet)
	if !wallet.Enabled || wallet.Currency != "TEST" || wallet.Funded != "5000" || wallet.Reserved != "2000" || wallet.Available != "3000" {
		t.Fatalf("wallet: %+v", wallet)
	}
	var project, sponsor, recordedActor string
	if err := s.f.db.QueryRow(`SELECT f.project_id,s.uuid,a.uuid FROM community_funding f
JOIN users s ON s.id=f.sponsor_user_id JOIN users a ON a.id=f.actor_user_id WHERE f.transaction_id=?`,
		response.Intent.TransactionID).Scan(&project, &sponsor, &recordedActor); err != nil {
		t.Fatal(err)
	}
	if project != s.project.ID || sponsor != s.ownerID || recordedActor != s.memberID {
		t.Fatalf("funding attribution: %s %s %s", project, sponsor, recordedActor)
	}
	var ids []string
	communityRequest(t, s.f, s.memberToken, http.MethodPut, "/debuglet", SubmitDebugletsRequest{
		Debuglets: request.Debuglets, TransactionId: response.Intent.TransactionID, AuthKey: response.Intent.AuthKey,
	}, 200, &ids)
	if len(ids) != 1 || iaCount(t, s.f.db, "community_measurements") != 1 {
		t.Fatal("sponsored run was not admitted and shared")
	}
}

func TestCommunityFundingRejectsOutsidersAndRemovedMembers(t *testing.T) {
	s := newCommunityFundingFixture(t, true)
	request := s.request()
	before := ecRowCounts(t, s.f)
	communityRequest(t, s.f, s.outsiderToken, http.MethodPut, "/payment/intent", request, 404, nil)
	communityRequest(t, s.f, s.outsiderToken, http.MethodGet, "/communities/"+s.community.ID+"/wallet", nil, 404, nil)
	if after := ecRowCounts(t, s.f); !reflect.DeepEqual(before, after) {
		t.Fatalf("outsider wrote payment rows: %v -> %v", before, after)
	}
	response := s.intent(t, request)
	submission := SubmitDebugletsRequest{Debuglets: request.Debuglets, TransactionId: response.Intent.TransactionID, AuthKey: response.Intent.AuthKey}
	communityRequest(t, s.f, s.outsiderToken, http.MethodPut, "/debuglet", submission, 401, nil)
	communityRequest(t, s.f, s.ownerToken, http.MethodDelete, "/communities/"+s.community.ID+"/members/"+s.memberID, nil, 204, nil)
	before = ecRowCounts(t, s.f)
	communityRequest(t, s.f, s.memberToken, http.MethodPut, "/debuglet", submission, 404, nil)
	communityRequest(t, s.f, s.memberToken, http.MethodPut, "/payment/intent", request, 404, nil)
	if after := ecRowCounts(t, s.f); !reflect.DeepEqual(before, after) {
		t.Fatalf("removed member wrote payment rows: %v -> %v", before, after)
	}
	changed, err := s.f.queries.ClaimDebugletOrder(t.Context(), database.ClaimDebugletOrderParams{
		TransactionID: response.Intent.TransactionID, OrderID: request.Debuglets[0].OrderID,
		DebugletID: sql.NullInt64{}, PaidStatus: int64(models.Paid), OutstandingState: int64(models.Outstanding),
	})
	if err != nil || changed != 0 {
		t.Fatalf("SQL admission ignored membership removal: %d, %v", changed, err)
	}
}

func TestCommunityFundingSavedProgramMismatchRollsBack(t *testing.T) {
	s := newCommunityFundingFixture(t, true)
	wf := communityTestWorkflow()
	program, err := workflow.Generate(wf)
	if err != nil {
		t.Fatal(err)
	}
	var saved wire.CommunityExperiment
	communityRequest(t, s.f, s.ownerToken, http.MethodPost, "/community-projects/"+s.project.ID+"/experiments",
		communityExperimentRequest{Name: "Shared HTTP", Kind: "workflow", Document: communityTestJSON(t, wf),
			Bundle: communityTestJSON(t, communityTestBundle(t, wf, program))}, 201, &saved)
	request := s.request()
	request.CommunityExperimentID, request.CommunityExperimentRevision = saved.ID, &saved.Revision
	before := ecRowCounts(t, s.f)
	var envelope ErrorResponse
	communityRequest(t, s.f, s.memberToken, http.MethodPut, "/payment/intent", request, 400, &envelope)
	if envelope.Code != CodeIntentMismatch {
		t.Fatalf("mismatch code: %s", envelope.Code)
	}
	if after := ecRowCounts(t, s.f); !reflect.DeepEqual(before, after) || iaCount(t, s.f.db, "community_funding") != 0 || iaCount(t, s.f.db, "community_measurements") != 0 {
		t.Fatalf("mismatch retained payment rows: %v -> %v", before, after)
	}
	s.assertAllowances(t, alWant("5000", "0", "0", "5000"), alWant("3000", "0", "0", "3000"))
}

func TestCommunityFundingDisabledAllowanceCreatesNoCredits(t *testing.T) {
	s := newCommunityFundingFixture(t, false)
	var wallet communityWalletResponse
	communityRequest(t, s.f, s.memberToken, http.MethodGet, "/communities/"+s.community.ID+"/wallet", nil, 200, &wallet)
	if wallet.Enabled || wallet.Funded != "0" || wallet.Available != "0" {
		t.Fatalf("disabled allowance shown as usable money: %+v", wallet)
	}
	before := ecRowCounts(t, s.f)
	var envelope ErrorResponse
	communityRequest(t, s.f, s.memberToken, http.MethodPut, "/payment/intent", s.request(), 503, &envelope)
	if envelope.Code != CodeUnavailable {
		t.Fatalf("disabled allowance code: %s", envelope.Code)
	}
	if after := ecRowCounts(t, s.f); !reflect.DeepEqual(before, after) || iaCount(t, s.f.db, "allowance_grants") != 0 {
		t.Fatalf("disabled allowance created credit: %v -> %v", before, after)
	}
}

func TestCommunityFundingDepositCannotBeSubmittedOrDiscovered(t *testing.T) {
	s := newCommunityFundingFixture(t, true)
	id := uuid.NewString()
	if _, err := s.f.queries.CreateTransaction(t.Context(), database.CreateTransactionParams{
		ID: id, AuthKey: "deposit-key", Price: 7, Currency: "USDC", Method: "SUI",
		ExpiresAt: models.NewUTCTime(time.Now().Add(time.Hour)), Status: int64(models.Paid), Hash: "community-deposit:" + s.community.ID,
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.f.queries.SetTransactionOwner(t.Context(), database.SetTransactionOwnerParams{TransactionID: id, Uuid: uuid.MustParse(s.ownerID)}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.f.db.Exec(`INSERT INTO community_topups(transaction_id,community_id,created_by,refund_address,network,coin_type)
SELECT ?,?,id,'0x1','testnet','test-coin' FROM users WHERE uuid=?`, id, s.community.ID, s.ownerID); err != nil {
		t.Fatal(err)
	}
	body := SubmitDebugletsRequest{Debuglets: s.request().Debuglets, TransactionId: id, AuthKey: "deposit-key"}
	var refusal ErrorResponse
	communityRequest(t, s.f, s.ownerToken, http.MethodPut, "/debuglet", body, 400, &refusal)
	if refusal.Code != CodeIntentMismatch {
		t.Fatalf("deposit refusal: %+v", refusal)
	}
	var known, unknown ErrorResponse
	communityRequest(t, s.f, s.outsiderToken, http.MethodPut, "/debuglet", body, 401, &known)
	body.TransactionId = uuid.NewString()
	communityRequest(t, s.f, s.outsiderToken, http.MethodPut, "/debuglet", body, 401, &unknown)
	if !reflect.DeepEqual(known, unknown) {
		t.Fatalf("foreign deposit differs from unknown: %+v / %+v", known, unknown)
	}
	if iaCount(t, s.f.db, "debuglets") != 0 {
		t.Fatal("deposit admitted a run")
	}
}

func TestCommunityFundingUSDCSubmissionHonorsDisabledChain(t *testing.T) {
	s := newCommunityFundingFixture(t, true)
	request := s.request()
	response := s.intent(t, request)
	if _, err := s.f.db.Exec("UPDATE transactions SET method='COMMUNITY',currency='USDC' WHERE id=?", response.Intent.TransactionID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.f.db.Exec("UPDATE community_funding SET currency='USDC' WHERE transaction_id=?", response.Intent.TransactionID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.f.db.Exec("UPDATE debuglet_order SET currency='USDC' WHERE transaction_id=?", response.Intent.TransactionID); err != nil {
		t.Fatal(err)
	}
	var refusal ErrorResponse
	communityRequest(t, s.f, s.memberToken, http.MethodPut, "/debuglet", SubmitDebugletsRequest{
		Debuglets: request.Debuglets, TransactionId: response.Intent.TransactionID, AuthKey: response.Intent.AuthKey,
	}, 503, &refusal)
	if refusal.Code != CodePaymentsDisabled {
		t.Fatalf("sponsored USDC classified incorrectly: %+v", refusal)
	}
	if iaCount(t, s.f.db, "debuglets") != 0 {
		t.Fatal("disabled USDC admitted a run")
	}
}

func TestCommunityFundingHistoryLimitRollsBackAndExpiredIntentReleasesSlot(t *testing.T) {
	s := newCommunityFundingFixture(t, true)
	request := s.request()
	first := s.intent(t, request)
	tx, err := s.f.db.BeginTx(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	// Fill the remaining history with zero-price pending intents, without
	// spending the sponsor's grant or relying on admission-rate limits.
	if _, err := tx.Exec(`WITH RECURSIVE n(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM n WHERE x<1023)
INSERT INTO transactions(id,auth_key,price,currency,method,expires_at,status,hash)
SELECT 'history-'||x,'',0,'TEST','TEST',?,?,'history' FROM n`,
		models.NewUTCTime(time.Now().Add(time.Hour)), models.Paid); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(`INSERT INTO transaction_users(transaction_id,user_id)
SELECT t.id,u.id FROM transactions t JOIN users u ON u.uuid=? WHERE t.id LIKE 'history-%'`, s.memberID); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(`INSERT INTO community_funding(transaction_id,community_id,project_id,sponsor_user_id,actor_user_id,currency,network)
SELECT t.id,?,?,o.id,a.id,'TEST','' FROM transactions t JOIN users o ON o.uuid=? JOIN users a ON a.uuid=?
WHERE t.id LIKE 'history-%'`, s.community.ID, s.project.ID, s.ownerID, s.memberID); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(`INSERT INTO debuglet_order(transaction_id,order_id,executor_id,price,currency,state,refund_address)
SELECT id,1,?,0,'TEST',?,'' FROM transactions WHERE id LIKE 'history-%'`, ccExecutorID, models.Outstanding); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(`INSERT INTO community_measurements(project_id,measurement_id,shared_by,shared_at)
SELECT ?,t.id,u.id,unixepoch() FROM transactions t JOIN users u ON u.uuid=? WHERE t.id LIKE 'history-%'`, s.project.ID, s.memberID); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	before := ecRowCounts(t, s.f)
	communityRequest(t, s.f, s.memberToken, http.MethodPut, "/payment/intent", request, 409, nil)
	if after := ecRowCounts(t, s.f); !reflect.DeepEqual(before, after) || iaCount(t, s.f.db, "community_funding") != 1024 || iaCount(t, s.f.db, "community_measurements") != 1024 {
		t.Fatalf("full history retained refused reservation: %v -> %v", before, after)
	}
	s.assertAllowances(t, alWant("5000", "2000", "0", "3000"), alWant("3000", "0", "0", "3000"))
	if _, err := s.f.db.Exec("UPDATE transactions SET expires_at=? WHERE id=?",
		models.NewUTCTime(time.Now().Add(-time.Hour)), first.Intent.TransactionID); err != nil {
		t.Fatal(err)
	}
	s.intent(t, request)
	if iaCount(t, s.f.db, "community_measurements") != 1024 {
		t.Fatal("expired intent failed to release its history slot")
	}
	var retained int
	if err := s.f.db.QueryRow("SELECT COUNT(*) FROM community_measurements WHERE measurement_id=?", first.Intent.TransactionID).Scan(&retained); err != nil || retained != 0 {
		t.Fatalf("expired unadmitted measurement retained: %d, %v", retained, err)
	}
	var expired ErrorResponse
	communityRequest(t, s.f, s.memberToken, http.MethodPut, "/debuglet", SubmitDebugletsRequest{
		Debuglets: request.Debuglets, TransactionId: first.Intent.TransactionID, AuthKey: first.Intent.AuthKey,
	}, 400, &expired)
	if expired.Code != CodePaymentIncomplete {
		t.Fatalf("expired intent remains uploadable: %+v", expired)
	}
	s.assertAllowances(t, alWant("5000", "2000", "0", "3000"), alWant("3000", "0", "0", "3000"))
}
