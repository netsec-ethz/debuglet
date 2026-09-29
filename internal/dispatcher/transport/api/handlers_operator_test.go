// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package api

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/config"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/database"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/enrollment"
	pb "github.com/netsec-ethz/debuglet/protocol"
)

func operatorFixture(t *testing.T) (*ccFixture, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().AddDate(1, 0, 0)}
	der, err := x509.CreateCertificate(rand.Reader, ca, ca, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	privateDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	certFile, keyFile := filepath.Join(dir, "ca.pem"), filepath.Join(dir, "key.pem")
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER}), 0600); err != nil {
		t.Fatal(err)
	}
	signer, err := enrollment.NewSigner(certFile, keyFile, certFile)
	if err != nil {
		t.Fatal(err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if err != nil {
		t.Fatal(err)
	}
	f := ccNewFixtureWith(t, ExecutorOnboarding(config.ExecutorOnboardingConfig{
		Enabled: true, DispatcherURL: "https://dispatcher.example/api", GRPCAddress: "dispatcher.example:9001", YamuxAddress: "dispatcher.example:9000",
	}, signer))
	return f, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}))
}

func operatorRequest(t *testing.T, f *ccFixture, token, method, path string, payload any, want int, into any) {
	t.Helper()
	var body []byte
	if payload != nil {
		var err error
		body, err = json.Marshal(payload)
		if err != nil {
			t.Fatal(err)
		}
	}
	status, _, data, response := authRequest(t, f, method, path, body, authBearer(token))
	if status != want {
		t.Fatalf("%s %s: status %d, want %d: %s", method, path, status, want, data)
	}
	oaCheckResponse(t, oaContract(t), method, path, status, data)
	if into != nil {
		if err := json.Unmarshal(data, into); err != nil {
			t.Fatal(err)
		}
	}
	if strings.Contains(path, "enrollment") || method == http.MethodPost && path == "/operator/executors" {
		if status < 300 && response.Header.Get("Cache-Control") != "no-store" {
			t.Fatal("credential response is cacheable")
		}
	}
}

func TestOwnedExecutorEnrollmentAndRecovery(t *testing.T) {
	f, csr := operatorFixture(t)
	_, alice, _ := authAccount(t, f, "Alice")
	_, bob, _ := authAccount(t, f, "Bob")
	var setup ExecutorSetupResponse
	operatorRequest(t, f, alice, http.MethodPost, "/operator/executors", map[string]string{"name": " Alice's node "}, 201, &setup)
	id := setup.Executor.ID
	if _, err := uuid.Parse(id); err != nil {
		t.Fatal(err)
	}
	if setup.Executor.Name != "Alice's node" || setup.Executor.Status != "pending" || setup.Executor.Ready || setup.Token == "" || setup.ExpiresAt < time.Now().Add(23*time.Hour).Unix() {
		t.Fatalf("unexpected setup: %+v", setup.Executor)
	}
	var list OwnedExecutorsResponse
	operatorRequest(t, f, bob, http.MethodGet, "/operator/executors", nil, 200, &list)
	if !list.Enabled || len(list.Executors) != 0 {
		t.Fatalf("Bob saw other machines: %+v", list)
	}
	operatorRequest(t, f, bob, http.MethodPost, "/operator/executors/"+id+"/enrollment-token", nil, 404, nil)
	operatorRequest(t, f, alice, http.MethodGet, "/operator/executors", nil, 200, &list)
	if len(list.Executors) != 1 || list.Executors[0].ID != id {
		t.Fatalf("public inventory leaked into owned inventory: %+v", list)
	}
	request := map[string]string{"executor_id": id, "token": setup.Token, "csr": csr}
	var issued map[string]string
	operatorRequest(t, f, "", http.MethodPost, "/executor-enrollment", request, 200, &issued)
	block, _ := pem.Decode([]byte(issued["certificate_pem"]))
	if block == nil {
		t.Fatal("missing executor certificate")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if cert.Subject.CommonName != id || issued["executor_id"] != id || issued["ca_pem"] == "" || issued["grpc_address"] != "dispatcher.example:9001" || issued["yamux_address"] != "dispatcher.example:9000" {
		t.Fatal("wrong installed identity or addresses")
	}
	fingerprint := sha256.Sum256(cert.Raw)
	bound := hex.EncodeToString(fingerprint[:])
	store := enrollment.NewStore(f.db)
	if err := store.Bound(f.ctx, id, bound); err != nil {
		t.Fatalf("response did not commit binding: %v", err)
	}
	operatorRequest(t, f, "", http.MethodPost, "/executor-enrollment", request, 401, nil)
	operatorRequest(t, f, alice, http.MethodGet, "/operator/executors", nil, 200, &list)
	if list.Executors[0].Status != "offline" || list.Executors[0].Ready {
		t.Fatalf("issued certificate was reported connected: %+v", list)
	}

	// A new browser token recovers a lost installation response without
	// interrupting the old machine until the replacement actually enrolls.
	operatorRequest(t, f, alice, http.MethodPost, "/operator/executors/"+id+"/enrollment-token", nil, 200, &setup)
	if err := store.Bound(f.ctx, id, bound); err != nil {
		t.Fatalf("issuing replacement revoked working certificate: %v", err)
	}
	request["token"] = setup.Token
	operatorRequest(t, f, "", http.MethodPost, "/executor-enrollment", request, 200, nil)
	if err := store.Bound(f.ctx, id, bound); !errors.Is(err, enrollment.ErrWrongNode) {
		t.Fatalf("new installation did not replace old identity: %v", err)
	}

	owner := apiTestOwner(t, f.d, id)
	if err := apiTestRegister(f.ctx, f.d, owner, &pb.HelloResponse{ExecutorId: id, Version: "operator-test", Currency: "TEST"}, "127.0.0.1"); err != nil {
		t.Fatal(err)
	}
	if !owner.MarkRegistered() {
		t.Fatal("mark executor registered")
	}
	mutation := apiTestMutation(t, f.ctx, owner)
	_, err = f.d.OnHeartbeat(f.ctx, mutation, &pb.HeartbeatRequest{ExecutorId: id})
	mutation.Finish()
	if err != nil {
		t.Fatal(err)
	}
	operatorRequest(t, f, alice, http.MethodGet, "/operator/executors", nil, 200, &list)
	if list.Executors[0].Status != "online" || !list.Executors[0].Ready || list.Executors[0].Version != "operator-test" {
		t.Fatalf("connected executor not ready: %+v", list)
	}
}

func TestOwnedExecutorRefusalsAndQuota(t *testing.T) {
	f, csr := operatorFixture(t)
	_, alice, _ := authAccount(t, f, "Alice")
	operatorRequest(t, f, "", http.MethodPost, "/operator/executors", map[string]string{"name": "node"}, 401, nil)
	for _, name := range []string{"", "\n", strings.Repeat("a", 81), "node\x00name"} {
		operatorRequest(t, f, alice, http.MethodPost, "/operator/executors", map[string]string{"name": name}, 400, nil)
	}
	status, _ := authStatus(t, f, http.MethodPost, "/operator/executors", []byte(`{"name":"node"}`), map[string]string{"Cookie": sessionCookieName + "=" + alice})
	if status != http.StatusForbidden {
		t.Fatalf("cookie write without CSRF: %d", status)
	}
	var setup ExecutorSetupResponse
	for i := 0; i < 10; i++ {
		operatorRequest(t, f, alice, http.MethodPost, "/operator/executors", map[string]string{"name": "node"}, 201, &setup)
	}
	operatorRequest(t, f, alice, http.MethodPost, "/operator/executors", map[string]string{"name": "node"}, 409, nil)
	request := map[string]string{"executor_id": setup.Executor.ID, "token": setup.Token, "csr": "not a CSR"}
	operatorRequest(t, f, "", http.MethodPost, "/executor-enrollment", request, 400, nil)
	request["csr"], request["token"] = csr, "wrong-token"
	operatorRequest(t, f, "", http.MethodPost, "/executor-enrollment", request, 401, nil)
	request["token"] = setup.Token
	if _, err := f.db.ExecContext(f.ctx, "UPDATE executor_enrollment_tokens SET expires_at = ?", time.Now().Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	operatorRequest(t, f, "", http.MethodPost, "/executor-enrollment", request, 401, nil)
	account, _, _ := authAccount(t, f, "unrelated")
	rows, err := database.New(f.db).ListOwnedExecutors(f.ctx, uuid.MustParse(account.ID))
	if err != nil || len(rows) != 0 {
		t.Fatalf("ownership query: rows=%v err=%v", rows, err)
	}
}

func TestOwnedExecutorOnboardingDisabled(t *testing.T) {
	f := ccNewFixtureWith(t)
	_, account, _ := authAccount(t, f, "user")
	var list OwnedExecutorsResponse
	operatorRequest(t, f, account, http.MethodGet, "/operator/executors", nil, 200, &list)
	if list.Enabled || list.Executors == nil || len(list.Executors) != 0 || list.DispatcherURL != "" {
		t.Fatalf("disabled onboarding: %+v", list)
	}
	operatorRequest(t, f, account, http.MethodPost, "/operator/executors", map[string]string{"name": "node"}, 503, nil)
	operatorRequest(t, f, "", http.MethodPost, "/executor-enrollment", map[string]string{}, 503, nil)
}
