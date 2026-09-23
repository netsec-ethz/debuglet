package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/netsec-ethz/debuglet/internal/connections"
)

// The installed CLI and the Go SDK against a dispatcher that enforces
// authentication: an account is registered and logged in once, the whole
// wallet-free workflow then runs as that account, and no command output, error
// or receipt repeats the credential it used.

// authCLIIssuedFile is where dbl login --register stores one of a new account's
// credentials when the operator names no file.
func authCLIIssuedFile(config, name string) string {
	return filepath.Join(filepath.Dir(config), name)
}

// authCLICredential reads the stored credential of one profile.
func authCLICredential(t *testing.T, config, profile string) connections.Credential {
	t.Helper()
	store, err := connections.LoadCredentials(config)
	if err != nil {
		t.Fatalf("load credentials: %v", err)
	}
	credential, found := store.Credentials[profile]
	if !found {
		t.Fatalf("no credential stored for %q", profile)
	}
	return credential
}

// authCLINoSecret fails when any of the given outputs repeats a credential.
func authCLINoSecret(t *testing.T, what string, secrets []string, outputs ...[]byte) {
	t.Helper()
	for _, secret := range secrets {
		if strings.TrimSpace(secret) == "" {
			continue
		}
		for _, output := range outputs {
			if strings.Contains(string(output), secret) {
				t.Fatalf("%s repeated a credential in its output: %s", what, output)
			}
		}
	}
}

// TestAuthenticatedCLIWorkflow drives the installed dbl against a dispatcher
// that enforces authentication: connect, register, login, discover nodes,
// submit, read the owned result, cancel, and log out. It also covers what must
// never happen on the way: a credential in command output or in a receipt, a
// credential sent to another dispatcher, and a silent failure after logout.
func TestAuthenticatedCLIWorkflow(t *testing.T) {
	f := ccNewFixtureWith(t)
	f.dbl = ccBuildCLI(t)
	home := t.TempDir()
	config := filepath.Join(home, "debuglet", "config.json")
	wasm := filepath.Join(home, "guest.wasm")
	if err := os.WriteFile(wasm, ccGuest, 0o600); err != nil {
		t.Fatalf("write guest: %v", err)
	}

	code, _, stderr := f.runCLI("--config", config, "connect", f.root.URL, "--name", "local")
	if code != 0 {
		t.Fatalf("dbl connect exit %d: %s", code, stderr)
	}

	// Before a credential exists, a command that needs one says what to do
	// rather than failing obscurely.
	code, stdout, stderr := f.runCLI("--config", config, "--dispatcher", "local", "run",
		"--wasm", wasm, "--executor", ccExecutorID, "--duration", "2s", "--floor-bps", "0", "--ceil-bps", "0")
	if code == 0 {
		t.Fatalf("dbl run without a credential succeeded: %s", stdout)
	}
	if !strings.Contains(string(stderr), "dbl login") {
		t.Fatalf("dbl run without a credential did not name the action: %s", stderr)
	}

	// Registering an account issues its credentials. The command prints
	// neither of them; the recovery code goes to an owner-only file.
	code, stdout, stderr = f.runCLI("--config", config, "--dispatcher", "local", "login", "--register", "researcher")
	if code != 0 {
		t.Fatalf("dbl login --register exit %d: %s", code, stderr)
	}
	credential := authCLICredential(t, config, "local")
	if credential.Token == "" || credential.Endpoint != f.root.URL {
		t.Fatalf("stored credential %+v, want a token bound to %s", credential.Endpoint, f.root.URL)
	}
	secrets := []string{credential.Token}

	// Both issued credentials are on disk, owner-only, and neither was printed.
	accountKeyPath := authCLIIssuedFile(config, "account-key-local.txt")
	recoveryPath := authCLIIssuedFile(config, "recovery-local.txt")
	for _, path := range []string{accountKeyPath, recoveryPath} {
		issued, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		if strings.TrimSpace(string(issued)) == "" {
			t.Fatalf("%s is empty", path)
		}
		secrets = append(secrets, strings.TrimSpace(string(issued)))
		authCLIAssertPrivate(t, path)
	}
	authCLINoSecret(t, "dbl login", secrets, stdout, stderr)

	// The credential store keeps the session and nothing else: a copy of it
	// must not be permanent access to the account.
	credentialFile, err := connections.CredentialPath(config)
	if err != nil {
		t.Fatalf("credential path: %v", err)
	}
	authCLIAssertPrivate(t, credentialFile)
	stored, err := os.ReadFile(credentialFile)
	if err != nil {
		t.Fatalf("read the credential file: %v", err)
	}
	accountKey := strings.TrimSpace(string(mustRead(t, accountKeyPath)))
	if strings.Contains(string(stored), accountKey) {
		t.Fatal("the credential file holds the account key")
	}

	// Registering again must not overwrite credentials someone still relies on.
	code, _, stderr = f.runCLI("--config", config, "--dispatcher", "local", "login", "--register", "second")
	if code == 0 || !strings.Contains(string(stderr), "already exists") {
		t.Fatalf("a second registration overwrote the stored credentials: exit %d: %s", code, stderr)
	}

	// The endpoint metadata a profile listing prints stays free of secrets.
	code, stdout, stderr = f.runCLI("--config", config, "--output", "json", "dispatcher", "list")
	if code != 0 {
		t.Fatalf("dbl dispatcher list exit %d: %s", code, stderr)
	}
	if !strings.Contains(string(stdout), f.root.URL) {
		t.Fatalf("dbl dispatcher list does not show the endpoint: %s", stdout)
	}
	authCLINoSecret(t, "dbl dispatcher list", secrets, stdout, stderr)

	// Discovery, submission, the owned result and cancellation, all as the
	// authenticated account.
	code, stdout, stderr = f.runCLI("--config", config, "--dispatcher", "local", "--output", "json", "executor", "list")
	if code != 0 {
		t.Fatalf("dbl executor list exit %d: %s", code, stderr)
	}
	if !strings.Contains(string(stdout), ccExecutorID) {
		t.Fatalf("dbl executor list did not report the executor: %s", stdout)
	}

	f.peer.setUploadHook(nil)
	code, stdout, stderr = f.runCLI("--config", config, "--dispatcher", "local", "--output", "json", "run",
		"--wasm", wasm, "--executor", ccExecutorID, "--allow", "127.0.0.1", "--duration", "2s",
		"--floor-bps", fmt.Sprint(ccFloorBW), "--ceil-bps", fmt.Sprint(ccFloorBW))
	if code != 0 {
		t.Fatalf("dbl run exit %d: %s", code, stderr)
	}
	ccAssertNoAuthKey(t, "dbl run", stdout, stderr)
	authCLINoSecret(t, "dbl run receipt", secrets, stdout, stderr)
	var receipt struct {
		ID            string `json:"id"`
		TransactionID string `json:"transaction_id"`
		State         string `json:"state"`
	}
	ccDecode(t, "dbl run", stdout, &receipt)
	if receipt.ID == "" || receipt.State != "submitted" {
		t.Fatalf("receipt %+v", receipt)
	}

	code, stdout, stderr = f.runCLI("--config", config, "--dispatcher", "local", "--output", "json", "status", receipt.ID)
	if code != 0 {
		t.Fatalf("dbl status exit %d: %s", code, stderr)
	}
	authCLINoSecret(t, "dbl status", secrets, stdout, stderr)

	code, _, stderr = f.runCLI("--config", config, "--dispatcher", "local", "logs", "--limit", "5", receipt.ID)
	if code != 0 {
		t.Fatalf("dbl logs exit %d: %s", code, stderr)
	}

	f.peer.setAbortHook(nil)
	code, _, stderr = f.runCLI("--config", config, "--dispatcher", "local", "cancel", receipt.ID)
	if code != 0 {
		t.Fatalf("dbl cancel exit %d: %s", code, stderr)
	}

	t.Run("a credential is never sent to another dispatcher", func(t *testing.T) {
		// A second saved connection at another origin has no credential of its
		// own, so it is served as an anonymous request rather than with the
		// first connection's token.
		code, _, stderr := f.runCLI("--config", config, "connect", f.prefix.URL+"/api", "--name", "other")
		if code != 0 {
			t.Fatalf("dbl connect other exit %d: %s", code, stderr)
		}
		code, stdout, stderr := f.runCLI("--config", config, "--dispatcher", "other", "status", receipt.ID)
		if code == 0 {
			t.Fatalf("the second connection reached the first's run: %s", stdout)
		}
		if !strings.Contains(string(stderr), "dbl login") {
			t.Fatalf("the second connection did not report an authentication failure: %s", stderr)
		}
		if _, found := authCLICredentialMaybe(t, config, "other"); found {
			t.Fatal("connecting a second dispatcher copied a credential to it")
		}
	})

	t.Run("a credential recorded for another endpoint is refused", func(t *testing.T) {
		// Rewriting the profile's endpoint must not make the stored token
		// travel with it.
		moved := authCLIRewriteEndpoint(t, config, "local", f.prefix.URL+"/api")
		defer moved()
		code, stdout, stderr := f.runCLI("--config", config, "--dispatcher", "local", "status", receipt.ID)
		if code == 0 {
			t.Fatalf("a moved endpoint kept using the stored credential: %s", stdout)
		}
		if !strings.Contains(string(stderr), "issued for another dispatcher endpoint") {
			t.Fatalf("the mismatch was not reported: %s", stderr)
		}
	})

	t.Run("logout revokes the session and forgets it", func(t *testing.T) {
		code, stdout, stderr := f.runCLI("--config", config, "--dispatcher", "local", "logout")
		if code != 0 {
			t.Fatalf("dbl logout exit %d: %s", code, stderr)
		}
		authCLINoSecret(t, "dbl logout", secrets, stdout, stderr)
		if _, found := authCLICredentialMaybe(t, config, "local"); found {
			t.Fatal("dbl logout kept the credential")
		}
		// The revoked session is refused even when it is presented directly,
		// so logging out is not merely a local forget.
		if status, _ := authAs(t, f, credential.Token, http.MethodGet, "/me", nil); status != http.StatusUnauthorized {
			t.Fatalf("the revoked session still authenticates: %d", status)
		}
		// And the next command that needs a credential says what to do.
		code, stdout, stderr = f.runCLI("--config", config, "--dispatcher", "local", "status", receipt.ID)
		if code == 0 {
			t.Fatalf("a command after logout succeeded: %s", stdout)
		}
		if !strings.Contains(string(stderr), "dbl login") {
			t.Fatalf("the failure after logout is not actionable: %s", stderr)
		}
	})
}

// mustRead reads one file the test has already created.
func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return data
}

// authCLICredentialMaybe reports whether a profile has a stored credential.
func authCLICredentialMaybe(t *testing.T, config, profile string) (connections.Credential, bool) {
	t.Helper()
	store, err := connections.LoadCredentials(config)
	if err != nil {
		t.Fatalf("load credentials: %v", err)
	}
	credential, found := store.Credentials[profile]
	return credential, found
}

// authCLIAssertPrivate fails when a file holding a credential is readable by
// anyone but its owner.
func authCLIAssertPrivate(t *testing.T, path string) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	if info.Mode().Perm() != connections.CredentialFileMode {
		t.Fatalf("%s has mode %v, want %v", path, info.Mode().Perm(), connections.CredentialFileMode)
	}
}

// authCLIRewriteEndpoint points a saved profile at another endpoint and
// returns a function restoring the original file.
func authCLIRewriteEndpoint(t *testing.T, config, profile, endpoint string) func() {
	t.Helper()
	original, err := os.ReadFile(config)
	if err != nil {
		t.Fatalf("read the connections file: %v", err)
	}
	var stored connections.Config
	if err := json.Unmarshal(original, &stored); err != nil {
		t.Fatalf("decode the connections file: %v", err)
	}
	for i := range stored.Dispatchers {
		if stored.Dispatchers[i].Name == profile {
			stored.Dispatchers[i].Endpoint = endpoint
		}
	}
	rewritten, err := json.MarshalIndent(stored, "", "  ")
	if err != nil {
		t.Fatalf("encode the connections file: %v", err)
	}
	if err := os.WriteFile(config, append(rewritten, '\n'), 0o600); err != nil {
		t.Fatalf("write the connections file: %v", err)
	}
	return func() {
		if err := os.WriteFile(config, original, 0o600); err != nil {
			t.Fatalf("restore the connections file: %v", err)
		}
	}
}
