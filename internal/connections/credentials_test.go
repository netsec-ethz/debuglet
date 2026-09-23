package connections

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Credentials live beside the endpoint metadata but never in it: a profile
// listing, an endpoint diagnostic and a receipt all repeat an endpoint, and
// none of them may repeat a secret. These tests pin that separation, the file
// permissions and the rule that a credential only goes to the dispatcher it
// was issued for.

const (
	credTestEndpoint = "http://127.0.0.1:9000"
	credTestOther    = "http://127.0.0.2:9000"
	credTestToken    = "dbs_selector.verifier"
)

func credTestConfig(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "debuglet", "config.json")
}

// savedCredential is a fresh configuration whose "local" profile already holds
// the fixture credential, which is the starting state of most of these tests.
func savedCredential(t *testing.T) (config, file string) {
	t.Helper()
	config = credTestConfig(t)
	if err := SaveCredential(config, "local", Credential{Endpoint: credTestEndpoint, Token: credTestToken}); err != nil {
		t.Fatalf("SaveCredential: %v", err)
	}
	file, err := CredentialPath(config)
	if err != nil {
		t.Fatalf("CredentialPath: %v", err)
	}
	return config, file
}

func TestCredentialsAreStoredPrivatelyBesideTheConnections(t *testing.T) {
	config, file := savedCredential(t)
	if filepath.Dir(file) != filepath.Dir(config) || filepath.Base(file) != CredentialFileName {
		t.Fatalf("credential file %s is not %s beside %s", file, CredentialFileName, config)
	}
	info, err := os.Stat(file)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if info.Mode().Perm() != CredentialFileMode {
		t.Fatalf("credential file mode %v, want %v", info.Mode().Perm(), CredentialFileMode)
	}

	// The connections file is the endpoint metadata and holds no secret.
	if err := Save(config, Profile{Name: "local", Endpoint: credTestEndpoint}, true); err != nil {
		t.Fatalf("Save: %v", err)
	}
	connections, err := os.ReadFile(config)
	if err != nil {
		t.Fatalf("read the connections file: %v", err)
	}
	if strings.Contains(string(connections), credTestToken) {
		t.Fatalf("the connections file holds a credential: %s", connections)
	}
}

func TestCredentialFileReadableByOthersIsRefused(t *testing.T) {
	config, file := savedCredential(t)
	if err := os.Chmod(file, 0644); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	if _, err := LoadCredentials(config); err == nil {
		t.Fatal("a world-readable credential file was accepted")
	} else if !strings.Contains(err.Error(), "chmod 600") {
		t.Fatalf("the refusal does not name the fix: %v", err)
	}
}

func TestCredentialGoesOnlyToTheEndpointItWasIssuedFor(t *testing.T) {
	config, _ := savedCredential(t)
	credential, err := CredentialFor(config, "local", credTestEndpoint)
	if err != nil {
		t.Fatalf("CredentialFor: %v", err)
	}
	if credential.Token != credTestToken {
		t.Fatalf("the credential of its own endpoint was not returned: %+v", credential)
	}

	// The same profile pointed at another dispatcher: the token stays put and
	// the caller is told why.
	if _, err := CredentialFor(config, "local", credTestOther); err == nil {
		t.Fatal("a credential was offered to another endpoint")
	} else if !strings.Contains(err.Error(), "another dispatcher endpoint") {
		t.Fatalf("the refusal is not actionable: %v", err)
	}

	// Another profile has its own credential or none; it never inherits one.
	other, err := CredentialFor(config, "other", credTestEndpoint)
	if err != nil {
		t.Fatalf("CredentialFor(other): %v", err)
	}
	if other.Token != "" {
		t.Fatalf("a profile without a credential received %+v", other)
	}

	// An endpoint the operator named directly belongs to no saved connection,
	// so it presents no credential at all.
	unnamed, err := CredentialFor(config, "", credTestEndpoint)
	if err != nil {
		t.Fatalf("CredentialFor(no name): %v", err)
	}
	if unnamed.Token != "" {
		t.Fatalf("an endpoint without a saved connection received %+v", unnamed)
	}
}

// TestCredentialForWithoutASavedConnectionReadsNothing covers the environment
// the installed acceptance run gives the CLI: no $XDG_CONFIG_HOME and no
// $HOME, so the client configuration directory cannot be located at all. A
// lookup that has no saved connection to look up must not try.
func TestCredentialForWithoutASavedConnectionReadsNothing(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", "")
	t.Setenv("HOME", "")
	if _, err := os.UserConfigDir(); err == nil {
		t.Skip("this platform locates a configuration directory without HOME")
	}
	// The default path is deliberately used: an unnamed lookup must not even
	// resolve it.
	credential, err := CredentialFor("", "", credTestEndpoint)
	if err != nil {
		t.Fatalf("CredentialFor without a saved connection: %v", err)
	}
	if credential.Token != "" {
		t.Fatalf("an unnamed lookup produced %+v", credential)
	}
	// A named lookup does need the directory and says so.
	if _, err := CredentialFor("", "local", credTestEndpoint); err == nil {
		t.Fatal("a named lookup resolved without a configuration directory")
	}
}

func TestRemoveCredentialForgetsOnlyThatProfile(t *testing.T) {
	config := credTestConfig(t)
	for _, name := range []string{"local", "lab"} {
		if err := SaveCredential(config, name, Credential{Endpoint: credTestEndpoint, Token: credTestToken + name}); err != nil {
			t.Fatalf("SaveCredential(%s): %v", name, err)
		}
	}
	if err := RemoveCredential(config, "local"); err != nil {
		t.Fatalf("RemoveCredential: %v", err)
	}
	store, err := LoadCredentials(config)
	if err != nil {
		t.Fatalf("LoadCredentials: %v", err)
	}
	if _, found := store.Credentials["local"]; found {
		t.Fatal("the removed credential is still stored")
	}
	if store.Credentials["lab"].Token == "" {
		t.Fatal("removing one credential forgot another")
	}
	// Forgetting what is not there is the state the caller asked for.
	if err := RemoveCredential(config, "local"); err != nil {
		t.Fatalf("second RemoveCredential: %v", err)
	}
}

func TestLoadCredentialsAcceptsAnAbsentFile(t *testing.T) {
	store, err := LoadCredentials(credTestConfig(t))
	if err != nil {
		t.Fatalf("LoadCredentials: %v", err)
	}
	if store.SchemaVersion != 1 || len(store.Credentials) != 0 {
		t.Fatalf("an absent credential file produced %+v", store)
	}
}

func TestIncompleteCredentialIsRefused(t *testing.T) {
	config := credTestConfig(t)
	for _, credential := range []Credential{
		{Token: credTestToken},
		{Endpoint: credTestEndpoint},
	} {
		if err := SaveCredential(config, "local", credential); err == nil {
			t.Fatalf("an incomplete credential was stored: %+v", credential)
		}
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(config), CredentialFileName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a refused credential created a file: %v", err)
	}
}
