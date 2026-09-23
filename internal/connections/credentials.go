package connections

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
)

// Credentials are kept apart from the endpoint metadata in config.json: a
// profile listing, a receipt and a diagnostic may repeat an endpoint, and none
// of them may repeat a secret.

// CredentialFileName is the credential file, beside the connections file.
const CredentialFileName = "credentials.json"

// CredentialFileMode is the permission the credential file is written with and
// required to have; one readable by anyone else is refused rather than used.
const CredentialFileMode fs.FileMode = 0600

// maxCredentialFile bounds the credential file that is read.
const maxCredentialFile = 1 << 20

// Credential is what one CLI profile presents to one dispatcher. Endpoint
// records which dispatcher issued it, so it can never be sent to another one.
// Only the session is kept, so a copy of this file yields one expiring session
// rather than permanent access to the account.
type Credential struct {
	Endpoint  string `json:"endpoint"`
	Token     string `json:"token"`
	ExpiresAt int64  `json:"expires_at,omitempty"`
}

// CredentialStore is the on-disk credential file.
type CredentialStore struct {
	SchemaVersion int                   `json:"schema_version"`
	Credentials   map[string]Credential `json:"credentials"`
}

// CredentialPath returns the credential file beside the given connections
// file, or beside the default one when path is empty.
func CredentialPath(path string) (string, error) {
	resolved, err := configPath(path)
	if err != nil {
		return "", err
	}
	return filepath.Join(filepath.Dir(resolved), CredentialFileName), nil
}

// LoadCredentials reads the credential file. An absent file is an empty store;
// one other users can read is refused rather than used.
func LoadCredentials(path string) (CredentialStore, error) {
	empty := CredentialStore{SchemaVersion: 1, Credentials: map[string]Credential{}}
	file, err := CredentialPath(path)
	if err != nil {
		return CredentialStore{}, err
	}
	info, err := os.Stat(file)
	if errors.Is(err, os.ErrNotExist) {
		return empty, nil
	}
	if err != nil {
		return CredentialStore{}, err
	}
	if !info.Mode().IsRegular() || info.Size() > maxCredentialFile {
		return CredentialStore{}, errors.New("credential file must be a regular file no larger than 1 MiB")
	}
	if info.Mode().Perm()&^CredentialFileMode != 0 {
		return CredentialStore{}, fmt.Errorf("credential file %s is readable by other users; run: chmod 600 %s", file, file)
	}
	f, err := os.Open(file)
	if err != nil {
		return CredentialStore{}, err
	}
	defer f.Close()
	var store CredentialStore
	dec := json.NewDecoder(io.LimitReader(f, maxCredentialFile+1))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&store); err != nil {
		// The file holds secrets; its text never reaches a diagnostic.
		return CredentialStore{}, errors.New("invalid credential file JSON")
	}
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return CredentialStore{}, errors.New("trailing credential file JSON")
	}
	if store.SchemaVersion != 1 {
		return CredentialStore{}, errors.New("unsupported credential file schema")
	}
	if store.Credentials == nil {
		store.Credentials = map[string]Credential{}
	}
	for name := range store.Credentials {
		if err := ValidateName(name); err != nil {
			return CredentialStore{}, err
		}
	}
	return store, nil
}

// writeCredentials replaces the credential file atomically, owner-only.
func writeCredentials(path string, store CredentialStore) error {
	file, err := CredentialPath(path)
	if err != nil {
		return err
	}
	data, err := json.MarshalIndent(store, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(file), 0700); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(file), ".credentials-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	// CreateTemp is already owner-only; setting the mode explicitly keeps the
	// guarantee independent of that and of the process umask.
	chmodErr := f.Chmod(CredentialFileMode)
	_, writeErr := f.Write(append(data, '\n'))
	if err := errors.Join(chmodErr, writeErr, f.Close()); err != nil {
		return err
	}
	return os.Rename(f.Name(), file)
}

// SaveCredential records the credential of one profile, replacing its own.
func SaveCredential(path, name string, credential Credential) error {
	if err := ValidateName(name); err != nil {
		return err
	}
	if credential.Endpoint == "" || credential.Token == "" {
		return errors.New("a stored credential needs both its endpoint and its token")
	}
	store, err := LoadCredentials(path)
	if err != nil {
		return err
	}
	store.Credentials[name] = credential
	return writeCredentials(path, store)
}

// RemoveCredential forgets the credential of one profile. Forgetting one that
// is not there is the state the caller asked for, not an error.
func RemoveCredential(path, name string) error {
	if err := ValidateName(name); err != nil {
		return err
	}
	store, err := LoadCredentials(path)
	if err != nil {
		return err
	}
	if _, found := store.Credentials[name]; !found {
		return nil
	}
	delete(store.Credentials, name)
	return writeCredentials(path, store)
}

// CredentialFor returns the credential to present at endpoint for one saved
// connection. One recorded for a different endpoint is refused rather than
// sent, so selecting another profile can never deliver one dispatcher's
// credential to another origin; a connection with none stored yields an empty
// credential, because unauthenticated requests still reach a dispatcher
// serving the local development profile. An empty name is an endpoint the
// operator named directly, so nothing is looked up and the client
// configuration directory is not even located: commands that need no saved
// connection keep working where there is no such directory.
func CredentialFor(path, name, endpoint string) (Credential, error) {
	if name == "" {
		return Credential{}, nil
	}
	store, err := LoadCredentials(path)
	if err != nil {
		return Credential{}, err
	}
	credential, found := store.Credentials[name]
	if !found {
		return Credential{}, nil
	}
	if credential.Endpoint != endpoint {
		return Credential{}, fmt.Errorf("the stored credential for %q was issued for another dispatcher endpoint; run dbl login", name)
	}
	return credential, nil
}
