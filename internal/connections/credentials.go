package connections

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/netsec-ethz/debuglet/internal/fsutil"
)

// ErrCredentialEndpointMismatch means a saved session belongs to a different
// endpoint than the profile now selects. Callers may forget it locally, but
// must never present it to the newly selected endpoint.
var ErrCredentialEndpointMismatch = errors.New("stored credential belongs to another dispatcher endpoint")

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
	Token     string `json:"token,omitempty"`
	Storage   string `json:"storage,omitempty"`
	SecretID  string `json:"secret_id,omitempty"`
	ExpiresAt int64  `json:"expires_at,omitempty"`
	AccountID string `json:"account_id,omitempty"`
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
	if store.SchemaVersion != 1 && store.SchemaVersion != 2 {
		return CredentialStore{}, errors.New("unsupported credential file schema")
	}
	if store.Credentials == nil {
		store.Credentials = map[string]Credential{}
	}
	for name, credential := range store.Credentials {
		if err := ValidateName(name); err != nil {
			return CredentialStore{}, err
		}
		if credential.Storage == "system" {
			id, err := hex.DecodeString(credential.SecretID)
			if store.SchemaVersion != 2 || err != nil || len(id) != 32 || credential.Token != "" || credential.Endpoint == "" {
				return CredentialStore{}, errors.New("invalid system credential metadata")
			}
		} else if credential.Storage != "" || credential.SecretID != "" {
			return CredentialStore{}, errors.New("unsupported credential storage")
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
	store.SchemaVersion = 1
	for _, credential := range store.Credentials {
		if credential.Storage == "system" {
			store.SchemaVersion = 2
		}
	}
	data, err := json.MarshalIndent(store, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(file), 0700); err != nil {
		return err
	}
	// The mode is set explicitly, independent of the process umask.
	return fsutil.WriteFile(file, append(data, '\n'), CredentialFileMode)
}

// SaveCredential records the credential of one profile, replacing its own.
func SaveCredential(path, name string, credential Credential) error {
	_, err := SaveCredentialWithStorage(context.Background(), path, name, credential, "file")
	return err
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
	credential, found := store.Credentials[name]
	if !found {
		return nil
	}
	delete(store.Credentials, name)
	if err := writeCredentials(path, store); err != nil {
		return err
	}
	if credential.Storage == "system" {
		if _, err := secretTool(context.Background(), "clear", credential.SecretID, nil); err != nil {
			return errors.New("local profile cleared, but system secret cleanup failed; remove the Debuglet CLI entry from your desktop keyring and revoke it from the console Credentials page")
		}
	}
	return nil
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
func CredentialFor(ctx context.Context, path, name, endpoint string) (Credential, error) {
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
		return Credential{}, fmt.Errorf("%w: the stored credential for %q was issued for another dispatcher endpoint; run dbl login", ErrCredentialEndpointMismatch, name)
	}
	if credential.Storage == "system" {
		credential.Token, err = loadSystemCredential(ctx, path, name, credential)
		if err != nil {
			return Credential{}, err
		}
	}
	return credential, nil
}
