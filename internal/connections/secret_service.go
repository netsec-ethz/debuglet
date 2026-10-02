// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package connections

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"time"
)

// ResolveCredentialStorage selects the requested backend before login issues a
// credential. Auto falls back only when the desktop facility is absent.
func ResolveCredentialStorage(mode string) (string, error) {
	switch mode {
	case "file":
		return mode, nil
	case "auto", "system":
	default:
		return "", errors.New("credential store must be auto, system or file")
	}
	_, err := secretToolPath()
	if err == nil {
		return "system", nil
	}
	if mode == "system" {
		return "", err
	}
	return "file", nil
}

func secretToolPath() (string, error) {
	if runtime.GOOS == "linux" && os.Getenv("DBUS_SESSION_BUS_ADDRESS") != "" {
		if path, err := exec.LookPath("secret-tool"); err == nil {
			return path, nil
		}
	}
	return "", errors.New("system credential storage requires Linux, secret-tool and a desktop D-Bus session; use --credential-store file on a headless host")
}

// CredentialStorageResult describes a committed local login. Failure to remove
// an older secret is reported separately, since the replacement is already saved.
type CredentialStorageResult struct {
	Storage string
	Warning string
}

// SaveCredentialWithStorage saves a credential using the selected backend.
func SaveCredentialWithStorage(ctx context.Context, path, name string, credential Credential, storage string) (CredentialStorageResult, error) {
	result := CredentialStorageResult{Storage: storage}
	if err := ValidateName(name); err != nil {
		return result, err
	}
	if credential.Endpoint == "" || credential.Token == "" {
		return result, errors.New("a stored credential needs both its endpoint and its token")
	}
	if storage != "file" && storage != "system" {
		return result, errors.New("resolve the credential store before saving")
	}
	if err := ctx.Err(); err != nil {
		return result, err
	}
	store, err := LoadCredentials(path)
	if err != nil {
		return result, err
	}
	previous := store.Credentials[name]
	credential.Storage, credential.SecretID = "", ""
	if storage == "system" {
		binding, err := credentialBinding(path, name, credential)
		if err != nil {
			return result, err
		}
		payload, _ := json.Marshal(systemCredential{Token: credential.Token, Binding: binding})
		// secret-tool's stdin input is bounded to 8192 bytes.
		if len(payload) >= 8192 {
			return result, errors.New("credential is too large for the system store")
		}
		var id [32]byte
		if _, err := rand.Read(id[:]); err != nil {
			return result, err
		}
		credential.Storage, credential.SecretID = "system", hex.EncodeToString(id[:])
		if _, err := secretTool(ctx, "store", credential.SecretID, payload); err != nil {
			// A timed-out service may have committed before its reply was lost.
			_, _ = secretTool(context.Background(), "clear", credential.SecretID, nil)
			return result, err
		}
		credential.Token = ""
	}
	store.Credentials[name] = credential
	err = ctx.Err()
	if err == nil {
		err = writeCredentials(path, store)
	}
	if err != nil {
		// Directory sync can fail after the atomic rename committed. Preserve
		// the secret if the published metadata already refers to it.
		saved, readErr := LoadCredentials(path)
		if readErr == nil && saved.Credentials[name] == credential {
			result.Warning = "Credential saved, but filesystem durability could not be confirmed. "
		} else {
			if credential.Storage == "system" {
				if _, cleanupErr := secretTool(context.Background(), "clear", credential.SecretID, nil); cleanupErr != nil {
					return result, fmt.Errorf("%w; remove the unused Debuglet CLI entry from your desktop keyring", err)
				}
			}
			return result, err
		}
	}
	if previous.Storage == "system" {
		if _, err := secretTool(context.Background(), "clear", previous.SecretID, nil); err != nil {
			result.Warning += "Login saved, but an older system secret could not be removed. Remove the old Debuglet CLI entry from your desktop keyring."
		}
	}
	return result, nil
}

type systemCredential struct {
	Token   string `json:"token"`
	Binding string `json:"binding"`
}

func credentialBinding(path, name string, credential Credential) (string, error) {
	file, err := CredentialPath(path)
	if err != nil {
		return "", err
	}
	file, err = filepath.Abs(file)
	if err != nil {
		return "", err
	}
	data, _ := json.Marshal([]string{file, name, credential.Endpoint, credential.AccountID})
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:]), nil
}

func loadSystemCredential(ctx context.Context, path, name string, credential Credential) (string, error) {
	data, err := secretTool(ctx, "lookup", credential.SecretID, nil)
	if err != nil {
		return "", err
	}
	binding, err := credentialBinding(path, name, credential)
	if err != nil {
		return "", err
	}
	var secret systemCredential
	if json.Unmarshal(data, &secret) != nil || secret.Token == "" || secret.Binding != binding {
		return "", errors.New("system credential does not match this profile; run dbl login again")
	}
	return secret.Token, nil
}

func secretTool(ctx context.Context, operation, id string, input []byte) ([]byte, error) {
	path, err := secretToolPath()
	if err != nil {
		return nil, err
	}
	args := []string{operation}
	if operation == "store" {
		args = append(args, "--label=Debuglet CLI")
	}
	args = append(args, "application", "org.debuglet.cli", "credential", id)
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, path, args...)
	cmd.WaitDelay = time.Second
	cmd.Stdin = bytes.NewReader(input)
	cmd.Stderr = io.Discard
	output := boundedSecretOutput{}
	cmd.Stdout = &output
	if err := cmd.Run(); err != nil {
		// Utility diagnostics may contain secrets; do not expose them.
		return nil, errors.New("system credential store operation failed; unlock your desktop keyring and retry, or explicitly log in with --credential-store file")
	}
	return output.buffer.Bytes(), nil
}

type boundedSecretOutput struct{ buffer bytes.Buffer }

func (b *boundedSecretOutput) Write(p []byte) (int, error) {
	if b.buffer.Len()+len(p) > 8192 {
		return 0, errors.New("system credential response is too large")
	}
	return b.buffer.Write(p)
}
