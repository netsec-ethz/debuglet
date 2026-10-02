// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package connections

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func fixtureSecretTool(t *testing.T) string {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("Secret Service integration is supported on Linux")
	}
	dir := t.TempDir()
	tool := `#!/bin/sh
set -eu
for id do :; done
printf '%s\n' "$@" >> "$SECRET_TOOL_FIXTURE/args"
if [ "${SECRET_TOOL_FAIL:-}" = "$1" ]; then
  printf 'fixture-secret-must-not-leak' >&2
  exit 1
fi
case "$1" in
  store)
    cat > "$SECRET_TOOL_FIXTURE/$id"
    if [ -n "${SECRET_TOOL_BLOCK_METADATA:-}" ]; then mkdir "$SECRET_TOOL_BLOCK_METADATA"; fi
    ;;
  lookup) cat "$SECRET_TOOL_FIXTURE/$id" ;;
  clear) rm -f "$SECRET_TOOL_FIXTURE/$id" ;;
esac
`
	if err := os.WriteFile(filepath.Join(dir, "secret-tool"), []byte(tool), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("DBUS_SESSION_BUS_ADDRESS", "unix:path=/test-owned-session")
	t.Setenv("SECRET_TOOL_FIXTURE", dir)
	return dir
}

func TestCredentialStorageSelection(t *testing.T) {
	t.Setenv("DBUS_SESSION_BUS_ADDRESS", "")
	for _, mode := range []string{"auto", "file"} {
		storage, err := ResolveCredentialStorage(mode)
		if err != nil || storage != "file" {
			t.Fatalf("headless %s: %s %v", mode, storage, err)
		}
	}
	for _, mode := range []string{"system", "unknown"} {
		if _, err := ResolveCredentialStorage(mode); err == nil {
			t.Fatalf("accepted unavailable store %q", mode)
		}
	}
	fixtureSecretTool(t)
	if storage, err := ResolveCredentialStorage("auto"); err != nil || storage != "system" {
		t.Fatalf("desktop auto: %s %v", storage, err)
	}
}

func TestSystemCredentialLifecycleAndIsolation(t *testing.T) {
	dir := fixtureSecretTool(t)
	config := credTestConfig(t)
	credential := Credential{Endpoint: credTestEndpoint, Token: credTestToken, AccountID: "alice"}
	if _, err := SaveCredentialWithStorage(t.Context(), config, "local", credential, "system"); err != nil {
		t.Fatal(err)
	}
	store, err := LoadCredentials(config)
	if err != nil || store.SchemaVersion != 2 || store.Credentials["local"].Token != "" {
		t.Fatalf("system metadata: %+v %v", store, err)
	}
	file, _ := CredentialPath(config)
	data, _ := os.ReadFile(file)
	args, _ := os.ReadFile(filepath.Join(dir, "args"))
	if strings.Contains(string(data)+string(args), credTestToken) || strings.Contains(string(args), credTestEndpoint) {
		t.Fatal("credential or endpoint leaked to file/utility arguments")
	}
	got, err := CredentialFor(t.Context(), config, "local", credTestEndpoint)
	if err != nil || got.Token != credTestToken {
		t.Fatalf("saved system credential: %v", err)
	}
	if _, err := CredentialFor(t.Context(), config, "local", credTestOther); err == nil {
		t.Fatal("system credential offered to another dispatcher")
	}
	store.Credentials["copied"] = store.Credentials["local"]
	if err := writeCredentials(config, store); err != nil {
		t.Fatal(err)
	}
	if _, err := CredentialFor(t.Context(), config, "copied", credTestEndpoint); err == nil {
		t.Fatal("system credential reference transferred across profiles")
	}
	delete(store.Credentials, "copied")
	if err := writeCredentials(config, store); err != nil {
		t.Fatal(err)
	}
	oldID := store.Credentials["local"].SecretID
	credential.Token = "replacement-token"
	if result, err := SaveCredentialWithStorage(t.Context(), config, "local", credential, "system"); err != nil || result.Warning != "" {
		t.Fatalf("replacement: %+v %v", result, err)
	}
	if _, err := os.Stat(filepath.Join(dir, oldID)); !os.IsNotExist(err) {
		t.Fatal("old system secret retained")
	}
	if err := RemoveCredential(config, "local"); err != nil {
		t.Fatal(err)
	}
	got, err = CredentialFor(t.Context(), config, "local", credTestEndpoint)
	if err != nil || got.Token != "" {
		t.Fatal("logout retained a credential")
	}
	entries, _ := os.ReadDir(dir)
	for _, entry := range entries {
		if len(entry.Name()) == 64 {
			t.Fatal("logout left a system secret")
		}
	}
}

func TestSystemCredentialFailuresPreserveSavedLogin(t *testing.T) {
	dir := fixtureSecretTool(t)
	config, _ := savedCredential(t)
	t.Setenv("SECRET_TOOL_FAIL", "store")
	if _, err := SaveCredentialWithStorage(t.Context(), config, "local", Credential{Endpoint: credTestEndpoint, Token: "new-token"}, "system"); err == nil || strings.Contains(err.Error(), "fixture-secret") {
		t.Fatalf("failed store diagnostics: %v", err)
	}
	got, err := CredentialFor(t.Context(), config, "local", credTestEndpoint)
	if err != nil || got.Token != credTestToken {
		t.Fatal("failed system write changed previous login")
	}
	t.Setenv("SECRET_TOOL_FAIL", "")
	if _, err := SaveCredentialWithStorage(t.Context(), config, "local", Credential{Endpoint: credTestEndpoint, Token: "new-token"}, "system"); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SECRET_TOOL_FAIL", "lookup")
	if _, err := CredentialFor(t.Context(), config, "local", credTestEndpoint); err == nil {
		t.Fatal("unavailable keyring silently fell back")
	}
	t.Setenv("SECRET_TOOL_FAIL", "clear")
	result, err := SaveCredentialWithStorage(t.Context(), config, "local", Credential{Endpoint: credTestEndpoint, Token: "file-token"}, "file")
	if err != nil || result.Warning == "" {
		t.Fatalf("cleanup failure invalidated committed login: %+v %v", result, err)
	}
	got, err = CredentialFor(t.Context(), config, "local", credTestEndpoint)
	if err != nil || got.Token != "file-token" {
		t.Fatal("cleanup failure left new login unreadable")
	}
	args, _ := os.ReadFile(filepath.Join(dir, "args"))
	if strings.Contains(string(args), "new-token") {
		t.Fatal("secret leaked to command arguments")
	}
}

func TestSystemCredentialCleansUpWhenMetadataCannotBeWritten(t *testing.T) {
	dir := fixtureSecretTool(t)
	config := filepath.Join(t.TempDir(), "config.json")
	file, _ := CredentialPath(config)
	t.Setenv("SECRET_TOOL_BLOCK_METADATA", file)
	if _, err := SaveCredentialWithStorage(t.Context(), config, "local", Credential{Endpoint: credTestEndpoint, Token: credTestToken}, "system"); err == nil {
		t.Fatal("metadata failure accepted")
	}
	entries, _ := os.ReadDir(dir)
	for _, entry := range entries {
		if len(entry.Name()) == 64 {
			t.Fatal("failed metadata write orphaned a system secret")
		}
	}
}

func TestSystemCredentialLookupCancellationAndOversizeOutput(t *testing.T) {
	dir := fixtureSecretTool(t)
	config := credTestConfig(t)
	if _, err := SaveCredentialWithStorage(t.Context(), config, "local", Credential{Endpoint: credTestEndpoint, Token: credTestToken}, "system"); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := CredentialFor(ctx, config, "local", credTestEndpoint); err == nil {
		t.Fatal("cancelled credential lookup succeeded")
	}
	store, _ := LoadCredentials(config)
	item := filepath.Join(dir, store.Credentials["local"].SecretID)
	if err := os.WriteFile(item, []byte(strings.Repeat("x", 16384)), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := CredentialFor(t.Context(), config, "local", credTestEndpoint); err == nil {
		t.Fatal("oversized system response accepted")
	}
}
