// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package main

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	apispec "github.com/netsec-ethz/debuglet/api"
)

func TestReleaseCompatibilityIdentifiesBothComponents(t *testing.T) {
	dist, out, record := packageFixture(t)
	if err := os.MkdirAll(out, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir("configs", 0700); err != nil {
		t.Fatal(err)
	}
	console := consoleSelection{Repository: "https://gitlab.inf.ethz.ch/OU-PERRIG/yimin/debuglet/debuglet-dashboard", Revision: strings.Repeat("b", 40)}
	if err := writeJSON("configs/release-compatibility.json", console); err != nil {
		t.Fatal(err)
	}
	if err := writeReleaseCompatibility(dist, out, record.Metadata.SourceSHA); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(out, "compatibility.json"))
	if err != nil {
		t.Fatal(err)
	}
	var got releaseCompatibility
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	if got.SchemaVersion != 1 || got.CoreVersion != record.Metadata.Version || got.CoreSourceSHA != record.Metadata.SourceSHA || got.CoreAPIVersion != apispec.Version || got.OpenAPISHA256 != fmt.Sprintf("%x", sha256.Sum256(apispec.OpenAPI)) || got.consoleSelection != console {
		t.Fatalf("wrong compatibility identity: %+v", got)
	}
	sums, err := os.ReadFile(filepath.Join(out, "SHA256SUMS-compatibility"))
	if err != nil || string(sums) != fmt.Sprintf("%x  compatibility.json\n", sha256.Sum256(data)) {
		t.Fatalf("sidecar checksum: %q, %v", sums, err)
	}
	if err := writeReleaseCompatibility(dist, out, strings.Repeat("c", 40)); err == nil {
		t.Fatal("sidecar accepted a different core source")
	}
	for _, revision := range []string{"main", strings.Repeat("0", 40), ""} {
		console.Revision = revision
		if err := writeJSON("configs/release-compatibility.json", console); err != nil {
			t.Fatal(err)
		}
		if err := writeReleaseCompatibility(dist, out, record.Metadata.SourceSHA); err == nil {
			t.Fatalf("accepted ambiguous console revision %q", revision)
		}
	}
}
