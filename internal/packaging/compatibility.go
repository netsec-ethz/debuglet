// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	apispec "github.com/netsec-ethz/debuglet/api"
	"github.com/netsec-ethz/debuglet/internal/artifact"
)

type consoleSelection struct {
	Repository string `json:"console_repository"`
	Revision   string `json:"console_revision"`
}

type releaseCompatibility struct {
	SchemaVersion  int    `json:"schema_version"`
	CoreVersion    string `json:"core_version"`
	CoreSourceSHA  string `json:"core_source_sha"`
	CoreAPIVersion string `json:"core_api_version"`
	OpenAPISHA256  string `json:"core_openapi_sha256"`
	consoleSelection
}

// Keep the independently shipped console selection beside the package, not
// inside the core binary manifest. This records a pair for release review;
// it does not download the console or assert that acceptance checks passed.
func writeReleaseCompatibility(dist, out, sha string) error {
	record, err := loadRecord(dist, sha)
	if err != nil {
		return err
	}
	data, err := os.ReadFile("configs/release-compatibility.json")
	if err != nil {
		return err
	}
	var console consoleSelection
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&console); err != nil {
		return fmt.Errorf("console release selection: %w", err)
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return errors.New("console release selection must contain one JSON object")
	}
	if console.Repository != "https://gitlab.inf.ethz.ch/OU-PERRIG/yimin/debuglet/debuglet-dashboard" || !artifact.ValidSourceSHA(console.Revision) || console.Revision == strings.Repeat("0", 40) {
		return errors.New("console release selection requires the console repository and exact reviewed commit")
	}
	value := releaseCompatibility{SchemaVersion: 1, CoreVersion: record.Metadata.Version,
		CoreSourceSHA: record.Metadata.SourceSHA, CoreAPIVersion: apispec.Version,
		OpenAPISHA256: fmt.Sprintf("%x", sha256.Sum256(apispec.OpenAPI)), consoleSelection: console}
	path := filepath.Join(out, "compatibility.json")
	if err := writeJSON(path, value); err != nil {
		return err
	}
	file, err := artifact.HashFile(path)
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(out, "SHA256SUMS-compatibility"), []byte(file.SHA256+"  compatibility.json\n"), 0644)
}
