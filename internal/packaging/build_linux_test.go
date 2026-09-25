//go:build linux

package main

import (
	"context"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/netsec-ethz/debuglet/internal/artifact"
)

func TestGuestSamplesIndependentOfCandidateIdentity(t *testing.T) {
	if runtime.Version() != artifact.Toolchain || runtime.GOARCH != "amd64" {
		t.Skip("build requires the pinned toolchain on Linux amd64")
	}
	samples := map[string]string{}
	for name, pkg := range targets {
		if strings.HasSuffix(name, ".wasm") {
			samples[name] = pkg
		}
	}
	saved := targets
	targets = samples
	t.Cleanup(func() { targets = saved })
	t.Setenv("CI_COMMIT_TAG", "")
	t.Setenv("GO", "")
	t.Chdir(filepath.Join("..", ".."))
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	var records []buildRecord
	for _, sha := range []string{strings.Repeat("a", 40), strings.Repeat("b", 40)} {
		dist := t.TempDir()
		if err := build(ctx, dist, sha); err != nil {
			t.Fatal(err)
		}
		record, err := loadRecord(dist, sha)
		if err != nil {
			t.Fatal(err)
		}
		records = append(records, record)
	}
	if records[0].Metadata.Version == records[1].Metadata.Version {
		t.Fatalf("candidate versions coincide: %s", records[0].Metadata.Version)
	}
	for name := range samples {
		if records[0].Compiled[name] != records[1].Compiled[name] {
			t.Errorf("%s differs between candidates: %+v and %+v", name, records[0].Compiled[name], records[1].Compiled[name])
		}
	}
}
