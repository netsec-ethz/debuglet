package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDoctorFallbackDoesNotRequireBTF(t *testing.T) {
	for _, check := range executorHostChecks("", "fallback") {
		if check.ID == "btf" && (check.Status != "not_checked" || !strings.Contains(check.Detail, "not required")) {
			t.Fatalf("fallback unnecessarily requires BTF: %+v", check)
		}
	}
	for _, counter := range []string{"auto", "fallback"} {
		check := capabilityCheck(counter)
		if check.Status != "pass" && check.Status != "not_checked" {
			t.Fatalf("missing optional privileges must not reject %s: %+v", counter, check)
		}
		if !strings.Contains(check.Next, "no ") {
			t.Fatalf("capability observation claims readiness: %+v", check)
		}
	}
}

func TestDoctorUnwritableState(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0700) })
	checks := stateChecks(filepath.Join(dir, "executor.sqlite"))
	if checks[0].ID != "state_permissions" || checks[0].Status != "failure" || checks[0].Next == "" {
		t.Fatalf("unwritable state passed: %+v", checks)
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 0 {
		t.Fatal("permission check wrote state")
	}
}
