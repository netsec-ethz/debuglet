// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package demo

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestIncompletePackageExplainsRecovery(t *testing.T) {
	for _, extra := range []string{"", "cfg", "bin/dispatcher"} {
		t.Run(extra, func(t *testing.T) {
			root := t.TempDir()
			if err := os.MkdirAll(filepath.Join(root, "bin"), 0700); err != nil {
				t.Fatal(err)
			}
			executable := filepath.Join(root, "bin", "dbl")
			if err := os.WriteFile(executable, []byte("built CLI"), 0700); err != nil {
				t.Fatal(err)
			}
			if extra != "" {
				if err := os.MkdirAll(filepath.Join(root, extra), 0700); err != nil {
					t.Fatal(err)
				}
			}
			_, err := ResolveAssets(executable)
			if err == nil {
				t.Fatal("accepted incomplete package")
			}
			for _, want := range []string{"not running from a complete installed package", root, "Local roles and --sample", "install the full bundle", "--wasm FILE"} {
				if !strings.Contains(err.Error(), want) {
					t.Fatalf("missing %q: %v", want, err)
				}
			}
		})
	}
}
