// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package service

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/netsec-ethz/debuglet/internal/demo"
	"github.com/netsec-ethz/debuglet/internal/storagecheck"
)

func TestServiceInvalidatesForegroundBackupReceipt(t *testing.T) {
	for _, action := range []string{"install", "start"} {
		for _, blocked := range []bool{false, true} {
			name := action
			if blocked {
				name += " blocked"
			}
			t.Run(name, func(t *testing.T) {
				f := newFixture(t)
				if _, err := f.install(storagecheck.Executor, "worker", false); err != nil {
					t.Fatal(err)
				}
				marker := filepath.Join(StateDirectory(f.root, storagecheck.Executor, "worker"), demo.OfflineStateFile)
				if blocked {
					if err := os.Mkdir(marker, 0700); err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(filepath.Join(marker, "keep"), []byte("unrelated"), 0600); err != nil {
						t.Fatal(err)
					}
				} else if err := os.WriteFile(marker, []byte("restored foreground receipt"), 0600); err != nil {
					t.Fatal(err)
				}
				before := len(f.manager.recorded())
				var err error
				if action == "install" {
					_, err = f.install(storagecheck.Executor, "worker", true)
				} else {
					_, err = f.installer.Start(context.Background(), storagecheck.Executor, "worker")
				}
				if blocked {
					if err == nil {
						t.Fatal("started service despite receipt invalidation failure")
					}
					for _, call := range f.manager.recorded()[before:] {
						if strings.HasPrefix(call, "start ") {
							t.Fatalf("manager started despite refusal: %s", call)
						}
					}
					data, readErr := os.ReadFile(filepath.Join(marker, "keep"))
					if readErr != nil || string(data) != "unrelated" {
						t.Fatal("removed unowned receipt contents")
					}
				} else {
					if err != nil {
						t.Fatal(err)
					}
					if _, err := os.Stat(marker); !errors.Is(err, os.ErrNotExist) {
						t.Fatalf("service kept foreground receipt: %v", err)
					}
				}
			})
		}
	}
}
