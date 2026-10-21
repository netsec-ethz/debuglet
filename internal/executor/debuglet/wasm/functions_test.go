// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package wasm

import (
	"testing"

	"github.com/netsec-ethz/debuglet/internal/guestio"
)

func TestAdvertisedHostFunctionsAreExported(t *testing.T) {
	exports := make(map[string]bool)
	for _, f := range Functions(nil) {
		exports[f.Module+"."+f.Name] = true
	}
	for _, name := range guestio.SupportedHostFunctions() {
		if !exports[name] {
			t.Errorf("advertised function %s is not exported", name)
		}
	}
}
